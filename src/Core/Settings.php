<?php

declare(strict_types=1);

namespace Fellowship\Core;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Fellowship's configuration, split across two option rows.
 *
 * <b>Why two.</b> `fellowship_settings` holds values that are public by
 * nature — an OAuth client id is published in the app binary anyway, and
 * a retention window is not a secret. `fellowship_secrets` holds the
 * client secrets, the FCM service-account JSON and Link's log-shipping
 * token, each encrypted at rest with {@see Cipher}. Keeping them apart means a settings export,
 * a debug dump or a support screenshot of the public row cannot leak a
 * credential, and it makes the answer to "is this safe to show?" a
 * property of where the value lives rather than of who remembered.
 *
 * Both rows are autoload-false: they are read on REST and admin
 * requests, not on every front-end page view.
 */
final class Settings
{
    public const OPTION_PUBLIC = 'fellowship_settings';
    public const OPTION_SECRETS = 'fellowship_secrets';

    private const CIPHER_DOMAIN = 'fellowship-secrets';

    /** Default days a message is kept before the sweep removes it. */
    public const DEFAULT_RETENTION_DAYS = 180;

    private readonly Cipher $cipher;

    public function __construct(?Cipher $cipher = null)
    {
        $this->cipher = $cipher ?? new Cipher(self::CIPHER_DOMAIN);
    }

    public function getClientId(string $provider): string
    {
        return $this->publicString('client_id_' . $this->normaliseProvider($provider));
    }

    public function setClientId(string $provider, string $value): void
    {
        $this->writePublic('client_id_' . $this->normaliseProvider($provider), trim($value));
    }

    public function getClientSecret(string $provider): string
    {
        $stored = $this->secretString('client_secret_' . $this->normaliseProvider($provider));
        return $stored === '' ? '' : $this->cipher->decrypt($stored);
    }

    public function setClientSecret(string $provider, string $value): void
    {
        $key = 'client_secret_' . $this->normaliseProvider($provider);
        $value = trim($value);
        $this->writeSecret($key, $value === '' ? '' : $this->cipher->encrypt($value));
    }

    /**
     * The Firebase service-account JSON used to push. Empty means
     * Fellowship cannot push at all, which is a configuration fault
     * rather than a per-handset one — see
     * {@see \Fellowship\Push\FcmTransport}.
     */
    public function getFcmServiceAccount(): string
    {
        $stored = $this->secretString('fcm_service_account');
        return $stored === '' ? '' : $this->cipher->decrypt($stored);
    }

    public function setFcmServiceAccount(string $value): void
    {
        $value = trim($value);
        $this->writeSecret('fcm_service_account', $value === '' ? '' : $this->cipher->encrypt($value));
    }

    /**
     * How many days a message is kept before the daily sweep deletes it
     * and its recipient rows.
     *
     * Zero means "keep indefinitely", which is a deliberate option and
     * not the default: message bodies are fellowship business held
     * against named members, and a retention window that somebody chose
     * is easier to defend under GDPR than one nobody did.
     */
    public function getRetentionDays(): int
    {
        $all = get_option(self::OPTION_PUBLIC, []);
        if (!is_array($all) || !isset($all['retention_days'])) {
            return self::DEFAULT_RETENTION_DAYS;
        }

        $days = (int) $all['retention_days'];
        return $days >= 0 ? $days : self::DEFAULT_RETENTION_DAYS;
    }

    public function setRetentionDays(int $days): void
    {
        $this->writePublic('retention_days', (string) max(0, $days));
    }

    /**
     * Whether a handset may compose to a whole committee, as opposed to
     * only replying and messaging individuals.
     *
     * Off by default. Sending to a committee from a phone is a wider
     * reach than most members need, and the failure mode of getting it
     * wrong — a private message fanned out to a committee — is not one
     * that can be taken back.
     */
    public function allowsCommitteeSendFromApp(): bool
    {
        $all = get_option(self::OPTION_PUBLIC, []);
        return is_array($all) && !empty($all['app_committee_send']);
    }

    public function setCommitteeSendFromApp(bool $enabled): void
    {
        $all = get_option(self::OPTION_PUBLIC, []);
        if (!is_array($all)) {
            $all = [];
        }

        if ($enabled) {
            $all['app_committee_send'] = true;
        } else {
            unset($all['app_committee_send']);
        }

        update_option(self::OPTION_PUBLIC, $all, false);
    }

    /**
     * Where Link ships its logs: Better Stack's HTTP ingest endpoint.
     *
     * Not a secret — it names a region and a source, not a credential —
     * so it lives in the public row beside the client ids. Empty means
     * handsets are not asked to ship at all.
     */
    public function getLogEndpoint(): string
    {
        return $this->publicString('log_endpoint');
    }

    /**
     * Stores the endpoint as {@see self::normaliseLogEndpoint()} left it.
     * Callers validate first; a value that would not survive that is not
     * something to store quietly.
     */
    public function setLogEndpoint(string $value): void
    {
        $this->writePublic('log_endpoint', self::normaliseLogEndpoint($value) ?? '');
    }

    /**
     * The Better Stack source token handed to enrolled handsets.
     *
     * With the secrets rather than the public row although Better Stack
     * treats it as write-only: it cannot read a log back, but it can fill
     * the source with anything and spend its quota doing so. The whole
     * reason it is here rather than in the app is that it reaches only
     * handsets that have signed in.
     */
    public function getLogSourceToken(): string
    {
        $stored = $this->secretString('log_source_token');
        return $stored === '' ? '' : $this->cipher->decrypt($stored);
    }

    public function setLogSourceToken(string $value): void
    {
        $value = trim($value);
        $this->writeSecret('log_source_token', $value === '' ? '' : $this->cipher->encrypt($value));
    }

    /**
     * An endpoint as it should be stored, or null when it must be refused.
     *
     * Better Stack's dashboard shows the ingest address as a bare host
     * name, so that is what gets pasted; it is given `https://`. An
     * explicit `http://` is refused rather than upgraded: the token rides
     * every batch as a bearer header, and a value that says plain HTTP is
     * a mistake to point out, not one to correct behind somebody's back.
     * Link applies the same rule on its side and ships nothing to an
     * endpoint that fails it.
     */
    public static function normaliseLogEndpoint(string $value): ?string
    {
        $value = trim($value);
        if ($value === '') {
            return '';
        }

        if (!str_contains($value, '://')) {
            $value = 'https://' . $value;
        }

        $parts = parse_url($value);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || ($parts['host'] ?? '') === '') {
            return null;
        }

        return rtrim($value, '/');
    }

    private function publicString(string $key): string
    {
        $all = get_option(self::OPTION_PUBLIC, []);
        return is_array($all) && isset($all[$key]) && is_string($all[$key]) ? $all[$key] : '';
    }

    private function secretString(string $key): string
    {
        $all = get_option(self::OPTION_SECRETS, []);
        return is_array($all) && isset($all[$key]) && is_string($all[$key]) ? $all[$key] : '';
    }

    private function writePublic(string $key, string $value): void
    {
        $all = get_option(self::OPTION_PUBLIC, []);
        if (!is_array($all)) {
            $all = [];
        }

        if ($value === '') {
            unset($all[$key]);
        } else {
            $all[$key] = $value;
        }

        update_option(self::OPTION_PUBLIC, $all, false);
    }

    private function writeSecret(string $key, string $value): void
    {
        $all = get_option(self::OPTION_SECRETS, []);
        if (!is_array($all)) {
            $all = [];
        }

        if ($value === '') {
            unset($all[$key]);
        } else {
            $all[$key] = $value;
        }

        update_option(self::OPTION_SECRETS, $all, false);
    }

    private function normaliseProvider(string $provider): string
    {
        return preg_replace('/[^a-z0-9_]/', '', strtolower($provider)) ?? '';
    }
}
