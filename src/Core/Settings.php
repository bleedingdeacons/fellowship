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
 * client secrets and the FCM service-account JSON, each encrypted at
 * rest with {@see Cipher}. Keeping them apart means a settings export,
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
