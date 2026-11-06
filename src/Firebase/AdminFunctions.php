<?php

declare(strict_types=1);

namespace Fellowship\Firebase;

if (!defined('ABSPATH')) {
    exit;
}

use Closure;
use Fellowship\Core\UserAgent;
use Fellowship\Logger\HasLogger;
use Fellowship\Push\ServiceAccount;

/**
 * Calls the `admin*` Cloud Functions, as the service account.
 *
 * Google checks the caller's ID token before any code runs, because these functions
 * can only be invoked by that account.
 */
final class AdminFunctions
{
    use HasLogger;

    /** Where the Functions are deployed. Firestore's region can't change either. */
    private const REGION = 'europe-west2';

    private const TIMEOUT_SECONDS = 15;

    /** @var Closure(): ?ServiceAccount */
    private readonly Closure $account;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    /** @param callable(): ?ServiceAccount $account Read per call. */
    public function __construct(callable $account, private readonly GoogleTokens $tokens)
    {
        $this->account = Closure::fromCallable($account);
    }

    public function isConfigured(): bool
    {
        return ($this->account)() !== null;
    }

    /**
     * Cut off every device a member has.
     *
     * @param bool $remove Remove the devices rather than only revoke them, for an erasure.
     *
     * @throws FirebaseUnavailable When the function couldn't be called or refused.
     */
    public function revokeMember(int $memberId, bool $remove = false): void
    {
        $this->call('adminRevokeMember', ['memberId' => $memberId, 'remove' => $remove]);
    }

    /**
     * @param array<string, mixed> $data
     *
     * @return array<mixed>
     *
     * @throws FirebaseUnavailable When the function couldn't be called or refused.
     */
    private function call(string $function, array $data): array
    {
        $account = ($this->account)();
        if ($account === null) {
            throw new FirebaseUnavailable('No service account is configured.');
        }

        $url = 'https://' . self::REGION . '-' . rawurlencode($account->projectId)
            . '.cloudfunctions.net/' . rawurlencode($function);

        $token = $this->tokens->idToken($account, $url);
        if ($token === '') {
            throw new FirebaseUnavailable('No Google ID token could be had.');
        }

        $response = wp_remote_post($url, [
            'timeout'    => self::TIMEOUT_SECONDS,
            'user-agent' => UserAgent::plugin(),
            'headers'    => [
                'Authorization' => 'Bearer ' . $token,
                'Content-Type'  => 'application/json; charset=utf-8',
            ],
            'body'       => (string) wp_json_encode($data),
        ]);

        if (is_wp_error($response)) {
            self::logWarning('An admin function could not be reached', [
                'function' => $function,
                'error'    => $response->get_error_message(),
            ]);
            throw new FirebaseUnavailable('An admin function could not be reached.');
        }

        $status = (int) wp_remote_retrieve_response_code($response);
        $body = json_decode((string) wp_remote_retrieve_body($response), true);

        if ($status < 200 || $status >= 300) {
            self::logWarning('An admin function refused a call', [
                'function' => $function,
                'status'   => $status,
                'reason'   => is_array($body) ? (string) ($body['reason'] ?? '') : '',
            ]);
            throw new FirebaseUnavailable('An admin function answered ' . $status . '.');
        }

        return is_array($body) ? $body : [];
    }
}
