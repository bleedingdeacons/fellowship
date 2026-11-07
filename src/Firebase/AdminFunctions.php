<?php

declare(strict_types=1);

namespace Fellowship\Firebase;

if (!defined('ABSPATH')) {
    exit;
}

use Closure;
use Fellowship\Core\UserAgent;
use Fellowship\Logger\HasLogger;
use Fellowship\Messaging\MessageDelivery;
use Fellowship\Push\ServiceAccount;

/**
 * Calls the `admin*` Cloud Functions, as the service account.
 *
 * Google checks the caller's ID token before any code runs, because these functions
 * can only be invoked by that account.
 */
final class AdminFunctions implements MessageDelivery
{
    use HasLogger;

    /** Where the Functions are deployed. Firestore's region can't change either. */
    private const REGION = 'europe-west2';

    /**
     * Long enough for a cold start, and for resolving an audience, which calls back
     * into this site.
     */
    private const TIMEOUT_SECONDS = 30;

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
     * Cut one device off and keep its record.
     *
     * @throws FirebaseUnavailable When the function couldn't be called or refused.
     */
    public function revoke(string $deviceId): void
    {
        $this->call('adminRevoke', ['deviceId' => $deviceId]);
    }

    /**
     * Delete one device's record and its inbox.
     *
     * @throws FirebaseUnavailable When the function couldn't be called or refused.
     */
    public function remove(string $deviceId): void
    {
        $this->call('adminRemove', ['deviceId' => $deviceId]);
    }

    public function resolve(array $audience): array
    {
        $answer = $this->call('adminResolve', $audience);

        $devices = [];
        foreach (is_array($answer['devices'] ?? null) ? $answer['devices'] : [] as $device) {
            if (is_array($device) && is_string($device['deviceId'] ?? null) && is_string($device['publicKey'] ?? null)) {
                $devices[] = ['deviceId' => $device['deviceId'], 'publicKey' => $device['publicKey']];
            }
        }

        return [
            'id'      => is_int($answer['id'] ?? null) ? $answer['id'] : 0,
            'members' => is_int($answer['members'] ?? null) ? $answer['members'] : 0,
            'devices' => $devices,
        ];
    }

    public function deliver(array $audience, int $id, array $envelopes): int
    {
        $answer = $this->call('adminSend', $audience + ['id' => $id, 'envelopes' => $envelopes]);

        return is_int($answer['reachable'] ?? null) ? $answer['reachable'] : 0;
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
            $reason = is_array($body) && is_string($body['reason'] ?? null) ? $body['reason'] : '';

            self::logWarning('An admin function refused a call', [
                'function' => $function,
                'status'   => $status,
                'reason'   => $reason,
            ]);

            throw new FirebaseUnavailable(
                'An admin function answered ' . $status . '.',
                $reason,
                is_array($body) && is_string($body['message'] ?? null) ? $body['message'] : '',
            );
        }

        return is_array($body) ? $body : [];
    }
}
