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
 * Reads and writes Firestore over REST, as the service account.
 *
 * <b>This bypasses the security rules</b>, because the service account does. So
 * only Fellowship's own code calls it, with paths it built itself.
 *
 * Nothing about a member goes in. Devices are opaque ids and member ids, and the
 * member list stays in WordPress.
 */
final class FirestoreClient
{
    use HasLogger;

    private const TIMEOUT_SECONDS = 10;

    /** @var Closure(): ?ServiceAccount */
    private readonly Closure $account;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    /**
     * @param callable(): ?ServiceAccount $account Read per call, so a replaced
     *                                             service account takes effect
     *                                             without a restart.
     */
    public function __construct(callable $account, private readonly GoogleTokens $tokens)
    {
        $this->account = Closure::fromCallable($account);
    }

    public function isConfigured(): bool
    {
        return ($this->account)() !== null;
    }

    /**
     * One document's fields, or null when it doesn't exist.
     *
     * @return array<string, mixed>|null
     *
     * @throws FirebaseUnavailable When Firestore couldn't be asked.
     */
    public function get(string $path): ?array
    {
        [$status, $body] = $this->request('GET', $this->documentUrl($path), null);

        if ($status === 404) {
            return null;
        }

        if ($status !== 200 || !is_array($body)) {
            throw $this->unavailable('read', $status);
        }

        return self::decodeFields($body['fields'] ?? []);
    }

    /**
     * Write these integer fields, leaving the document's others alone.
     *
     * @param array<string, int> $fields
     *
     * @throws FirebaseUnavailable When Firestore couldn't be asked.
     */
    public function setIntegers(string $path, array $fields): void
    {
        $query = implode('&', array_map(
            static fn(string $name): string => 'updateMask.fieldPaths=' . rawurlencode($name),
            array_keys($fields),
        ));

        $encoded = [];
        foreach ($fields as $name => $value) {
            $encoded[$name] = ['integerValue' => (string) $value];
        }

        [$status] = $this->request('PATCH', $this->documentUrl($path) . '?' . $query, ['fields' => $encoded]);

        if ($status !== 200) {
            throw $this->unavailable('write', $status);
        }
    }

    /**
     * A page of a collection, newest first by this field.
     *
     * @param list<string> $fields Which to fetch.
     *
     * @return list<array{id: string, fields: array<string, mixed>}>
     *
     * @throws FirebaseUnavailable When Firestore couldn't be asked.
     */
    public function query(string $collection, array $fields, string $newestBy, int $limit, int $offset): array
    {
        $account = ($this->account)();
        if ($account === null) {
            throw new FirebaseUnavailable('No service account is configured.');
        }

        [$status, $body] = $this->request(
            'POST',
            $this->root($account) . ':runQuery',
            [
                'structuredQuery' => [
                    'from'    => [['collectionId' => $collection]],
                    'select'  => ['fields' => array_map(
                        static fn(string $field): array => ['fieldPath' => $field],
                        $fields,
                    )],
                    'orderBy' => [['field' => ['fieldPath' => $newestBy], 'direction' => 'DESCENDING']],
                    'limit'   => $limit,
                    'offset'  => $offset,
                ],
            ],
        );

        if ($status !== 200 || !is_array($body)) {
            throw $this->unavailable('query', $status);
        }

        $rows = [];
        foreach ($body as $row) {
            $document = is_array($row) ? ($row['document'] ?? null) : null;
            if (!is_array($document) || !is_string($document['name'] ?? null)) {
                continue;
            }

            $rows[] = [
                'id'     => substr((string) strrchr('/' . $document['name'], '/'), 1),
                'fields' => self::decodeFields($document['fields'] ?? []),
            ];
        }

        return $rows;
    }

    /** A Firestore timestamp as Unix seconds, or 0 when there isn't one. */
    public static function epoch(mixed $timestamp): int
    {
        if (!is_string($timestamp) || $timestamp === '') {
            return 0;
        }

        $epoch = strtotime($timestamp);

        return $epoch === false ? 0 : $epoch;
    }

    /**
     * The member id of every live device.
     *
     * @return list<int>
     *
     * @throws FirebaseUnavailable When Firestore couldn't be asked.
     */
    public function liveDeviceMemberIds(): array
    {
        $account = ($this->account)();
        if ($account === null) {
            return [];
        }

        [$status, $body] = $this->request(
            'POST',
            $this->root($account) . ':runQuery',
            [
                'structuredQuery' => [
                    'from'   => [['collectionId' => 'devices']],
                    'select' => ['fields' => [['fieldPath' => 'memberId']]],
                    'where'  => [
                        'fieldFilter' => [
                            'field' => ['fieldPath' => 'status'],
                            'op'    => 'EQUAL',
                            'value' => ['stringValue' => 'live'],
                        ],
                    ],
                ],
            ],
        );

        if ($status !== 200 || !is_array($body)) {
            throw $this->unavailable('query', $status);
        }

        $ids = [];
        foreach ($body as $row) {
            $document = is_array($row) ? ($row['document'] ?? null) : null;
            if (!is_array($document)) {
                continue;
            }

            $memberId = self::decodeFields($document['fields'] ?? [])['memberId'] ?? null;
            if (is_int($memberId) && $memberId > 0) {
                $ids[] = $memberId;
            }
        }

        return $ids;
    }

    /**
     * @param array<string, mixed>|null $json
     *
     * @return array{0: int, 1: mixed}
     *
     * @throws FirebaseUnavailable When there is no way to ask.
     */
    private function request(string $method, string $url, ?array $json): array
    {
        $account = ($this->account)();
        if ($account === null) {
            throw new FirebaseUnavailable('No service account is configured.');
        }

        $token = $this->tokens->accessToken($account, GoogleTokens::DATASTORE_SCOPE);
        if ($token === '') {
            throw new FirebaseUnavailable('No Google access token could be had.');
        }

        $args = [
            'method'     => $method,
            'timeout'    => self::TIMEOUT_SECONDS,
            'user-agent' => UserAgent::plugin(),
            'headers'    => [
                'Authorization' => 'Bearer ' . $token,
                'Content-Type'  => 'application/json; charset=utf-8',
            ],
        ];
        if ($json !== null) {
            $args['body'] = (string) wp_json_encode($json);
        }

        $response = wp_remote_request($url, $args);

        if (is_wp_error($response)) {
            self::logWarning('Firestore could not be reached', ['error' => $response->get_error_message()]);
            throw new FirebaseUnavailable('Firestore could not be reached.');
        }

        return [
            (int) wp_remote_retrieve_response_code($response),
            json_decode((string) wp_remote_retrieve_body($response), true),
        ];
    }

    private function unavailable(string $action, int $status): FirebaseUnavailable
    {
        self::logWarning('Firestore refused a request', ['action' => $action, 'status' => $status]);

        return new FirebaseUnavailable('Firestore answered ' . $status . ' to a ' . $action . '.');
    }

    /** @throws FirebaseUnavailable When no service account is configured. */
    private function documentUrl(string $path): string
    {
        $account = ($this->account)();
        if ($account === null) {
            throw new FirebaseUnavailable('No service account is configured.');
        }

        $segments = array_map('rawurlencode', explode('/', $path));

        return $this->root($account) . '/' . implode('/', $segments);
    }

    private function root(ServiceAccount $account): string
    {
        return 'https://firestore.googleapis.com/v1/projects/' . rawurlencode($account->projectId)
            . '/databases/(default)/documents';
    }

    /**
     * Firestore's typed values, as plain PHP.
     *
     * @return array<string, mixed>
     */
    private static function decodeFields(mixed $fields): array
    {
        if (!is_array($fields)) {
            return [];
        }

        $decoded = [];
        foreach ($fields as $name => $value) {
            if (is_array($value)) {
                $decoded[(string) $name] = self::decodeValue($value);
            }
        }

        return $decoded;
    }

    /** @param array<mixed> $value */
    private static function decodeValue(array $value): mixed
    {
        return match (true) {
            array_key_exists('integerValue', $value)   => (int) $value['integerValue'],
            array_key_exists('stringValue', $value)    => (string) $value['stringValue'],
            array_key_exists('booleanValue', $value)   => (bool) $value['booleanValue'],
            array_key_exists('doubleValue', $value)    => (float) $value['doubleValue'],
            array_key_exists('timestampValue', $value) => (string) $value['timestampValue'],
            default                                    => null,
        };
    }
}
