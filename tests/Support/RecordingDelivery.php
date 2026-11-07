<?php

declare(strict_types=1);

namespace Fellowship\Tests\Support;

use Fellowship\Firebase\FirebaseUnavailable;
use Fellowship\Messaging\MessageDelivery;

/**
 * The far side of a send, as far as WordPress can tell.
 *
 * Refuses an audience naming nobody, as the real one does, because that refusal is
 * what stops a request naming nobody becoming a broadcast.
 */
final class RecordingDelivery implements MessageDelivery
{
    /** @var list<array{deviceId: string, publicKey: string}> */
    public array $devices = [];

    /** @var list<array<string, mixed>> */
    public array $resolved = [];

    /** @var list<array{audience: array<string, mixed>, id: int, envelopes: list<array{deviceId: string, k: string, p: string}>}> */
    public array $delivered = [];

    /** @var list<FirebaseUnavailable> Thrown in turn by {@see deliver()}. */
    public array $deliverFailures = [];

    public ?FirebaseUnavailable $resolveFailure = null;

    public int $nextId = 1837075327412518;

    public function __construct(?string $publicKey = null)
    {
        $this->devices = [['deviceId' => 'd_sue', 'publicKey' => $publicKey ?? self::publicKey()]];
    }

    public function resolve(array $audience): array
    {
        $this->resolved[] = $audience;

        if ($this->resolveFailure !== null) {
            throw $this->resolveFailure;
        }

        $named = ($audience['everyone'] ?? false) === true
            || ($audience['memberIds'] ?? []) !== []
            || ($audience['committees'] ?? []) !== []
            || ($audience['gsrs'] ?? false) === true;

        if (!$named) {
            throw new FirebaseUnavailable('Refused.', 'fellowship_no_audience', 'Choose who this message is for.');
        }

        return ['id' => $this->nextId++, 'members' => count($this->devices), 'devices' => $this->devices];
    }

    public function deliver(array $audience, int $id, array $envelopes): int
    {
        if ($this->deliverFailures !== []) {
            throw array_shift($this->deliverFailures);
        }

        $this->delivered[] = ['audience' => $audience, 'id' => $id, 'envelopes' => $envelopes];

        return count($envelopes);
    }

    /** A real key, as a handset presents it. */
    public static function publicKey(): string
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_private(self::privateKey()));

        return is_array($details)
            ? (preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '')
            : '';
    }

    public static function privateKey(): string
    {
        static $pem = null;

        if ($pem === null) {
            $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            openssl_pkey_export($resource, $pem);
        }

        return (string) $pem;
    }
}
