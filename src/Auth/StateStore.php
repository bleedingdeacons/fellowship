<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The short-lived state that ties an OAuth redirect back to the request
 * that started it.
 *
 * `state` defeats CSRF on the callback; `nonce` binds the returned ID
 * token to this particular sign-in so a token captured elsewhere cannot
 * be replayed here. Both are single-use: {@see consume()} deletes the
 * record before returning it, so a replayed callback finds nothing.
 *
 * <b>A PKCE `code_verifier` rides along for providers that require one.</b>
 * Facebook does — its token endpoint refuses an exchange whose authorise
 * leg carried a `code_challenge` without a matching verifier — and Google,
 * Microsoft and Apple simply leave it null. The verifier never leaves this
 * server: only its SHA-256 challenge goes out on the authorise leg, which
 * is the whole point of the mechanism.
 */
final class StateStore
{
    private const PREFIX = 'fellowship_oauth_state_';
    private const TTL_SECONDS = 600; // 10 minutes

    /**
     * @return array{state: string, nonce: string, code_verifier: string|null}
     */
    public function issue(string $provider, string $deviceRedirect, ?string $codeVerifier = null): array
    {
        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));

        set_transient(
            self::PREFIX . $state,
            [
                'provider'        => $provider,
                'nonce'           => $nonce,
                'device_redirect' => $deviceRedirect,
                'code_verifier'   => $codeVerifier,
            ],
            self::TTL_SECONDS,
        );

        return ['state' => $state, 'nonce' => $nonce, 'code_verifier' => $codeVerifier];
    }

    /**
     * @return array{provider: string, nonce: string, device_redirect: string, code_verifier: string|null}|null
     */
    public function consume(string $state): ?array
    {
        if ($state === '') {
            return null;
        }

        $key = self::PREFIX . $state;
        $stored = get_transient($key);
        if (!is_array($stored)) {
            return null;
        }

        delete_transient($key);

        $verifier = $stored['code_verifier'] ?? null;

        return [
            'provider'        => (string) ($stored['provider'] ?? ''),
            'nonce'           => (string) ($stored['nonce'] ?? ''),
            'device_redirect' => (string) ($stored['device_redirect'] ?? ''),
            'code_verifier'   => is_string($verifier) && $verifier !== '' ? $verifier : null,
        ];
    }
}
