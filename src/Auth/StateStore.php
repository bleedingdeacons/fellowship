<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Guardian\State\StateStore as GuardianStateStore;

/**
 * Fellowship's view of the single-use OAuth state: what Guardian's
 * {@see GuardianStateStore} stores, plus what Fellowship needs back after the
 * provider returns.
 *
 * The state, nonce and PKCE verifier — and their single-use semantics — are
 * Guardian's. What this adds is where the sign-in goes afterwards:
 *
 * - `device_redirect`, the app URI the callback bounces back to, validated
 *   when the flow began and out of the provider's reach ever since.
 * - The audience the sign-in is for, and that audience's opaque context —
 *   see {@see SignInAudience}. A record written before audiences existed has
 *   neither, and reads back as Link's with an empty context.
 *
 * The key prefix is the one this class always used, and Guardian stores these
 * fields flat beside its own, exactly as this class used to. So a sign-in in
 * flight across the upgrade still completes.
 */
final class StateStore
{
    private const PREFIX = 'fellowship_oauth_state_';

    private readonly GuardianStateStore $store;

    public function __construct(?GuardianStateStore $store = null)
    {
        $this->store = $store ?? new GuardianStateStore(self::PREFIX);
    }

    /**
     * @return array{state: string, nonce: string, code_verifier: string|null}
     */
    public function issue(
        string $provider,
        string $deviceRedirect,
        ?string $codeVerifier = null,
        string $audience = LinkAudience::NAME,
        string $context = '',
    ): array {
        return $this->store->issue($provider, $codeVerifier, [
            'device_redirect' => $deviceRedirect,
            'audience'        => $audience,
            'context'         => $context,
        ]);
    }

    /**
     * @return array{
     *     provider: string,
     *     nonce: string,
     *     device_redirect: string,
     *     code_verifier: string|null,
     *     audience: string,
     *     context: string
     * }|null
     */
    public function consume(string $state): ?array
    {
        $stored = $this->store->consume($state);
        if ($stored === null) {
            return null;
        }

        $extra = $stored['extra'];
        $redirect = $extra['device_redirect'] ?? '';
        $audience = $extra['audience'] ?? '';
        $context = $extra['context'] ?? '';

        return [
            'provider'        => $stored['provider'],
            'nonce'           => $stored['nonce'],
            'device_redirect' => is_string($redirect) ? $redirect : '',
            'code_verifier'   => $stored['code_verifier'],
            'audience'        => is_string($audience) && $audience !== '' ? $audience : LinkAudience::NAME,
            'context'         => is_string($context) ? $context : '',
        ];
    }
}
