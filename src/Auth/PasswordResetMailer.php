<?php

declare(strict_types=1);

namespace Fellowship\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use function add_action;
use function add_query_arg;
use function wp_mail;

/**
 * Emails the one-time link a member uses to set or reset their password.
 *
 * The link carries only the raw reset token (`?token=…`); the address is
 * not put in the URL, and only the token's SHA-256 hash is stored server
 * side. Plain-text body — it carries a security-sensitive link to an
 * inbox and plain text avoids any HTML-injection surface.
 *
 * A thin wrapper over wp_mail returning its success flag so the caller can
 * react to a send failure. The message never states whether an account
 * existed — the caller only invokes this for eligible members, and the
 * endpoint's response is identical regardless, so nothing here leaks
 * account existence.
 *
 * <b>The link is a deep link into the app, not a web page.</b> Reach mails
 * a URL to a page it serves, because Reach has a front end. Fellowship has
 * none: it is a REST server for a handset, and standing up a public page
 * to collect a password would be a new attack surface built solely to
 * receive one. `link://password?token=…` opens the app that asked for the
 * link, on the phone that asked for it, which is where the member already
 * is. The token is printed underneath as well, so a member who opens the
 * mail on a desktop can paste it into the app rather than being stuck.
 *
 * <b>Why sending is queued rather than done on the spot.</b> The
 * request-reset endpoint answers `{sent: true}` whether or not a link
 * went out, so its *body* reveals nothing — but the two branches did not
 * cost the same. Sending is a synchronous SMTP round trip; not sending
 * is a return. Tens to hundreds of milliseconds, measurable from
 * outside, is enough to tell whether an address belongs to an eligible
 * member — exactly the account enumeration the constant response exists
 * to prevent. {@see queue()} defers the work past the response so both
 * branches answer in the same time, which is the same reasoning
 * {@see PasswordAuthenticator::burnTime()} applies on the login path.
 */
final class PasswordResetMailer
{
    /**
     * Links waiting to go out after the response.
     *
     * @var array<int, array{email: string, token: string}>
     */
    private array $pending = [];

    /** Whether the shutdown flush has been registered this request. */
    private bool $hooked = false;

    /**
     * Queue the set/reset link for $email, to be sent once the response
     * has been handed back — see the class docblock for why.
     *
     * The hook is registered on first use rather than at construction:
     * most requests queue nothing, and a request that queues twice
     * should still flush once.
     */
    public function queue(string $email, string $rawToken): void
    {
        $this->pending[] = ['email' => $email, 'token' => $rawToken];

        if ($this->hooked) {
            return;
        }
        $this->hooked = true;

        // Late priority so anything else still writing to the response
        // has already run by the time we start talking to an SMTP server.
        add_action('shutdown', [$this, 'flush'], PHP_INT_MAX);
    }

    /**
     * Send everything {@see queue()} has accumulated.
     *
     * Public because it is the shutdown callback, and because it is
     * where the sending is actually observable — the registration above
     * is asserted separately as a hook.
     *
     * `fastcgi_finish_request()` is called first where the SAPI provides
     * it (PHP-FPM, which is the usual deployment): it returns the
     * response to the client and lets the rest of the script run
     * unwatched, which is what makes the timing genuinely equal rather
     * than merely later. Where it is absent the send still happens after
     * WordPress has finished with the response, which narrows the
     * window without closing it — worth being clear about rather than
     * claiming more than the platform gives.
     */
    public function flush(): void
    {
        if ($this->pending === []) {
            return;
        }

        $queued = $this->pending;
        $this->pending = [];

        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        }

        foreach ($queued as $item) {
            $this->send($item['email'], $item['token']);
        }
    }

    /**
     * Send the set/reset link to $email immediately. Returns wp_mail's
     * success flag.
     *
     * Callers on the enumeration-sensitive path want {@see queue()};
     * this stays public because it is the unit of work, and the queue is
     * only a decision about when to run it.
     */
    public function send(string $email, string $rawToken): bool
    {
        $blogName = (string) get_bloginfo('name');
        $siteName = $blogName !== '' ? $blogName : 'your intergroup';

        $link = add_query_arg('token', $rawToken, 'link://password');

        $subject = sprintf('[%s] Set your Link password', $siteName);

        $lines = [
            'Someone (hopefully you) asked to set or reset the password for the Link app.',
            '',
            'Open this link on the phone Link is installed on, within the next hour:',
            '',
            $link,
            '',
            'If you are reading this somewhere other than that phone, open Link,',
            'choose "Set a password" and paste in this code instead:',
            '',
            $rawToken,
            '',
            'The link can be used once and expires after 60 minutes. If you did not',
            'request this, you can safely ignore this email — nothing has changed,',
            'and you can still sign in with Google, Microsoft, Apple or Facebook.',
        ];

        $body    = implode("\n", $lines);
        $headers = ['Content-Type: text/plain; charset=UTF-8'];

        return (bool) wp_mail($email, $subject, $body, $headers);
    }
}
