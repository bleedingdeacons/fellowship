<?php

declare(strict_types=1);

namespace Fellowship\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Core\Capabilities;
use Fellowship\Devices\MemberGate;
use Fellowship\Directory\DirectoryPresenter;
use Fellowship\Messaging\Message;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\MessageRequest;
use Unity\Committees\Interfaces\CommitteeRepository;
use Unity\Members\Interfaces\Member;
use WP_Error;

/**
 * Compose a message to the whole fellowship, a committee, or one member.
 *
 * <b>No free-text recipient field, deliberately.</b> Naming individuals
 * by typing email addresses into a form would be both a way to send
 * fellowship business to a typo and a reason for somebody to have the
 * address list open beside them. So one member is chosen the way the app
 * chooses one: from the address book Link is given
 * ({@see DirectoryPresenter}), by anonymous name, and addressed by opaque
 * member id, so this screen never sees an address.
 *
 * Choosing from that list carries its rules with it. A member with no Link
 * device is shown but cannot be chosen, as in the app, because a message
 * to them would wait unread with nothing to say so. The signed-in member
 * is left out: they would be excluded from their own message and it would
 * reach nobody.
 *
 * <b>One field, and a value it does not recognise is refused.</b> Every
 * audience travels in `audience` as `everyone`, `committee:<slug>` or
 * `member:<id>`. Anything else is an error, never a fall-back to
 * everyone: the broadcast is the one send that must only ever happen on
 * purpose.
 *
 * The confirmation step is not politeness. "Everyone" on a live
 * intergroup is several hundred handsets and there is no unsend, so the
 * count is shown before the send and not after it.
 *
 * <b>A message is credited to whoever wrote it, when they are a
 * member.</b> The signed-in user's WordPress email is looked up in Unity
 * the way a handset's is, and a match sends under that member's name and
 * id — so the app can address a reply straight back to them. A user who
 * is not a member still sends as the intergroup, under the site's name,
 * with nobody for a reply to go to. The screen says which it will be
 * before anything is sent.
 */
final class ComposePage
{
    public const PAGE_SLUG = 'fellowship-compose';
    public const SEND_ACTION = 'fellowship_send_message';

    private const CAPABILITY = Capabilities::SEND_MESSAGES;
    private const NONCE = 'fellowship_compose';

    /** The `audience` values. See the class comment. */
    private const EVERYONE = 'everyone';
    private const COMMITTEE_PREFIX = 'committee:';
    private const MEMBER_PREFIX = 'member:';

    /**
     * Where a refused send's reason waits between the redirect and the
     * render, keyed per user.
     *
     * <b>It used to travel in the query string.</b> That put a
     * server-supplied message into the URL, and therefore into browser
     * history, the web server's access log, and any referrer header the
     * next request sends — for a string this code does not choose and
     * cannot bound, since a WP_Error may carry anything a calling plugin
     * put in it. A one-shot transient carries it without any of that.
     *
     * It also lets {@see redirect()} take nothing but a fixed code, which
     * is what a redirect target should be built from.
     */
    private const ERROR_TRANSIENT = 'fellowship_compose_error_';

    /** Long enough to survive the redirect, short enough to be forgotten. */
    private const ERROR_TTL = 60;

    public function __construct(
        private readonly MessageApi $api,
        private readonly CommitteeRepository $committees,
        private readonly MemberGate $gate,
        private readonly DirectoryPresenter $directory,
    ) {
    }

    public function register(): void
    {
        add_action('admin_menu', [$this, 'addMenu']);
        add_action('admin_post_' . self::SEND_ACTION, [$this, 'handleSend']);
    }

    public function addMenu(): void
    {
        add_submenu_page(
            MessagesPage::MENU_SLUG,
            __('Compose', 'fellowship'),
            __('Compose', 'fellowship'),
            self::CAPABILITY,
            self::PAGE_SLUG,
            [$this, 'render'],
        );
    }

    public function render(): void
    {
        if (!current_user_can(self::CAPABILITY)) {
            return;
        }

        echo '<div class="wrap">';
        echo '<h1>' . esc_html__('Compose a message', 'fellowship') . '</h1>';

        $this->notice();

        echo '<p class="description">'
            . esc_html__(
                'Message bodies are encrypted to each handset before they leave this site, and are never shown in a notification. Members read them inside the Link app.',
                'fellowship'
            )
            . '</p>';

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="' . esc_attr(self::SEND_ACTION) . '">';
        wp_nonce_field(self::NONCE);

        echo '<table class="form-table" role="presentation"><tbody>';

        echo '<tr><th scope="row"><label for="fellowship-audience">' . esc_html__('Send to', 'fellowship') . '</label></th><td>';
        echo '<select name="audience" id="fellowship-audience">';
        echo '<option value="' . esc_attr(self::EVERYONE) . '">' . esc_html__('Everyone with a device', 'fellowship') . '</option>';

        $committees = $this->committees->findAll();
        if ($committees !== []) {
            echo '<optgroup label="' . esc_attr__('Committees', 'fellowship') . '">';
            foreach ($committees as $committee) {
                echo '<option value="' . esc_attr(self::COMMITTEE_PREFIX . $committee->getSlug()) . '">'
                    . esc_html($committee->getName())
                    . '</option>';
            }
            echo '</optgroup>';
        }

        $members = $this->members();
        if ($members !== []) {
            echo '<optgroup label="' . esc_attr__('Members', 'fellowship') . '">';
            foreach ($members as $member) {
                // Disabled rather than left out, as the app does: the
                // admin can see the member exists and why they cannot be
                // written to, rather than wondering where they went.
                echo '<option value="' . esc_attr(self::MEMBER_PREFIX . $member['id']) . '"'
                    . ($member['hasDevice'] ? '' : ' disabled')
                    . '>'
                    . esc_html($this->memberLabel($member))
                    . '</option>';
            }
            echo '</optgroup>';
        }

        echo '</select>';
        echo '<p class="description">'
            . esc_html__('A committee includes its sub-committees. A member can be chosen once they have Link on a handset.', 'fellowship')
            . '</p>';
        echo '</td></tr>';

        echo '<tr><th scope="row"><label for="fellowship-subject">' . esc_html__('Subject', 'fellowship') . '</label></th><td>';
        echo '<input type="text" name="subject" id="fellowship-subject" class="regular-text" maxlength="'
            . esc_attr((string) MessageRequest::SUBJECT_MAX) . '" required>';
        echo '</td></tr>';

        echo '<tr><th scope="row"><label for="fellowship-body">' . esc_html__('Message', 'fellowship') . '</label></th><td>';
        echo '<textarea name="body" id="fellowship-body" rows="8" class="large-text" maxlength="'
            . esc_attr((string) MessageRequest::BODY_MAX) . '" required></textarea>';
        echo '<p class="description">'
            . esc_html(sprintf(
                /* translators: %d: maximum characters */
                __('Up to %d characters. Longer messages are truncated.', 'fellowship'),
                MessageRequest::BODY_MAX
            ))
            . '</p>';
        echo '</td></tr>';

        echo '</tbody></table>';

        $this->sendingAs();

        submit_button(__('Send message', 'fellowship'));

        echo '</form></div>';
    }

    public function handleSend(): void
    {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You are not allowed to send messages.', 'fellowship'), '', ['response' => 403]);
        }

        check_admin_referer(self::NONCE);

        // A Symfony rule matching ->redirect() with a non-literal argument. This
        // is not Symfony's redirect: it is the private helper below, which builds
        // wp_safe_redirect(add_query_arg([...], admin_url('admin.php'))). The base
        // URL is fixed, the argument only ever becomes a query-parameter *value*,
        // and wp_safe_redirect refuses an off-site host regardless. It matched on
        // the method name alone.
        // nosemgrep: php.symfony.security.audit.symfony-non-literal-redirect.symfony-non-literal-redirect
        $this->redirect($this->sendFromRequest());
    }

    /**
     * The body of the above, split out so it can be driven directly.
     *
     * The handler ends in wp_safe_redirect() and exit, which a test
     * cannot follow, so the decision is separated from the redirect --
     * the same split DevicesPage uses for the password code, and the same
     * one Reach settled on in CallRequestsPage::completeFromRequest().
     * Behaviour-identical: what was two calls to redirect() is now one
     * return value and one call.
     *
     * @return string The result code the notice is keyed on.
     */
    public function sendFromRequest(): string
    {
        $audience = $this->audienceFromRequest();

        // Passed through the same API another plugin would call. One path in
        // means one place where validation, audit and the send actually happen,
        // and it seals the same payload a handset's send seals, so a member
        // reached from here receives exactly what the app would have sent them.
        $result = $audience instanceof WP_Error
            ? $audience
            : $this->api->send([
                'subject' => (string) ($_POST['subject'] ?? ''),
                'body'    => (string) ($_POST['body'] ?? ''),
            ] + $audience, $this->author());

        if ($result instanceof WP_Error) {
            // The reason waits in a one-shot per-user transient rather
            // than travelling in the query string, where it would be a
            // server-supplied message rendered from a URL.
            set_transient(
                self::ERROR_TRANSIENT . get_current_user_id(),
                $result->get_error_message(),
                self::ERROR_TTL,
            );

            return 'error';
        }

        return 'sent';
    }

    /**
     * The posted `audience`, as the input keys {@see MessageApi} takes.
     *
     * An empty input array is the broadcast, so it is returned only for
     * the one value that asks for it. Everything else that is not a
     * committee or a positive member id is refused.
     *
     * @return array<string, mixed>|WP_Error
     */
    private function audienceFromRequest(): array|WP_Error
    {
        $audience = sanitize_text_field((string) ($_POST['audience'] ?? ''));

        if ($audience === self::EVERYONE) {
            return [];
        }

        if (str_starts_with($audience, self::COMMITTEE_PREFIX)) {
            $slug = substr($audience, strlen(self::COMMITTEE_PREFIX));
            if ($slug !== '') {
                return ['committee' => $slug];
            }
        }

        if (str_starts_with($audience, self::MEMBER_PREFIX)) {
            $id = substr($audience, strlen(self::MEMBER_PREFIX));
            if (ctype_digit($id) && (int) $id > 0) {
                return ['member_ids' => [(int) $id]];
            }
        }

        return new WP_Error('fellowship_no_audience', __('Choose who this message is for.', 'fellowship'));
    }

    /**
     * Members who may be chosen from here: the app's address book, less
     * the signed-in member.
     *
     * @return list<array<string, mixed>>
     */
    private function members(): array
    {
        $author = $this->author();
        $authorId = $author?->getId() ?? 0;

        return array_values(array_filter(
            $this->directory->forApp(false)['members'],
            static fn(array $member): bool => (int) ($member['id'] ?? 0) !== $authorId,
        ));
    }

    /**
     * "Dave P — Bristol Tuesday, GSR, Secretary", and a reason when they
     * cannot be chosen. What the app shows beside a name, and nothing a
     * person could be contacted by.
     *
     * @param array<string, mixed> $member
     */
    private function memberLabel(array $member): string
    {
        $details = array_filter([
            (string) ($member['group'] ?? ''),
            !empty($member['gsr']) ? __('GSR', 'fellowship') : '',
            (string) ($member['position'] ?? ''),
        ], static fn(string $part): bool => $part !== '');

        $label = (string) ($member['name'] ?? '');
        if ($details !== []) {
            $label .= ' — ' . implode(', ', $details);
        }

        if (empty($member['hasDevice'])) {
            $label .= ' ' . __('(no Link device)', 'fellowship');
        }

        return $label;
    }

    /**
     * The member the signed-in user is, or null when they are not one.
     *
     * Matched on email through {@see MemberGate}, the same rule that
     * decides whether a handset may enrol, so a WordPress user is credited
     * as exactly the member who could have sent this from the app.
     */
    private function author(): ?Member
    {
        return $this->gate->authorisedMember(wp_get_current_user()->user_email);
    }

    /**
     * Say who the message will be from, before it is sent.
     */
    private function sendingAs(): void
    {
        $author = $this->author();

        $text = $author !== null
            ? sprintf(
                /* translators: %s: the sender's anonymous name */
                __('Sent as %s. Replies from the app will come to you, and you will not receive a copy.', 'fellowship'),
                $author->getAnonymousName()
            )
            : __('Sent from the intergroup, not a member: your WordPress email is not a Unity member\'s, so replies cannot be addressed back to anybody.', 'fellowship');

        echo '<p class="description">' . esc_html($text) . '</p>';
    }

    /**
     * Back to this screen with a one-word outcome.
     *
     * Every part of the target is fixed here: the page slug is a constant,
     * the result is one of two literals, and the base comes from
     * admin_url(). wp_safe_redirect then refuses anything that is somehow
     * not on this host.
     */
    private function redirect(string $result): void
    {
        wp_safe_redirect(add_query_arg(
            ['page' => self::PAGE_SLUG, 'fellowship_result' => $result],
            admin_url('admin.php'),
        ));

        exit;
    }

    private function notice(): void
    {
        // $_GET rather than filter_input, which reads the *original*
        // request and therefore cannot be driven by a test at all — the
        // same substitution DevicesPage::authoriseAction carries, and for
        // the same reason. sanitize_key is the validation either way, and
        // the value is only ever compared against a fixed set of literals
        // below.
        $result = sanitize_key((string) ($_GET['fellowship_result'] ?? ''));

        if ($result === 'sent') {
            echo '<div class="notice notice-success is-dismissible"><p>'
                . esc_html__('The message was sent.', 'fellowship')
                . '</p></div>';
            return;
        }

        if ($result === 'error') {
            // Read once and deleted, so a refresh does not re-show a
            // failure the member has already been told about.
            $key = self::ERROR_TRANSIENT . get_current_user_id();
            $stored = get_transient($key);
            delete_transient($key);

            $detail = is_string($stored) && $stored !== ''
                ? $stored
                : __('The message could not be sent.', 'fellowship');

            echo '<div class="notice notice-error is-dismissible"><p>' . esc_html($detail) . '</p></div>';
        }
    }
}
