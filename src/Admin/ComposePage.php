<?php

declare(strict_types=1);

namespace Fellowship\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Core\Capabilities;
use Fellowship\Messaging\Message;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\MessageRequest;
use Unity\Committees\Interfaces\CommitteeRepository;
use WP_Error;

/**
 * Compose a message to a committee or to the whole fellowship.
 *
 * <b>No free-text recipient field, deliberately.</b> Naming individuals
 * from here would mean typing email addresses into a form, which is both
 * a way to send fellowship business to a typo and a reason for somebody
 * to have the address list open beside them. Individual messages are what
 * the app is for, where recipients are chosen from a list and addressed
 * by id. This screen does the thing the app cannot: reach a committee, or
 * everybody.
 *
 * The confirmation step is not politeness. "Everyone" on a live
 * intergroup is several hundred handsets and there is no unsend, so the
 * count is shown before the send and not after it.
 */
final class ComposePage
{
    public const PAGE_SLUG = 'fellowship-compose';
    public const SEND_ACTION = 'fellowship_send_message';

    private const CAPABILITY = Capabilities::SEND_MESSAGES;
    private const NONCE = 'fellowship_compose';

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
        echo '<select name="committee" id="fellowship-audience">';
        echo '<option value="">' . esc_html__('Everyone with a device', 'fellowship') . '</option>';
        foreach ($this->committees->findAll() as $committee) {
            echo '<option value="' . esc_attr($committee->getSlug()) . '">'
                . esc_html($committee->getName())
                . '</option>';
        }
        echo '</select>';
        echo '<p class="description">'
            . esc_html__('A committee includes its sub-committees.', 'fellowship')
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

        submit_button(__('Send message', 'fellowship'));

        echo '</form></div>';
    }

    public function handleSend(): void
    {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You are not allowed to send messages.', 'fellowship'), '', ['response' => 403]);
        }

        check_admin_referer(self::NONCE);

        // Passed through the same API another plugin would call, rather
        // than reaching for the dispatcher directly. One path in means
        // one place where validation, audit and the send actually happen.
        $result = $this->api->send([
            'subject'   => (string) ($_POST['subject'] ?? ''),
            'body'      => (string) ($_POST['body'] ?? ''),
            'committee' => sanitize_text_field((string) ($_POST['committee'] ?? '')),
        ]);

        if ($result instanceof WP_Error) {
            set_transient(
                self::ERROR_TRANSIENT . get_current_user_id(),
                $result->get_error_message(),
                self::ERROR_TTL,
            );

            $this->redirect('error');
        }

        $this->redirect('sent');
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
        $result = sanitize_key((string) filter_input(INPUT_GET, 'fellowship_result'));

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
