<?php

declare(strict_types=1);

namespace Fellowship\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Firebase\FirebaseUnavailable;
use Fellowship\Messaging\LoggedMessage;
use Fellowship\Messaging\MessageLog;
use Scrutiny\Privacy\PersonalDataPolicy;
use Unity\Members\Interfaces\MemberRepository;

/**
 * The message log: who sent what kind of message, and how far it has got. Sent,
 * delivered to a handset, read.
 *
 * <b>It can't show what a message said.</b> Messages are end-to-end encrypted, so no
 * subject, body or committee name is held anywhere this site can read. That is the
 * point of the design, and it replaces the old trade where an admin could read every
 * message.
 *
 * <b>Guarded by Scrutiny's view capability, not by Fellowship's own.</b> Who wrote to
 * the fellowship and when is still personal data, and the site already has one answer
 * to who may read that.
 */
final class MessagesPage
{
    public const MENU_SLUG = 'fellowship';
    public const PAGE_SLUG = 'fellowship';

    private const CAPABILITY = PersonalDataPolicy::VIEW_CAPABILITY;

    private const PER_PAGE = 25;

    public function __construct(
        private readonly MessageLog $messages,
        private readonly MemberRepository $members,
    ) {
    }

    public function register(): void
    {
        add_action('admin_menu', [$this, 'addMenu']);
    }

    public function addMenu(): void
    {
        add_menu_page(
            __('Fellowship', 'fellowship'),
            __('Fellowship', 'fellowship'),
            self::CAPABILITY,
            self::MENU_SLUG,
            [$this, 'render'],
            'dashicons-email-alt',
            57,
        );

        // The top-level menu's own first item, so it does not appear
        // twice under a name WordPress derives from the menu title.
        add_submenu_page(
            self::MENU_SLUG,
            __('Messages', 'fellowship'),
            __('Messages', 'fellowship'),
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

        $page = max(1, (int) filter_var($_GET['paged'] ?? null, FILTER_VALIDATE_INT));

        echo '<div class="wrap">';
        echo '<h1>' . esc_html__('Fellowship messages', 'fellowship') . '</h1>';

        try {
            // One more than a page, which is how to tell there is a next page without
            // counting the collection.
            $rows = $this->messages->page(self::PER_PAGE + 1, ($page - 1) * self::PER_PAGE);
        } catch (FirebaseUnavailable) {
            echo '<div class="notice notice-error"><p>'
                . esc_html__('Firebase could not be reached, so the message log can\'t be shown right now. Nothing has been lost. Please try again.', 'fellowship')
                . '</p></div></div>';
            return;
        }

        if ($rows === []) {
            echo '<p>' . esc_html__('No messages have been sent yet.', 'fellowship') . '</p>';
            echo '</div>';
            return;
        }

        $hasMore = count($rows) > self::PER_PAGE;

        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr>';
        echo '<th scope="col">' . esc_html__('Sent', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('From', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Audience', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Delivery', 'fellowship') . '</th>';
        echo '</tr></thead><tbody>';

        foreach (array_slice($rows, 0, self::PER_PAGE) as $message) {
            echo '<tr>';
            echo '<td>' . esc_html($this->when($message->createdAt)) . '</td>';
            echo '<td>' . esc_html($this->sender($message)) . '</td>';
            echo '<td>' . esc_html($this->audience($message->audience)) . '</td>';
            echo '<td>' . esc_html($this->delivery($message)) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table>';

        echo '<p class="description">'
            . esc_html__('Messages are end-to-end encrypted, so this log can\'t show what any of them said. Delivered means one of the member\'s handsets has opened the message; read means they have read it in Link. A push Google accepted but no handset has yet opened is still only sent.', 'fellowship')
            . '</p>';

        $this->pagination($page, $hasMore ? $page + 1 : $page);

        echo '</div>';
    }

    /**
     * How far a message has got, in the terms of Link's ticks: sent,
     * delivered, read.
     *
     * <b>Delivered is a handset's word, never FCM's.</b> It comes from
     * the receipt a handset sends once it has the message open, counting
     * a read as one — see {@see \Fellowship\Messaging\Recipient::isReceived()}.
     * FCM accepting a push is not shown at all: it says nothing about
     * whether a handset got it, and this column is looked at precisely
     * when somebody says a message did not arrive.
     *
     * One recipient is said in a word; more are counted, because "read"
     * of a committee message would otherwise mean "read by somebody".
     */
    private function delivery(LoggedMessage $message): string
    {
        if ($message->recipients === 0) {
            return __('Reached nobody', 'fellowship');
        }

        if ($message->recipients === 1) {
            return match (true) {
                $message->read > 0     => __('Read', 'fellowship'),
                $message->received > 0 => __('Delivered', 'fellowship'),
                default                => __('Sent', 'fellowship'),
            };
        }

        return sprintf(
            /* translators: 1: recipients, 2: how many have it on a handset, 3: how many have read it */
            __('%1$d recipients: %2$d delivered, %3$d read', 'fellowship'),
            $message->recipients,
            $message->received,
            $message->read,
        );
    }

    /** The intergroup when nobody wrote it, and a member whose record has gone says so. */
    private function sender(LoggedMessage $message): string
    {
        if ($message->senderMemberId <= 0) {
            return __('Intergroup', 'fellowship');
        }

        $member = $this->members->findById($message->senderMemberId);
        if ($member === null) {
            return __('(no member record)', 'fellowship');
        }

        $name = trim($member->getAnonymousName());

        return $name !== '' ? $name : __('(unnamed member)', 'fellowship');
    }

    /** The kind of audience, which is all that is kept: a committee's name says what it is. */
    private function audience(string $kind): string
    {
        return match ($kind) {
            LoggedMessage::AUDIENCE_EVERYONE => __('Everyone', 'fellowship'),
            LoggedMessage::AUDIENCE_PART     => __('A committee or the GSRs', 'fellowship'),
            LoggedMessage::AUDIENCE_MEMBERS  => __('Named members', 'fellowship'),
            LoggedMessage::AUDIENCE_MIXED    => __('Named members and a committee or the GSRs', 'fellowship'),
            default                          => __('Unknown', 'fellowship'),
        };
    }

    private function when(int $epoch): string
    {
        if ($epoch <= 0) {
            return '';
        }

        // wp_date renders in the site's timezone, which is what an admin
        // reading this screen means by "when".
        $formatted = wp_date('j M Y H:i', $epoch);
        return is_string($formatted) ? $formatted : '';
    }

    private function pagination(int $page, int $pages): void
    {
        if ($pages <= 1) {
            return;
        }

        $links = paginate_links([
            'base'      => add_query_arg('paged', '%#%'),
            'format'    => '',
            'current'   => $page,
            'total'     => $pages,
            'prev_text' => '&laquo;',
            'next_text' => '&raquo;',
        ]);

        if (is_string($links)) {
            // Taint traced from $_GET['paged'], which is cast to int before it
            // goes anywhere: max(1, (int) filter_var(..., FILTER_VALIDATE_INT)),
            // then passed to pagination(int $page, ...) under strict_types. An
            // int cannot carry a payload, and the generated markup is run through
            // wp_kses_post on top. Semgrep follows the superglobal to the echo
            // without treating either the cast or wp_kses_post as a sanitiser.
            // nosemgrep: php.lang.security.taint-unsafe-echo-tag.taint-unsafe-echo-tag
            echo '<div class="tablenav"><div class="tablenav-pages">' . wp_kses_post($links) . '</div></div>';
        }
    }
}
