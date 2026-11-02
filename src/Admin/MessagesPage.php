<?php

declare(strict_types=1);

namespace Fellowship\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Messaging\MessageRepository;
use Fellowship\Messaging\MessageRequest;
use Fellowship\Messaging\RecipientRepository;
use Scrutiny\Privacy\PersonalDataPolicy;

/**
 * The message log — what was sent, to whom, and how far it has got:
 * sent, delivered to a handset, read.
 *
 * <b>Guarded by Scrutiny's view capability, not by Fellowship's own.</b>
 * Message bodies are fellowship business held against named members;
 * reading them is reading personal data, and the site already has one
 * answer to who may do that. A second capability here would let the two
 * drift apart.
 *
 * This screen is also the plainest statement of the design trade the
 * plugin made: an admin can read these messages, which is what makes a
 * committee broadcast and an audit possible, and is the reason the
 * retention window exists.
 */
final class MessagesPage
{
    public const MENU_SLUG = 'fellowship';
    public const PAGE_SLUG = 'fellowship';

    private const CAPABILITY = PersonalDataPolicy::VIEW_CAPABILITY;

    private const PER_PAGE = 25;

    public function __construct(
        private readonly MessageRepository $messages,
        private readonly RecipientRepository $recipients,
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

        $page  = max(1, (int) filter_var($_GET['paged'] ?? null, FILTER_VALIDATE_INT));
        $total = $this->messages->countAll();
        $rows  = $this->messages->list(self::PER_PAGE, ($page - 1) * self::PER_PAGE);

        echo '<div class="wrap">';
        echo '<h1>' . esc_html__('Fellowship messages', 'fellowship') . '</h1>';

        if ($rows === []) {
            echo '<p>' . esc_html__('No messages have been sent yet.', 'fellowship') . '</p>';
            echo '</div>';
            return;
        }

        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr>';
        echo '<th scope="col">' . esc_html__('Sent', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('From', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Subject', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Audience', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Delivery', 'fellowship') . '</th>';
        echo '</tr></thead><tbody>';

        // One grouped query for the page, the one Link's ticks are drawn
        // from, rather than two counts per row.
        $receipts = $this->recipients->receiptsFor(array_map(
            static fn($message): int => $message->id,
            $rows,
        ));

        foreach ($rows as $message) {
            echo '<tr>';
            echo '<td>' . esc_html($this->when($message->createdAt)) . '</td>';
            echo '<td>' . esc_html($message->senderName !== '' ? $message->senderName : __('Intergroup', 'fellowship'));
            if ($message->cameFromApp()) {
                echo ' <span class="description">' . esc_html__('(from Link)', 'fellowship') . '</span>';
            }
            echo '</td>';
            echo '<td><strong>' . esc_html($message->subject) . '</strong>';
            echo '<div class="row-actions"><span>' . esc_html($this->excerpt($message->body)) . '</span></div>';
            echo '</td>';
            echo '<td>' . esc_html($this->audience($message->audienceType, $message->audienceRef)) . '</td>';
            echo '<td>' . esc_html($this->delivery($receipts[$message->id] ?? null)) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table>';

        echo '<p class="description">'
            . esc_html__('Delivered means one of the member\'s handsets has opened the message; read means they have read it in Link. A push Google accepted but no handset has yet opened is still only sent.', 'fellowship')
            . '</p>';

        $this->pagination($page, $total);

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
     *
     * @param array{recipients: int, received: int, read: int}|null $counts
     */
    private function delivery(?array $counts): string
    {
        if ($counts === null || $counts['recipients'] === 0) {
            return __('Reached nobody', 'fellowship');
        }

        if ($counts['recipients'] === 1) {
            return match (true) {
                $counts['read'] > 0     => __('Read', 'fellowship'),
                $counts['received'] > 0 => __('Delivered', 'fellowship'),
                default                 => __('Sent', 'fellowship'),
            };
        }

        return sprintf(
            /* translators: 1: recipients, 2: how many have it on a handset, 3: how many have read it */
            __('%1$d recipients: %2$d delivered, %3$d read', 'fellowship'),
            $counts['recipients'],
            $counts['received'],
            $counts['read'],
        );
    }

    private function audience(string $type, string $ref): string
    {
        $slugs = array_values(array_filter(explode(',', $ref), static fn(string $s): bool => $s !== ''));

        // All GSRs travels among the committee slugs as a token nobody
        // should have to read; it is said in words, and ahead of the
        // committees, as it is stored.
        if (in_array(MessageRequest::ALL_GSRS, $slugs, true)) {
            $slugs = array_values(array_diff($slugs, [MessageRequest::ALL_GSRS]));
            $rest  = $slugs === [] ? '' : sprintf(__('committee: %s', 'fellowship'), implode(', ', $slugs));

            return implode(', ', array_filter([
                $type === 'mixed' ? __('Named members', 'fellowship') : '',
                __('All GSRs', 'fellowship'),
                $rest,
            ]));
        }

        // The ref holds slugs joined with commas, so a send to several
        // reads as a list rather than as one oddly-named committee.
        $named = str_replace(',', ', ', $ref);

        return match ($type) {
            'committee' => sprintf(__('Committee: %s', 'fellowship'), $named),
            'members'   => __('Named members', 'fellowship'),
            'mixed'     => sprintf(__('Named members and committee: %s', 'fellowship'), $named),
            default     => __('Everyone', 'fellowship'),
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

    private function excerpt(string $body): string
    {
        $body = trim(preg_replace('/\s+/', ' ', $body) ?? '');
        return mb_strlen($body) <= 120 ? $body : mb_substr($body, 0, 120) . '…';
    }

    private function pagination(int $page, int $total): void
    {
        $pages = (int) ceil($total / self::PER_PAGE);
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
