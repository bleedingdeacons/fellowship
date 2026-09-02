<?php

declare(strict_types=1);

namespace Fellowship\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Messaging\MessageRepository;
use Fellowship\Messaging\RecipientRepository;
use Scrutiny\Privacy\PersonalDataPolicy;

/**
 * The message log — what was sent, to whom, and how much of it has been
 * read.
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

        $page  = max(1, (int) filter_input(INPUT_GET, 'paged', FILTER_VALIDATE_INT));
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
        echo '<th scope="col">' . esc_html__('Read', 'fellowship') . '</th>';
        echo '</tr></thead><tbody>';

        foreach ($rows as $message) {
            $sent = $this->recipients->countForMessage($message->id);
            $read = $this->recipients->countReadForMessage($message->id);

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
            echo '<td>' . esc_html(sprintf('%d / %d', $read, $sent)) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table>';

        $this->pagination($page, $total);

        echo '</div>';
    }

    private function audience(string $type, string $ref): string
    {
        return match ($type) {
            'committee' => sprintf(__('Committee: %s', 'fellowship'), $ref),
            'members'   => __('Named members', 'fellowship'),
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
            echo '<div class="tablenav"><div class="tablenav-pages">' . wp_kses_post($links) . '</div></div>';
        }
    }
}
