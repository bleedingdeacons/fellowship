<?php

declare(strict_types=1);

namespace Fellowship\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Core\Capabilities;
use Fellowship\Devices\Device;
use Fellowship\Devices\DeviceRepository;
use Scrutiny\Audit\Interfaces\AuditLogger;
use Scrutiny\Privacy\PersonalDataPolicy;
use Unity\Members\Interfaces\MemberRepository;

/**
 * Enrolled handsets, and the two ways to cut one off.
 *
 * <b>Revoke and remove are not the same thing, and the difference is the
 * point of having both.</b>
 *
 * *Revoke* is the ordinary answer to a lost or stolen phone: the token
 * stops working immediately — the repository's lookup refuses revoked
 * rows outright, so it is indistinguishable from an unknown token — and
 * the row stays, so this screen can still show that the device existed
 * and when it was cut off. That record is the useful part when somebody
 * asks what happened.
 *
 * *Remove* deletes the row. It is for tidying up test enrolments and for
 * an erasure request, and it destroys the evidence that the device ever
 * existed. It is offered second and confirmed, because "revoke" is
 * almost always what was meant.
 *
 * Reading this screen needs Scrutiny's view capability — it lists
 * members against devices. Acting on it needs Fellowship's own
 * {@see Capabilities::MANAGE_DEVICES}, so a reader who may audit is not
 * thereby able to sign somebody's phone out.
 */
final class DevicesPage
{
    public const PAGE_SLUG = 'fellowship-devices';
    public const REVOKE_ACTION = 'fellowship_revoke_device';
    public const REMOVE_ACTION = 'fellowship_remove_device';

    private const VIEW_CAPABILITY = PersonalDataPolicy::VIEW_CAPABILITY;
    private const MANAGE_CAPABILITY = Capabilities::MANAGE_DEVICES;

    private const NONCE = 'fellowship_device_action';
    private const PER_PAGE = 25;

    public function __construct(
        private readonly DeviceRepository $devices,
        private readonly MemberRepository $members,
        private readonly AuditLogger $auditLogger,
    ) {
    }

    public function register(): void
    {
        add_action('admin_menu', [$this, 'addMenu']);
        add_action('admin_post_' . self::REVOKE_ACTION, [$this, 'handleRevoke']);
        add_action('admin_post_' . self::REMOVE_ACTION, [$this, 'handleRemove']);
    }

    public function addMenu(): void
    {
        add_submenu_page(
            MessagesPage::MENU_SLUG,
            __('Devices', 'fellowship'),
            __('Devices', 'fellowship'),
            self::VIEW_CAPABILITY,
            self::PAGE_SLUG,
            [$this, 'render'],
        );
    }

    public function render(): void
    {
        if (!current_user_can(self::VIEW_CAPABILITY)) {
            return;
        }

        // A reader who cannot manage is shown no buttons rather than ones
        // that answer 403. The handlers check again regardless: what the
        // page chose to render is not a permission check.
        $canManage = current_user_can(self::MANAGE_CAPABILITY);

        $page  = max(1, (int) ($_GET['paged'] ?? 1));
        $total = $this->devices->countAll();
        $rows  = $this->devices->list(self::PER_PAGE, ($page - 1) * self::PER_PAGE);

        echo '<div class="wrap">';
        echo '<h1>' . esc_html__('Link devices', 'fellowship') . '</h1>';

        $this->notice();

        if ($rows === []) {
            echo '<p>' . esc_html__('No handsets have been enrolled yet.', 'fellowship') . '</p></div>';
            return;
        }

        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr>';
        echo '<th scope="col">' . esc_html__('Member', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Device', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Push', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Enrolled', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Last seen', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Status', 'fellowship') . '</th>';
        echo '</tr></thead><tbody>';

        foreach ($rows as $device) {
            echo '<tr>';
            echo '<td>' . esc_html($this->memberName($device)) . '</td>';
            echo '<td>' . esc_html($device->label !== '' ? $device->label : __('(unnamed)', 'fellowship'));
            echo ' <span class="description">' . esc_html($device->platform) . '</span></td>';
            echo '<td>' . esc_html($device->wantsPush() ? __('Yes', 'fellowship') : __('Poll only', 'fellowship')) . '</td>';
            echo '<td>' . esc_html($this->when($device->createdAt)) . '</td>';
            echo '<td>' . esc_html($device->lastSeenAt > 0 ? $this->when($device->lastSeenAt) : '—') . '</td>';
            echo '<td>' . wp_kses_post($this->status($device, $canManage)) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table>';
        echo '</div>';
    }

    public function handleRevoke(): void
    {
        $id = $this->authoriseAction();

        if ($this->devices->revoke($id, time())) {
            $this->auditLogger->log(
                AuditLogger::ACTION_DELETE,
                AuditLogger::ENTITY_MEMBER,
                $this->memberIdFor($id),
                'authentication',
                'Link device revoked;device:' . $id . ';by:admin:' . get_current_user_id(),
            );
        }

        $this->redirect('revoked');
    }

    public function handleRemove(): void
    {
        $id = $this->authoriseAction();

        // Read before the delete: afterwards there is no row to ask, and
        // an audit entry that cannot say whose device it was is close to
        // no audit entry at all.
        $memberId = $this->memberIdFor($id);

        // Revoked first, then deleted. If the delete fails the handset is
        // still cut off, which is the half that matters; the other order
        // would leave a working credential behind on a failed delete.
        $this->devices->revoke($id, time());

        if ($this->devices->remove($id)) {
            $this->auditLogger->log(
                AuditLogger::ACTION_DELETE,
                AuditLogger::ENTITY_MEMBER,
                $memberId,
                'authentication',
                'Link device removed;device:' . $id . ';by:admin:' . get_current_user_id(),
            );
        }

        $this->redirect('removed');
    }

    /**
     * Check the capability and the nonce, and return the device id.
     * Dies rather than returning on refusal.
     */
    private function authoriseAction(): int
    {
        if (!current_user_can(self::MANAGE_CAPABILITY)) {
            wp_die(esc_html__('You are not allowed to manage devices.', 'fellowship'), '', ['response' => 403]);
        }

        $id = (int) ($_POST['device'] ?? 0);
        check_admin_referer(self::NONCE . '_' . $id);

        if ($id <= 0) {
            wp_die(esc_html__('No device was named.', 'fellowship'), '', ['response' => 400]);
        }

        return $id;
    }

    private function status(Device $device, bool $canManage): string
    {
        if ($device->isRevoked()) {
            return '<span class="description">'
                . esc_html(sprintf(__('Revoked %s', 'fellowship'), $this->when((int) $device->revokedAt)))
                . '</span>' . ($canManage ? ' ' . $this->button(self::REMOVE_ACTION, $device->id, __('Remove', 'fellowship'), true) : '');
        }

        $status = '';

        if ($device->hasKeyFault()) {
            // Worth saying loudly: this handset is enrolled, looks
            // healthy, and cannot read a word it is sent.
            $status .= '<span style="color:#b32d2e"><strong>'
                . esc_html__('Cannot read messages', 'fellowship')
                . '</strong></span><br>';
        }

        if (!$canManage) {
            return $status . esc_html__('Active', 'fellowship');
        }

        return $status
            . $this->button(self::REVOKE_ACTION, $device->id, __('Revoke', 'fellowship'), false)
            . ' '
            . $this->button(self::REMOVE_ACTION, $device->id, __('Remove', 'fellowship'), true);
    }

    private function button(string $action, int $deviceId, string $label, bool $confirm): string
    {
        $form  = '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline">';
        $form .= '<input type="hidden" name="action" value="' . esc_attr($action) . '">';
        $form .= '<input type="hidden" name="device" value="' . esc_attr((string) $deviceId) . '">';
        $form .= wp_nonce_field(self::NONCE . '_' . $deviceId, '_wpnonce', true, false);
        $form .= '<button type="submit" class="button button-small"';

        if ($confirm) {
            $form .= ' onclick="return confirm(' . esc_attr(wp_json_encode(
                __('Remove this device permanently? Revoking keeps the record instead.', 'fellowship')
            ) ?: '""') . ')"';
        }

        $form .= '>' . esc_html($label) . '</button></form>';

        return $form;
    }

    /**
     * The member a device belongs to, or 0 when the row has gone.
     *
     * Zero rather than a guess: an audit entry attributing somebody
     * else's id to this action would be worse than one that admits it
     * does not know.
     */
    private function memberIdFor(int $deviceId): int
    {
        $device = $this->devices->findById($deviceId);

        return $device === null ? 0 : $device->memberId;
    }

    private function memberName(Device $device): string
    {
        $member = $device->memberId > 0 ? $this->members->findById($device->memberId) : null;
        if ($member === null) {
            $member = $this->members->findByEmail($device->memberEmail);
        }

        if ($member === null) {
            // The member has gone from Unity but the device row remains.
            // Worth showing as such rather than as a blank cell: it means
            // a handset that will fail its next request, and somebody may
            // want to remove the row.
            return __('(no member record)', 'fellowship');
        }

        $name = trim($member->getAnonymousName());
        return $name !== '' ? $name : __('(unnamed member)', 'fellowship');
    }

    private function when(int $epoch): string
    {
        if ($epoch <= 0) {
            return '';
        }

        $formatted = wp_date('j M Y H:i', $epoch);
        return is_string($formatted) ? $formatted : '';
    }

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
        $result = isset($_GET['fellowship_result']) ? sanitize_key((string) $_GET['fellowship_result']) : '';

        $message = match ($result) {
            'revoked' => __('The device was revoked. Its record has been kept.', 'fellowship'),
            'removed' => __('The device was removed.', 'fellowship'),
            default   => '',
        };

        if ($message !== '') {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html($message) . '</p></div>';
        }
    }
}
