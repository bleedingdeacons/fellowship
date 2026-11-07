<?php

declare(strict_types=1);

namespace Fellowship\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Core\Capabilities;
use Fellowship\Devices\LinkDevice;
use Fellowship\Devices\LinkDevices;
use Fellowship\Devices\MemberGate;
use Fellowship\Firebase\FirebaseUnavailable;
use Scrutiny\Audit\Interfaces\AuditLogger;
use Scrutiny\Privacy\PersonalDataPolicy;
use Unity\Members\Interfaces\MemberRepository;

/**
 * Enrolled handsets, and the two ways to cut one off.
 *
 * <b>Revoke and remove are not the same thing, and the difference is the
 * point of having both.</b>
 *
 * *Revoke* is the ordinary answer to a lost or stolen phone: the device is
 * cut off immediately, even with a token that hasn't expired, and the
 * record stays, so this screen can still show that the device existed and
 * when it was cut off. That record is the useful part when somebody asks
 * what happened.
 *
 * *Remove* deletes the record and the device's inbox. It is for tidying up
 * test enrolments and for an erasure request, and it destroys the evidence
 * that the device ever existed. It is offered second and confirmed, because
 * "revoke" is almost always what was meant.
 *
 * Devices live in Firebase, so reading and changing them can fail in a way a
 * table never did. This screen says so rather than showing an empty list or
 * claiming a device was cut off when it wasn't.
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
    public const RESET_ACTION = 'fellowship_send_password_code';

    private const VIEW_CAPABILITY = PersonalDataPolicy::VIEW_CAPABILITY;
    private const MANAGE_CAPABILITY = Capabilities::MANAGE_DEVICES;

    private const NONCE = 'fellowship_device_action';
    private const PER_PAGE = 25;

    /** A Firebase device id. Anything else was never on this screen. */
    private const DEVICE_ID = '/^d_[a-f0-9]{1,64}$/';

    public function __construct(
        private readonly LinkDevices $devices,
        private readonly MemberRepository $members,
        private readonly AuditLogger $auditLogger,
        private readonly PasswordAuthenticator $passwords,
        private readonly MemberGate $gate,
    ) {
    }

    public function register(): void
    {
        add_action('admin_menu', [$this, 'addMenu']);
        add_action('admin_post_' . self::REVOKE_ACTION, [$this, 'handleRevoke']);
        add_action('admin_post_' . self::REMOVE_ACTION, [$this, 'handleRemove']);
        add_action('admin_post_' . self::RESET_ACTION, [$this, 'handleSendResetCode']);
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

        $page = max(1, (int) filter_var($_GET['paged'] ?? null, FILTER_VALIDATE_INT));

        echo '<div class="wrap">';
        echo '<h1>' . esc_html__('Link devices', 'fellowship') . '</h1>';

        $this->notice();

        if ($canManage) {
            $this->resetCodeForm();
        }

        try {
            // One more than a page, which is how to tell there is a next page.
            $rows = $this->devices->page(self::PER_PAGE + 1, ($page - 1) * self::PER_PAGE);
        } catch (FirebaseUnavailable) {
            echo '<div class="notice notice-error"><p>'
                . esc_html__('Firebase could not be reached, so the devices can\'t be shown right now. Please try again.', 'fellowship')
                . '</p></div></div>';
            return;
        }

        if ($rows === []) {
            echo '<p>' . esc_html__('No handsets have been enrolled yet.', 'fellowship') . '</p></div>';
            return;
        }

        $hasMore = count($rows) > self::PER_PAGE;

        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr>';
        echo '<th scope="col">' . esc_html__('Member', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Device', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Push', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Enrolled', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Last seen', 'fellowship') . '</th>';
        echo '<th scope="col">' . esc_html__('Status', 'fellowship') . '</th>';
        echo '</tr></thead><tbody>';

        foreach (array_slice($rows, 0, self::PER_PAGE) as $device) {
            echo '<tr>';
            echo '<td>' . esc_html($this->memberName($device)) . '</td>';
            echo '<td>' . esc_html($device->label !== '' ? $device->label : __('(unnamed)', 'fellowship'));
            echo ' <span class="description">' . esc_html($device->platform) . '</span></td>';
            // "Poll only" on its own sends somebody to the Firebase console for a
            // handset that simply has not been given a token yet. The reason is the
            // actionable half.
            echo '<td>';
            if ($device->hasPushToken) {
                echo esc_html__('Yes', 'fellowship');
            } else {
                echo esc_html__('Poll only', 'fellowship');
                echo ' <span class="description">' . esc_html__('no push token yet', 'fellowship') . '</span>';
            }
            echo '</td>';
            echo '<td>' . esc_html($this->when($device->createdAt)) . '</td>';
            echo '<td>' . esc_html($device->lastSeenAt > 0 ? $this->when($device->lastSeenAt) : '—') . '</td>';
            echo '<td>';
            $this->status($device, $canManage);
            echo '</td>';
            echo '</tr>';
        }

        echo '</tbody></table>';

        $this->pagination($page, $hasMore ? $page + 1 : $page);

        echo '</div>';
    }

    public function handleRevoke(): void
    {
        // A Symfony rule matching ->redirect() with a non-literal argument. This
        // is not Symfony's redirect: it is the private helper below, which builds
        // wp_safe_redirect(add_query_arg([...], admin_url('admin.php'))). The base
        // URL is fixed, the argument only ever becomes a query-parameter *value*,
        // and wp_safe_redirect refuses an off-site host regardless. It matched on
        // the method name alone.
        // nosemgrep: php.symfony.security.audit.symfony-non-literal-redirect.symfony-non-literal-redirect
        $this->redirect($this->revokeFromRequest());
    }

    /**
     * The body of the above, split out so it can be driven directly.
     * See ComposePage::sendFromRequest() for the reasoning.
     */
    public function revokeFromRequest(): string
    {
        $id = $this->authoriseAction();

        try {
            $device = $this->devices->find($id);

            // Already cut off, or gone: nothing happened, so nothing is recorded as
            // having happened.
            if ($device === null || $device->revoked) {
                return 'revoked';
            }

            $this->devices->revoke($id);
        } catch (FirebaseUnavailable) {
            return 'firebase_unavailable';
        }

        $this->auditLogger->log(
            AuditLogger::ACTION_DELETE,
            AuditLogger::ENTITY_MEMBER,
            $device->memberId,
            'authentication',
            'Link device revoked;device:' . $id . ';by:admin:' . get_current_user_id(),
        );

        return 'revoked';
    }

    public function handleRemove(): void
    {
        // A Symfony rule matching ->redirect() with a non-literal argument. This
        // is not Symfony's redirect: it is the private helper below, which builds
        // wp_safe_redirect(add_query_arg([...], admin_url('admin.php'))). The base
        // URL is fixed, the argument only ever becomes a query-parameter *value*,
        // and wp_safe_redirect refuses an off-site host regardless. It matched on
        // the method name alone.
        // nosemgrep: php.symfony.security.audit.symfony-non-literal-redirect.symfony-non-literal-redirect
        $this->redirect($this->removeFromRequest());
    }

    /**
     * The body of the above, split out so it can be driven directly.
     */
    public function removeFromRequest(): string
    {
        $id = $this->authoriseAction();

        try {
            // Read before the delete: afterwards there is nothing to ask, and an audit
            // entry that cannot say whose device it was is close to no audit entry at
            // all. Zero rather than a guess when it has gone already.
            $memberId = $this->devices->find($id)->memberId ?? 0;

            $this->devices->remove($id);
        } catch (FirebaseUnavailable) {
            return 'firebase_unavailable';
        }

        $this->auditLogger->log(
            AuditLogger::ACTION_DELETE,
            AuditLogger::ENTITY_MEMBER,
            $memberId,
            'authentication',
            'Link device removed;device:' . $id . ';by:admin:' . get_current_user_id(),
        );

        return 'removed';
    }

    /**
     * Email a member a code for setting a Link password.
     *
     * <b>Triggering is not setting, and the difference is the whole
     * reason this is safe.</b> The code goes to the member's own address;
     * an admin can start the flow but cannot finish it, so this does not
     * become a way to enrol a handset as somebody else and read their
     * messages. An admin screen that set a password directly would be
     * exactly that, which is why there is not one.
     *
     * Gated on MANAGE_DEVICES rather than a capability of its own: it is
     * the same question that capability already answers — control over a
     * member's ability to sign in — and revoking a handset is the more
     * drastic half of it.
     */
    public function handleSendResetCode(): void
    {
        if (!current_user_can(self::MANAGE_CAPABILITY)) {
            wp_die(esc_html__('You are not allowed to manage devices.', 'fellowship'), '', ['response' => 403]);
        }

        check_admin_referer(self::NONCE . '_reset');

        // A Symfony rule matching ->redirect() with a non-literal argument. This
        // is not Symfony's redirect: it is the private helper below, which builds
        // wp_safe_redirect(add_query_arg([...], admin_url('admin.php'))). The base
        // URL is fixed, the argument only ever becomes a query-parameter *value*,
        // and wp_safe_redirect refuses an off-site host regardless. It matched on
        // the method name alone.
        // nosemgrep: php.symfony.security.audit.symfony-non-literal-redirect.symfony-non-literal-redirect
        $this->redirect($this->sendResetCodeFromRequest());
    }

    /**
     * The body of the above, split out so it can be driven directly.
     *
     * The handler ends in wp_safe_redirect() and exit, which a test
     * cannot follow. Splitting the decision from the redirect is the
     * suite's existing answer to that -- see Reach's
     * CallRequestsPage::completeFromRequest() -- and it is
     * behaviour-identical.
     *
     * @return string The result code the notice is keyed on.
     */
    public function sendResetCodeFromRequest(): string
    {
        // sanitize_email + is_email rather than filter_input, which the
        // revoke handler above uses. filter_input reads the *original*
        // request rather than $_POST, so a split-out method cannot be
        // driven through it -- which is the entire reason this method is
        // split out. The validation is not weaker for it: is_email is
        // WordPress's own check and the value is only ever used to look a
        // member up.
        $posted = isset($_POST['member_email']) ? wp_unslash($_POST['member_email']) : '';
        $email = strtolower(trim(sanitize_email(is_string($posted) ? $posted : '')));

        if ($email === '' || !is_email($email)) {
            return 'code_bad_address';
        }

        // <b>Deliberately not the REST endpoint's non-answer.</b> There,
        // saying whether an address belongs to a member would let anybody
        // enumerate the fellowship, so the response never varies. Here the
        // operator is authenticated and can already read the member list,
        // so refusing to say leaks nothing and only wastes their time --
        // they would be left watching for a mail that was never going to
        // arrive.
        $member = $this->gate->authorisedMember($email);
        if ($member === null) {
            return 'code_not_a_member';
        }

        if (!$this->passwords->beginReset($email, time())) {
            // The address is a member's, so the only thing that stops a
            // send now is the anti-flood cooldown. Reported rather than
            // swallowed: a button that silently does nothing is a button
            // somebody presses four more times.
            return 'code_too_soon';
        }

        $this->auditLogger->log(
            AuditLogger::ACTION_UPDATE,
            AuditLogger::ENTITY_MEMBER,
            $member->getId(),
            'authentication',
            'Link password code sent;by:admin:' . get_current_user_id(),
        );

        return 'code_sent';
    }

    /**
     * The one thing on this screen that is not about a device.
     *
     * <b>An address rather than a row, deliberately.</b> The member who
     * most needs this has no handset yet — they cannot use either
     * sign-in button and have nothing in the table below — so a
     * per-row button would be missing for exactly the case it exists to
     * solve.
     *
     * Shown only to somebody who can manage devices, and checked again in
     * the handler: what the page chose to render is not a permission
     * check.
     */
    private function resetCodeForm(): void
    {
        echo '<h2>' . esc_html__('Password code', 'fellowship') . '</h2>';

        echo '<p class="description">'
            . esc_html__(
                'Emails a member a one-time code for setting a Link password. Most members sign in with Google or Apple and never need one; this is for a member whose address is not one of those accounts.',
                'fellowship'
            )
            . '</p>';

        echo '<p class="description">'
            . esc_html__(
                'The code goes to the member, not to you. You can start this and they finish it in the app — nobody here can set a password on their behalf.',
                'fellowship'
            )
            . '</p>';

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="' . esc_attr(self::RESET_ACTION) . '">';
        wp_nonce_field(self::NONCE . '_reset');

        echo '<input type="email" name="member_email" class="regular-text" required '
            . 'placeholder="' . esc_attr__('The address the intergroup holds for them', 'fellowship') . '"> ';

        submit_button(__('Email a code', 'fellowship'), 'secondary', 'submit', false);

        echo '</form>';
    }

    /**
     * Check the capability and the nonce, and return the device id.
     * Dies rather than returning on refusal.
     */
    private function authoriseAction(): string
    {
        if (!current_user_can(self::MANAGE_CAPABILITY)) {
            wp_die(esc_html__('You are not allowed to manage devices.', 'fellowship'), '', ['response' => 403]);
        }

        // <b>Validated before anything else reads it.</b> This value is concatenated
        // into the nonce action name on the next line and into a Firestore path after
        // that, so it has to be a device id and nothing that merely contains one.
        //
        // The superglobal rather than filter_input, which reads the *original* request
        // and so cannot be driven by a test at all.
        $posted = $_POST['device'] ?? null;
        $id = is_string($posted) && preg_match(self::DEVICE_ID, $posted) === 1 ? $posted : '';

        check_admin_referer(self::NONCE . '_' . $id);

        if ($id === '') {
            wp_die(esc_html__('No device was named.', 'fellowship'), '', ['response' => 400]);
        }

        return $id;
    }

    /**
     * The status cell, echoed rather than returned.
     *
     * It builds markup — a coloured span, and up to two forms — so
     * returning it would mean printing a string of HTML at the call
     * site, and the only tool for that is wp_kses_post(). That reads as
     * "trust me, this is fine", and it is not what is keeping the cell
     * safe: every dynamic value below is escaped where it is written.
     * Echoing directly keeps the escaping next to the value it protects
     * and leaves no HTML-carrying string for anything to have to trust.
     */
    private function status(LinkDevice $device, bool $canManage): void
    {
        if ($device->revoked) {
            echo '<span class="description">'
                . esc_html(sprintf(__('Revoked %s', 'fellowship'), $this->when($device->revokedAt)))
                . '</span>';

            if ($canManage) {
                echo ' ';
                $this->button(self::REMOVE_ACTION, $device->id, __('Remove', 'fellowship'), true);
            }

            return;
        }

        if ($device->keyFault) {
            // Worth saying loudly: this handset is enrolled, looks
            // healthy, and cannot read a word it is sent.
            echo '<span style="color:#b32d2e"><strong>'
                . esc_html__('Cannot read messages', 'fellowship')
                . '</strong></span><br>';
        }

        if (!$canManage) {
            echo esc_html__('Active', 'fellowship');

            return;
        }

        $this->button(self::REVOKE_ACTION, $device->id, __('Revoke', 'fellowship'), false);
        echo ' ';
        $this->button(self::REMOVE_ACTION, $device->id, __('Remove', 'fellowship'), true);
    }

    private function button(string $action, string $deviceId, string $label, bool $confirm): void
    {
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline">';
        echo '<input type="hidden" name="action" value="' . esc_attr($action) . '">';
        echo '<input type="hidden" name="device" value="' . esc_attr($deviceId) . '">';

        wp_nonce_field(self::NONCE . '_' . $deviceId, '_wpnonce', true, true);

        echo '<button type="submit" class="button button-small"';

        if ($confirm) {
            echo ' onclick="return confirm(' . esc_attr(wp_json_encode(
                __('Remove this device permanently? Revoking keeps the record instead.', 'fellowship')
            ) ?: '""') . ')"';
        }

        echo '>' . esc_html($label) . '</button></form>';
    }

    private function memberName(LinkDevice $device): string
    {
        $member = $device->memberId > 0 ? $this->members->findById($device->memberId) : null;

        if ($member === null) {
            // The member has gone from Unity but the device remains. Worth showing as
            // such rather than as a blank cell: it means a handset that will fail its
            // next request, and somebody may want to remove it.
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
            // Taint traced from $_GET['paged'], which is cast to int before it goes
            // anywhere. See MessagesPage::pagination().
            // nosemgrep: php.lang.security.taint-unsafe-echo-tag.taint-unsafe-echo-tag
            echo '<div class="tablenav"><div class="tablenav-pages">' . wp_kses_post($links) . '</div></div>';
        }
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
        $result = sanitize_key((string) ($_GET['fellowship_result'] ?? ''));

        $message = match ($result) {
            'revoked'   => __('The device was revoked. Its record has been kept.', 'fellowship'),
            'removed'   => __('The device was removed.', 'fellowship'),
            'code_sent' => __('A code has been emailed to that member. It lasts an hour and can be used once.', 'fellowship'),
            default     => '',
        };

        if ($message !== '') {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html($message) . '</p></div>';

            return;
        }

        // The ways it does not work, each needing a different thing
        // from whoever is reading it.
        $warning = match ($result) {
            'firebase_unavailable' => __('Firebase could not be reached, so nothing has changed. That device is not cut off yet: please try again.', 'fellowship'),
            'code_bad_address' => __('That is not a valid email address.', 'fellowship'),
            'code_not_a_member' => __('No member holds that address. Check it against the membership record — sign-in matches on the address the intergroup has.', 'fellowship'),
            'code_too_soon' => __('A code was sent to that member less than two minutes ago. Wait, then try again — the first one is still valid.', 'fellowship'),
            default => '',
        };

        if ($warning !== '') {
            echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html($warning) . '</p></div>';
        }
    }
}
