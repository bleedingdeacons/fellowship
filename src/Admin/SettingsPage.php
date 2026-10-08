<?php

declare(strict_types=1);

namespace Fellowship\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Core\Settings;
use Fellowship\Push\ServiceAccount;
use Fellowship\Rest\DeviceAuthController;
use Guardian\Admin\ProviderCredentialsSection;
use Guardian\Admin\ProviderField;

use function rest_url;

/**
 * OAuth credentials, the Firebase service account, and the two policy
 * switches.
 *
 * <b>Secrets are write-only from here.</b> A stored client secret or
 * service account is shown as "configured" and never rendered back into
 * the form: a settings screen that redisplays a credential puts it in
 * every screenshot, every screen-share and every browser's saved-form
 * cache. Submitting the field empty leaves what is stored alone;
 * clearing one is an explicit tick.
 */
final class SettingsPage
{
    public const PAGE_SLUG = 'fellowship-settings';
    public const SAVE_ACTION = 'fellowship_save_settings';

    private const CAPABILITY = 'manage_options';
    private const NONCE = 'fellowship_settings';

    public function __construct(private readonly Settings $settings)
    {
    }

    public function register(): void
    {
        add_action('admin_menu', [$this, 'addMenu']);
        add_action('admin_post_' . self::SAVE_ACTION, [$this, 'handleSave']);
    }

    public function addMenu(): void
    {
        add_submenu_page(
            MessagesPage::MENU_SLUG,
            __('Settings', 'fellowship'),
            __('Settings', 'fellowship'),
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
        echo '<h1>' . esc_html__('Fellowship settings', 'fellowship') . '</h1>';

        $this->notice();

        echo '<p>' . esc_html__('The Link app signs in through these providers. Register the redirect URI shown under each one with that provider.', 'fellowship') . '</p>';

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="' . esc_attr(self::SAVE_ACTION) . '">';
        wp_nonce_field(self::NONCE);

        echo '<h2>' . esc_html__('Sign-in providers', 'fellowship') . '</h2>';
        $this->providerSection()->render();

        echo '<h2>' . esc_html__('Push notifications', 'fellowship') . '</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';
        echo '<tr><th scope="row"><label for="fcm_service_account">' . esc_html__('Firebase service account', 'fellowship') . '</label></th><td>';
        echo '<textarea name="fcm_service_account" id="fcm_service_account" rows="6" class="large-text code" placeholder="'
            . esc_attr__('Paste the service-account JSON to replace what is stored', 'fellowship') . '"></textarea>';
        echo '<p class="description">' . esc_html($this->fcmStatus()) . '</p>';
        echo '<label><input type="checkbox" name="clear_fcm" value="1"> '
            . esc_html__('Clear the stored service account', 'fellowship') . '</label>';
        echo '<p class="description">'
            . esc_html__('Without a service account, messages are still stored and delivered — handsets collect them on their next poll instead of being woken.', 'fellowship')
            . '</p>';
        echo '</td></tr>';
        echo '</tbody></table>';

        echo '<h2>' . esc_html__('Policy', 'fellowship') . '</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';

        echo '<tr><th scope="row">' . esc_html__('Committee sends from the app', 'fellowship') . '</th><td>';
        echo '<label><input type="checkbox" name="app_committee_send" value="1"'
            . checked($this->settings->allowsCommitteeSendFromApp(), true, false) . '> '
            . esc_html__('Let members send to a whole committee from Link', 'fellowship') . '</label>';
        echo '<p class="description">'
            . esc_html__('Off by default. A message sent to a committee by mistake cannot be taken back.', 'fellowship')
            . '</p>';
        echo '</td></tr>';

        echo '<tr><th scope="row"><label for="retention_days">' . esc_html__('Keep messages for', 'fellowship') . '</label></th><td>';
        echo '<input type="number" name="retention_days" id="retention_days" min="0" step="1" class="small-text" value="'
            . esc_attr((string) $this->settings->getRetentionDays()) . '"> ' . esc_html__('days', 'fellowship');
        echo '<p class="description">'
            . esc_html__('Messages and their delivery records are deleted after this many days. Zero keeps them indefinitely, which is a decision worth making deliberately — they are personal data.', 'fellowship')
            . '</p>';
        echo '</td></tr>';

        echo '</tbody></table>';

        submit_button();

        echo '</form></div>';
    }

    public function handleSave(): void
    {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You are not allowed to change these settings.', 'fellowship'), '', ['response' => 403]);
        }

        check_admin_referer(self::NONCE);

        // A Symfony rule matching ->redirect() with a non-literal argument. This
        // is not Symfony's redirect: it is the private helper below, which builds
        // wp_safe_redirect(add_query_arg([...], admin_url('admin.php'))). The base
        // URL is fixed, the argument only ever becomes a query-parameter *value*,
        // and wp_safe_redirect refuses an off-site host regardless. It matched on
        // the method name alone.
        // nosemgrep: php.symfony.security.audit.symfony-non-literal-redirect.symfony-non-literal-redirect
        $this->redirect($this->saveFromRequest());
    }

    /**
     * The body of the above, split out so it can be driven directly.
     *
     * The handler ends in wp_safe_redirect() and exit, which a test
     * cannot follow. Same split as ComposePage::sendFromRequest() and
     * DevicesPage::sendResetCodeFromRequest(), and behaviour-identical:
     * what were two calls to redirect() are now two return values and one
     * call.
     *
     * @return string The result code the notice is keyed on.
     */
    public function saveFromRequest(): string
    {
        // Client ids and secrets: Guardian's section unslashes, sanitises
        // the ids, and treats an empty secret field as "leave it alone" and
        // only the explicit tick as "clear it".
        $this->providerSection()->save($_POST);

        // wp_unslash, and this is the field that made the omission
        // visible. WordPress runs wp_magic_quotes() over $_POST on every
        // request, so a pasted service account arrives with every quote
        // and every escape backslashed. json_decode refuses it, fromJson()
        // answers null, and the screen tells somebody their file does not
        // look like a service account -- of a file that is perfectly valid.
        // No correct service account could be saved here at all, which is
        // why the field had never been populated on any site.
        //
        // The fields above are slashed identically and simply never showed
        // it: client ids and OAuth secrets are alphanumeric with dashes,
        // so addslashes leaves them byte-for-byte alone. They are unslashed
        // now because the next secret with a quote or a backslash in it
        // would be corrupted silently rather than refused loudly, which is
        // the worse of the two failures.
        $fcm = trim((string) wp_unslash($_POST['fcm_service_account'] ?? ''));
        if (!empty($_POST['clear_fcm'])) {
            $this->settings->setFcmServiceAccount('');
        } elseif ($fcm !== '') {
            // Parsed before it is stored. A service account that will not
            // parse is a setting that looks saved and pushes nothing, and
            // the moment to find that out is now rather than at the first
            // message.
            if (ServiceAccount::fromJson($fcm) === null) {
                return 'bad_service_account';
            }

            $this->settings->setFcmServiceAccount($fcm);
        }

        $this->settings->setCommitteeSendFromApp(!empty($_POST['app_committee_send']));
        $this->settings->setRetentionDays((int) ($_POST['retention_days'] ?? Settings::DEFAULT_RETENTION_DAYS));

        return 'saved';
    }

    /**
     * The client id and secret rows for the four providers, from Guardian.
     * Every provider but Apple comes back to the one callback; Apple signs
     * in on the handset and has no redirect.
     */
    private function providerSection(): ProviderCredentialsSection
    {
        $callbackUrl = rest_url(DeviceAuthController::NAMESPACE . '/auth/callback');

        return new ProviderCredentialsSection($this->settings, [
            ProviderField::google($callbackUrl),
            ProviderField::microsoft($callbackUrl),
            ProviderField::facebook($callbackUrl),
            ProviderField::apple(),
        ]);
    }

    private function fcmStatus(): string
    {
        $stored = $this->settings->getFcmServiceAccount();
        if ($stored === '') {
            return __('No service account is stored — messages will be delivered by polling only.', 'fellowship');
        }

        $account = ServiceAccount::fromJson($stored);
        if ($account === null) {
            return __('A service account is stored but could not be read. Push is not working.', 'fellowship');
        }

        return sprintf(
            /* translators: %s: Firebase project id */
            __('A service account for project "%s" is stored.', 'fellowship'),
            $account->projectId,
        );
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

        if ($result === 'saved') {
            echo '<div class="notice notice-success is-dismissible"><p>'
                . esc_html__('Settings saved.', 'fellowship') . '</p></div>';
            return;
        }

        if ($result === 'bad_service_account') {
            echo '<div class="notice notice-error is-dismissible"><p>'
                . esc_html__('That does not look like a Firebase service-account JSON file. Nothing was changed.', 'fellowship')
                . '</p></div>';
            return;
        }
    }
}
