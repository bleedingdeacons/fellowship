<?php

declare(strict_types=1);

namespace Fellowship\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Auth\Providers\AppleProvider;
use Fellowship\Auth\Providers\FacebookProvider;
use Fellowship\Auth\Providers\GoogleProvider;
use Fellowship\Auth\Providers\MicrosoftProvider;
use Fellowship\Core\Settings;
use Fellowship\Push\ServiceAccount;
use Fellowship\Rest\DeviceAuthController;

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

        echo '<p>' . esc_html__('The Link app signs in through these providers. The redirect URI to register with each of them is:', 'fellowship') . '</p>';
        echo '<p><code>' . esc_html(rest_url(DeviceAuthController::NAMESPACE . '/auth/callback')) . '</code></p>';

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="' . esc_attr(self::SAVE_ACTION) . '">';
        wp_nonce_field(self::NONCE);

        echo '<h2>' . esc_html__('Sign in with Google', 'fellowship') . '</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';
        $this->textRow(
            'google_client_id',
            __('Client ID', 'fellowship'),
            $this->settings->getClientId(GoogleProvider::PROVIDER_NAME),
        );
        $this->secretRow(
            'google_client_secret',
            __('Client secret', 'fellowship'),
            $this->settings->getClientSecret(GoogleProvider::PROVIDER_NAME) !== '',
        );
        echo '</tbody></table>';

        echo '<h2>' . esc_html__('Sign in with Microsoft', 'fellowship') . '</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';
        $this->textRow(
            'microsoft_client_id',
            __('Application (client) ID', 'fellowship'),
            $this->settings->getClientId(MicrosoftProvider::PROVIDER_NAME),
        );
        $this->secretRow(
            'microsoft_client_secret',
            __('Client secret', 'fellowship'),
            $this->settings->getClientSecret(MicrosoftProvider::PROVIDER_NAME) !== '',
        );
        echo '<tr><td colspan="2"><p class="description">'
            . esc_html__('Register the app in Entra as "Personal Microsoft accounts only". Work and school accounts are refused on purpose: only the consumer tenant guarantees the address in the token is one Microsoft verified.', 'fellowship')
            . '</p></td></tr>';
        echo '</tbody></table>';

        echo '<h2>' . esc_html__('Sign in with Facebook', 'fellowship') . '</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';
        $this->textRow(
            'facebook_client_id',
            __('App ID', 'fellowship'),
            $this->settings->getClientId(FacebookProvider::PROVIDER_NAME),
        );
        $this->secretRow(
            'facebook_client_secret',
            __('App secret', 'fellowship'),
            $this->settings->getClientSecret(FacebookProvider::PROVIDER_NAME) !== '',
        );
        echo '<tr><td colspan="2"><p class="description">'
            . esc_html__('Facebook Login must have the "openid" and "email" permissions. Nothing else is requested.', 'fellowship')
            . '</p></td></tr>';
        echo '</tbody></table>';

        echo '<h2>' . esc_html__('Sign in with Apple', 'fellowship') . '</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';
        $this->textRow(
            'apple_client_id',
            __('Service ID (audience)', 'fellowship'),
            $this->settings->getClientId(AppleProvider::PROVIDER_NAME),
        );
        echo '<tr><td colspan="2"><p class="description">'
            . esc_html__('Apple signs in on the handset itself, so no client secret is needed here — only the identifier the ID token is issued for.', 'fellowship')
            . '</p></td></tr>';
        echo '</tbody></table>';

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
        $this->settings->setClientId(
            GoogleProvider::PROVIDER_NAME,
            sanitize_text_field((string) ($_POST['google_client_id'] ?? '')),
        );
        $this->settings->setClientId(
            AppleProvider::PROVIDER_NAME,
            sanitize_text_field((string) ($_POST['apple_client_id'] ?? '')),
        );

        $this->settings->setClientId(
            MicrosoftProvider::PROVIDER_NAME,
            sanitize_text_field((string) ($_POST['microsoft_client_id'] ?? '')),
        );
        $this->settings->setClientId(
            FacebookProvider::PROVIDER_NAME,
            sanitize_text_field((string) ($_POST['facebook_client_id'] ?? '')),
        );

        // An empty secret field means "leave it alone", not "clear it" —
        // the field is never populated with the stored value, so an empty
        // submission is the normal case for anyone editing something else
        // on this screen. Clearing is the checkbox's job.
        //
        // Extracted to a loop when the second and third providers arrived:
        // three copies of the same six lines is where one of them
        // eventually gets the wrong constant pasted into it.
        foreach (
            [
            GoogleProvider::PROVIDER_NAME    => 'google_client_secret',
            MicrosoftProvider::PROVIDER_NAME => 'microsoft_client_secret',
            FacebookProvider::PROVIDER_NAME  => 'facebook_client_secret',
            ] as $provider => $field
        ) {
            $submitted = trim((string) ($_POST[$field] ?? ''));

            if (!empty($_POST['clear_' . $field])) {
                $this->settings->setClientSecret($provider, '');
            } elseif ($submitted !== '') {
                $this->settings->setClientSecret($provider, $submitted);
            }
        }

        $fcm = trim((string) ($_POST['fcm_service_account'] ?? ''));
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

    private function textRow(string $name, string $label, string $value): void
    {
        echo '<tr><th scope="row"><label for="' . esc_attr($name) . '">' . esc_html($label) . '</label></th><td>';
        echo '<input type="text" name="' . esc_attr($name) . '" id="' . esc_attr($name)
            . '" class="regular-text" value="' . esc_attr($value) . '">';
        echo '</td></tr>';
    }

    private function secretRow(string $name, string $label, bool $configured): void
    {
        echo '<tr><th scope="row"><label for="' . esc_attr($name) . '">' . esc_html($label) . '</label></th><td>';
        echo '<input type="password" name="' . esc_attr($name) . '" id="' . esc_attr($name)
            . '" class="regular-text" autocomplete="new-password" placeholder="'
            . esc_attr__('Leave blank to keep what is stored', 'fellowship') . '">';
        echo '<p class="description">' . esc_html(
            $configured
                ? __('A secret is stored.', 'fellowship')
                : __('No secret is stored — Google sign-in will not work.', 'fellowship')
        ) . '</p>';
        echo '<label><input type="checkbox" name="clear_' . esc_attr($name) . '" value="1"> '
            . esc_html__('Clear the stored secret', 'fellowship') . '</label>';
        echo '</td></tr>';
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
        }
    }
}
