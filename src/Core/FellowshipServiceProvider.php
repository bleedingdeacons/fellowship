<?php

declare(strict_types=1);

namespace Fellowship\Core;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Admin\ComposePage;
use Fellowship\Admin\DevicesPage;
use Fellowship\Admin\MessagesPage;
use Fellowship\Admin\SettingsPage;
use Closure;
use Fellowship\Auth\AudienceProviders;
use Fellowship\Auth\AudienceRegistry;
use Fellowship\Auth\DeviceCodeStore;
use Fellowship\Auth\DeviceRedirectValidator;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Auth\IdentityBroker;
use Fellowship\Auth\LinkAudience;
use Fellowship\Auth\PasswordAuthenticator;
use Unity\Auth\Interfaces\PasswordCredentialRepository;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Auth\StateStore;
use Guardian\Credentials\CredentialStore;
use Guardian\Jwt\JwtVerifier;
use Guardian\ProviderRegistry;
use Guardian\Providers\AppleProvider;
use Guardian\Providers\FacebookProvider;
use Guardian\Providers\GoogleProvider;
use Guardian\Providers\MicrosoftProvider;
use Guardian\Providers\OAuthProvider;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\DeviceRepository;
use Fellowship\Devices\MemberGate;
use Fellowship\Devices\WpdbDeviceRepository;
use Fellowship\Cli\DirectoryCli;
use Fellowship\Directory\DirectoryPresenter;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\MessageDispatcher;
use Fellowship\Messaging\MessageRepository;
use Fellowship\Messaging\RecipientRepository;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Messaging\WpdbMessageRepository;
use Fellowship\Messaging\WpdbRecipientRepository;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Rest\DeviceAuthController;
use Fellowship\Rest\DirectoryController;
use Fellowship\Rest\MessageController;
use Psr\Container\ContainerInterface;
use Scrutiny\Audit\Interfaces\AuditLogger;
use Unity\Committees\Interfaces\CommitteeRepository;
use Unity\Groups\Interfaces\GroupRepository;
use Unity\Core\Interfaces\Container;
use Unity\Members\Interfaces\MemberRepository;
use Unity\Positions\Interfaces\PositionRepository;

/**
 * Registers Fellowship's services into Unity's container.
 *
 * Fellowship has no container of its own — like Trumpet and Promises it
 * registers into Unity's, which is what lets it type-hint Unity's
 * repositories directly rather than reaching for globals.
 *
 * <b>{@see MemberGate} is registered first and shared</b>, because it is
 * the single answer to "may this person use Link?" and four different
 * things consult it. See that class on why it is one object rather than
 * a rule written out four times.
 */
final class FellowshipServiceProvider
{
    /** Every provider Fellowship registers, by Guardian's name for it. */
    private const PROVIDERS = [
        GoogleProvider::PROVIDER_NAME,
        MicrosoftProvider::PROVIDER_NAME,
        FacebookProvider::PROVIDER_NAME,
        AppleProvider::PROVIDER_NAME,
    ];

    /**
     * Builds a named provider around a credential store: Settings for the
     * registry, an audience's own client for {@see AudienceProviders}.
     * One definition, so the two can never be built differently.
     *
     * @return Closure(string, CredentialStore): ?OAuthProvider
     */
    private static function providerFactory(JwtVerifier $verifier): Closure
    {
        return static fn(string $name, CredentialStore $credentials): ?OAuthProvider => match ($name) {
            GoogleProvider::PROVIDER_NAME    => new GoogleProvider($credentials, $verifier, UserAgent::plugin()),
            MicrosoftProvider::PROVIDER_NAME => new MicrosoftProvider($credentials, $verifier, UserAgent::plugin()),
            FacebookProvider::PROVIDER_NAME  => new FacebookProvider($credentials, $verifier, UserAgent::plugin()),
            AppleProvider::PROVIDER_NAME     => new AppleProvider($credentials, $verifier),
            default                          => null,
        };
    }

    public function register(Container $container): void
    {
        // ── Core ──
        $container->register(Settings::class, fn() => new Settings());
        $container->register(RateLimiter::class, fn() => new RateLimiter());
        $container->register(MessageSealer::class, fn() => new MessageSealer());

        // ── Identity ──
        $container->register(MemberGate::class, fn(ContainerInterface $c) => new MemberGate(
            $c->get(MemberRepository::class),
        ));
        // Guardian's verifier, logging to Fellowship's channel and fetching
        // key sets as Fellowship.
        $container->register(JwtVerifier::class, fn() => new JwtVerifier(UserAgent::plugin(), 'fellowship'));
        $container->register(StateStore::class, fn() => new StateStore());
        $container->register(DeviceCodeStore::class, fn() => new DeviceCodeStore());
        $container->register(DeviceTokenMinter::class, fn() => new DeviceTokenMinter());
        $container->register(DeviceRedirectValidator::class, fn() => new DeviceRedirectValidator());

        $container->register(ProviderRegistry::class, function (ContainerInterface $c) {
            $registry = new ProviderRegistry();
            // Registration is the permission model — a provider absent
            // from here is unreachable, not merely unconfigured. See
            // ProviderRegistry. The providers are Guardian's; Settings is
            // the CredentialStore they read client ids and secrets from.
            $settings = $c->get(Settings::class);
            $build = self::providerFactory($c->get(JwtVerifier::class));
            foreach (self::PROVIDERS as $name) {
                $provider = $build($name, $settings);
                if ($provider !== null) {
                    $registry->register($provider);
                }
            }
            return $registry;
        });

        // The same providers rebuilt around an audience's own client, for
        // an audience that brings one. See BringsOwnClient.
        $container->register(AudienceProviders::class, fn(ContainerInterface $c) => new AudienceProviders(
            $c->get(ProviderRegistry::class),
            self::providerFactory($c->get(JwtVerifier::class)),
        ));

        // ── Devices ──
        $container->register(DeviceRepository::class, function () {
            global $wpdb;
            return new WpdbDeviceRepository($wpdb);
        });
        $container->register(CurrentDevice::class, fn(ContainerInterface $c) => new CurrentDevice(
            $c->get(DeviceRepository::class),
            $c->get(DeviceTokenMinter::class),
            $c->get(MemberGate::class),
        ));

        // ── Signing in on behalf of other plugins ──
        //
        // One registry, shared: the controller's callback reads it and
        // another plugin writes into it through the broker, on
        // fellowship/loaded. See SignInAudience.
        $container->register(AudienceRegistry::class, fn(ContainerInterface $c) => new AudienceRegistry(
            new LinkAudience($c->get(DeviceRedirectValidator::class), $c->get(MemberGate::class)),
        ));
        $container->register(IdentityBroker::class, fn(ContainerInterface $c) => new IdentityBroker(
            $c->get(AudienceRegistry::class),
            $c->get(ProviderRegistry::class),
            $c->get(StateStore::class),
            $c->get(DeviceCodeStore::class),
            $c->get(CurrentDevice::class),
            $c->get(DeviceRepository::class),
            $c->get(MemberGate::class),
            $c->get(AudienceProviders::class),
        ));

        // ── Messages ──
        $container->register(MessageRepository::class, function () {
            global $wpdb;
            return new WpdbMessageRepository($wpdb);
        });
        $container->register(RecipientRepository::class, function () {
            global $wpdb;
            return new WpdbRecipientRepository($wpdb);
        });
        $container->register(RecipientResolver::class, fn(ContainerInterface $c) => new RecipientResolver(
            $c->get(MemberRepository::class),
            $c->get(CommitteeRepository::class),
            $c->get(MemberGate::class),
        ));

        // ── Push ──
        $container->register(FcmClient::class, fn() => new FcmClient());
        $container->register(FcmTransport::class, fn(ContainerInterface $c) => new FcmTransport(
            $c->get(FcmClient::class),
            $c->get(Settings::class),
            $c->get(MessageSealer::class),
        ));

        $container->register(MessageDispatcher::class, fn(ContainerInterface $c) => new MessageDispatcher(
            $c->get(MessageRepository::class),
            $c->get(RecipientRepository::class),
            $c->get(DeviceRepository::class),
            $c->get(FcmTransport::class),
        ));

        $container->register(MessageApi::class, fn(ContainerInterface $c) => new MessageApi(
            $c->get(MessageDispatcher::class),
            $c->get(RecipientResolver::class),
            $c->get(AuditLogger::class),
        ));

        $container->register(DirectoryCli::class, fn(ContainerInterface $c) => new DirectoryCli(
            $c->get(DirectoryPresenter::class),
            $c->get(Settings::class),
        ));

        $container->register(DirectoryPresenter::class, fn(ContainerInterface $c) => new DirectoryPresenter(
            $c->get(MemberRepository::class),
            $c->get(CommitteeRepository::class),
            $c->get(MemberGate::class),
            // Whether each member has a live device, for the app's
            // hasDevice flag. One findAllLive() per directory read.
            $c->get(DeviceRepository::class),
            // Feature-detected, the way Promises detects Unity's
            // repositories: Unity ships headless and a deployment need not
            // have groups bound. Absent, the directory is built without
            // home groups rather than failing to build — see
            // DirectoryPresenter::groupTitle().
            $c->has(GroupRepository::class) ? $c->get(GroupRepository::class) : null,
            // The same, for intergroup service positions.
            $c->has(PositionRepository::class) ? $c->get(PositionRepository::class) : null,
        ));

        // ── Password sign-in ──
        //
        // The credential store is Unity's, and is deliberately not
        // registered here. Fellowship used to bind its own implementation
        // over its own wp_fellowship_credentials table, and Reach did the
        // same over its own — so a member who set a password in one could
        // not sign into the other with it, and a reset in one left the
        // other stale with nothing to say so. A member has one password.
        //
        // Unity declares the contract and binds nothing to it, as it
        // does for every repository; tsml-for-unity supplies the
        // implementation, into the same container this provider writes
        // into. PasswordAuthenticator below resolves it unchanged.

        $container->register(PasswordPolicy::class, fn(): PasswordPolicy => new PasswordPolicy());

        $container->register(PasswordResetMailer::class, fn(): PasswordResetMailer => new PasswordResetMailer());

        $container->register(PasswordAuthenticator::class, fn(ContainerInterface $c) => new PasswordAuthenticator(
            $c->get(PasswordCredentialRepository::class),
            $c->get(MemberGate::class),
            $c->get(PasswordResetMailer::class),
            $c->get(PasswordPolicy::class),
        ));

        // ── REST ──
        $container->register(DeviceAuthController::class, fn(ContainerInterface $c) => new DeviceAuthController(
            $c->get(DeviceRepository::class),
            $c->get(DeviceTokenMinter::class),
            $c->get(DeviceCodeStore::class),
            $c->get(DeviceRedirectValidator::class),
            $c->get(MemberGate::class),
            $c->get(CurrentDevice::class),
            $c->get(ProviderRegistry::class),
            $c->get(StateStore::class),
            $c->get(RateLimiter::class),
            $c->get(AuditLogger::class),
            $c->get(PasswordAuthenticator::class),
            $c->get(AudienceRegistry::class),
            $c->get(AudienceProviders::class),
        ));

        $container->register(MessageController::class, fn(ContainerInterface $c) => new MessageController(
            $c->get(CurrentDevice::class),
            $c->get(MessageRepository::class),
            $c->get(RecipientRepository::class),
            $c->get(MessageDispatcher::class),
            $c->get(RecipientResolver::class),
            $c->get(MessageSealer::class),
            $c->get(MemberRepository::class),
            $c->get(Settings::class),
            $c->get(RateLimiter::class),
            $c->get(AuditLogger::class),
        ));

        $container->register(DirectoryController::class, fn(ContainerInterface $c) => new DirectoryController(
            $c->get(CurrentDevice::class),
            $c->get(DirectoryPresenter::class),
            $c->get(Settings::class),
            $c->get(AuditLogger::class),
        ));

        // ── Admin ──
        $container->register(MessagesPage::class, fn(ContainerInterface $c) => new MessagesPage(
            $c->get(MessageRepository::class),
            $c->get(RecipientRepository::class),
        ));
        $container->register(ComposePage::class, fn(ContainerInterface $c) => new ComposePage(
            $c->get(MessageApi::class),
            $c->get(CommitteeRepository::class),
            $c->get(MemberGate::class),
        ));
        $container->register(DevicesPage::class, fn(ContainerInterface $c) => new DevicesPage(
            $c->get(DeviceRepository::class),
            $c->get(MemberRepository::class),
            $c->get(AuditLogger::class),
            $c->get(PasswordAuthenticator::class),
            $c->get(MemberGate::class),
        ));
        $container->register(SettingsPage::class, fn(ContainerInterface $c) => new SettingsPage(
            $c->get(Settings::class),
        ));
    }
}
