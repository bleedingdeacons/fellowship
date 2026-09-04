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
use Fellowship\Auth\DeviceCodeStore;
use Fellowship\Auth\DeviceRedirectValidator;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Auth\JwtVerifier;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordCredentialRepository;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Auth\Providers\AppleProvider;
use Fellowship\Auth\WpdbPasswordCredentialRepository;
use Fellowship\Auth\Providers\FacebookProvider;
use Fellowship\Auth\Providers\GoogleProvider;
use Fellowship\Auth\Providers\MicrosoftProvider;
use Fellowship\Auth\ProviderRegistry;
use Fellowship\Auth\StateStore;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\DeviceRepository;
use Fellowship\Devices\MemberGate;
use Fellowship\Devices\WpdbDeviceRepository;
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
use Unity\Core\Interfaces\Container;
use Unity\Members\Interfaces\MemberRepository;

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
        $container->register(JwtVerifier::class, fn() => new JwtVerifier());
        $container->register(StateStore::class, fn() => new StateStore());
        $container->register(DeviceCodeStore::class, fn() => new DeviceCodeStore());
        $container->register(DeviceTokenMinter::class, fn() => new DeviceTokenMinter());
        $container->register(DeviceRedirectValidator::class, fn() => new DeviceRedirectValidator());

        $container->register(ProviderRegistry::class, function (ContainerInterface $c) {
            $registry = new ProviderRegistry();
            // Registration is the permission model — a provider absent
            // from here is unreachable, not merely unconfigured. See
            // ProviderRegistry.
            $registry->register(new GoogleProvider($c->get(Settings::class), $c->get(JwtVerifier::class)));
            $registry->register(new MicrosoftProvider($c->get(Settings::class), $c->get(JwtVerifier::class)));
            $registry->register(new FacebookProvider($c->get(Settings::class), $c->get(JwtVerifier::class)));
            $registry->register(new AppleProvider($c->get(Settings::class), $c->get(JwtVerifier::class)));
            return $registry;
        });

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

        $container->register(DirectoryPresenter::class, fn(ContainerInterface $c) => new DirectoryPresenter(
            $c->get(MemberRepository::class),
            $c->get(CommitteeRepository::class),
            $c->get(MemberGate::class),
        ));

        // ── Password sign-in ──
        //
        // Registered whether or not anybody has set a password: the
        // credential table is empty until somebody asks for a link, and a
        // conditional registration would only move the decision somewhere
        // it is harder to see.
        $container->register(
            PasswordCredentialRepository::class,
            function (): PasswordCredentialRepository {
                global $wpdb;

                if (!$wpdb instanceof \wpdb) {
                    throw new \RuntimeException('Password credentials need $wpdb.');
                }

                return new WpdbPasswordCredentialRepository($wpdb);
            }
        );

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
        ));
        $container->register(DevicesPage::class, fn(ContainerInterface $c) => new DevicesPage(
            $c->get(DeviceRepository::class),
            $c->get(MemberRepository::class),
            $c->get(AuditLogger::class),
        ));
        $container->register(SettingsPage::class, fn(ContainerInterface $c) => new SettingsPage(
            $c->get(Settings::class),
        ));
    }
}
