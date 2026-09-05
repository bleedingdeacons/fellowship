<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use Brain\Monkey\Functions;
use Fellowship\Admin\ComposePage;
use Fellowship\Admin\DevicesPage;
use Fellowship\Admin\MessagesPage;
use Fellowship\Admin\SettingsPage;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordCredentialRepository;
use Fellowship\Auth\ProviderRegistry;
use Fellowship\Auth\Providers\AppleProvider;
use Fellowship\Auth\Providers\FacebookProvider;
use Fellowship\Auth\Providers\GoogleProvider;
use Fellowship\Auth\Providers\MicrosoftProvider;
use Fellowship\Core\FellowshipServiceProvider;
use Fellowship\Devices\DeviceRepository;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\MessageRepository;
use Fellowship\Messaging\RecipientRepository;
use Fellowship\Push\FcmTransport;
use Fellowship\Rest\DeviceAuthController;
use Fellowship\Rest\DirectoryController;
use Fellowship\Rest\MessageController;
use Fellowship\Tests\Support\RecordingWpdb;
use Unity\Testing\Doubles\FakeContainer;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;

/**
 * The object graph.
 *
 * <b>A wiring test earns its place here for one reason: this container is
 * Unity's, not Fellowship's.</b> Every service is registered into a
 * container the plugin does not own, resolving dependencies — the member
 * repository, the committee repository, the audit logger — that other
 * plugins put there. A missing or renamed registration upstream does not
 * fail at boot; it fails the first time somebody opens a screen or a
 * handset calls a route, which is to say in production.
 *
 * So what is asserted is that every entry point can actually be *built*,
 * not merely that a factory was registered. Resolving them is the whole
 * point — a factory that throws when called is exactly the failure this
 * catches, and registration alone would not.
 *
 * The four sign-in providers get their own assertion because they are the
 * one list that is easy to extend in half: adding a provider class and
 * forgetting to register it produces a server that refuses that provider
 * with "unknown sign-in provider" while the app cheerfully offers the
 * button.
 *
 * @covers \Fellowship\Core\FellowshipServiceProvider
 */
final class ContainerWiringTest extends TestCase
{
    private FakeContainer $container;

    protected function setUp(): void
    {
        parent::setUp();

        $GLOBALS['wpdb'] = new RecordingWpdb();

        Functions\when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);

        // What Unity and Scrutiny are expected to have put there already.
        $this->container = new FakeContainer([
            'Unity\\Members\\Interfaces\\MemberRepository' => new InMemoryMemberRepository(),
            'Unity\\Committees\\Interfaces\\CommitteeRepository' => new InMemoryCommitteeRepository(),
            'Scrutiny\\Audit\\Interfaces\\AuditLogger' => new \Scrutiny\Testing\Doubles\SpyAuditLogger(),
        ]);

        (new FellowshipServiceProvider())->register($this->container);
    }

    /**
     * @return list<array{class-string}>
     */
    public static function services(): array
    {
        return [
            [DeviceAuthController::class],
            [MessageController::class],
            [DirectoryController::class],
            [MessageApi::class],
            [SettingsPage::class],
            [MessagesPage::class],
            [ComposePage::class],
            [DevicesPage::class],
            [DeviceRepository::class],
            [MessageRepository::class],
            [RecipientRepository::class],
            [PasswordCredentialRepository::class],
            [PasswordAuthenticator::class],
            [ProviderRegistry::class],
            [FcmTransport::class],
        ];
    }

    /**
     * @param class-string $service
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('services')]
    public function testEveryServiceCanBeBuilt(string $service): void
    {
        // Built, not merely registered. A factory that throws when called
        // is the failure this exists to catch, and asserting on
        // registration alone would sail straight past it.
        self::assertTrue($this->container->has($service), $service . ' was never registered.');
        self::assertInstanceOf($service, $this->container->get($service));
    }

    public function testEverySignInProviderIsRegistered(): void
    {
        // The list that is easy to extend in half: a provider class with
        // no registration is a server that refuses it while the app
        // offers the button.
        $registry = $this->container->get(ProviderRegistry::class);

        $expected = [
            GoogleProvider::PROVIDER_NAME,
            MicrosoftProvider::PROVIDER_NAME,
            FacebookProvider::PROVIDER_NAME,
            AppleProvider::PROVIDER_NAME,
        ];

        foreach ($expected as $name) {
            self::assertNotNull($registry->get($name), $name . ' is not registered.');
        }
    }

    public function testAnUnknownProviderIsNotInvented(): void
    {
        self::assertNull($this->container->get(ProviderRegistry::class)->get('myspace'));
    }

    public function testTheSameInstanceComesBackEachTime(): void
    {
        // The repositories hold no state, but the container's contract is
        // one instance per id, and a factory that ignored it would give
        // the admin screens a different device repository from the REST
        // controllers.
        self::assertSame(
            $this->container->get(DeviceRepository::class),
            $this->container->get(DeviceRepository::class),
        );
    }
}
