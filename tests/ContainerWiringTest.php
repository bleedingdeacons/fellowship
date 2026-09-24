<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Scrutiny\Testing\Doubles\SpyAuditLogger;
use function Brain\Monkey\Functions\when;
use Fellowship\Admin\ComposePage;
use Fellowship\Admin\DevicesPage;
use Fellowship\Admin\MessagesPage;
use Fellowship\Admin\SettingsPage;
use Fellowship\Auth\PasswordAuthenticator;
use Unity\Auth\Interfaces\PasswordCredentialRepository;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
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
 */

covers(\Fellowship\Core\FellowshipServiceProvider::class);

beforeEach(function () {
    $GLOBALS['wpdb'] = new RecordingWpdb();

    when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);

    // What Unity and Scrutiny are expected to have put there already.
    $this->container = new FakeContainer([
        'Unity\\Members\\Interfaces\\MemberRepository' => new InMemoryMemberRepository(),
        'Unity\\Committees\\Interfaces\\CommitteeRepository' => new InMemoryCommitteeRepository(),
        'Scrutiny\\Audit\\Interfaces\\AuditLogger' => new SpyAuditLogger(),
        // The password store is Unity's too, from the same upgrade
        // that gave it a table of its own. Fellowship no longer binds
        // one, so if this line goes the failure is the honest one:
        // PasswordAuthenticator cannot be built.
        PasswordCredentialRepository::class => new InMemoryPasswordCredentialRepository(),
    ]);

    (new FellowshipServiceProvider())->register($this->container);
});

/**
 * @param class-string $service
 */
test('every service can be built', function (string $service) {
    // Built, not merely registered. A factory that throws when called
    // is the failure this exists to catch, and asserting on
    // registration alone would sail straight past it.
    expect($this->container->has($service))->toBeTrue($service . ' was never registered.');
    expect($this->container->get($service))->toBeInstanceOf($service);
})->with([
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
]);

test('every sign in provider is registered', function () {
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
        expect($registry->get($name))->not->toBeNull($name . ' is not registered.');
    }
});

test('an unknown provider is not invented', function () {
    expect($this->container->get(ProviderRegistry::class)->get('myspace'))->toBeNull();
});

test('the same instance comes back each time', function () {
    // The repositories hold no state, but the container's contract is
    // one instance per id, and a factory that ignored it would give
    // the admin screens a different device repository from the REST
    // controllers.
    expect($this->container->get(DeviceRepository::class))->toBe($this->container->get(DeviceRepository::class));
});
