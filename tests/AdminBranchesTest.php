<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\ComposePage;
use Fellowship\Admin\DevicesPage;
use Fellowship\Admin\SettingsPage;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\MemberGate;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\MessageDispatcher;
use Fellowship\Messaging\MessageRequest;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\CommitteeStub;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;

/**
 * The states an admin screen only reaches when something is wrong.
 *
 * <b>Every branch here is one somebody meets on a bad day</b>, which is
 * exactly when a screen has to be right: a handset that cannot read what
 * it is sent, a member deleted out from under a device row, a service
 * account that was pasted in but will not parse. The happy path is
 * covered elsewhere; what is asserted here is that none of these renders
 * as a blank cell, and that each says something different from the
 * others — a screen that reports two distinct faults identically is a
 * screen that sends somebody looking in the wrong place.
 *
 * <b>The fan-out records "pushed" per member, not per device.</b> A
 * member with two handsets gets one recipient row, so "at least one of
 * their handsets was told" is the honest claim — see Recipient::$pushedAt
 * on why it is not called delivery.
 */

covers(\Fellowship\Admin\SettingsPage::class, \Fellowship\Admin\DevicesPage::class, \Fellowship\Admin\ComposePage::class, \Fellowship\Messaging\MessageDispatcher::class);

const ADMIN_BRANCHES_MEMBER = 'member@example.org';

beforeEach(function () {
    $_POST = [];
    $_GET = [];
    WpState::$userCan = true;
    FakeWpHttp::reset();

    when('admin_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-admin/' . $p);
    when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);
    when('get_current_user_id')->justReturn(3);
    when('submit_button')->justReturn(null);
    when('paginate_links')->justReturn('');
    when('wp_date')->alias(static fn(string $f, int $t): string => date($f, $t));
    when('wp_generate_uuid4')->alias(static fn(): string => '1111-' . random_int(1, 999999999));

    $this->devices = new InMemoryDeviceRepository();
    $this->messages = new InMemoryMessageRepository();
    $this->recipients = new InMemoryRecipientRepository();
    $this->audit = new SpyAuditLogger();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: ADMIN_BRANCHES_MEMBER),
    ]);
});

// ── The settings screen ───────────────────────────────────────────

test('a stored service account is named by its project', function () {
    // Which is how somebody checks they pasted the right one in,
    // without the screen ever showing the credential back.
    $settings = new Settings();
    $settings->setFcmServiceAccount(adminBranchesAccountJson());

    $markup = captureOutput(fn() => (new SettingsPage($settings))->render());

    expect($markup)->toContain('intergroup-fellowship');
});

test('a service account that will not parse is said to be broken', function () {
    // A row that is present but unreadable pushes nothing, and looks
    // identical to a working one from the options table.
    $settings = new Settings();
    $settings->setFcmServiceAccount('{"project_id":"x"}');

    $markup = captureOutput(fn() => (new SettingsPage($settings))->render());

    expect($markup)->toContain('could not be read');
});

test('the screen says when a secret is stored without showing it', function () {
    $settings = new Settings();
    $settings->setClientSecret('google', 'a-client-secret');

    $markup = captureOutput(fn() => (new SettingsPage($settings))->render());

    expect($markup)->toContain('A secret is stored');
    expect($markup)->not->toContain('a-client-secret');
});

test('a service account can be cleared outright', function () {
    // Not the same as leaving the field blank, which keeps what is
    // stored. There has to be a way to take one off a site.
    $settings = new Settings();
    $settings->setFcmServiceAccount(adminBranchesAccountJson());

    $_POST['clear_fcm'] = '1';

    expect((new SettingsPage($settings))->saveFromRequest())->toBe('saved');
    expect($settings->getFcmServiceAccount())->toBe('');
});

test('a service account that will not parse is refused rather than stored', function () {
    // The moment to find out is now, not at the first message.
    $settings = new Settings();

    $_POST['fcm_service_account'] = '{"project_id":"x"}';

    expect((new SettingsPage($settings))->saveFromRequest())->toBe('bad_service_account');
    expect($settings->getFcmServiceAccount())->toBe('');
});

test('a pasted service account survives the slashes WordPress adds', function () {
    // Every other test on this handler sets $_POST unslashed, and that
    // is not how a request arrives. WordPress runs wp_magic_quotes()
    // over $_POST, so a pasted service account reaches the handler with
    // every quote and every escape backslashed. Without wp_unslash()
    // json_decode refuses it, and the screen tells somebody a perfectly
    // valid file is not a service account -- meaning no correct one can
    // be saved on any site at all. That shipped, and the tests stayed
    // green throughout, because they all set $_POST by hand.
    //
    // So setting it the way the runtime really does is the entire point
    // here. Do not 'tidy' the addslashes away.
    $settings = new Settings();
    $json = adminBranchesAccountJson();

    $_POST['fcm_service_account'] = addslashes($json);

    expect((new SettingsPage($settings))->saveFromRequest())->toBe('saved');
    expect($settings->getFcmServiceAccount())->toBe($json);
});

test('a client secret survives the slashes WordPress adds', function () {
    // The same omission sat on every field here and only the service
    // account showed it, because ids and secrets are usually
    // alphanumeric and addslashes leaves them alone. A secret holding a
    // quote would have been stored corrupted and silently failed to
    // authenticate, which is worse than being refused.
    $settings = new Settings();
    $secret = 'a"secret\with-both';

    $_POST['google_client_secret'] = addslashes($secret);

    expect((new SettingsPage($settings))->saveFromRequest())->toBe('saved');
    expect($settings->getClientSecret('google'))->toBe($secret);
});

// ── The device list ───────────────────────────────────────────────

test('a revoked handset is shown as revoked rather than hidden', function () {
    // The row stays so somebody can see what happened and when.
    adminBranchesEnrol();
    $this->devices->revoke(1, 1788000100);

    expect(captureOutput(fn() => adminBranchesDevicesPage()->render()))->toContain('Revoked');
});

test('a handset that cannot read its messages is flagged loudly', function () {
    // Enrolled, looks healthy, and cannot read a word it is sent.
    // The only place that is visible is this screen.
    adminBranchesEnrol();
    $this->devices->markKeyFault(1, 1788000100);

    expect(captureOutput(fn() => adminBranchesDevicesPage()->render()))->toContain('Cannot read messages');
});

test('a device whose member has gone says so rather than showing a blank', function () {
    // It means a handset that will fail its next request, and
    // somebody may want to remove the row.
    adminBranchesEnrol();
    $this->members = new InMemoryMemberRepository([]);

    expect(captureOutput(fn() => adminBranchesDevicesPage()->render()))->toContain('no member record');
});

test('a member with no anonymous name is named as such', function () {
    adminBranchesEnrol();
    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: '', personalEmail: ADMIN_BRANCHES_MEMBER),
    ]);

    expect(captureOutput(fn() => adminBranchesDevicesPage()->render()))->toContain('unnamed member');
});

test('a member is found by address when the device carries no id', function () {
    // Device rows predating the id column carry only the address,
    // and they still belong to somebody.
    $this->devices->create('hash-1', ADMIN_BRANCHES_MEMBER, 0, 'Pixel 6a', 'android', 'spki', 'fcm', 'token-1', 1788000000);

    expect(captureOutput(fn() => adminBranchesDevicesPage()->render()))->toContain('Dave P');
});

// ── The compose screen ────────────────────────────────────────────

test('every committee is offered as an audience', function () {
    $markup = captureOutput(fn() => adminBranchesComposePage([
        new CommitteeStub(id: 2, slug: 'steering', name: 'Steering'),
        new CommitteeStub(id: 3, slug: 'archives', name: 'Archives'),
    ])->render());

    expect($markup)->toContain('steering');
    expect($markup)->toContain('Archives');
});

test('a failure with no stored reason still says something', function () {
    // The transient is read once and deleted, so a refresh finds
    // nothing — and a bare "error" with no words is worse than a
    // generic sentence.
    $_GET['fellowship_result'] = 'error';

    expect(captureOutput(fn() => adminBranchesComposePage()->render()))->toContain('could not be sent');
});

// ── The fan-out ───────────────────────────────────────────────────

test('a member with a handset is marked as pushed to', function () {
    $settings = new Settings();
    $settings->setFcmServiceAccount(adminBranchesAccountJson());

    adminBranchesEnrol(adminBranchesPublicKey());

    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(200, '{}');

    $message = adminBranchesDispatch($settings);

    $recipients = $this->recipients->forMessage($message);

    expect($recipients)->toHaveCount(1);
    expect($recipients[0]->pushedAt)->not->toBeNull();
});

test('a member with no handset is still a recipient', function () {
    // They will read it when they enrol. A recipient row that is
    // never written is a message they can never see.
    $settings = new Settings();
    $settings->setFcmServiceAccount(adminBranchesAccountJson());

    $message = adminBranchesDispatch($settings);

    $recipients = $this->recipients->forMessage($message);

    expect($recipients)->toHaveCount(1);
    expect($recipients[0]->pushedAt)->toBeNull();
});

test('a push that fails leaves the recipient unpushed', function () {
    // Not an error: the handset collects it on its next poll, and
    // claiming it was pushed would make the log say something untrue.
    $settings = new Settings();
    $settings->setFcmServiceAccount(adminBranchesAccountJson());

    adminBranchesEnrol(adminBranchesPublicKey());

    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
    FakeWpHttp::pushResponse(404, '{"error":{"status":"NOT_FOUND"}}');

    $message = adminBranchesDispatch($settings);

    expect($this->recipients->forMessage($message)[0]->pushedAt)->toBeNull();
});

// ── Fixtures ──────────────────────────────────────────────────────

function adminBranchesDispatch(Settings $settings): int
{
    $request = MessageRequest::fromArray([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => [ADMIN_BRANCHES_MEMBER],
    ]);

    expect($request)->toBeInstanceOf(MessageRequest::class);

    $dispatcher = new MessageDispatcher(
        test()->messages,
        test()->recipients,
        test()->devices,
        new FcmTransport(new FcmClient(), $settings, new MessageSealer()),
    );

    return $dispatcher->dispatch(
        $request,
        [['email' => ADMIN_BRANCHES_MEMBER, 'member_id' => 7]],
        '',
        0,
        'Intergroup',
    )->id;
}

function adminBranchesDevicesPage(): DevicesPage
{
    $gate = new MemberGate(test()->members);

    return new DevicesPage(
        test()->devices,
        test()->members,
        test()->audit,
        new PasswordAuthenticator(
            new InMemoryPasswordCredentialRepository(),
            $gate,
            new PasswordResetMailer(),
            new PasswordPolicy(),
        ),
        $gate,
    );
}

/** @param list<CommitteeStub> $committees */
function adminBranchesComposePage(array $committees = []): ComposePage
{
    $gate = new MemberGate(test()->members);
    $settings = new Settings();

    return new ComposePage(
        new MessageApi(
            new MessageDispatcher(
                test()->messages,
                test()->recipients,
                test()->devices,
                new FcmTransport(new FcmClient(), $settings, new MessageSealer()),
            ),
            new RecipientResolver(test()->members, new InMemoryCommitteeRepository($committees), $gate),
            test()->audit,
        ),
        new InMemoryCommitteeRepository($committees),
    );
}

function adminBranchesEnrol(string $publicKey = 'spki'): void
{
    test()->devices->create(
        'hash-1',
        ADMIN_BRANCHES_MEMBER,
        7,
        'Pixel 6a',
        'android',
        $publicKey,
        'fcm',
        'token-1',
        1788000000,
    );
}

function adminBranchesAccountJson(): string
{
    // Signed with a keypair generated for this run. A fake key would
    // make every push stop before the first HTTP call, so the fan-out
    // below would assert nothing at all.
    return (string) wp_json_encode([
        'type' => 'service_account',
        'project_id' => 'intergroup-fellowship',
        'client_email' => 'pusher@intergroup-fellowship.iam.gserviceaccount.com',
        'private_key' => adminBranchesPrivateKey(),
        'token_uri' => 'https://oauth2.googleapis.com/token',
    ]);
}

function adminBranchesPrivateKey(): string
{
    static $pem = null;

    if ($pem === null) {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            test()->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
        }

        openssl_pkey_export($resource, $exported);
        $pem = (string) $exported;
    }

    return $pem;
}

function adminBranchesPublicKey(): string
{
    $resource = openssl_pkey_get_private(adminBranchesPrivateKey());
    expect($resource)->not->toBeFalse();

    $details = openssl_pkey_get_details($resource);
    expect($details)->toBeArray();

    return preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';
}
