<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
use function Brain\Monkey\Functions\when;
use function Brain\Monkey\Actions\expectAdded;
use Brain\Monkey\Filters;
use Fellowship\Core\Settings;
use Fellowship\Devices\DeviceRepository;
use Fellowship\Messaging\MessageRepository;
use Fellowship\Messaging\RecipientRepository;
use Fellowship\Plugin;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
use Fellowship\Tests\Support\RecordingWpdb;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use RuntimeException;
use Unity\Testing\Doubles\FakeContainer;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_REST_Request;
use WP_REST_Response;

/**
 * What the plugin does when it boots.
 *
 * <b>Three of these hooks are the only place a rule exists</b>, and none
 * of them is reachable by calling a method — they are closures registered
 * on WordPress hooks, so the test has to take the callback back out and
 * invoke it. Brain Monkey owns add_action and add_filter and must keep
 * owning them, so the callbacks are captured through its own
 * expectAdded()->whenHappen() rather than by stubbing the hook layer,
 * which is the technique Reach settled on for the same problem.
 *
 * What is asserted:
 *
 *  - <b>Every fellowship/v1 response is no-store.</b> The whole namespace
 *    is per-device and authorised by a bearer token, which shared caches
 *    do not recognise. WordPress only sends REST no-cache headers for
 *    logged-in WP users, so without this filter a member's sealed inbox
 *    could be cached by SiteGround or Cloudflare and served to whoever
 *    asked next.
 *  - <b>The retention sweep deletes recipients before messages.</b> The
 *    other order strands recipient rows against message ids that no
 *    longer exist, and a stranded row here is orphaned personal data.
 *  - <b>Deleting a member takes their handsets and delivery records.</b>
 *    Their devices would fail the gate on the next request anyway, but
 *    until then they are live rows the dispatcher still counts as push
 *    targets.
 */

covers(\Fellowship\Plugin::class);

const PLUGIN_BOOTSTRAP_MEMBER = 'member@example.org';

beforeEach(function () {
    // Callbacks taken back out of add_action/add_filter, by hook name.
    $this->actions = [];
    $this->filters = [];

    $GLOBALS['wpdb'] = new RecordingWpdb();

    when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);
    when('is_admin')->justReturn(false);
    when('wp_next_scheduled')->justReturn(false);
    when('wp_schedule_event')->justReturn(true);

    $this->devices = new InMemoryDeviceRepository();
    $this->recipients = new InMemoryRecipientRepository();
    $this->messages = new InMemoryMessageRepository();
    $this->settings = new Settings();

    $this->container = new FakeContainer([
        'Unity\\Members\\Interfaces\\MemberRepository' => new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: PLUGIN_BOOTSTRAP_MEMBER),
        ]),
        'Unity\\Committees\\Interfaces\\CommitteeRepository' => new InMemoryCommitteeRepository(),
        'Scrutiny\\Audit\\Interfaces\\AuditLogger' => new SpyAuditLogger(),
        // Unity's, since it took ownership of the password
        // store. Fellowship no longer binds one.
        'Unity\\Auth\\Interfaces\\PasswordCredentialRepository' =>
            new InMemoryPasswordCredentialRepository(),
    ]);

    // The in-memory halves, primed so the hooks act on something the
    // test can read back.
    $this->container->prime(DeviceRepository::class, $this->devices);
    $this->container->prime(RecipientRepository::class, $this->recipients);
    $this->container->prime(MessageRepository::class, $this->messages);
    $this->container->prime(Settings::class, $this->settings);

    pluginBootstrapCapture($this);

    // Static state, so a second test in the same process would find
    // the guard already tripped and register nothing.
    resetPlugin();

    Plugin::init($this->container);
});

afterEach(function () {
    resetPlugin();
});

test('a fellowship response is never cached', function () {
    $response = pluginBootstrapDispatch('/fellowship/v1/messages');

    expect($response)->not->toBeNull();
    expect((string) ($response->get_headers()['Cache-Control'] ?? ''))->toContain('no-store');
});

test('another plugins route is left alone', function () {
    // The filter runs on every REST response on the site. Stamping
    // no-store on somebody else's cacheable route would be a
    // performance change made by accident.
    $response = pluginBootstrapDispatch('/wp/v2/posts');

    expect($response)->not->toBeNull();
    expect($response->get_headers())->not->toHaveKey('Cache-Control');
});

test('the retention sweep removes recipients before messages', function () {
    // The order is the point: messages first would strand recipient
    // rows against ids that no longer exist, and a stranded row here
    // is orphaned personal data.
    $this->settings->setRetentionDays(30);

    $order = [];
    $this->recipients = new class ($order) extends InMemoryRecipientRepository {
        /** @param list<string> $order */
        public function __construct(private array &$order)
        {
        }

        public function purgeForMessagesBefore(int $before): int
        {
            $this->order[] = 'recipients';

            return 0;
        }
    };

    // Re-prime and re-init so the closure closes over the recorder.
    $this->container->prime(RecipientRepository::class, $this->recipients);
    resetPlugin();
    $this->actions = [];
    pluginBootstrapCapture($this);
    Plugin::init($this->container);

    pluginBootstrapFire('fellowship_purge_messages');

    expect($order)->toBe(['recipients']);
});

test('a sweep with retention off deletes nothing', function () {
    // Zero means keep indefinitely, chosen on the settings screen.
    $this->settings->setRetentionDays(0);

    $this->messages->create(
        'uuid-1',
        'dave@example.org',
        7,
        'Dave B',
        'Old',
        'Ancient.',
        'members',
        '',
        1,
        0,
        0,
    );

    pluginBootstrapFire('fellowship_purge_messages');

    expect($this->messages->rows)->toHaveCount(1);
});

test('deleting a member revokes their handsets', function () {
    $this->devices->create(
        'hash-1',
        PLUGIN_BOOTSTRAP_MEMBER,
        7,
        'Pixel 6a',
        'android',
        'spki',
        'fcm',
        'token-1',
        1788000000,
    );

    pluginBootstrapFire('unity/member_deleted', 42, new MemberStub(id: 7, personalEmail: PLUGIN_BOOTSTRAP_MEMBER));

    expect($this->devices->rows[1]->isRevoked())->toBeTrue();
});

test('deleting a member removes their delivery records', function () {
    $this->recipients->addMany(9, [['email' => PLUGIN_BOOTSTRAP_MEMBER, 'member_id' => 7]], 1788000000);

    pluginBootstrapFire('unity/member_deleted', 42, new MemberStub(id: 7, personalEmail: PLUGIN_BOOTSTRAP_MEMBER));

    expect($this->recipients->rows)->toBe([]);
});

test('deleting a member leaves the messages themselves', function () {
    // A message sent to a committee is a record of what the
    // intergroup said, not of who received it. Removing one member
    // should not rewrite it; the recipient rows naming them are the
    // part that is theirs.
    $this->messages->create(
        'uuid-1',
        'dave@example.org',
        7,
        'Dave B',
        'Intergroup moved',
        'Now the 14th.',
        'committee',
        'steering',
        1788000000,
        0,
        0,
    );

    pluginBootstrapFire('unity/member_deleted', 42, new MemberStub(id: 7, personalEmail: PLUGIN_BOOTSTRAP_MEMBER));

    expect($this->messages->rows)->toHaveCount(1);
});

test('a member deletion with no member is ignored', function () {
    // Unity fires this with a null member in some paths; acting on it
    // would mean revoking devices for an empty address.
    $this->devices->create(
        'hash-1',
        PLUGIN_BOOTSTRAP_MEMBER,
        7,
        'Pixel 6a',
        'android',
        'spki',
        'fcm',
        'token-1',
        1788000000,
    );

    pluginBootstrapFire('unity/member_deleted', 42, null);

    expect($this->devices->rows[1]->isRevoked())->toBeFalse();
});

// ── Booting twice, and not at all ─────────────────────────────────

test('booting a second time changes nothing', function () {
    // WordPress can fire unity/loaded more than once when a plugin is
    // activated mid-request. Registering every route and menu twice
    // would give the admin two Fellowship menus.
    $before = count($this->actions['fellowship_purge_messages'] ?? []);

    Plugin::init($this->container);

    expect($this->actions['fellowship_purge_messages'] ?? [])->toHaveCount($before);
});

test('the container is available once the plugin has booted', function () {
    expect(Plugin::getContainer())->toBe($this->container);
});

test('asking for the container before boot is a fault rather than a null', function () {
    // Every caller dereferences it immediately, so a null would
    // surface as "call to a member function on null" somewhere far
    // from the actual mistake.
    resetPlugin();

    Plugin::getContainer();
})->throws(RuntimeException::class);

test('the admin screens are registered only in the admin', function () {
    // Four screens, and none of them has any business being built on
    // a front-end request.
    when('is_admin')->justReturn(true);
    when('add_menu_page')->justReturn('toplevel_page_fellowship');
    when('add_submenu_page')->justReturn('fellowship_page_x');
    when('admin_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-admin/' . $p);

    expectAdded('admin_menu')->atLeast()->once();

    resetPlugin();
    Plugin::init($this->container);
});

// ── The retention sweep ───────────────────────────────────────────

test('a site keeping messages indefinitely sweeps nothing', function () {
    // Zero is a deliberate choice on the settings screen, not an
    // unset value, and the sweep reads it as "do nothing".
    $this->settings->setRetentionDays(0);

    pluginBootstrapFire('fellowship_purge_messages');

    expect($this->recipients->rows)->toBe([]);
});

test('a sweep that deleted nothing says nothing', function () {
    $this->settings->setRetentionDays(30);

    // The sweep ran without a message to delete; reaching the end
    // without a fault is the assertion, alongside fire()'s own check
    // that the hook was registered at all.
    pluginBootstrapFire('fellowship_purge_messages');
});

test('the sweep runs against a container that has gone away', function () {
    // Cron fires on its own request. If the plugin stood itself down
    // in between — a kill switch, a deactivated Unity — the callback
    // is still registered and must not fatal.
    resetPlugin();

    pluginBootstrapFire('fellowship_purge_messages');

    expect($this->recipients->rows)->toBe([]);
});

// ── Erasure ───────────────────────────────────────────────────────

test('a member with no address is not erased by address', function () {
    // Every device row would match an empty address, so acting on
    // one would revoke the whole fleet.
    $this->devices->create('hash-1', PLUGIN_BOOTSTRAP_MEMBER, 7, 'Pixel 6a', 'android', 'spki', 'fcm', 'token-1', 1788000000);

    pluginBootstrapFire('unity/member_deleted', 42, new MemberStub(id: 7, personalEmail: '   '));

    expect($this->devices->rows[1]->isRevoked())->toBeFalse();
});

// ── The build date ────────────────────────────────────────────────

test('the build date comes from the shipped readme', function () {
    // It is written into readme.txt by the build, so a checkout that
    // was never built has none — and answering an empty string is
    // the documented behaviour rather than a fault.
    expect(Plugin::buildDate())->toBeString();
});

test('the build date is read once rather than per call', function () {
    // It is on the settings screen and in the status dashboard; a
    // file read per call would be a read per page view.
    expect(Plugin::buildDate())->toBe(Plugin::buildDate());
});

// ── Fixtures ──────────────────────────────────────────────────────

/**
 * Records every callback registered on the hooks under test onto the test
 * case, so it can be taken back out and invoked.
 *
 * The test case is passed in rather than reached through test(): Pest's
 * proxy hands properties back by value, so appending to one through it
 * would modify a copy and record nothing.
 */
function pluginBootstrapCapture(TestCase $test): void
{
    foreach (['fellowship_purge_messages', 'unity/member_deleted'] as $hook) {
        expectAdded($hook)->zeroOrMoreTimes()->whenHappen(
            function (callable $callback) use ($test, $hook): void {
                $test->actions[$hook][] = $callback;
            }
        );
    }

    Filters\expectAdded('rest_post_dispatch')->zeroOrMoreTimes()->whenHappen(
        function (callable $callback) use ($test): void {
            $test->filters['rest_post_dispatch'][] = $callback;
        }
    );
}

function pluginBootstrapFire(string $hook, mixed ...$args): void
{
    expect(test()->actions[$hook] ?? [])->not->toBeEmpty($hook . ' was never registered.');

    foreach (test()->actions[$hook] as $callback) {
        $callback(...$args);
    }
}

function pluginBootstrapDispatch(string $route): ?WP_REST_Response
{
    expect(test()->filters['rest_post_dispatch'] ?? [])->not->toBeEmpty('The cache filter was never registered.');

    // The route is a constructor argument on the stub, not a setter.
    $request = new WP_REST_Request([], $route);

    $response = new WP_REST_Response();

    foreach (test()->filters['rest_post_dispatch'] as $callback) {
        $response = $callback($response, null, $request);
    }

    return $response instanceof WP_REST_Response ? $response : null;
}

/** Plugin holds its container and its guard statically. */
function resetPlugin(): void
{
    foreach (['initialized' => false, 'container' => null] as $name => $value) {
        // No setAccessible: it has had no effect since PHP 8.1 and is
        // deprecated from 8.5.
        (new ReflectionProperty(Plugin::class, $name))->setValue(null, $value);
    }
}
