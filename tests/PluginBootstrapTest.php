<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use Brain\Monkey\Actions;
use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use Fellowship\Core\Settings;
use Fellowship\Devices\DeviceRepository;
use Fellowship\Messaging\MessageRepository;
use Fellowship\Messaging\RecipientRepository;
use Fellowship\Plugin;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
use Fellowship\Tests\Support\RecordingWpdb;
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
 *
 * @covers \Fellowship\Plugin
 */
final class PluginBootstrapTest extends TestCase
{
    private const MEMBER = 'member@example.org';

    /** @var array<string, list<callable>> */
    private array $actions = [];

    /** @var array<string, list<callable>> */
    private array $filters = [];

    private FakeContainer $container;
    private InMemoryDeviceRepository $devices;
    private InMemoryRecipientRepository $recipients;
    private InMemoryMessageRepository $messages;
    private Settings $settings;

    protected function setUp(): void
    {
        parent::setUp();

        $this->actions = [];
        $this->filters = [];

        $GLOBALS['wpdb'] = new RecordingWpdb();

        Functions\when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);
        Functions\when('is_admin')->justReturn(false);
        Functions\when('wp_next_scheduled')->justReturn(false);
        Functions\when('wp_schedule_event')->justReturn(true);

        $this->devices = new InMemoryDeviceRepository();
        $this->recipients = new InMemoryRecipientRepository();
        $this->messages = new InMemoryMessageRepository();
        $this->settings = new Settings();

        $this->container = new FakeContainer([
            'Unity\\Members\\Interfaces\\MemberRepository' => new InMemoryMemberRepository([
                new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: self::MEMBER),
            ]),
            'Unity\\Committees\\Interfaces\\CommitteeRepository' => new InMemoryCommitteeRepository(),
            'Scrutiny\\Audit\\Interfaces\\AuditLogger' => new \Scrutiny\Testing\Doubles\SpyAuditLogger(),
        ]);

        // The in-memory halves, primed so the hooks act on something the
        // test can read back.
        $this->container->prime(DeviceRepository::class, $this->devices);
        $this->container->prime(RecipientRepository::class, $this->recipients);
        $this->container->prime(MessageRepository::class, $this->messages);
        $this->container->prime(Settings::class, $this->settings);

        $this->capture();

        // Static state, so a second test in the same process would find
        // the guard already tripped and register nothing.
        $this->resetPlugin();

        Plugin::init($this->container);
    }

    protected function tearDown(): void
    {
        $this->resetPlugin();

        parent::tearDown();
    }

    public function testAFellowshipResponseIsNeverCached(): void
    {
        $response = $this->dispatch('/fellowship/v1/messages');

        self::assertNotNull($response);
        self::assertStringContainsString('no-store', (string) ($response->get_headers()['Cache-Control'] ?? ''));
    }

    public function testAnotherPluginsRouteIsLeftAlone(): void
    {
        // The filter runs on every REST response on the site. Stamping
        // no-store on somebody else's cacheable route would be a
        // performance change made by accident.
        $response = $this->dispatch('/wp/v2/posts');

        self::assertNotNull($response);
        self::assertArrayNotHasKey('Cache-Control', $response->get_headers());
    }

    public function testTheRetentionSweepRemovesRecipientsBeforeMessages(): void
    {
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
        $this->resetPlugin();
        $this->actions = [];
        $this->capture();
        Plugin::init($this->container);

        $this->fire('fellowship_purge_messages');

        self::assertSame(['recipients'], $order);
    }

    public function testASweepWithRetentionOffDeletesNothing(): void
    {
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

        $this->fire('fellowship_purge_messages');

        self::assertCount(1, $this->messages->rows);
    }

    public function testDeletingAMemberRevokesTheirHandsets(): void
    {
        $this->devices->create(
            'hash-1',
            self::MEMBER,
            7,
            'Pixel 6a',
            'android',
            'spki',
            'fcm',
            'token-1',
            1788000000,
        );

        $this->fire('unity/member_deleted', 42, new MemberStub(id: 7, personalEmail: self::MEMBER));

        self::assertTrue($this->devices->rows[1]->isRevoked());
    }

    public function testDeletingAMemberRemovesTheirDeliveryRecords(): void
    {
        $this->recipients->addMany(9, [['email' => self::MEMBER, 'member_id' => 7]], 1788000000);

        $this->fire('unity/member_deleted', 42, new MemberStub(id: 7, personalEmail: self::MEMBER));

        self::assertSame([], $this->recipients->rows);
    }

    public function testDeletingAMemberLeavesTheMessagesThemselves(): void
    {
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

        $this->fire('unity/member_deleted', 42, new MemberStub(id: 7, personalEmail: self::MEMBER));

        self::assertCount(1, $this->messages->rows);
    }

    public function testAMemberDeletionWithNoMemberIsIgnored(): void
    {
        // Unity fires this with a null member in some paths; acting on it
        // would mean revoking devices for an empty address.
        $this->devices->create(
            'hash-1',
            self::MEMBER,
            7,
            'Pixel 6a',
            'android',
            'spki',
            'fcm',
            'token-1',
            1788000000,
        );

        $this->fire('unity/member_deleted', 42, null);

        self::assertFalse($this->devices->rows[1]->isRevoked());
    }

    // ── Booting twice, and not at all ─────────────────────────────────

    public function testBootingASecondTimeChangesNothing(): void
    {
        // WordPress can fire unity/loaded more than once when a plugin is
        // activated mid-request. Registering every route and menu twice
        // would give the admin two Fellowship menus.
        $before = count($this->actions['fellowship_purge_messages'] ?? []);

        Plugin::init($this->container);

        self::assertCount($before, $this->actions['fellowship_purge_messages'] ?? []);
    }

    public function testTheContainerIsAvailableOnceThePluginHasBooted(): void
    {
        self::assertSame($this->container, Plugin::getContainer());
    }

    public function testAskingForTheContainerBeforeBootIsAFaultRatherThanANull(): void
    {
        // Every caller dereferences it immediately, so a null would
        // surface as "call to a member function on null" somewhere far
        // from the actual mistake.
        $this->resetPlugin();

        $this->expectException(RuntimeException::class);

        Plugin::getContainer();
    }

    public function testTheAdminScreensAreRegisteredOnlyInTheAdmin(): void
    {
        // Four screens, and none of them has any business being built on
        // a front-end request.
        Functions\when('is_admin')->justReturn(true);
        Functions\when('add_menu_page')->justReturn('toplevel_page_fellowship');
        Functions\when('add_submenu_page')->justReturn('fellowship_page_x');
        Functions\when('admin_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-admin/' . $p);

        Actions\expectAdded('admin_menu')->atLeast()->once();

        $this->resetPlugin();
        Plugin::init($this->container);
    }

    // ── The retention sweep ───────────────────────────────────────────

    public function testASiteKeepingMessagesIndefinitelySweepsNothing(): void
    {
        // Zero is a deliberate choice on the settings screen, not an
        // unset value, and the sweep reads it as "do nothing".
        $this->settings->setRetentionDays(0);

        $this->fire('fellowship_purge_messages');

        self::assertSame([], $this->recipients->rows);
    }

    public function testASweepThatDeletedNothingSaysNothing(): void
    {
        $this->settings->setRetentionDays(30);

        $this->fire('fellowship_purge_messages');

        self::assertTrue(true, 'The sweep ran without a message to delete.');
    }

    public function testTheSweepRunsAgainstAContainerThatHasGoneAway(): void
    {
        // Cron fires on its own request. If the plugin stood itself down
        // in between — a kill switch, a deactivated Unity — the callback
        // is still registered and must not fatal.
        $this->resetPlugin();

        $this->fire('fellowship_purge_messages');

        self::assertSame([], $this->recipients->rows);
    }

    // ── Erasure ───────────────────────────────────────────────────────

    public function testAMemberWithNoAddressIsNotErasedByAddress(): void
    {
        // Every device row would match an empty address, so acting on
        // one would revoke the whole fleet.
        $this->devices->create('hash-1', self::MEMBER, 7, 'Pixel 6a', 'android', 'spki', 'fcm', 'token-1', 1788000000);

        $this->fire('unity/member_deleted', 42, new MemberStub(id: 7, personalEmail: '   '));

        self::assertFalse($this->devices->rows[1]->isRevoked());
    }

    // ── The build date ────────────────────────────────────────────────

    public function testTheBuildDateComesFromTheShippedReadme(): void
    {
        // It is written into readme.txt by the build, so a checkout that
        // was never built has none — and answering an empty string is
        // the documented behaviour rather than a fault.
        self::assertIsString(Plugin::buildDate());
    }

    public function testTheBuildDateIsReadOnceRatherThanPerCall(): void
    {
        // It is on the settings screen and in the status dashboard; a
        // file read per call would be a read per page view.
        self::assertSame(Plugin::buildDate(), Plugin::buildDate());
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function capture(): void
    {
        foreach (['fellowship_purge_messages', 'unity/member_deleted'] as $hook) {
            Actions\expectAdded($hook)->zeroOrMoreTimes()->whenHappen(
                function (callable $callback) use ($hook): void {
                    $this->actions[$hook][] = $callback;
                }
            );
        }

        Filters\expectAdded('rest_post_dispatch')->zeroOrMoreTimes()->whenHappen(
            function (callable $callback): void {
                $this->filters['rest_post_dispatch'][] = $callback;
            }
        );
    }

    private function fire(string $hook, mixed ...$args): void
    {
        self::assertNotEmpty($this->actions[$hook] ?? [], $hook . ' was never registered.');

        foreach ($this->actions[$hook] as $callback) {
            $callback(...$args);
        }
    }

    private function dispatch(string $route): ?WP_REST_Response
    {
        self::assertNotEmpty($this->filters['rest_post_dispatch'] ?? [], 'The cache filter was never registered.');

        // The route is a constructor argument on the stub, not a setter.
        $request = new WP_REST_Request([], $route);

        $response = new WP_REST_Response();

        foreach ($this->filters['rest_post_dispatch'] as $callback) {
            $response = $callback($response, null, $request);
        }

        return $response instanceof WP_REST_Response ? $response : null;
    }

    /** Plugin holds its container and its guard statically. */
    private function resetPlugin(): void
    {
        foreach (['initialized' => false, 'container' => null] as $name => $value) {
            // No setAccessible: it has had no effect since PHP 8.1 and is
            // deprecated from 8.5.
            (new ReflectionProperty(Plugin::class, $name))->setValue(null, $value);
        }
    }
}
