<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use Brain\Monkey\Functions;
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
use Fellowship\Tests\Support\InMemoryRecipientRepository;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;

/**
 * Storing a message and fanning it out, and the one door every send goes
 * through.
 *
 * <b>The message is stored before anything is pushed, and that ordering
 * is the whole reliability story.</b> Push is the fast path; the store is
 * the reliable one. A handset that was asleep, out of signal, or whose
 * FCM token had silently rotated collects the message on its next poll,
 * so a failed push must never mean a lost message.
 *
 * <b>MessageApi is the only way in.</b> The admin screen, the REST
 * controller and the `fellowship/send_message` action all pass through
 * it, which is what keeps validation, the member gate and the audit entry
 * in one place rather than three.
 *
 * @covers \Fellowship\Messaging\MessageDispatcher
 * @covers \Fellowship\Messaging\MessageApi
 */
final class DispatcherTest extends TestCase
{
    private InMemoryMessageRepository $messages;
    private InMemoryRecipientRepository $recipients;
    private InMemoryDeviceRepository $devices;
    private InMemoryMemberRepository $members;
    private SpyAuditLogger $audit;
    private Settings $settings;

    protected function setUp(): void
    {
        parent::setUp();

        Functions\when('wp_generate_uuid4')->alias(
            static fn(): string => '11111111-2222-4333-8444-555555555555'
        );
        Functions\when('get_current_user_id')->justReturn(3);

        $this->messages = new InMemoryMessageRepository();
        $this->recipients = new InMemoryRecipientRepository();
        $this->devices = new InMemoryDeviceRepository();
        $this->audit = new SpyAuditLogger();
        $this->settings = new Settings();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
            new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: 'sue@example.org'),
        ]);
    }

    // ── The dispatcher ────────────────────────────────────────────────

    public function testAMessageIsStoredWithItsRecipients(): void
    {
        $message = $this->dispatcher()->dispatch(
            $this->request(),
            [['email' => 'sue@example.org', 'member_id' => 8]],
            'dave@example.org',
            7,
            'Dave P',
        );

        self::assertCount(1, $this->messages->rows);
        self::assertCount(1, $this->recipients->forMessage($message->id));
    }

    public function testAMessageIsStoredEvenWhenNothingCanBePushed(): void
    {
        // No service account, so push is off entirely. The message must
        // still be stored, because the poll is what actually delivers it.
        $message = $this->dispatcher()->dispatch(
            $this->request(),
            [['email' => 'sue@example.org', 'member_id' => 8]],
            'dave@example.org',
            7,
            'Dave P',
        );

        self::assertNotNull($this->messages->findById($message->id));
    }

    public function testAMessageWithNoRecipientsIsStillStored(): void
    {
        // A committee nobody is on. The message is a record of what was
        // said, and the admin log should show it went nowhere rather than
        // showing nothing at all.
        $message = $this->dispatcher()->dispatch(
            $this->request(),
            [],
            'dave@example.org',
            7,
            'Dave P',
        );

        self::assertNotNull($this->messages->findById($message->id));
        self::assertSame([], $this->recipients->forMessage($message->id));
    }

    public function testTheSendingDeviceIsRecordedWhenItCameFromTheApp(): void
    {
        // Which is how the admin log distinguishes a message sent from a
        // handset from one composed in WordPress.
        $message = $this->dispatcher()->dispatch(
            $this->request(),
            [['email' => 'sue@example.org', 'member_id' => 8]],
            'dave@example.org',
            7,
            'Dave P',
            senderDeviceId: 4,
        );

        self::assertSame(4, $message->senderDeviceId);
    }

    // ── The one door in ───────────────────────────────────────────────

    public function testTheApiSendsAndAudits(): void
    {
        $result = $this->api()->send([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_emails' => ['sue@example.org'],
        ]);

        self::assertNotInstanceOf(WP_Error::class, $result);
        self::assertCount(1, $this->messages->rows);
        self::assertNotEmpty($this->audit->entries);
    }

    public function testTheApiRefusesAMessageWithNoSubject(): void
    {
        $result = $this->api()->send([
            'subject' => '',
            'body' => 'Now the 14th.',
            'member_emails' => ['sue@example.org'],
        ]);

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame([], $this->messages->rows);
    }

    public function testTheApiRefusesAMessageWithNoBody(): void
    {
        $result = $this->api()->send([
            'subject' => 'Intergroup moved',
            'body' => '',
            'member_emails' => ['sue@example.org'],
        ]);

        self::assertInstanceOf(WP_Error::class, $result);
    }

    public function testAMessageThatReachesNobodyIsStillRecorded(): void
    {
        // Not a refusal, and worth stating plainly because the opposite
        // is the intuitive guess: the message is a record of what the
        // intergroup said, so it is stored with no recipients rather than
        // rejected. The admin log shows the recipient count, which is
        // where "this went nowhere" is meant to become visible.
        //
        // The two callers that must not allow it guard separately: the
        // REST controller refuses a handset addressing the whole
        // fellowship, and the compose screen refuses an empty audience.
        $result = $this->api()->send([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_emails' => ['stranger@example.org'],
        ]);

        self::assertNotInstanceOf(WP_Error::class, $result);
        self::assertCount(1, $this->messages->rows);
        self::assertSame([], $this->recipients->rows);
    }

    public function testARefusedSendWritesNoAuditEntry(): void
    {
        // Otherwise the log fills with entries for things that did not
        // happen, and the ones that did become harder to find.
        $this->api()->send([
            'subject' => '',
            'body' => '',
        ]);

        self::assertSame([], $this->audit->entries);
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function dispatcher(): MessageDispatcher
    {
        return new MessageDispatcher(
            $this->messages,
            $this->recipients,
            $this->devices,
            new FcmTransport(new FcmClient(), $this->settings, new MessageSealer()),
        );
    }

    private function api(): MessageApi
    {
        return new MessageApi(
            $this->dispatcher(),
            new RecipientResolver(
                $this->members,
                new InMemoryCommitteeRepository(),
                new MemberGate($this->members),
            ),
            $this->audit,
        );
    }

    private function request(): MessageRequest
    {
        $built = MessageRequest::fromArray([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_emails' => ['sue@example.org'],
        ]);

        self::assertNotInstanceOf(WP_Error::class, $built);

        return $built;
    }
}
