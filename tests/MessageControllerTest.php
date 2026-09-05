<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use Brain\Monkey\Functions;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Core\RateLimiter;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Messaging\Message;
use Fellowship\Messaging\MessageDispatcher;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Rest\MessageController;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
use RuntimeException;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryCommitteeRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * The message surface a handset talks to.
 *
 * <b>Two properties carry most of the weight here, and neither is
 * visible from the outside.</b>
 *
 * The inbox hands back <i>sealed</i> envelopes and nothing else. The
 * bodies are stored in plain text and this server can read them — that is
 * a documented decision, and what makes the admin log and the audit
 * possible — but nothing readable may cross the wire, because the wire is
 * where an intercepted response would be somebody's messages.
 *
 * And a handset only ever sees its own. Every read is scoped to the
 * member behind the bearer token, so naming somebody else's message
 * answers exactly as naming one that does not exist.
 *
 * @covers \Fellowship\Rest\MessageController
 */
final class MessageControllerTest extends TestCase
{
    private const MEMBER = 'member@example.org';
    private const OTHER = 'other@example.org';

    private InMemoryDeviceRepository $devices;
    private InMemoryMessageRepository $messages;
    private InMemoryRecipientRepository $recipients;
    private InMemoryMemberRepository $members;
    private DeviceTokenMinter $minter;
    private SpyAuditLogger $audit;
    private string $publicKey = '';
    private string $privateKey = '';

    protected function setUp(): void
    {
        parent::setUp();

        Functions\when('is_ssl')->justReturn(true);
        Functions\when('wp_generate_uuid4')->alias(static fn(): string => '1111-' . random_int(1, 999999999));

        $this->devices = new InMemoryDeviceRepository();
        $this->messages = new InMemoryMessageRepository();
        $this->recipients = new InMemoryRecipientRepository();
        $this->minter = new DeviceTokenMinter();
        $this->audit = new SpyAuditLogger();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: self::MEMBER),
            new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: self::OTHER),
        ]);

        $this->keypair();
    }

    // ── The inbox ─────────────────────────────────────────────────────

    public function testAnEmptyInboxIsNotAnError(): void
    {
        $token = $this->enrol();

        $response = $this->controller()->inbox($this->request([], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertSame([], ((array) $response->get_data())['messages']);
    }

    public function testTheInboxHandsBackSealedEnvelopesAndNothingElse(): void
    {
        // The assertion that matters: the subject and body must not
        // appear anywhere in the response.
        $token = $this->enrol();
        $this->giveMessage('Intergroup moved', 'Now the 14th, same room.');

        $response = $this->controller()->inbox($this->request([], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);

        $data = (array) $response->get_data();
        self::assertCount(1, $data['messages']);
        self::assertArrayHasKey('k', $data['messages'][0]);
        self::assertArrayHasKey('p', $data['messages'][0]);

        $encoded = (string) json_encode($data);
        self::assertStringNotContainsString('Intergroup moved', $encoded);
        self::assertStringNotContainsString('same room', $encoded);
    }

    public function testAHandsetOnlySeesItsOwnMessages(): void
    {
        $token = $this->enrol();

        // Addressed to somebody else entirely.
        $message = $this->messages->create(
            'uuid-2',
            'sender@example.org',
            9,
            'Sender',
            'Not for you',
            'Private.',
            'members',
            '',
            1788000000,
            0,
            0,
        );
        $this->recipients->addMany($message->id, [['email' => self::OTHER, 'member_id' => 8]], 1788000000);

        $response = $this->controller()->inbox($this->request([], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertSame([], ((array) $response->get_data())['messages']);
    }

    public function testThePollOnlyReturnsWhatTheHandsetDoesNotHold(): void
    {
        $token = $this->enrol();
        $this->giveMessage('First', 'One.');
        $second = $this->giveMessage('Second', 'Two.');

        $response = $this->controller()->inbox($this->request(['since' => $second - 1], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertCount(1, ((array) $response->get_data())['messages']);
    }

    public function testTheUnreadCountComesBackWithTheInbox(): void
    {
        $token = $this->enrol();
        $this->giveMessage('First', 'One.');
        $this->giveMessage('Second', 'Two.');

        $response = $this->controller()->inbox($this->request([], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertSame(2, ((array) $response->get_data())['unread']);
    }

    public function testAMessageThatCannotBeSealedIsOmittedRatherThanFatal(): void
    {
        // A handset whose stored key has gone. It sees a short inbox and
        // a 200, and reports the fault separately — better than a 500
        // that takes every other message with it.
        $token = $this->enrolWithKey('not-a-key');
        $this->giveMessage('Intergroup moved', 'Now the 14th.');

        $response = $this->controller()->inbox($this->request([], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertSame([], ((array) $response->get_data())['messages']);
    }

    public function testAnUnauthenticatedInboxIsRefused(): void
    {
        self::assertInstanceOf(WP_Error::class, $this->controller()->inbox($this->request([])));
    }

    public function testARevokedHandsetGetsNoInbox(): void
    {
        $token = $this->enrol();
        $this->devices->revoke(1, time());

        self::assertInstanceOf(WP_Error::class, $this->controller()->inbox($this->request([], $token)));
    }

    // ── Marking read ──────────────────────────────────────────────────

    public function testMarkingReadLowersTheUnreadCount(): void
    {
        $token = $this->enrol();
        $id = $this->giveMessage('Intergroup moved', 'Now the 14th.');

        $response = $this->controller()->markRead($this->request(['id' => $id], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertSame(0, ((array) $response->get_data())['unread']);
    }

    public function testMarkingSomebodyElsesMessageReadIsANotFound(): void
    {
        // Indistinguishable from a message that does not exist, which is
        // the point: naming another member's message must not confirm it
        // is there.
        $token = $this->enrol();

        $message = $this->messages->create(
            'uuid-3',
            'sender@example.org',
            9,
            'Sender',
            'Not for you',
            'Private.',
            'members',
            '',
            1788000000,
            0,
            0,
        );
        $this->recipients->addMany($message->id, [['email' => self::OTHER, 'member_id' => 8]], 1788000000);

        $response = $this->controller()->markRead($this->request(['id' => $message->id], $token));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_no_such_message', $response->get_error_code());
    }

    public function testMarkingAMessageThatDoesNotExistIsTheSameRefusal(): void
    {
        $token = $this->enrol();

        $response = $this->controller()->markRead($this->request(['id' => 999], $token));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_no_such_message', $response->get_error_code());
    }

    // ── Sending ───────────────────────────────────────────────────────

    public function testAHandsetMayNotAddressTheWholeFellowship(): void
    {
        // That is a broadcast. It belongs to whoever holds the send
        // capability in WordPress, and the app has no undo.
        $token = $this->enrol();

        $response = $this->controller()->send($this->request([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_no_audience', $response->get_error_code());
    }

    public function testACommitteeSendIsRefusedUntilTheIntergroupEnablesIt(): void
    {
        // A handset writing to a whole committee is a decision the
        // intergroup makes, not a default it inherits.
        $token = $this->enrol();

        $response = $this->controller()->send($this->request([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'committee' => 'steering',
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_committee_send_disabled', $response->get_error_code());
    }

    public function testAMessageAddressedToNobodyReachableIsRefused(): void
    {
        // An id the app holds that resolves to no address at all — a
        // member deleted since the address book was fetched.
        $token = $this->enrol();

        $response = $this->controller()->send($this->request([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_ids' => [4242],
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
    }

    public function testMemberIdsThatAreNotAListAreTreatedAsNone(): void
    {
        // The app sends JSON; a malformed body must be refused rather
        // than fatal on a foreach.
        $token = $this->enrol();

        $response = $this->controller()->send($this->request([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_ids' => 'seven',
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
    }

    public function testAMemberCanSendToAnotherMemberByOpaqueId(): void
    {
        // The whole point of the address book: the app never learns an
        // address, and sends an id back for the server to resolve.
        $token = $this->enrol();

        $response = $this->controller()->send($this->request([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_ids' => [8],
        ], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertSame(201, $response->get_status());
    }

    public function testTooManyMessagesFromOneHandsetAreRefused(): void
    {
        // Keyed on the device rather than the member, so one runaway
        // app cannot silence that member's other handset.
        $token = $this->enrol();
        $controller = $this->controller();

        for ($i = 0; $i < 40; $i++) {
            $response = $controller->send($this->request([
                'subject' => 'Intergroup moved',
                'body' => 'Now the 14th.',
                'member_ids' => [8],
            ], $token));

            if ($response instanceof WP_Error && $response->get_error_code() === 'fellowship_rate_limited') {
                self::assertTrue(true);

                return;
            }
        }

        self::fail('The send endpoint never rate-limited a repeated handset.');
    }

    public function testAStorageFailureIsFiveHundredRatherThanAFatal(): void
    {
        $token = $this->enrol();

        $response = $this->controller(null, $this->throwingMessages())->send($this->request([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_ids' => [8],
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_send_failed', $response->get_error_code());
    }

    public function testAMessageAddressedOnlyToItsOwnSenderReachesNobody(): void
    {
        // The resolver drops the sender from their own audience, so a
        // handset naming only itself resolves to an empty list. Storing
        // it would put a message in the log that nobody can ever read.
        $token = $this->enrol();

        $response = $this->controller()->send($this->request([
            'subject' => 'Note to self',
            'body' => 'Remember the 14th.',
            'member_ids' => [7],
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_no_recipients', $response->get_error_code());
    }

    // ── Replying ──────────────────────────────────────────────────────

    public function testAMemberMayReplyToAMessageTheyReceived(): void
    {
        $token = $this->enrol();
        $id = $this->giveMessage('Intergroup moved', 'Now the 14th.');

        $response = $this->controller()->send($this->request([
            'subject' => 'Re: Intergroup moved',
            'body' => 'Understood.',
            'member_ids' => [8],
            'reply_to' => $id,
        ], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
    }

    public function testAMemberMayReplyToAMessageTheySentThemselves(): void
    {
        // Without this, answering in a thread you started would be
        // refused — which is most of a conversation.
        $token = $this->enrol();
        $own = $this->storeFrom(self::MEMBER, 'Intergroup moved');

        $response = $this->controller()->send($this->request([
            'subject' => 'Re: Intergroup moved',
            'body' => 'One more thing.',
            'member_ids' => [8],
            'reply_to' => $own,
        ], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
    }

    public function testReplyingToAMessageThatIsNoneOfTheirsReadsAsNotFound(): void
    {
        // "Not found" rather than "not yours": answering differently
        // would let a handset walk the id space to learn what exists.
        $token = $this->enrol();
        $strangers = $this->storeFrom(self::OTHER, 'Private');

        $response = $this->controller()->send($this->request([
            'subject' => 'Re: Private',
            'body' => 'Reading over your shoulder.',
            'member_ids' => [8],
            'reply_to' => $strangers,
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_no_such_message', $response->get_error_code());
    }

    public function testReplyingToAMessageThatNeverExistedReadsTheSame(): void
    {
        $token = $this->enrol();

        $response = $this->controller()->send($this->request([
            'subject' => 'Re: nothing',
            'body' => 'Hello?',
            'member_ids' => [8],
            'reply_to' => 4242,
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_no_such_message', $response->get_error_code());
    }

    // ── Marking read ──────────────────────────────────────────────────

    public function testMarkingAMessageReadAnswersTheRemainingUnreadCount(): void
    {
        // The app puts it on its badge, so it comes back from the same
        // call rather than needing a second round trip.
        $token = $this->enrol();
        $id = $this->giveMessage('Intergroup moved', 'Now the 14th.');
        $this->giveMessage('Second', 'Also unread.');

        $response = $this->controller()->markRead($this->request(['id' => $id], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);

        $data = (array) $response->get_data();

        self::assertTrue($data['ok']);
        self::assertSame(1, $data['unread']);
    }

    public function testMarkingSomebodyElsesMessageReadIsNotFound(): void
    {
        $token = $this->enrol();
        $strangers = $this->storeFrom(self::OTHER, 'Private');

        $response = $this->controller()->markRead($this->request(['id' => $strangers], $token));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_no_such_message', $response->get_error_code());
    }

    public function testMarkingReadWithNoTokenIsRefused(): void
    {
        self::assertInstanceOf(WP_Error::class, $this->controller()->markRead($this->request(['id' => 1])));
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function controller(?Settings $settings = null, ?InMemoryMessageRepository $store = null): MessageController
    {
        $gate = new MemberGate($this->members);
        $settings ??= new Settings();
        $sealer = new MessageSealer();

        return new MessageController(
            new CurrentDevice($this->devices, $this->minter, $gate, $this->members),
            $this->messages,
            $this->recipients,
            new MessageDispatcher(
                $store ?? $this->messages,
                $this->recipients,
                $this->devices,
                // Unconfigured: no service account, so nothing is pushed
                // and the dispatcher takes its documented degraded path.
                // Push has its own tests; this is about what the REST
                // surface answers.
                new FcmTransport(new FcmClient(), $settings, $sealer),
            ),
            new RecipientResolver($this->members, new InMemoryCommitteeRepository(), $gate),
            $sealer,
            $this->members,
            $settings,
            new RateLimiter(),
            $this->audit,
        );
    }

    /** Store a message from a given address, addressed to nobody in particular. */
    private function storeFrom(string $senderEmail, string $subject): int
    {
        return $this->messages->create(
            'uuid-' . $senderEmail . '-' . $subject,
            $senderEmail,
            $senderEmail === self::MEMBER ? 7 : 8,
            'Dave P',
            $subject,
            'Now the 14th.',
            'members',
            '',
            1788000000,
            0,
            0,
        )->id;
    }

    private function throwingMessages(): InMemoryMessageRepository
    {
        return new class extends InMemoryMessageRepository {
            public function create(
                string $uuid,
                string $senderEmail,
                int $senderMemberId,
                string $senderName,
                string $subject,
                string $body,
                string $audienceType,
                string $audienceRef,
                int $createdAt,
                int $replyToId,
                int $senderDeviceId,
            ): Message {
                throw new RuntimeException('The messages table is gone.');
            }
        };
    }

    /** Enrol a handset for the member and answer its bearer token. */
    private function enrol(): string
    {
        return $this->enrolWithKey($this->publicKey);
    }

    private function enrolWithKey(string $publicKey): string
    {
        $token = $this->minter->mint();

        $this->devices->create(
            $this->minter->hash($token),
            self::MEMBER,
            7,
            'Pixel 6a',
            'android',
            $publicKey,
            'fcm',
            'token-1',
            1788000000,
        );

        return $token;
    }

    /** Address a message to the member, and answer its id. */
    private function giveMessage(string $subject, string $body): int
    {
        $message = $this->messages->create(
            'uuid-' . $subject,
            'sender@example.org',
            9,
            'Dave B',
            $subject,
            $body,
            'members',
            '',
            1788000000,
            0,
            0,
        );

        $this->recipients->addMany($message->id, [['email' => self::MEMBER, 'member_id' => 7]], 1788000000);

        return $message->id;
    }

    /**
     * @param array<string, mixed> $params
     */
    private function request(array $params, string $token = ''): WP_REST_Request
    {
        $request = new WP_REST_Request();

        foreach ($params as $key => $value) {
            $request->set_param($key, $value);
        }

        if ($token !== '') {
            $request->set_header('authorization', 'Bearer ' . $token);
        }

        return $request;
    }

    private function keypair(): void
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            self::markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
        }

        openssl_pkey_export($resource, $this->privateKey);

        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        $this->publicKey = preg_replace('/\s+|-----[^-]*-----/', '', (string) $details['key']) ?? '';
    }
}
