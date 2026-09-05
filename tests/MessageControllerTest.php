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
use Fellowship\Messaging\MessageDispatcher;
use Fellowship\Messaging\RecipientResolver;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Rest\MessageController;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
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

    // ── Fixtures ──────────────────────────────────────────────────────

    private function controller(): MessageController
    {
        $gate = new MemberGate($this->members);
        $settings = new Settings();
        $sealer = new MessageSealer();

        return new MessageController(
            new CurrentDevice($this->devices, $this->minter, $gate, $this->members),
            $this->messages,
            $this->recipients,
            new MessageDispatcher(
                $this->messages,
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
