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
 * Sending a message from a handset.
 *
 * <b>The refusals here are about blast radius.</b> A handset may write to
 * named members and, if the site allows it, to a committee — but never to
 * the whole fellowship. That is a broadcast, it belongs to whoever holds
 * the send capability in WordPress, and the app has no undo.
 *
 * The other property worth pinning is that a handset never names an
 * address. It sends opaque member ids and the server resolves them, so a
 * compromised handset cannot read the membership out of its own outbox —
 * and a reply it is not entitled to is refused as "not found" rather than
 * "not yours", because answering differently would let it walk the id
 * space to learn which messages exist.
 *
 * @covers \Fellowship\Rest\MessageController
 */
final class MessageSendTest extends TestCase
{
    private const MEMBER = 'member@example.org';
    private const OTHER = 'other@example.org';

    private InMemoryDeviceRepository $devices;
    private InMemoryMessageRepository $messages;
    private InMemoryRecipientRepository $recipients;
    private InMemoryMemberRepository $members;
    private DeviceTokenMinter $minter;
    private Settings $settings;

    protected function setUp(): void
    {
        parent::setUp();

        Functions\when('is_ssl')->justReturn(true);

        // Not in any shared stub group: it lives in wp-includes/functions.php
        // and only the dispatcher reaches for it.
        Functions\when('wp_generate_uuid4')->alias(
            static fn(): string => '11111111-2222-4333-8444-555555555555'
        );

        $this->devices = new InMemoryDeviceRepository();
        $this->messages = new InMemoryMessageRepository();
        $this->recipients = new InMemoryRecipientRepository();
        $this->minter = new DeviceTokenMinter();
        $this->settings = new Settings();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: self::MEMBER),
            new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: self::OTHER),
        ]);
    }

    public function testAMessageToANamedMemberIsSent(): void
    {
        $token = $this->enrol();

        $response = $this->controller()->send($this->request([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_ids' => [8],
        ], $token));

        self::assertInstanceOf(WP_REST_Response::class, $response);
        self::assertCount(1, $this->messages->rows);
    }

    public function testTheRecipientIsResolvedFromAnIdAndNotAnAddress(): void
    {
        // The handset never learns anybody's address: it sends opaque
        // ids, and the server resolves them.
        $token = $this->enrol();

        $this->controller()->send($this->request([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_ids' => [8],
        ], $token));

        $written = $this->recipients->rows;
        self::assertNotEmpty($written);
        self::assertSame(self::OTHER, $written[0]->memberEmail);
    }

    public function testAHandsetMayNotWriteToTheWholeFellowship(): void
    {
        // A broadcast belongs to whoever holds the WordPress capability.
        // The app has no undo.
        $token = $this->enrol();

        $response = $this->controller()->send($this->request([
            'subject' => 'Everybody',
            'body' => 'Listen up.',
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame([], $this->messages->rows);
    }

    public function testCommitteeSendingIsRefusedUnlessTheSiteAllowsIt(): void
    {
        $token = $this->enrol();

        $response = $this->controller()->send($this->request([
            'subject' => 'Steering',
            'body' => 'Agenda attached.',
            'committee' => 'steering',
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_committee_send_disabled', $response->get_error_code());
    }

    public function testAMessageWithNoSubjectIsRefused(): void
    {
        $token = $this->enrol();

        $response = $this->controller()->send($this->request([
            'subject' => '',
            'body' => 'Now the 14th.',
            'member_ids' => [8],
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
    }

    public function testAMessageWithNoBodyIsRefused(): void
    {
        $token = $this->enrol();

        $response = $this->controller()->send($this->request([
            'subject' => 'Intergroup moved',
            'body' => '',
            'member_ids' => [8],
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
    }

    public function testReplyingToAMessageTheHandsetNeverReceivedIsANotFound(): void
    {
        // Not "not yours": answering differently would let a handset walk
        // the id space to learn which messages exist.
        $token = $this->enrol();

        $message = $this->messages->create(
            'uuid-x',
            'sender@example.org',
            9,
            'Sender',
            'Private',
            'Not for you.',
            'members',
            '',
            1788000000,
            0,
            0,
        );
        $this->recipients->addMany($message->id, [['email' => self::OTHER, 'member_id' => 8]], 1788000000);

        $response = $this->controller()->send($this->request([
            'subject' => 'Re: Private',
            'body' => 'Reply.',
            'member_ids' => [8],
            'reply_to' => $message->id,
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame('fellowship_no_such_message', $response->get_error_code());
    }

    public function testAnUnauthenticatedSendIsRefused(): void
    {
        $response = $this->controller()->send($this->request([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_ids' => [8],
        ]));

        self::assertInstanceOf(WP_Error::class, $response);
        self::assertSame([], $this->messages->rows);
    }

    public function testARevokedHandsetCannotSend(): void
    {
        $token = $this->enrol();
        $this->devices->revoke(1, time());

        $response = $this->controller()->send($this->request([
            'subject' => 'Intergroup moved',
            'body' => 'Now the 14th.',
            'member_ids' => [8],
        ], $token));

        self::assertInstanceOf(WP_Error::class, $response);
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function controller(): MessageController
    {
        $gate = new MemberGate($this->members);
        $sealer = new MessageSealer();
        $minter = $this->minter;

        return new MessageController(
            new CurrentDevice($this->devices, $minter, $gate, $this->members),
            $this->messages,
            $this->recipients,
            new MessageDispatcher(
                $this->messages,
                $this->recipients,
                $this->devices,
                new FcmTransport(new FcmClient(), $this->settings, $sealer),
            ),
            new RecipientResolver($this->members, new InMemoryCommitteeRepository(), $gate),
            $sealer,
            $this->members,
            $this->settings,
            new RateLimiter(),
            new SpyAuditLogger(),
        );
    }

    private function enrol(): string
    {
        $token = $this->minter->mint();

        $this->devices->create(
            $this->minter->hash($token),
            self::MEMBER,
            7,
            'Pixel 6a',
            'android',
            'spki',
            'fcm',
            'token-1',
            1788000000,
        );

        return $token;
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
}
