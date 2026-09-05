<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use BleedingDeacons\WpMocks\WpState;
use Brain\Monkey\Functions;
use Fellowship\Admin\ComposePage;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\MemberGate;
use Fellowship\Messaging\MessageApi;
use Fellowship\Messaging\MessageDispatcher;
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

/**
 * Sending from the admin compose screen.
 *
 * <b>This is the broadcast path</b> — the one a handset is deliberately
 * refused. Whoever holds the send capability can address the whole
 * fellowship from here, and there is no undo, so what the screen does
 * with a refusal matters as much as what it does with a success.
 *
 * A refusal's reason waits in a one-shot per-user transient rather than
 * travelling in the query string. A server-supplied message rendered out
 * of a URL is a reflected-content problem however carefully it is
 * escaped, and it was fixed that way once already.
 *
 * @covers \Fellowship\Admin\ComposePage
 */
final class ComposeSendTest extends TestCase
{
    private InMemoryMessageRepository $messages;
    private InMemoryRecipientRepository $recipients;
    private SpyAuditLogger $audit;
    private InMemoryMemberRepository $members;

    protected function setUp(): void
    {
        parent::setUp();

        $_POST = [];

        WpState::$userCan = true;

        Functions\when('get_current_user_id')->justReturn(3);
        Functions\when('wp_generate_uuid4')->alias(
            static fn(): string => '11111111-2222-4333-8444-555555555555'
        );

        $this->messages = new InMemoryMessageRepository();
        $this->recipients = new InMemoryRecipientRepository();
        $this->audit = new SpyAuditLogger();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
            new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: 'sue@example.org'),
        ]);
    }

    public function testAMessageToTheWholeFellowshipIsSentFromHere(): void
    {
        // What the app may not do. Naming no audience is the broadcast.
        $_POST['subject'] = 'Intergroup moved';
        $_POST['body'] = 'Now the 14th, same room.';

        self::assertSame('sent', $this->page()->sendFromRequest());
        self::assertCount(1, $this->messages->rows);
        self::assertCount(2, $this->recipients->rows);
    }

    public function testSendingIsAudited(): void
    {
        $_POST['subject'] = 'Intergroup moved';
        $_POST['body'] = 'Now the 14th.';

        $this->page()->sendFromRequest();

        self::assertNotEmpty($this->audit->entries);
    }

    public function testAMessageWithNoSubjectIsRefused(): void
    {
        $_POST['subject'] = '';
        $_POST['body'] = 'Now the 14th.';

        self::assertSame('error', $this->page()->sendFromRequest());
        self::assertSame([], $this->messages->rows);
    }

    public function testAMessageWithNoBodyIsRefused(): void
    {
        $_POST['subject'] = 'Intergroup moved';
        $_POST['body'] = '';

        self::assertSame('error', $this->page()->sendFromRequest());
    }

    public function testTheReasonWaitsInATransientRatherThanTheQueryString(): void
    {
        // A server-supplied message rendered out of a URL is a
        // reflected-content problem however carefully it is escaped.
        $_POST['subject'] = '';
        $_POST['body'] = '';

        $this->page()->sendFromRequest();

        // The constant is private, so the assertion is that *something*
        // was stored for this user rather than that a particular key was:
        // naming the key here would only restate the implementation.
        self::assertNotSame([], WpState::$transients);

        $stored = implode('|', array_map('strval', WpState::$transients));

        self::assertNotSame('', $stored);
    }

    public function testARefusedSendWritesNoAuditEntry(): void
    {
        $_POST['subject'] = '';
        $_POST['body'] = '';

        $this->page()->sendFromRequest();

        self::assertSame([], $this->audit->entries);
    }

    private function page(): ComposePage
    {
        $gate = new MemberGate($this->members);
        $settings = new Settings();
        $sealer = new MessageSealer();

        return new ComposePage(
            new MessageApi(
                new MessageDispatcher(
                    $this->messages,
                    $this->recipients,
                    new InMemoryDeviceRepository(),
                    new FcmTransport(new FcmClient(), $settings, $sealer),
                ),
                new RecipientResolver($this->members, new InMemoryCommitteeRepository(), $gate),
                $this->audit,
            ),
            new InMemoryCommitteeRepository(),
        );
    }
}
