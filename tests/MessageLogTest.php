<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use BleedingDeacons\WpMocks\WpState;
use Brain\Monkey\Functions;
use Fellowship\Admin\MessagesPage;
use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Devices\CurrentDevice;
use Fellowship\Devices\MemberGate;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryMessageRepository;
use Fellowship\Tests\Support\InMemoryRecipientRepository;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;
use WP_REST_Request;

/**
 * The admin message log, and who the server thinks is calling.
 *
 * <b>The log is the reason message bodies are stored readable.</b> That
 * was a decision rather than an oversight — it is what makes an admin
 * composing to a committee, this screen, and Scrutiny's audit possible at
 * all — so what the screen shows about each message is the visible half
 * of that trade, and the delivery counts are what make "this went
 * nowhere" noticeable.
 *
 * <b>CurrentDevice is the single answer to "who is calling?"</b> Every
 * authenticated route runs through it, and it re-runs the member gate on
 * every request rather than trusting the token alone — so a member who
 * stops qualifying is refused on their next call rather than at their
 * next enrolment.
 *
 * @covers \Fellowship\Admin\MessagesPage
 * @covers \Fellowship\Devices\CurrentDevice
 */
final class MessageLogTest extends TestCase
{
    private const MEMBER = 'member@example.org';

    private InMemoryMessageRepository $messages;
    private InMemoryRecipientRepository $recipients;
    private InMemoryDeviceRepository $devices;
    private InMemoryMemberRepository $members;
    private DeviceTokenMinter $minter;

    protected function setUp(): void
    {
        parent::setUp();

        $_GET = [];
        WpState::$userCan = true;

        Functions\when('paginate_links')->justReturn('');
        Functions\when('wp_date')->alias(static fn(string $f, int $t): string => date($f, $t));

        $this->messages = new InMemoryMessageRepository();
        $this->recipients = new InMemoryRecipientRepository();
        $this->devices = new InMemoryDeviceRepository();
        $this->minter = new DeviceTokenMinter();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: self::MEMBER),
        ]);
    }

    public function testTheLogShowsWhoSentWhatAndToWhom(): void
    {
        $this->give('committee', 'steering', 'Dave P');

        $markup = $this->render();

        self::assertStringContainsString('Intergroup moved', $markup);
        self::assertStringContainsString('Dave P', $markup);
        self::assertStringContainsString('steering', $markup);
    }

    public function testAMessageFromTheAppIsMarkedAsSuch(): void
    {
        // Which is how somebody reading the log tells a member's message
        // from one the intergroup sent.
        $this->give('members', '', 'Dave P', fromApp: true);

        self::assertStringContainsString('from Link', $this->render());
    }

    public function testAMessageWithNoSenderReadsAsTheIntergroup(): void
    {
        // A send through the API has no member behind it. Showing a blank
        // sender would look like data loss.
        $this->give('all', '', '');

        self::assertStringContainsString('Intergroup', $this->render());
    }

    public function testTheLogShowsHowManyReadIt(): void
    {
        // The half of the screen that makes "this went nowhere" visible.
        $id = $this->give('members', '', 'Dave P');

        $this->recipients->addMany($id, [
            ['email' => self::MEMBER, 'member_id' => 7],
            ['email' => 'sue@example.org', 'member_id' => 8],
        ], 1788000000);
        $this->recipients->markRead($id, self::MEMBER, 1788000100);

        self::assertStringContainsString('1 / 2', $this->render());
    }

    public function testEachAudienceIsNamedInWords(): void
    {
        $this->give('all', '', 'Dave P');

        self::assertStringContainsString('Everyone', $this->render());
    }

    // ── Who is calling ────────────────────────────────────────────────

    public function testAnEnrolledHandsetIsRecognised(): void
    {
        $token = $this->enrol();

        $device = $this->currentDevice()->fromRequest($this->request($token));

        self::assertNotNull($device);
        self::assertSame(self::MEMBER, $device->memberEmail);
    }

    public function testARequestWithNoHeaderIsNobody(): void
    {
        self::assertNull($this->currentDevice()->fromRequest($this->request()));
    }

    public function testSomethingThatIsNotATokenIsNobody(): void
    {
        // Refused on shape before it ever reaches the database, so a
        // malformed header costs no query.
        self::assertNull($this->currentDevice()->fromRequest($this->request('not-a-token')));
    }

    public function testARevokedHandsetIsNobody(): void
    {
        $token = $this->enrol();
        $this->devices->revoke(1, time());

        self::assertNull($this->currentDevice()->fromRequest($this->request($token)));
    }

    public function testAMemberWhoNoLongerQualifiesIsRefusedOnTheirNextCall(): void
    {
        // The gate is re-run on every request rather than trusted from
        // enrolment, so somebody removed from Unity stops being able to
        // call immediately rather than at their next sign-in.
        $token = $this->enrol();

        $this->members = new InMemoryMemberRepository([]);

        self::assertNull($this->currentDevice()->fromRequest($this->request($token)));
    }

    public function testTheMemberBehindADeviceIsResolvedThroughTheSameGate(): void
    {
        // So the answer cannot disagree with whether the request was
        // allowed at all.
        $token = $this->enrol();
        $current = $this->currentDevice();

        $device = $current->fromRequest($this->request($token));

        self::assertNotNull($device);
        self::assertNotNull($current->memberFor($device));
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function render(): string
    {
        ob_start();

        try {
            (new MessagesPage($this->messages, $this->recipients))->render();
        } finally {
            $markup = (string) ob_get_clean();
        }

        return $markup;
    }

    private function give(string $audience, string $ref, string $sender, bool $fromApp = false): int
    {
        return $this->messages->create(
            'uuid-' . count($this->messages->rows),
            $sender === '' ? '' : 'dave@example.org',
            $sender === '' ? 0 : 7,
            $sender,
            'Intergroup moved',
            'Now the 14th, same room as usual.',
            $audience,
            $ref,
            1788000000,
            0,
            $fromApp ? 4 : 0,
        )->id;
    }

    private function currentDevice(): CurrentDevice
    {
        $gate = new MemberGate($this->members);

        return new CurrentDevice($this->devices, $this->minter, $gate, $this->members);
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

    private function request(string $token = ''): WP_REST_Request
    {
        $request = new WP_REST_Request();

        if ($token !== '') {
            $request->set_header('authorization', 'Bearer ' . $token);
        }

        return $request;
    }
}
