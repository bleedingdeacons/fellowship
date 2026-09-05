<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\TestCase;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Core\Settings;
use Fellowship\Crypto\MessageSealer;
use Fellowship\Devices\Device;
use Fellowship\Messaging\Message;
use Fellowship\Push\FcmClient;
use Fellowship\Push\FcmTransport;
use Fellowship\Push\ServiceAccount;

/**
 * Pushing a message to a handset.
 *
 * <b>Push is the fast path, never the reliable one</b>, and almost
 * everything here is about holding that line. Every failure below has to
 * end in false rather than an exception, because the message is already
 * stored and the handset will collect it on its next poll — a throw here
 * would turn a late message into a failed send for everybody else on the
 * same fan-out.
 *
 * The one distinction the client makes is worth keeping: a 401 or 403 is
 * a *configuration* fault that stops every push to everyone until
 * somebody fixes it, and is logged as an error. Anything else is about
 * one message — a dead registration token, a rate limit, a bad hour at
 * Google — and is a warning. Collapsing the two would either bury the
 * outage or cry wolf about a stale token.
 *
 * @covers \Fellowship\Push\FcmClient
 * @covers \Fellowship\Push\FcmTransport
 * @covers \Fellowship\Push\ServiceAccount
 */
final class PushTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        FakeWpHttp::reset();
    }

    // ── The service account ───────────────────────────────────────────

    public function testAServiceAccountIsReadFromItsJson(): void
    {
        $account = ServiceAccount::fromJson($this->accountJson());

        self::assertNotNull($account);
        self::assertSame('intergroup-fellowship', $account->projectId);
        self::assertStringContainsString('intergroup-fellowship', $account->sendEndpoint());
    }

    public function testJsonThatIsNotAServiceAccountIsRefused(): void
    {
        // Parsed when it is saved rather than at the first message: a
        // setting that looks stored and pushes nothing is the worst of
        // both.
        self::assertNull(ServiceAccount::fromJson(''));
        self::assertNull(ServiceAccount::fromJson('not json'));
        self::assertNull(ServiceAccount::fromJson('{"project_id":"x"}'));
    }

    public function testTheFingerprintChangesWithTheAccount(): void
    {
        // It keys the cached access token, so replacing the service
        // account has to invalidate the cache rather than leave a token
        // for the old project in play.
        $first = ServiceAccount::fromJson($this->accountJson());
        $second = ServiceAccount::fromJson($this->accountJson('other-project'));

        self::assertNotNull($first);
        self::assertNotNull($second);
        self::assertNotSame($first->fingerprint(), $second->fingerprint());
    }

    public function testTheFingerprintIsNotTheAccount(): void
    {
        $account = ServiceAccount::fromJson($this->accountJson());

        self::assertNotNull($account);
        self::assertStringNotContainsString('@', $account->fingerprint());
        self::assertStringNotContainsString('intergroup-fellowship', $account->fingerprint());
    }

    // ── The transport ─────────────────────────────────────────────────

    public function testASiteWithNoServiceAccountIsNotConfiguredToPush(): void
    {
        // Checked once by the dispatcher rather than per device, so a
        // site with no account logs one line instead of one per handset.
        self::assertFalse($this->transport()->isConfigured());
    }

    public function testASiteWithAServiceAccountIsConfigured(): void
    {
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        self::assertTrue($this->transport($settings)->isConfigured());
    }

    public function testNothingIsSentWhenThereIsNoServiceAccount(): void
    {
        // False, not an exception: the message is stored and the poll
        // will fetch it.
        self::assertFalse($this->transport()->send($this->device(), $this->message()));
        self::assertSame(0, FakeWpHttp::callCount());
    }

    public function testAHandsetWithNoPushTokenIsNotSentTo(): void
    {
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        $device = $this->device(pushToken: '');

        self::assertFalse($this->transport($settings)->send($device, $this->message()));
    }

    public function testAHandsetWithNoPublicKeyIsNotSentTo(): void
    {
        // There would be nothing to seal the payload to, and an unsealed
        // push is the one thing this design refuses: the body would
        // travel through Google in the clear.
        $settings = new Settings();
        $settings->setFcmServiceAccount($this->accountJson());

        $device = $this->device(publicKey: '');

        self::assertFalse($this->transport($settings)->send($device, $this->message()));
    }

    // ── The client ────────────────────────────────────────────────────

    public function testAnUnreachableTokenEndpointMeansNoSend(): void
    {
        $account = ServiceAccount::fromJson($this->accountJson());
        self::assertNotNull($account);

        FakeWpHttp::push(new \WP_Error('http_request_failed', 'offline'));

        self::assertFalse((new FcmClient())->send($account, ['token' => 'fcm-1']));
    }

    public function testATokenEndpointThatAnswersNoTokenMeansNoSend(): void
    {
        $account = ServiceAccount::fromJson($this->accountJson());
        self::assertNotNull($account);

        FakeWpHttp::pushResponse(200, '{"not_an_access_token":true}');

        self::assertFalse((new FcmClient())->send($account, ['token' => 'fcm-1']));
    }

    public function testARefusedSendIsReportedRatherThanThrown(): void
    {
        $account = ServiceAccount::fromJson($this->accountJson());
        self::assertNotNull($account);

        // A token, then a 403 from the send endpoint: the configuration
        // fault, which stops every push to everyone.
        FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
        FakeWpHttp::pushResponse(403, '{"error":{"status":"PERMISSION_DENIED"}}');

        self::assertFalse((new FcmClient())->send($account, ['token' => 'fcm-1']));
    }

    public function testADeadRegistrationTokenIsAlsoJustFalse(): void
    {
        // Ordinary and survivable: one handset reinstalled the app.
        $account = ServiceAccount::fromJson($this->accountJson());
        self::assertNotNull($account);

        FakeWpHttp::pushResponse(200, '{"access_token":"ya29.token","expires_in":3600}');
        FakeWpHttp::pushResponse(404, '{"error":{"status":"NOT_FOUND"}}');

        self::assertFalse((new FcmClient())->send($account, ['token' => 'fcm-1']));
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function transport(?Settings $settings = null): FcmTransport
    {
        return new FcmTransport(new FcmClient(), $settings ?? new Settings(), new MessageSealer());
    }

    private function device(string $pushToken = 'fcm-1', string $publicKey = 'spki'): Device
    {
        return new Device(
            4,
            'member@example.org',
            7,
            'Pixel 6a',
            'android',
            $publicKey,
            'fcm',
            $pushToken,
            1788000000,
        );
    }

    private function message(): Message
    {
        return new Message(
            9,
            'uuid-1',
            'dave@example.org',
            7,
            'Dave B',
            'Intergroup moved',
            'Now the 14th.',
            'committee',
            'steering',
            1788000000,
        );
    }

    private function accountJson(string $projectId = 'intergroup-fellowship'): string
    {
        // A structurally real account with a throwaway key. Nothing here
        // signs anything a test asserts on, and a committed fixture must
        // never carry a usable credential.
        return (string) wp_json_encode([
            'type' => 'service_account',
            'project_id' => $projectId,
            'client_email' => 'pusher@' . $projectId . '.iam.gserviceaccount.com',
            'private_key' => "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n",
            'token_uri' => 'https://oauth2.googleapis.com/token',
        ]);
    }
}
