<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
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
 */

covers(\Fellowship\Rest\MessageController::class);

const MESSAGE_SEND_MEMBER = 'member@example.org';

const MESSAGE_SEND_OTHER = 'other@example.org';

beforeEach(function () {
    when('is_ssl')->justReturn(true);

    // Not in any shared stub group: it lives in wp-includes/functions.php
    // and only the dispatcher reaches for it.
    when('wp_generate_uuid4')->alias(
        static fn(): string => '11111111-2222-4333-8444-555555555555'
    );

    $this->devices = new InMemoryDeviceRepository();
    $this->messages = new InMemoryMessageRepository();
    $this->recipients = new InMemoryRecipientRepository();
    $this->minter = new DeviceTokenMinter();
    $this->settings = new Settings();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: MESSAGE_SEND_MEMBER),
        new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: MESSAGE_SEND_OTHER),
    ]);
});

test('a message to a named member is sent', function () {
    $token = messageSendEnrol();

    $response = messageSendController()->send(messageSendRequest([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_ids' => [8],
    ], $token));

    expect($response)->toBeInstanceOf(WP_REST_Response::class);
    expect($this->messages->rows)->toHaveCount(1);
});

test('the recipient is resolved from an id and not an address', function () {
    // The handset never learns anybody's address: it sends opaque
    // ids, and the server resolves them.
    $token = messageSendEnrol();

    messageSendController()->send(messageSendRequest([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_ids' => [8],
    ], $token));

    $written = $this->recipients->rows;
    expect($written)->not->toBeEmpty();
    expect($written[0]->memberEmail)->toBe(MESSAGE_SEND_OTHER);
});

test('a handset may not write to the whole fellowship', function () {
    // A broadcast belongs to whoever holds the WordPress capability.
    // The app has no undo.
    $token = messageSendEnrol();

    $response = messageSendController()->send(messageSendRequest([
        'subject' => 'Everybody',
        'body' => 'Listen up.',
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($this->messages->rows)->toBe([]);
});

test('committee sending is refused unless the site allows it', function () {
    $token = messageSendEnrol();

    $response = messageSendController()->send(messageSendRequest([
        'subject' => 'Steering',
        'body' => 'Agenda attached.',
        'committee' => 'steering',
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_committee_send_disabled');
});

test('a message with no subject is refused', function () {
    $token = messageSendEnrol();

    $response = messageSendController()->send(messageSendRequest([
        'subject' => '',
        'body' => 'Now the 14th.',
        'member_ids' => [8],
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
});

test('a message with no body is refused', function () {
    $token = messageSendEnrol();

    $response = messageSendController()->send(messageSendRequest([
        'subject' => 'Intergroup moved',
        'body' => '',
        'member_ids' => [8],
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
});

test('replying to a message the handset never received is a not found', function () {
    // Not "not yours": answering differently would let a handset walk
    // the id space to learn which messages exist.
    $token = messageSendEnrol();

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
    $this->recipients->addMany($message->id, [['email' => MESSAGE_SEND_OTHER, 'member_id' => 8]], 1788000000);

    $response = messageSendController()->send(messageSendRequest([
        'subject' => 'Re: Private',
        'body' => 'Reply.',
        'member_ids' => [8],
        'reply_to' => $message->id,
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($response->get_error_code())->toBe('fellowship_no_such_message');
});

test('an unauthenticated send is refused', function () {
    $response = messageSendController()->send(messageSendRequest([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_ids' => [8],
    ]));

    expect($response)->toBeInstanceOf(WP_Error::class);
    expect($this->messages->rows)->toBe([]);
});

test('a revoked handset cannot send', function () {
    $token = messageSendEnrol();
    $this->devices->revoke(1, time());

    $response = messageSendController()->send(messageSendRequest([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_ids' => [8],
    ], $token));

    expect($response)->toBeInstanceOf(WP_Error::class);
});

// ── Fixtures ──────────────────────────────────────────────────────

function messageSendController(): MessageController
{
    $gate = new MemberGate(test()->members);
    $sealer = new MessageSealer();
    $minter = test()->minter;

    return new MessageController(
        new CurrentDevice(test()->devices, $minter, $gate, test()->members),
        test()->messages,
        test()->recipients,
        new MessageDispatcher(
            test()->messages,
            test()->recipients,
            test()->devices,
            new FcmTransport(new FcmClient(), test()->settings, $sealer),
        ),
        new RecipientResolver(test()->members, new InMemoryCommitteeRepository(), $gate),
        $sealer,
        test()->members,
        test()->settings,
        new RateLimiter(),
        new SpyAuditLogger(),
    );
}

function messageSendEnrol(): string
{
    $token = test()->minter->mint();

    test()->devices->create(
        test()->minter->hash($token),
        MESSAGE_SEND_MEMBER,
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
function messageSendRequest(array $params, string $token = ''): WP_REST_Request
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
