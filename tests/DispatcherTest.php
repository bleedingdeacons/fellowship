<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
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
 */

covers(\Fellowship\Messaging\MessageDispatcher::class, \Fellowship\Messaging\MessageApi::class);

beforeEach(function () {
    when('wp_generate_uuid4')->alias(
        static fn(): string => '11111111-2222-4333-8444-555555555555'
    );
    when('get_current_user_id')->justReturn(3);

    $this->messages = new InMemoryMessageRepository();
    $this->recipients = new InMemoryRecipientRepository();
    $this->devices = new InMemoryDeviceRepository();
    $this->audit = new SpyAuditLogger();
    $this->settings = new Settings();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: 'dave@example.org'),
        new MemberStub(id: 8, anonymousName: 'Sue M', personalEmail: 'sue@example.org'),
    ]);
});

// ── The dispatcher ────────────────────────────────────────────────

test('a message is stored with its recipients', function () {
    $message = dispatcherDispatcher()->dispatch(
        dispatcherRequest(),
        [['email' => 'sue@example.org', 'member_id' => 8]],
        'dave@example.org',
        7,
        'Dave P',
    );

    expect($this->messages->rows)->toHaveCount(1);
    expect($this->recipients->forMessage($message->id))->toHaveCount(1);
});

test('a message is stored even when nothing can be pushed', function () {
    // No service account, so push is off entirely. The message must
    // still be stored, because the poll is what actually delivers it.
    $message = dispatcherDispatcher()->dispatch(
        dispatcherRequest(),
        [['email' => 'sue@example.org', 'member_id' => 8]],
        'dave@example.org',
        7,
        'Dave P',
    );

    expect($this->messages->findById($message->id))->not->toBeNull();
});

test('a message with no recipients is still stored', function () {
    // A committee nobody is on. The message is a record of what was
    // said, and the admin log should show it went nowhere rather than
    // showing nothing at all.
    $message = dispatcherDispatcher()->dispatch(
        dispatcherRequest(),
        [],
        'dave@example.org',
        7,
        'Dave P',
    );

    expect($this->messages->findById($message->id))->not->toBeNull();
    expect($this->recipients->forMessage($message->id))->toBe([]);
});

test('the sending device is recorded when it came from the app', function () {
    // Which is how the admin log distinguishes a message sent from a
    // handset from one composed in WordPress.
    $message = dispatcherDispatcher()->dispatch(
        dispatcherRequest(),
        [['email' => 'sue@example.org', 'member_id' => 8]],
        'dave@example.org',
        7,
        'Dave P',
        senderDeviceId: 4,
    );

    expect($message->senderDeviceId)->toBe(4);
});

// ── The one door in ───────────────────────────────────────────────

test('the API sends and audits', function () {
    $result = dispatcherApi()->send([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['sue@example.org'],
    ]);

    expect($result)->not->toBeInstanceOf(WP_Error::class);
    expect($this->messages->rows)->toHaveCount(1);
    expect($this->audit->entries)->not->toBeEmpty();
});

test('the API refuses a message with no subject', function () {
    $result = dispatcherApi()->send([
        'subject' => '',
        'body' => 'Now the 14th.',
        'member_emails' => ['sue@example.org'],
    ]);

    expect($result)->toBeInstanceOf(WP_Error::class);
    expect($this->messages->rows)->toBe([]);
});

test('the API refuses a message with no body', function () {
    $result = dispatcherApi()->send([
        'subject' => 'Intergroup moved',
        'body' => '',
        'member_emails' => ['sue@example.org'],
    ]);

    expect($result)->toBeInstanceOf(WP_Error::class);
});

test('a message that reaches nobody is still recorded', function () {
    // Not a refusal, and worth stating plainly because the opposite
    // is the intuitive guess: the message is a record of what the
    // intergroup said, so it is stored with no recipients rather than
    // rejected. The admin log shows the recipient count, which is
    // where "this went nowhere" is meant to become visible.
    //
    // The two callers that must not allow it guard separately: the
    // REST controller refuses a handset addressing the whole
    // fellowship, and the compose screen refuses an empty audience.
    $result = dispatcherApi()->send([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['stranger@example.org'],
    ]);

    expect($result)->not->toBeInstanceOf(WP_Error::class);
    expect($this->messages->rows)->toHaveCount(1);
    expect($this->recipients->rows)->toBe([]);
});

test('a refused send writes no audit entry', function () {
    // Otherwise the log fills with entries for things that did not
    // happen, and the ones that did become harder to find.
    dispatcherApi()->send([
        'subject' => '',
        'body' => '',
    ]);

    expect($this->audit->entries)->toBe([]);
});

// ── Fixtures ──────────────────────────────────────────────────────

function dispatcherDispatcher(): MessageDispatcher
{
    return new MessageDispatcher(
        test()->messages,
        test()->recipients,
        test()->devices,
        new FcmTransport(new FcmClient(), test()->settings, new MessageSealer()),
    );
}

function dispatcherApi(): MessageApi
{
    return new MessageApi(
        dispatcherDispatcher(),
        new RecipientResolver(
            test()->members,
            new InMemoryCommitteeRepository(),
            new MemberGate(test()->members),
        ),
        test()->audit,
    );
}

function dispatcherRequest(): MessageRequest
{
    $built = MessageRequest::fromArray([
        'subject' => 'Intergroup moved',
        'body' => 'Now the 14th.',
        'member_emails' => ['sue@example.org'],
    ]);

    expect($built)->not->toBeInstanceOf(WP_Error::class);

    return $built;
}
