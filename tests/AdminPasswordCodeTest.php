<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use function Brain\Monkey\Functions\when;
use BleedingDeacons\WpMocks\Exceptions\WpDieException;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Admin\DevicesPage;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Devices\MemberGate;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Unity\Testing\Doubles\InMemoryPasswordCredentialRepository;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;

/**
 * Emailing a member a code from the admin screen.
 *
 * <b>What makes this safe is that triggering is not setting.</b> The code
 * goes to the member's own address, so an admin can start the flow and
 * cannot finish it. An admin screen that set a password directly would be
 * a way to enrol a handset as somebody else and read their messages,
 * which is why there is not one — and this file is where that boundary is
 * actually asserted rather than merely described in a comment.
 *
 * The other thing worth pinning is that this screen answers honestly
 * where the REST endpoint deliberately does not. The public endpoint
 * cannot say whether an address belongs to a member, or asking becomes a
 * way to enumerate the fellowship. Here the operator is already
 * authenticated and can already read the member list, so saying so leaks
 * nothing — and not saying would leave them watching for a mail that was
 * never going to arrive.
 */

covers(\Fellowship\Admin\DevicesPage::class);

const ADMIN_PASSWORD_CODE_MEMBER = 'member@example.org';

beforeEach(function () {
    $_POST = [];

    when('get_current_user_id')->justReturn(3);
    when('admin_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-admin/' . $p);

    $this->credentials = new InMemoryPasswordCredentialRepository();
    $this->mailer = new PasswordResetMailer();
    $this->audit = new SpyAuditLogger();

    $this->members = new InMemoryMemberRepository([
        new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: ADMIN_PASSWORD_CODE_MEMBER),
    ]);
});

test('a member is sent a code', function () {
    WpState::$userCan = true;
    $_POST['member_email'] = ADMIN_PASSWORD_CODE_MEMBER;

    $result = adminPasswordCodePage()->sendResetCodeFromRequest();

    expect($result)->toBe('code_sent');

    // Queued past the response in production; flushed here because
    // there is no shutdown to wait for.
    $this->mailer->flush();

    expect(WpState::$mail)->not->toBeEmpty();
    expect(WpState::$mail[0]['to'])->toBe(ADMIN_PASSWORD_CODE_MEMBER);
});

test('the code goes to the member and not to the admin', function () {
    // The property the whole design rests on. An admin who received
    // the code could finish the flow themselves and enrol a handset
    // as that member.
    WpState::$userCan = true;
    $_POST['member_email'] = ADMIN_PASSWORD_CODE_MEMBER;

    adminPasswordCodePage()->sendResetCodeFromRequest();
    $this->mailer->flush();

    expect(WpState::$mail)->not->toBeEmpty('Nothing was sent, so the assertion below would prove nothing.');

    foreach (WpState::$mail as $sent) {
        expect($sent['to'])->toBe(ADMIN_PASSWORD_CODE_MEMBER);
    }
});

test('the stored token is a hash and the mail carries the code', function () {
    // A database dump must not yield a usable code.
    WpState::$userCan = true;
    $_POST['member_email'] = ADMIN_PASSWORD_CODE_MEMBER;

    adminPasswordCodePage()->sendResetCodeFromRequest();
    $this->mailer->flush();

    $stored = $this->credentials->rows[ADMIN_PASSWORD_CODE_MEMBER]->resetTokenHash;
    $body = (string) WpState::$mail[0]['message'];

    expect(strlen($stored))->toBe(64, 'The stored token must be a SHA-256 hex digest.');
    expect($body)->not->toContain($stored);
});

test('an address no member holds is said so plainly', function () {
    // Deliberately unlike the REST endpoint, which must not reveal
    // this. See the class docblock.
    WpState::$userCan = true;
    $_POST['member_email'] = 'nobody@example.org';

    expect(adminPasswordCodePage()->sendResetCodeFromRequest())->toBe('code_not_a_member');
    expect($this->credentials->rows)->toBe([]);
});

test('something that is not an address is refused', function () {
    WpState::$userCan = true;
    $_POST['member_email'] = 'not an address';

    expect(adminPasswordCodePage()->sendResetCodeFromRequest())->toBe('code_bad_address');
});

test('an empty field is refused', function () {
    WpState::$userCan = true;
    $_POST['member_email'] = '';

    expect(adminPasswordCodePage()->sendResetCodeFromRequest())->toBe('code_bad_address');
});

test('the address is matched without regard to case', function () {
    // Whoever is typing it is reading it off a membership record, not
    // copying it from the database.
    WpState::$userCan = true;
    $_POST['member_email'] = 'Member@Example.ORG';

    expect(adminPasswordCodePage()->sendResetCodeFromRequest())->toBe('code_sent');
});

test('a second attempt inside the cooldown says so rather than lying', function () {
    // The reason beginReset now answers a bool. Before it did, this
    // path returned success and sent nothing — a button somebody
    // presses four more times.
    WpState::$userCan = true;
    $_POST['member_email'] = ADMIN_PASSWORD_CODE_MEMBER;

    expect(adminPasswordCodePage()->sendResetCodeFromRequest())->toBe('code_sent');
    expect(adminPasswordCodePage()->sendResetCodeFromRequest())->toBe('code_too_soon');
});

test('sending a code is audited', function () {
    // An admin acting on a member's ability to sign in is exactly
    // what the audit log is for.
    WpState::$userCan = true;
    $_POST['member_email'] = ADMIN_PASSWORD_CODE_MEMBER;

    adminPasswordCodePage()->sendResetCodeFromRequest();

    expect($this->audit->entries)->not->toBeEmpty();
});

test('a refused attempt is not audited', function () {
    // Otherwise the log fills with entries for things that did not
    // happen, and the ones that did become harder to find.
    WpState::$userCan = true;
    $_POST['member_email'] = 'nobody@example.org';

    adminPasswordCodePage()->sendResetCodeFromRequest();

    expect($this->audit->entries)->toBe([]);
});

test('an admin without the capability is refused', function () {
    // wp_die() throws under the test doubles, which is what makes the
    // guard assertable at all — the handler otherwise ends in a
    // redirect and an exit.
    WpState::$userCan = false;

    adminPasswordCodePage()->handleSendResetCode();
})->throws(WpDieException::class);

function adminPasswordCodePage(): DevicesPage
{
    $gate = new MemberGate(test()->members);

    return new DevicesPage(
        new InMemoryDeviceRepository(),
        test()->members,
        test()->audit,
        new PasswordAuthenticator(test()->credentials, $gate, test()->mailer, new PasswordPolicy()),
        $gate,
    );
}
