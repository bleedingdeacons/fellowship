<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Exceptions\WpDieException;
use BleedingDeacons\WpMocks\TestCase;
use BleedingDeacons\WpMocks\WpState;
use Brain\Monkey\Functions;
use Fellowship\Admin\DevicesPage;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Devices\MemberGate;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryPasswordCredentialRepository;
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
 *
 * @covers \Fellowship\Admin\DevicesPage
 */
final class AdminPasswordCodeTest extends TestCase
{
    private const MEMBER = 'member@example.org';

    private InMemoryPasswordCredentialRepository $credentials;
    private PasswordResetMailer $mailer;
    private SpyAuditLogger $audit;
    private InMemoryMemberRepository $members;

    protected function setUp(): void
    {
        parent::setUp();

        $_POST = [];

        Functions\when('get_current_user_id')->justReturn(3);
        Functions\when('admin_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-admin/' . $p);

        $this->credentials = new InMemoryPasswordCredentialRepository();
        $this->mailer = new PasswordResetMailer();
        $this->audit = new SpyAuditLogger();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: self::MEMBER),
        ]);
    }

    public function testAMemberIsSentACode(): void
    {
        WpState::$userCan = true;
        $_POST['member_email'] = self::MEMBER;

        $result = $this->page()->sendResetCodeFromRequest();

        self::assertSame('code_sent', $result);

        // Queued past the response in production; flushed here because
        // there is no shutdown to wait for.
        $this->mailer->flush();

        self::assertNotEmpty(WpState::$mail);
        self::assertSame(self::MEMBER, WpState::$mail[0]['to']);
    }

    public function testTheCodeGoesToTheMemberAndNotToTheAdmin(): void
    {
        // The property the whole design rests on. An admin who received
        // the code could finish the flow themselves and enrol a handset
        // as that member.
        WpState::$userCan = true;
        $_POST['member_email'] = self::MEMBER;

        $this->page()->sendResetCodeFromRequest();
        $this->mailer->flush();

        self::assertNotEmpty(WpState::$mail, 'Nothing was sent, so the assertion below would prove nothing.');

        foreach (WpState::$mail as $sent) {
            self::assertSame(self::MEMBER, $sent['to']);
        }
    }

    public function testTheStoredTokenIsAHashAndTheMailCarriesTheCode(): void
    {
        // A database dump must not yield a usable code.
        WpState::$userCan = true;
        $_POST['member_email'] = self::MEMBER;

        $this->page()->sendResetCodeFromRequest();
        $this->mailer->flush();

        $stored = $this->credentials->rows[self::MEMBER]->resetTokenHash;
        $body = (string) WpState::$mail[0]['message'];

        self::assertSame(64, strlen($stored), 'The stored token must be a SHA-256 hex digest.');
        self::assertStringNotContainsString($stored, $body);
    }

    public function testAnAddressNoMemberHoldsIsSaidSoPlainly(): void
    {
        // Deliberately unlike the REST endpoint, which must not reveal
        // this. See the class docblock.
        WpState::$userCan = true;
        $_POST['member_email'] = 'nobody@example.org';

        self::assertSame('code_not_a_member', $this->page()->sendResetCodeFromRequest());
        self::assertSame([], $this->credentials->rows);
    }

    public function testSomethingThatIsNotAnAddressIsRefused(): void
    {
        WpState::$userCan = true;
        $_POST['member_email'] = 'not an address';

        self::assertSame('code_bad_address', $this->page()->sendResetCodeFromRequest());
    }

    public function testAnEmptyFieldIsRefused(): void
    {
        WpState::$userCan = true;
        $_POST['member_email'] = '';

        self::assertSame('code_bad_address', $this->page()->sendResetCodeFromRequest());
    }

    public function testTheAddressIsMatchedWithoutRegardToCase(): void
    {
        // Whoever is typing it is reading it off a membership record, not
        // copying it from the database.
        WpState::$userCan = true;
        $_POST['member_email'] = 'Member@Example.ORG';

        self::assertSame('code_sent', $this->page()->sendResetCodeFromRequest());
    }

    public function testAsecondAttemptInsideTheCooldownSaysSoRatherThanLying(): void
    {
        // The reason beginReset now answers a bool. Before it did, this
        // path returned success and sent nothing — a button somebody
        // presses four more times.
        WpState::$userCan = true;
        $_POST['member_email'] = self::MEMBER;

        self::assertSame('code_sent', $this->page()->sendResetCodeFromRequest());
        self::assertSame('code_too_soon', $this->page()->sendResetCodeFromRequest());
    }

    public function testSendingACodeIsAudited(): void
    {
        // An admin acting on a member's ability to sign in is exactly
        // what the audit log is for.
        WpState::$userCan = true;
        $_POST['member_email'] = self::MEMBER;

        $this->page()->sendResetCodeFromRequest();

        self::assertNotEmpty($this->audit->entries);
    }

    public function testARefusedAttemptIsNotAudited(): void
    {
        // Otherwise the log fills with entries for things that did not
        // happen, and the ones that did become harder to find.
        WpState::$userCan = true;
        $_POST['member_email'] = 'nobody@example.org';

        $this->page()->sendResetCodeFromRequest();

        self::assertSame([], $this->audit->entries);
    }

    public function testAnAdminWithoutTheCapabilityIsRefused(): void
    {
        // wp_die() throws under the test doubles, which is what makes the
        // guard assertable at all — the handler otherwise ends in a
        // redirect and an exit.
        WpState::$userCan = false;

        $this->expectException(WpDieException::class);

        $this->page()->handleSendResetCode();
    }

    private function page(): DevicesPage
    {
        $gate = new MemberGate($this->members);

        return new DevicesPage(
            new InMemoryDeviceRepository(),
            $this->members,
            $this->audit,
            new PasswordAuthenticator($this->credentials, $gate, $this->mailer, new PasswordPolicy()),
            $gate,
        );
    }
}
