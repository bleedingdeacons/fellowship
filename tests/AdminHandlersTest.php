<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\Exceptions\WpDieException;
use BleedingDeacons\WpMocks\TestCase;
use BleedingDeacons\WpMocks\WpState;
use Brain\Monkey\Functions;
use Fellowship\Admin\DevicesPage;
use Fellowship\Admin\SettingsPage;
use Fellowship\Auth\PasswordAuthenticator;
use Fellowship\Auth\PasswordPolicy;
use Fellowship\Auth\PasswordResetMailer;
use Fellowship\Core\Schema;
use Fellowship\Core\Settings;
use Fellowship\Devices\MemberGate;
use Fellowship\Tests\Support\InMemoryDeviceRepository;
use Fellowship\Tests\Support\InMemoryPasswordCredentialRepository;
use Fellowship\Tests\Support\RecordingWpdb;
use Scrutiny\Testing\Doubles\SpyAuditLogger;
use Unity\Testing\Doubles\InMemoryMemberRepository;
use Unity\Testing\Doubles\MemberStub;

/**
 * What the admin POST handlers actually do, and the schema installer.
 *
 * <b>Revoking is the one that has to work.</b> It is how a lost or stolen
 * handset is cut off, and the effect is immediate and total: every lookup
 * that could authenticate carries `revoked_at IS NULL`, so the device
 * stops being found rather than being found and rejected.
 *
 * <b>Removing is not a tidier revoke.</b> It deletes the row, so it is
 * done second and only after the revoke has already landed — the other
 * order would leave a working credential behind on a failed delete.
 *
 * The service account is parsed before it is stored, because a setting
 * that looks saved and pushes nothing is the worst of both, and the
 * moment to find out is while somebody is looking at the screen.
 *
 * @covers \Fellowship\Admin\DevicesPage
 * @covers \Fellowship\Admin\SettingsPage
 * @covers \Fellowship\Core\Schema
 */
final class AdminHandlersTest extends TestCase
{
    private const MEMBER = 'member@example.org';

    private InMemoryDeviceRepository $devices;
    private InMemoryMemberRepository $members;
    private SpyAuditLogger $audit;

    protected function setUp(): void
    {
        parent::setUp();

        $_POST = [];
        WpState::$userCan = true;

        Functions\when('get_current_user_id')->justReturn(3);
        Functions\when('check_admin_referer')->justReturn(true);
        Functions\when('rest_url')->alias(static fn(string $p = ''): string => 'https://example.org/wp-json/' . $p);

        $this->devices = new InMemoryDeviceRepository();
        $this->audit = new SpyAuditLogger();

        $this->members = new InMemoryMemberRepository([
            new MemberStub(id: 7, anonymousName: 'Dave P', personalEmail: self::MEMBER),
        ]);
    }

    // ── Cutting a handset off ─────────────────────────────────────────

    public function testRevokingCutsTheHandsetOff(): void
    {
        $this->enrol();
        $_POST['device'] = '1';

        self::assertSame('revoked', $this->devicesPage()->revokeFromRequest());
        self::assertTrue($this->devices->rows[1]->isRevoked());
    }

    public function testARevokedHandsetCanNoLongerBeFoundByItsToken(): void
    {
        // Which is the whole mechanism: it is refused because it is not
        // there, not because something downstream checks a flag.
        $this->enrol();
        $_POST['device'] = '1';

        $this->devicesPage()->revokeFromRequest();

        self::assertNull($this->devices->findByTokenHash('hash-1'));
    }

    public function testRevokingIsAudited(): void
    {
        $this->enrol();
        $_POST['device'] = '1';

        $this->devicesPage()->revokeFromRequest();

        self::assertNotEmpty($this->audit->entries);
    }

    public function testRevokingSomethingAlreadyRevokedWritesNoSecondEntry(): void
    {
        // Otherwise the log gains an entry for a revocation that did not
        // happen, which makes the ones that did harder to find.
        $this->enrol();
        $_POST['device'] = '1';

        $this->devicesPage()->revokeFromRequest();
        $first = count($this->audit->entries);

        $this->devicesPage()->revokeFromRequest();

        self::assertCount($first, $this->audit->entries);
    }

    public function testRemovingRevokesFirstAndThenDeletes(): void
    {
        // The order matters: if the delete fails the handset is still cut
        // off, which is the half that counts. The other way round leaves
        // a working credential behind.
        $this->enrol();
        $_POST['device'] = '1';

        self::assertSame('removed', $this->devicesPage()->removeFromRequest());
        self::assertSame([], $this->devices->rows);
    }

    public function testADeviceIdThatIsNotAnIdIsRefused(): void
    {
        // Validated rather than cast: "12abc" must not quietly become 12,
        // because the value goes into the nonce action name.
        $this->enrol();
        $_POST['device'] = '1abc';

        $this->expectException(WpDieException::class);

        $this->devicesPage()->revokeFromRequest();
    }

    public function testNamingNoDeviceIsRefused(): void
    {
        $this->expectException(WpDieException::class);

        $this->devicesPage()->revokeFromRequest();
    }

    // ── Saving settings ───────────────────────────────────────────────

    public function testTheProviderCredentialsAreSaved(): void
    {
        $settings = new Settings();
        $_POST['google_client_id'] = 'google-client-id';
        $_POST['microsoft_client_id'] = 'ms-client-id';
        $_POST['google_client_secret'] = 'a-secret';

        self::assertSame('saved', (new SettingsPage($settings))->saveFromRequest());
        self::assertSame('google-client-id', $settings->getClientId('google'));
        self::assertSame('ms-client-id', $settings->getClientId('microsoft'));
        self::assertSame('a-secret', $settings->getClientSecret('google'));
    }

    public function testAnEmptySecretFieldLeavesTheStoredOneAlone(): void
    {
        // The field is never populated with the stored value, so an empty
        // submission is the normal case for anyone editing something else
        // on the screen. Treating it as "clear" would wipe a secret every
        // time somebody changed the retention window.
        $settings = new Settings();
        $settings->setClientSecret('google', 'a-secret');

        $_POST['google_client_secret'] = '';

        (new SettingsPage($settings))->saveFromRequest();

        self::assertSame('a-secret', $settings->getClientSecret('google'));
    }

    public function testTheCheckboxIsHowASecretIsCleared(): void
    {
        $settings = new Settings();
        $settings->setClientSecret('google', 'a-secret');

        $_POST['clear_google_client_secret'] = '1';

        (new SettingsPage($settings))->saveFromRequest();

        self::assertSame('', $settings->getClientSecret('google'));
    }

    public function testAServiceAccountThatWillNotParseIsRefusedBeforeItIsStored(): void
    {
        // A setting that looks saved and pushes nothing is the worst of
        // both, and the moment to find out is while somebody is looking
        // at the screen.
        $settings = new Settings();
        $_POST['fcm_service_account'] = 'not json';

        self::assertSame('bad_service_account', (new SettingsPage($settings))->saveFromRequest());
        self::assertSame('', $settings->getFcmServiceAccount());
    }

    public function testAValidServiceAccountIsStored(): void
    {
        $settings = new Settings();
        $_POST['fcm_service_account'] = (string) wp_json_encode([
            'project_id' => 'intergroup-fellowship',
            'client_email' => 'pusher@example.iam.gserviceaccount.com',
            'private_key' => '-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----',
        ]);

        self::assertSame('saved', (new SettingsPage($settings))->saveFromRequest());
        self::assertStringContainsString('intergroup-fellowship', $settings->getFcmServiceAccount());
    }

    public function testTheRetentionWindowIsSaved(): void
    {
        $settings = new Settings();
        $_POST['retention_days'] = '90';

        (new SettingsPage($settings))->saveFromRequest();

        self::assertSame(90, $settings->getRetentionDays());
    }

    public function testCommitteeSendingIsOffWhenTheBoxIsUnticked(): void
    {
        // An unticked checkbox posts nothing at all, so "absent" has to
        // mean off rather than "leave as it was".
        $settings = new Settings();
        $settings->setCommitteeSendFromApp(true);

        (new SettingsPage($settings))->saveFromRequest();

        self::assertFalse($settings->allowsCommitteeSendFromApp());
    }

    // ── The schema ────────────────────────────────────────────────────

    public function testEveryTableIsInstalled(): void
    {
        $wpdb = new RecordingWpdb();

        Schema::install($wpdb);

        $sql = implode(' ', $GLOBALS['__fellowship_dbdelta'] ?? []);

        foreach (['devices', 'messages', 'recipients', 'credentials'] as $table) {
            self::assertStringContainsString('fellowship_' . $table, $sql, $table . ' was not installed.');
        }
    }

    public function testInstallingIsSkippedWhenTheSchemaIsCurrent(): void
    {
        // Runs from Plugin::init on every request, so the common path has
        // to be one option read and nothing else.
        WpState::$options[Schema::OPTION] = Schema::VERSION;
        $GLOBALS['__fellowship_dbdelta'] = [];

        Schema::ensureInstalled();

        self::assertSame([], $GLOBALS['__fellowship_dbdelta']);
    }

    // ── Fixtures ──────────────────────────────────────────────────────

    private function devicesPage(): DevicesPage
    {
        $gate = new MemberGate($this->members);

        return new DevicesPage(
            $this->devices,
            $this->members,
            $this->audit,
            new PasswordAuthenticator(
                new InMemoryPasswordCredentialRepository(),
                $gate,
                new PasswordResetMailer(),
                new PasswordPolicy(),
            ),
            $gate,
        );
    }

    private function enrol(): void
    {
        $this->devices->create(
            'hash-1',
            self::MEMBER,
            7,
            'Pixel 6a',
            'android',
            'spki',
            'fcm',
            'token-1',
            1788000000,
        );
    }
}
