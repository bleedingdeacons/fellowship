<?php

declare(strict_types=1);

namespace Fellowship\Tests;

use BleedingDeacons\WpMocks\TestCase;
use BleedingDeacons\WpMocks\WpState;
use Fellowship\Core\Settings;

/**
 * What the settings screen stores, and where.
 *
 * <b>The split between the two options rows is the point.</b> Client ids,
 * the retention window and the committee-send flag live in
 * `fellowship_settings`; client secrets and the Firebase service account
 * live encrypted in `fellowship_secrets`. That makes "is this safe to
 * show?" a property of where the value lives rather than of who
 * remembered — and it is asserted here by reading the raw options back
 * and checking a secret is not in the public one.
 *
 * @covers \Fellowship\Core\Settings
 */
final class SettingsTest extends TestCase
{
    private Settings $settings;

    protected function setUp(): void
    {
        parent::setUp();

        $this->settings = new Settings();
    }

    public function testAClientIdRoundTrips(): void
    {
        $this->settings->setClientId('google', 'google-client-id');

        self::assertSame('google-client-id', $this->settings->getClientId('google'));
    }

    public function testAnUnsetClientIdIsEmptyRatherThanNull(): void
    {
        // Every caller concatenates or compares it; a null would be a
        // deprecation at best and a wrong comparison at worst.
        self::assertSame('', $this->settings->getClientId('google'));
    }

    public function testProvidersDoNotShareAClientId(): void
    {
        $this->settings->setClientId('google', 'google-client-id');
        $this->settings->setClientId('microsoft', 'ms-client-id');

        self::assertSame('google-client-id', $this->settings->getClientId('google'));
        self::assertSame('ms-client-id', $this->settings->getClientId('microsoft'));
    }

    public function testAClientSecretRoundTrips(): void
    {
        $this->settings->setClientSecret('google', 'a-client-secret');

        self::assertSame('a-client-secret', $this->settings->getClientSecret('google'));
    }

    public function testASecretIsNeverStoredInThePublicRow(): void
    {
        // The row that anything reading options might reasonably print.
        $this->settings->setClientSecret('google', 'a-client-secret');

        $public = (string) json_encode(WpState::$options[Settings::OPTION_PUBLIC] ?? []);

        self::assertStringNotContainsString('a-client-secret', $public);
    }

    public function testASecretIsNotStoredInTheClear(): void
    {
        $this->settings->setClientSecret('google', 'a-client-secret');

        $secrets = (string) json_encode(WpState::$options[Settings::OPTION_SECRETS] ?? []);

        self::assertStringNotContainsString('a-client-secret', $secrets);
    }

    public function testClearingASecretLeavesNothingBehind(): void
    {
        $this->settings->setClientSecret('google', 'a-client-secret');
        $this->settings->setClientSecret('google', '');

        self::assertSame('', $this->settings->getClientSecret('google'));
    }

    public function testTheServiceAccountIsHeldWithTheSecrets(): void
    {
        // It can push to every handset on the project. It is the most
        // dangerous single value this plugin stores.
        $this->settings->setFcmServiceAccount('{"project_id":"x"}');

        $public = (string) json_encode(WpState::$options[Settings::OPTION_PUBLIC] ?? []);

        self::assertSame('{"project_id":"x"}', $this->settings->getFcmServiceAccount());
        self::assertStringNotContainsString('project_id', $public);
    }

    public function testRetentionDefaultsToTheDocumentedWindow(): void
    {
        self::assertSame(Settings::DEFAULT_RETENTION_DAYS, $this->settings->getRetentionDays());
    }

    public function testRetentionCanBeSetToKeepIndefinitely(): void
    {
        // Zero is a deliberate choice on the settings screen, not an
        // unset value, and the sweep reads it as "do nothing".
        $this->settings->setRetentionDays(0);

        self::assertSame(0, $this->settings->getRetentionDays());
    }

    public function testANegativeRetentionIsNotStoredAsNegative(): void
    {
        // A negative window would make the sweep's cut-off a time in the
        // future, which deletes everything.
        $this->settings->setRetentionDays(-30);

        self::assertGreaterThanOrEqual(0, $this->settings->getRetentionDays());
    }

    public function testCommitteeSendingFromTheAppIsOffUntilItIsTurnedOn(): void
    {
        // A handset writing to a whole committee is a decision the
        // intergroup makes, not a default it inherits.
        self::assertFalse($this->settings->allowsCommitteeSendFromApp());

        $this->settings->setCommitteeSendFromApp(true);

        self::assertTrue($this->settings->allowsCommitteeSendFromApp());
    }
}
