<?php

declare(strict_types=1);

namespace Fellowship\Sync;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Core\Settings;
use Fellowship\Firebase\FirebaseUnavailable;
use Fellowship\Firebase\FirestoreClient;
use Fellowship\Logger\HasLogger;

/**
 * Tells Firebase how long to keep messages, which is set on the settings screen.
 *
 * The `sweep` Function reads `config/messaging`, and treats no value as keep for
 * ever. So this runs on saving and again every day: a save that couldn't reach
 * Firebase corrects itself, and a new project gets its value without anyone saving.
 */
final class RetentionSync
{
    use HasLogger;

    public const DOCUMENT = 'config/messaging';

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    public function __construct(
        private readonly Settings $settings,
        private readonly FirestoreClient $firestore,
    ) {
    }

    /** True when Firebase now has the value. Never throws: see the class remarks. */
    public function push(): bool
    {
        if (!$this->firestore->isConfigured()) {
            return false;
        }

        try {
            $this->firestore->setIntegers(self::DOCUMENT, ['retentionDays' => $this->settings->getRetentionDays()]);

            return true;
        } catch (FirebaseUnavailable) {
            self::logWarning('The retention setting could not be sent to Firebase; the daily check will try again');

            return false;
        }
    }
}
