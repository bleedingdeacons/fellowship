<?php

declare(strict_types=1);

namespace Fellowship\Sync;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Core\Settings;
use Fellowship\Firebase\AdminFunctions;
use Fellowship\Firebase\FirebaseUnavailable;
use Fellowship\Logger\HasLogger;

/**
 * Tells Firebase how long to keep messages, which is set on the settings screen.
 *
 * The `sweep` Function reads `config/messaging`, and treats no value as keep for
 * ever. So this runs on saving and again every day: a save that couldn't reach
 * Firebase corrects itself, and a new project gets its value without anyone saving.
 *
 * It goes through `adminSetRetention`, because the site's service account can read
 * Firestore but not write it.
 */
final class RetentionSync
{
    use HasLogger;

    protected static function logChannel(): string
    {
        return 'fellowship';
    }

    public function __construct(
        private readonly Settings $settings,
        private readonly AdminFunctions $functions,
    ) {
    }

    /** True when Firebase now has the value. Never throws: see the class remarks. */
    public function push(): bool
    {
        if (!$this->functions->isConfigured()) {
            return false;
        }

        try {
            $this->functions->setRetention($this->settings->getRetentionDays());

            return true;
        } catch (FirebaseUnavailable) {
            self::logWarning('The retention setting could not be sent to Firebase; the daily check will try again');

            return false;
        }
    }
}
