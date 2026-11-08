<?php

declare(strict_types=1);

namespace Fellowship\Messaging;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Core\Settings;
use WP_Error;

/**
 * Who a message reaches, as member ids, under the rules for who may address whom.
 *
 * For a phone. Only members send from one, which the device check has already
 * settled. The whole fellowship isn't a phone's to address, and committees and all
 * GSRs need the site's permission. The Compose screen and other plugins hold the
 * capability those rules exist to protect, so {@see MessageApi} goes straight to
 * {@see RecipientResolver::audienceOf()}.
 *
 * <b>Naming nobody is refused, never read as everyone.</b> In {@see MessageRequest}
 * an empty audience means everyone, so names that all turn out stale must not fall
 * through to it. Everyone has to be asked for, and only {@see MessageApi} can.
 *
 * The sender is left out, as every send leaves them out.
 */
final class AudienceResolver
{
    public function __construct(
        private readonly RecipientResolver $resolver,
        private readonly Settings $settings,
    ) {
    }

    /**
     * @param mixed $memberIds  Ids from the directory the phone was given.
     * @param mixed $committees Committee slugs.
     * @param mixed $gsrs       Whether to reach every GSR.
     */
    public function fromHandset(
        string $senderEmail,
        mixed $memberIds,
        mixed $committees,
        mixed $gsrs,
        mixed $everyone = false,
    ): ResolvedAudience|WP_Error {
        $committees = is_array($committees) ? $committees : [];
        $wantsGsrs = $gsrs !== null && $gsrs !== false && $gsrs !== '' && $gsrs !== 0 && $gsrs !== '0';
        $wantsPart = $committees !== [] || $wantsGsrs;

        if ($wantsPart && !$this->settings->allowsCommitteeSendFromApp()) {
            return new WP_Error(
                'fellowship_committee_send_disabled',
                'Sending to a committee or to all GSRs from the app is not enabled on this site.',
                ['status' => 403],
            );
        }

        // A phone may not address the whole fellowship.
        if (filter_var($everyone, FILTER_VALIDATE_BOOLEAN)) {
            return self::noAudience();
        }

        $named = is_array($memberIds) && $memberIds !== [];
        $emails = $this->resolver->emailsForIds($memberIds);

        if ($named && $emails === [] && !$wantsPart) {
            return RecipientResolver::noRecipients();
        }

        $built = MessageRequest::forAudience([
            'committees'    => $committees,
            'gsrs'          => $wantsGsrs,
            'member_emails' => $emails,
        ]);
        if ($built instanceof WP_Error) {
            return $built;
        }

        // Also catches a committee list that normalised away to nothing.
        if ($built->audienceType === Message::AUDIENCE_ALL) {
            return self::noAudience();
        }

        return $this->resolver->audienceOf($built, $senderEmail);
    }

    private static function noAudience(): WP_Error
    {
        return new WP_Error('fellowship_no_audience', 'Choose who this message is for.', ['status' => 400]);
    }
}
