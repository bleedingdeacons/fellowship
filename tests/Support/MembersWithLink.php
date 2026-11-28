<?php

declare(strict_types=1);

namespace Fellowship\Tests\Support;

use BleedingDeacons\WpMocks\WpState;
use Fellowship\Firebase\FirestoreClient;
use Fellowship\Firebase\GoogleTokens;
use Fellowship\Firebase\LiveMembers;
use Fellowship\Push\ServiceAccount;

/**
 * Who has a live Link device on Firebase, as the directory asks it, without
 * a request to Firestore.
 *
 * LiveMembers answers from its five-minute cache first, so the cache is
 * seeded with the given member ids and the client is merely configured.
 */
final class MembersWithLink
{
    public static function of(int ...$memberIds): LiveMembers
    {
        WpState::$transients['fellowship_firebase_live_members'] = array_fill_keys($memberIds, true);

        $account = ServiceAccount::fromJson((string) json_encode([
            'project_id'   => 'fellowship-test',
            'client_email' => 'site@fellowship-test.iam.gserviceaccount.com',
            'private_key'  => 'never used: the cache answers first',
        ]));

        return new LiveMembers(new FirestoreClient(static fn(): ?ServiceAccount => $account, new GoogleTokens()));
    }
}
