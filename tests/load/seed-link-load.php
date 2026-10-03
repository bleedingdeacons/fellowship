<?php

/**
 * Seed (or remove) what the Link read-path JMeter plan needs.
 *
 *   wp eval-file wp-content/plugins/fellowship/tests/load/seed-link-load.php seed 50 /path/to/devices.csv
 *   wp eval-file wp-content/plugins/fellowship/tests/load/seed-link-load.php seed 50 /path/to/devices.csv 500
 *   wp eval-file wp-content/plugins/fellowship/tests/load/seed-link-load.php reset
 *   wp eval-file wp-content/plugins/fellowship/tests/load/seed-link-load.php cleanup
 *
 * `seed N CSV [M]` mints one device per member for up to N authorised Unity
 * members, all sharing one freshly generated RSA-2048 key, and writes M
 * messages (default 1) each addressed to every one of them. The messages are
 * written through the repositories, not MessageDispatcher, so nothing is
 * pushed to anyone. The CSV is
 * `token,email,member_id,message_id,first_message_id`, with a header row:
 * `message_id` is the newest seeded message, which the read-after-push
 * scenarios use, and `first_message_id` the oldest, where the catch-up
 * scenario starts. M of 500 fills the ten pages of fifty that one Link sync
 * walks; it writes N × M recipient rows one at a time, so expect it to take
 * a while.
 *
 * `reset` marks every seeded message unread and unreceived again between
 * runs.
 *
 * `cleanup` deletes the seeded devices, the messages and their recipient
 * rows.
 *
 * The members are real Unity members, because CurrentDevice refuses a token
 * whose member does not pass MemberGate. The seeded messages therefore sit
 * in their inboxes until cleanup, and any real handset of theirs enrolled
 * on this site will collect them on its next poll. Seed a local or test
 * site, never production, and clean up afterwards.
 */

declare(strict_types=1);

use Fellowship\Auth\DeviceTokenMinter;
use Fellowship\Crypto\DevicePublicKey;
use Fellowship\Devices\DeviceRepository;
use Fellowship\Devices\MemberGate;
use Fellowship\Messaging\Message;
use Fellowship\Messaging\MessageRepository;
use Fellowship\Messaging\RecipientRepository;
use Fellowship\Messaging\WpdbMessageRepository;
use Fellowship\Messaging\WpdbRecipientRepository;
use Unity\Members\Interfaces\MemberRepository;

if (!defined('ABSPATH') || !function_exists('unity')) {
    fwrite(STDERR, "Run this through wp eval-file on a site with Unity and Fellowship active.\n");
    exit(1);
}

const LOAD_SEED_OPTION = 'fellowship_load_test_seed';
const LOAD_SEED_LABEL = 'jmeter-load';

/**
 * About the length of an ordinary message, so the seal and the response
 * size are not flattered by a one-line body.
 */
const LOAD_SEED_BODY = 'Seeded by tests/load/seed-link-load.php for a load test, and removed again by its '
    . 'cleanup. Safe to ignore. This is padded to roughly the length of an ordinary message from '
    . 'the intergroup, so that what the server seals and sends back for each one is about the size '
    . 'it would be in use: a meeting change, a request for cover on the phones, or a reminder about '
    . 'the next business meeting and what is on its agenda.';

/** @var list<string> $args */
$args = $args ?? [];
$mode = $args[0] ?? '';

global $wpdb;
$container = unity();

// Checked rather than left to the container: it throws for an unregistered
// service, and under eval-file that exception vanishes without a word.
if (!$container->has(DeviceRepository::class)) {
    WP_CLI::error('Fellowship is not active on this site.');
}

/**
 * The seeded message ids, from either shape of the option: a list from
 * this version, or the single id an earlier seed wrote.
 *
 * @return list<int>
 */
$seededMessageIds = static function (mixed $seed): array {
    if (!is_array($seed)) {
        return [];
    }

    $ids = $seed['message_ids'] ?? [$seed['message_id'] ?? 0];

    return array_values(array_filter(array_map('intval', (array) $ids), static fn(int $id): bool => $id > 0));
};

/** "IN (%d,%d,…)" for a list of ids, prepared. */
$inList = static function (array $ids) use ($wpdb): string {
    $placeholders = implode(',', array_fill(0, count($ids), '%d'));

    return (string) $wpdb->prepare("({$placeholders})", ...$ids);
};

if ($mode === 'cleanup') {
    $seed = get_option(LOAD_SEED_OPTION);
    if (!is_array($seed)) {
        WP_CLI::success('Nothing seeded.');
        return;
    }

    $devices = $container->get(DeviceRepository::class);
    $removed = 0;
    foreach ((array) ($seed['device_ids'] ?? []) as $id) {
        $removed += $devices->remove((int) $id) ? 1 : 0;
    }

    $messageIds = $seededMessageIds($seed);
    if ($messageIds !== []) {
        $in = $inList($messageIds);
        $wpdb->query('DELETE FROM ' . WpdbRecipientRepository::tableName($wpdb) . " WHERE message_id IN {$in}");
        $wpdb->query('DELETE FROM ' . WpdbMessageRepository::tableName($wpdb) . " WHERE id IN {$in}");
    }

    delete_option(LOAD_SEED_OPTION);
    WP_CLI::success(sprintf('Removed %d device(s) and %d message(s).', $removed, count($messageIds)));
    return;
}

if ($mode === 'reset') {
    // Mark the seeded messages unread and unreceived again, so the next run
    // measures a first read rather than the already-read path, which costs
    // one more SELECT per mark-read.
    $messageIds = $seededMessageIds(get_option(LOAD_SEED_OPTION));
    if ($messageIds === []) {
        WP_CLI::error('Nothing seeded.');
    }

    $reset = $wpdb->query(
        'UPDATE ' . WpdbRecipientRepository::tableName($wpdb)
        . ' SET read_at = NULL, received_at = NULL WHERE message_id IN ' . $inList($messageIds),
    );
    WP_CLI::success(sprintf('Reset %d recipient row(s) on %d message(s).', (int) $reset, count($messageIds)));
    return;
}

if ($mode !== 'seed' || !isset($args[1], $args[2])) {
    WP_CLI::error('Usage: seed <members> <csv-path> [messages-per-member] | reset | cleanup');
}

if (get_option(LOAD_SEED_OPTION) !== false) {
    WP_CLI::error('Already seeded. Run cleanup first.');
}

$count = max(1, (int) $args[1]);
$csvPath = $args[2];
$perMember = max(1, (int) ($args[3] ?? 1));

$pair = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$details = $pair === false ? false : openssl_pkey_get_details($pair);
if ($details === false || !isset($details['key'])) {
    WP_CLI::error('Could not generate an RSA key. On Windows, check OPENSSL_CONF.');
}

$publicKey = DevicePublicKey::normalise($details['key']);
if ($publicKey === '') {
    WP_CLI::error('Fellowship refused the generated public key.');
}

/** @var MemberGate $gate */
$gate = $container->get(MemberGate::class);
$authorised = array_values(array_filter(
    $container->get(MemberRepository::class)->findAll(),
    static fn($member): bool => $gate->isAuthorised($member),
));
$members = array_slice($authorised, 0, $count);

if ($members === []) {
    WP_CLI::error('No Unity member has a usable personal email.');
}

$recipients = [];
foreach ($members as $member) {
    $recipients[] = [
        'email'     => strtolower(trim($member->getPersonalEmail())),
        'member_id' => $member->getId(),
    ];
}

/** @var MessageRepository $messages */
$messages = $container->get(MessageRepository::class);
/** @var RecipientRepository $recipientRepository */
$recipientRepository = $container->get(RecipientRepository::class);

$now = time();
$messageIds = [];
$progress = WP_CLI\Utils\make_progress_bar('Writing messages', $perMember);

for ($i = 1; $i <= $perMember; $i++) {
    // Oldest first, a minute apart, so created_at runs the same way as
    // the ids a catch-up pages through.
    $createdAt = $now - ($perMember - $i) * 60;

    $message = $messages->create(
        wp_generate_uuid4(),
        '',
        0,
        'JMeter',
        sprintf('[jmeter] load test %d of %d', $i, $perMember),
        LOAD_SEED_BODY,
        Message::AUDIENCE_MEMBERS,
        '',
        $createdAt,
        0,
        0,
    );

    $recipientRepository->addMany($message->id, $recipients, $createdAt);
    $messageIds[] = $message->id;
    $progress->tick();
}

$progress->finish();

// Recorded before the devices, so a failure part-way through still leaves
// cleanup something to find.
update_option(LOAD_SEED_OPTION, ['device_ids' => [], 'message_ids' => $messageIds], false);

/** @var DeviceRepository $devices */
$devices = $container->get(DeviceRepository::class);
/** @var DeviceTokenMinter $minter */
$minter = $container->get(DeviceTokenMinter::class);

$deviceIds = [];
$rows = ['token,email,member_id,message_id,first_message_id'];
$newest = max($messageIds);
$oldest = min($messageIds);

foreach ($recipients as $recipient) {
    $token = $minter->mint();
    $device = $devices->create(
        $minter->hash($token),
        $recipient['email'],
        $recipient['member_id'],
        LOAD_SEED_LABEL,
        'android',
        $publicKey,
        '',
        '',
        $now,
    );

    $deviceIds[] = $device->id;
    $rows[] = implode(',', [$token, $recipient['email'], $recipient['member_id'], $newest, $oldest]);
}

update_option(LOAD_SEED_OPTION, ['device_ids' => $deviceIds, 'message_ids' => $messageIds], false);

if (file_put_contents($csvPath, implode("\n", $rows) . "\n") === false) {
    WP_CLI::warning("Seeded, but could not write {$csvPath}. Run cleanup and try another path.");
    return;
}

// Kept beside the CSV so an envelope can be opened by hand if the
// response bodies ever need checking. Test material only.
openssl_pkey_export($pair, $privatePem);
file_put_contents($csvPath . '.key.pem', $privatePem);

WP_CLI::success(sprintf(
    'Seeded %d device(s) and %d message(s), ids %d to %d. Tokens in %s.',
    count($deviceIds),
    count($messageIds),
    $oldest,
    $newest,
    $csvPath,
));
