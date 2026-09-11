<?php

declare(strict_types=1);

namespace Fellowship\Cli;

if (!defined('ABSPATH')) {
    exit;
}

use Fellowship\Core\Settings;
use Fellowship\Directory\DirectoryPresenter;
use WP_CLI;
use WP_CLI_Command;
use WP_CLI\Utils;

/**
 * Show the address book Link is given.
 *
 * <b>Why this exists.</b> The directory is only visible inside an enrolled
 * handset, so "what is actually in it?" was a question that needed a phone
 * to answer. That is a slow loop for what is usually a data question, and
 * it was hit for real on the test bed where the member list came back
 * empty with nothing to say why.
 *
 * <b>It prints what the app is sent and nothing else.</b> The output is
 * {@see DirectoryPresenter::forApp()} verbatim — the same array, from the
 * same call the REST controller makes. No second opinion about who ought
 * to be in it: a diagnostic that decided for itself would eventually
 * disagree with the thing it claims to describe, and be believed.
 *
 * ## EXAMPLES
 *
 *     wp fellowship directory
 *     wp fellowship directory --committees
 *     wp fellowship directory --format=json
 */
final class DirectoryCli extends WP_CLI_Command
{
    public function __construct(
        private readonly DirectoryPresenter $presenter,
        private readonly Settings $settings,
    ) {
    }

    /**
     * Print the members, and optionally the committees, Link would receive.
     *
     * ## OPTIONS
     *
     * [--committees]
     * : Also print the committees.
     *
     * [--format=<format>]
     * : Output format. Accepts table, json, csv, yaml, count. Default: table.
     *
     * ## EXAMPLES
     *
     *     wp fellowship directory
     *     wp fellowship directory --format=json --committees
     *
     * @param array<int, string>    $args      Positional arguments, unused.
     * @param array<string, string> $assocArgs Flags, as WP-CLI parsed them.
     */
    public function __invoke(array $args, array $assocArgs = []): void
    {
        unset($args);

        $format = (string) Utils\get_flag_value($assocArgs, 'format', 'table');
        $wantsCommittees = (bool) Utils\get_flag_value($assocArgs, 'committees', false);

        // Asked for what the site actually allows rather than forced on,
        // so this is the handset's view and not an idealised one: a site
        // with committee sends off is sent no committees at all.
        $allowed = $this->settings->allowsCommitteeSendFromApp();
        $directory = $this->presenter->forApp($wantsCommittees && $allowed);

        // One path for every format. format_items prints rather than
        // returns, and it is left to do the printing: wrapping it in echo
        // outputs the table and then echoes its null return, which happens
        // to look right and is not.
        //
        // Members and committees print as two collections in every format,
        // so --format=json gives two documents rather than one nested one.
        // Worth knowing before piping it, and the honest shape of "here
        // are two lists".

        $members = $directory['members'];

        if ($members === []) {
            // Said out loud, because an empty table reads as a broken
            // command. A member appears only with a usable personal email,
            // a shown profile and an anonymous name; which of those is
            // missing is a question for Unity, and this deliberately does
            // not guess.
            WP_CLI::warning('The directory has no members. Link would show an empty list.');
        } else {
            Utils\format_items($format, $members, ['id', 'name', 'group', 'gsr', 'position']);
        }

        if (!$wantsCommittees) {
            return;
        }

        if (!$allowed) {
            WP_CLI::log('');
            WP_CLI::warning('Committee sends are off for this site, so no committees are sent.');
            return;
        }

        WP_CLI::log('');
        Utils\format_items($format, $directory['committees'], ['slug', 'name', 'parent']);
    }
}
