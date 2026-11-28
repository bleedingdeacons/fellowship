# Fellowship

[![CI](https://github.com/bleedingdeacons/fellowship/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/bleedingdeacons/fellowship/actions/workflows/ci.yml)
[![Semgrep](https://github.com/bleedingdeacons/fellowship/actions/workflows/semgrep.yml/badge.svg?branch=main)](https://github.com/bleedingdeacons/fellowship/actions/workflows/semgrep.yml)
[![Coverage Status](https://coveralls.io/repos/github/bleedingdeacons/fellowship/badge.svg?branch=main)](https://coveralls.io/github/bleedingdeacons/fellowship?branch=main)
![PHPStan](https://img.shields.io/badge/dynamic/yaml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbleedingdeacons%2Ffellowship%2Fmain%2Fphpstan.neon.dist&query=%24.parameters.level&label=PHPStan&prefix=level%20&color=brightgreen)
![PHPCS](https://img.shields.io/badge/dynamic/xml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbleedingdeacons%2Ffellowship%2Fmain%2F.phpcs.xml.dist&query=%2Fruleset%2Frule%5B1%5D%2F%40ref&label=PHPCS&color=brightgreen)
![Version](https://img.shields.io/badge/version-1.19.8-blue)
![PHP](https://img.shields.io/badge/php-8.1%2B-777bb4)
![Licence](https://img.shields.io/badge/licence-MIT%20(Modified)-green)

The WordPress half of a messaging system for an AA intergroup. The other
half is [Link](https://github.com/bleedingdeacons/link), a .NET MAUI app
for Android and iOS, and between them sits a Firebase project: Firestore,
Firebase Auth, FCM and a set of Cloud Functions, in [`firebase/`](firebase/README.md).

**Fellowship decides who may use Link; Firebase carries the messages.** The
member list stays in WordPress, in Unity, and never leaves it. Fellowship
answers the questions only it can, as short signed statements a phone carries
to the Functions: is this sign-in a member, and which members does this
message reach. It also runs Link's password sign-in, the admin screens
(Devices, Messages, Compose) and the member watch that cuts off devices whose
member has gone.

It is built on **Unity** for member and committee data and **Scrutiny**
for GDPR audit logging.

## What it does

A member installs Link and signs in: with Google or Apple through Firebase
Auth, or with a Unity password through `/auth/identity/password`, which
answers a Firebase custom token. The phone then asks `/attest/member` for a
statement that this sign-in is a member, generates a keypair in its platform
keystore, and enrols with the `enrol` Function, sending the statement and the
public half. The private half never leaves the device.

Messages are addressed to named members, a committee or the GSRs, from the
app or from WordPress admin. A phone asks `/attest/audience` who a message
reaches, gets their devices' public keys from the Functions, seals one
envelope per device and hands them to `sendMessage`. A message written in
WordPress admin is sealed here in the same way and sent through `adminSend`,
under the name of the member who wrote it when the WordPress user is one, so
a reply from the app goes back to them.

## The encryption, stated precisely

**Messages are end-to-end encrypted.** Each is sealed on the sending phone,
or in WordPress for an admin Compose, to each recipient device's public key.
Neither Fellowship nor Firebase holds a private key, so neither can read a
message. Compose sees the text only because somebody typed it there, and
doesn't keep it.

**Scrutiny records an admin send's subject, never its body.** An audit entry
saying only that a message reached eleven people can't answer the question it
exists to answer, *which* message. A subject is member-typed text and may
carry personal data, so it is treated as hostile: delimiters stripped,
newlines flattened, length capped. See `Messaging\AuditDetail`.

**Passwords are Unity's, not Fellowship's.** A member has one password, in
`wp_unity_credentials`. Unity declares the contract and tsml-for-unity
supplies the table.

### How a message is sealed

RSA-2048 with OAEP encrypts 214 bytes, so the scheme is hybrid:

1. A fresh 32-byte content key per message per device.
2. The payload JSON is gzipped, then sealed with AES-256-GCM under that
   key. Envelope: 12-byte nonce, 16-byte tag, ciphertext, base64. Field `p`.
3. The content key is encrypted to the device's public key with RSA-OAEP,
   base64. Field `k`.

**OAEP uses SHA-1, deliberately.** PHP's `openssl_public_encrypt()` with
`OPENSSL_PKCS1_OAEP_PADDING` uses SHA-1 for the OAEP hash and MGF1, and Link
matches it with `RSAEncryptionPadding.OaepSHA1`. SHA-1's collision weakness
is a signature problem; OAEP relies on preimage resistance, which is intact.

The gzip is load-bearing. FCM caps a data message at 4KB and the wrapped key
alone is 344 base64 characters of it. `MessageRequest`'s caps keep the worst
case a known size, and `MessageSealerTest` will tell you if a new field breaks
it. Everything is inside the envelope: subject, body, sender, id.

The format is written out twice on purpose, and **each side's test does the
other side's job**. `MessageSealerTest` here opens what the sealer produces
the way the app does; Link's `MessagePayloadCipherTests` opens what a C#
transcription of this sealer produces. Drift on either side turns the other
side's test red.

## Identity, and what the app never learns

The directory Link shows when composing (`GET /directory`, with a Firebase
ID token) contains **anonymous names, opaque member ids, a home group,
whether the member is a GSR, and whether they have Link**. No email
addresses, no telephone numbers, so a stolen handset yields a list of first
names rather than the intergroup's contact database.

Everybody the gate admits is listed, whether or not they use Link; a member
without a live device on Firebase is shown but can't be chosen.

`MemberGate` is the single answer to "may this person use Link?": a Unity
member with a usable personal email. It is consulted at sign-in, when a
statement is signed, when an audience is resolved, and by the member watch.

## Devices, revoking and removing

Devices live in Firestore. The Devices screen reads them there and acts
through the admin Functions:

- *Revoke* (`adminRevoke`) is the answer to a lost phone: the device stops
  working at once and its record stays.
- *Remove* (`adminRemove`) deletes the record and its inbox, for test
  enrolments and erasure requests.

The member watch (`Sync\MemberWatch`) removes a deleted member's devices at
once, and each day revokes the devices of anyone the gate now refuses, unless
that would be an implausible share of members. Signing out of Link revokes
that phone through the `signOut` Function.

## REST API

Everything is under `fellowship/v1` and everything requires HTTPS.

| Route | Auth | What |
| --- | --- | --- |
| `POST /auth/identity/password` | none | Check a Unity password and answer a five-minute Firebase custom token, uid `pw_<member id>`. Enrols nothing. |
| `POST /auth/password/request` | none | Email a set-or-reset code. Answers the same whoever the address belongs to. |
| `POST /auth/password/complete` | none | Set the password with that code. |
| `POST /attest/member` | a Firebase sign-in under five minutes old | Answers `attestation`: this sign-in is this member. For `enrol`, `replaceKey` and `takeOverDevice`. |
| `POST /attest/audience` | a live device's Firebase ID token | `memberIds`, `committees` or `gsrs`: answers `attestation`, the member ids the message reaches, sender left out. For `resolveAudience` and `sendMessage`. |
| `GET /directory` | a live device's Firebase ID token | Address book. |
| `GET /auth/callback` | none | The browser leg of another plugin's sign-in; see below. |

**Why the phone carries the answers.** The Functions need WordPress's answers
without holding a copy of the member list, and can't ask for them: SiteGround
challenges calls from Google Cloud's shared addresses. So the phone asks here
and carries the answer, as a JWT signed RS256 by the site's service account,
`aud` `fellowship-functions:<project>`, five minutes long, naming the sign-in
or device it was issued to. The Functions check it against that account's
public keys at Google.

Link's old WordPress back end is gone: its device routes, its `/messages`
routes, the tables they used and the push code behind them. Link signs in and
sends only through Firebase.

## Sending from another plugin

```php
if (function_exists('fellowship_send_message')) {
    $id = fellowship_send_message([
        'subject'   => 'Intergroup meeting moved',
        'body'      => 'September intergroup is now the 14th.',
        'committee' => 'public-information',
    ]);
}
```

Address with `committee` (slug or id), `member_ids` (the opaque ids the
directory hands Link), `member_emails`, or none of them for everyone.
`member_ids` that resolve to nobody are refused with
`fellowship_no_recipients` rather than dropped, since a request naming
nobody would be a send to everyone. Returns the message id or a
`WP_Error`. There is an action form
too, `fellowship/send_message`, for callers that would rather not depend
on a function existing.

Unlike Reach's alerting API this one is **not** lock-screen constrained.
Alerts may carry no personal data because their text lands on a lock
screen; message bodies are sealed and never appear in a notification, so
a message may carry ordinary fellowship business.

## Signing in on behalf of another plugin

*Added 2026-09-28, for Freedom.*

Another plugin can use this sign-in. It gets either a Google-verified
address or a live Link enrolment, through `Fellowship\Auth\IdentityBroker`,
which is in the container. There is no second copy of the OAuth classes,
and Google's console is unchanged: Fellowship's own HTTPS `/auth/callback`
is still the only registered redirect.

The browser leg's two rules, where a code may be redirected and who may have
one, belong to an **audience**, a `SignInAudience`. A plugin registers its own
on `fellowship/loaded`:

```php
add_action('fellowship/loaded', function ($container) {
    $container->get(\Fellowship\Auth\IdentityBroker::class)->registerAudience(new MyAudience());
});
```

`link` is reserved and serves nothing. It was Link's own browser sign-in,
which ended when Link moved to Firebase: a code for it would have gone to
whichever app on the phone claimed `link://`.

- **`begin($provider, $audience, $context, $redirectUri)`** starts the
  browser leg for that audience and answers `{state, authorization_url}`.
  `$context` is at most 512 bytes. It is the plugin's own opaque data, and
  it comes back when the code is redeemed.
- **At the callback**, the audience decides whether the redirect is
  allowed and whether this person is admitted.
- **`redeem($code, $audience)`** spends the one-time code. A code is
  issued for one audience and refused by every other. Presenting it at the
  wrong one still spends it.
- **`sessionFor($firebaseIdToken)`** accepts a live Link enrolment in
  place of a second sign-in. The device is checked live in Firestore and the
  member gate is re-run on it, so it proves what another trip through the
  browser would have.
- **`isLive($deviceId)`** lets the plugin stop the moment Link's enrolment
  stops.

A state or code stored without an audience was Link's, and is refused.

**An audience may bring its own OAuth client.** By default every browser
sign-in uses the one client in Fellowship's settings, so a Register tablet
signing in through Freedom was shown Link's Google consent screen. An
audience that also implements `BringsOwnClient` can name a client of its
own for a sign-in (`clientFor($provider, $context)`, null for Fellowship's).
Fellowship then uses it for that sign-in's authorization URL, its code
exchange and its ID-token audience check. It is asked at the start and
again at the callback with the same context. The registry is still the
permission model: a provider Fellowship did not register stays
unreachable, and anything doubtful falls back to Fellowship's own client.
Each such client registers Fellowship's callback,
`/wp-json/fellowship/v1/auth/callback`, as an authorized redirect URI.

**Must agree.** Freedom now depends on these classes. Changing any of
them changes a second plugin:

- `IdentityBroker`, `SignInAudience`, `BrokeredIdentity`, `LinkSession`,
  `VerifiedIdentity`
- `FirebaseDeviceLookup`, through which the broker finds a Link device, and
  `tests/Support/InMemoryFirebaseDevices`, which Freedom's tests stand one in
  with
- `BringsOwnClient` and `ProviderClient`, through which an audience signs
  its people in with its own OAuth client (see below)
- `MemberGate`
- `MessageSealer` and `DevicePublicKey`, whose envelope Freedom reuses
- `RateLimiter`

`IdentityBroker`'s constructor also takes Guardian's `ProviderRegistry`, which
Freedom's test harness builds. That makes Guardian's major version part of
this contract too: Fellowship and Freedom's `require-dev` move together.

`VerifiedIdentity` stayed Fellowship's own type when the providers moved to
Guardian, precisely because it is on this list: a provider's answer is
converted at the callback, and nothing an audience sees changed.

## Conventions

`declare(strict_types=1)`, a namespaced `Fellowship\` PSR-4 autoloader, a
`FELLOWSHIP_KILL` kill switch, and a `fellowship/loaded` action. It
registers into Unity's container on `unity/loaded` and has no container
of its own, like Trumpet and Promises.

The OAuth providers, the ID-token verifier and the sign-in state come from
the [Guardian](https://github.com/bleedingdeacons/guardian) library, which
Fellowship requires through Composer and ships in its own `vendor/`. Reach
bundles it too; whichever plugin loads it first supplies it to both, so the
two move to a new Guardian major together. What stays here is everything
Fellowship's own: the one-time codes, the audiences and the member gate.

## Link on Firebase

The Firestore rules and Cloud Functions are in [`firebase/`](firebase/README.md),
in this repo because they and the `/attest/*` routes have to agree. They are
not in the plugin zip.

## Version numbers

Releases went from 1.0.0 to 1.10.0, then 2.0.0 to 2.11.1, and on 2026-11-05
went back to the 1.x line at **1.11.0**. The system is still being evolved, so
changes ship as features rather than major versions. So:

- **The v2.x tags and releases are history, and older than v1.11.0.** A note
  elsewhere saying "Fellowship 2.8.0" means that release, not a version above
  the current one.
- **Do not use `feat!` or `BREAKING CHANGE`.** Either would produce 2.0.0, which
  already exists.
- **WordPress sees 1.11.0 as older than 2.11.1**, so a site on 2.x has to be
  moved on purpose. `/deploy` does this, once the 2.x zips are out of
  `C:\Data\Plugins`, because it installs the highest version it finds there.

## Development

```bash
composer install
composer test
composer phpstan
composer phpcs
```

PHPStan runs at **level 8 with no baseline** and scans `../unity/src`,
`../scrutiny/src` and `../sentinel/src` — CI checks those out alongside.
The test suite needs Unity and Scrutiny as sibling checkouts too
(`UNITY_PATH` and `SCRUTINY_PATH` override).

Tests are written in [Pest](https://pestphp.com) (running on PHPUnit).
Run them with `composer test`, not `vendor/bin/phpunit` — PHPUnit cannot
load Pest's closure-based files. `tests/Pest.php` names the files that
run on wp-mocks' TestCase (and so have Brain Monkey); a new
WordPress-coupled test file has to be added there.

On Windows, set `OPENSSL_CONF` before running the tests. The crypto
tests generate RSA keypairs, and `openssl_pkey_new()` reads that config —
without it, key generation fails and those tests skip rather than run,
which is exactly how fifty RSA tests elsewhere in this suite came to skip
unnoticed:

```bash
OPENSSL_CONF=C:/tools/php85/extras/ssl/openssl.cnf composer test
```

A merge to `main` is the release: the `release` job derives the version
level from conventional-commit prefixes, builds the zip and publishes a
GitHub Release. The prefix has to be in the **PR title**, because that is
what a squash merge keeps.
