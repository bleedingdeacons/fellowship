# Fellowship

[![CI](https://github.com/bleedingdeacons/fellowship/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/bleedingdeacons/fellowship/actions/workflows/ci.yml)
[![Semgrep](https://github.com/bleedingdeacons/fellowship/actions/workflows/semgrep.yml/badge.svg?branch=main)](https://github.com/bleedingdeacons/fellowship/actions/workflows/semgrep.yml)
[![Coverage Status](https://coveralls.io/repos/github/bleedingdeacons/fellowship/badge.svg?branch=main)](https://coveralls.io/github/bleedingdeacons/fellowship?branch=main)
![PHPStan](https://img.shields.io/badge/dynamic/yaml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbleedingdeacons%2Ffellowship%2Fmain%2Fphpstan.neon.dist&query=%24.parameters.level&label=PHPStan&prefix=level%20&color=brightgreen)
![PHPCS](https://img.shields.io/badge/dynamic/xml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbleedingdeacons%2Ffellowship%2Fmain%2F.phpcs.xml.dist&query=%2Fruleset%2Frule%5B1%5D%2F%40ref&label=PHPCS&color=brightgreen)
![Version](https://img.shields.io/badge/version-1.0.2-blue)

The WordPress half of a messaging system for an AA intergroup. The other
half is [Link](https://github.com/bleedingdeacons/link), a .NET MAUI app
for Android and iOS.

Fellowship holds the messages and pushes them. Link reads them.

It is built on **Unity** for member and committee data and **Scrutiny**
for GDPR audit logging, and it is deliberately shaped like
**Reach**/**Hand** — the same suite's helpline alerting pair — because
that pair already solved device enrolment, sealed push payloads and
device revocation, and there was nothing to gain from solving them
differently.

## What it does

A member installs Link and signs in with Google or Apple. Fellowship
verifies the ID token against the provider's published keys, looks the
verified address up in Unity, and enrols the handset only if the address
belongs to a member. OAuth proves the person controls an address; Unity
decides whether that address is a member's. Neither half is sufficient
alone, which is why enrolment needs both.

At the same moment the handset generates a keypair in its platform
keystore and sends the public half. The private half never leaves the
device.

Messages are addressed to named members or to a whole committee, from the
app or from WordPress admin, and can be replied to.

## The encryption, stated precisely

**Fellowship can read your messages.** They are stored in plain text in
`wp_fellowship_messages`. This is not end-to-end encryption and must not
be described as such.

That was a decision, not an oversight. Server-readable bodies are what
make three things possible: an admin composing to a committee, the
message log, and Scrutiny auditing what was sent to whom. True
end-to-end would have cost all three, and would additionally have meant
that a lost phone loses a member's whole history with no recovery.

**What the server does not hold is any handset's private key.** It is
generated on the device at enrolment and only the public half is sent, so
a payload Fellowship sealed and pushed yesterday is one it cannot open
today — not with the database, and not with `wp-config.php` either. That
is the one respect in which this is stronger than Reach, which issues its
handsets a symmetric key and keeps a copy.

What the encryption buys is that a message is unreadable everywhere
between this server and the handset it is addressed to:

| Where | Protected by |
| --- | --- |
| Browser/app to server | HTTPS, enforced — every route refuses a plaintext request |
| Server at rest | Ordinary database protection, plus a retention window |
| Server to Google to handset | Sealed to that handset's own public key |
| Notification tray / lock screen | Nothing readable is there — the tray shows "New message" |

Because the retention window is the only thing limiting how long
readable personal data accumulates, it is a real control rather than
housekeeping. It defaults to 180 days.

### How a message is sealed

RSA-2048 with OAEP encrypts 214 bytes — less than one paragraph — so the
scheme is hybrid:

1. A fresh 32-byte content key per message per device.
2. The payload JSON is gzipped, then sealed with AES-256-GCM under that
   key. Envelope: 12-byte nonce, 16-byte tag, ciphertext, base64. Field
   `p`.
3. The content key is encrypted to the device's public key with RSA-OAEP,
   base64. Field `k`.

A fresh key every time is not caution for its own sake: GCM fails
catastrophically if a key and nonce are ever reused, and the surest way
never to reuse one is never to keep one.

**OAEP uses SHA-1, deliberately.** PHP's `openssl_public_encrypt()` with
`OPENSSL_PKCS1_OAEP_PADDING` uses SHA-1 for the OAEP hash and MGF1, with
no way to request SHA-256 through the API PHP exposes. Link matches it
with `RSAEncryptionPadding.OaepSHA1`. SHA-1's collision weakness is a
*signature* problem; OAEP relies on preimage resistance, which is intact.
Choosing SHA-256 here and finding the mismatch on a handset — where the
symptom is a message that arrives and will not open — is the more
expensive mistake.

The gzip is load-bearing. FCM caps a data message at 4KB and the wrapped
key alone is 344 base64 characters of it. `MessageRequest`'s caps are
what make the worst case a known quantity, and
`MessageSealerTest::testTheWorstCasePayloadTheApiAcceptsFitsInsideAnFcmDataMessage`
is what will tell you if a new field breaks it.

**Everything is inside the envelope** — subject, body, sender, id.
Nothing travels beside it for the handset to read first, because it does
not need anything first: it holds one key, it opens one blob, and what is
inside tells it what it has. Reach arrived at this the hard way, having
once left the alert id and priority in the clear.

### How that is actually verified

The format is written out twice on purpose, and **each side's test does
the other side's job**. `MessageSealerTest` here generates a keypair,
seals with the shipping sealer, and then opens the envelope in PHP the
way the app opens one. In the Link solution, `Sealing.cs` is this sealer
transcribed into C# and `MessagePayloadCipherTests` opens what it
produces with the shipping cipher. Drift on either side turns the test on
the opposite side red.

No fixture is committed, and that is deliberate: a fixture would have to
carry the private key that opens it, and a private key in a public
repository is what push protection blocks and Semgrep flags.

## Push is the fast path, not the reliable one

Every message is stored before any push is attempted, and Link polls as
well as listening. A phone in a tunnel catches up when it surfaces; a
handset whose FCM token silently rotated still gets its messages; a site
with no Firebase service account configured still delivers everything.

The polling route returns the *same sealed envelope* the push carries,
rather than plain JSON over TLS. It would have been easy to do the
latter — but then one message exists in two forms and the app needs two
readers, and how a message arrived becomes something the app has to care
about.

## Identity, and what the app never learns

The directory Link shows when composing contains **anonymous names and
opaque member ids**. No email addresses, no telephone numbers. A member
picks a recipient and Fellowship does the addressing server-side, so a
stolen handset yields a list of first names rather than the intergroup's
contact database — and a message cannot be addressed to a non-member by
inventing an address.

Members who have turned off `showMemberProfile()` in Unity are not
listed. They can still receive a committee message: being contactable by
the intergroup is not the same as being browsable by everyone.

`MemberGate` is the single answer to "may this person use Link?",
consulted at enrolment, on every authenticated request, when resolving an
audience, and when fanning out a push. One object rather than a rule
written out four times, because a gate that disagreed with itself between
enrolment and delivery would enrol people who never receive anything.

The gate is deliberately thin — a Unity member with a valid personal
email. Link is the fellowship's address book, not a privileged tool.

## Revoke and remove are different

*Revoke* is the answer to a lost phone: the token stops working
immediately — the repository's lookup refuses revoked rows, so it is
indistinguishable from an unknown token — and the row stays, so the
Devices screen can still show the device existed and when it was cut off.

*Remove* deletes the row. It is for test enrolments and erasure requests,
and it destroys the evidence the device ever existed. It is offered
second and confirmed, because revoke is almost always what was meant.

A handset can also revoke itself, which is what signing out does.

## Replacing a key, and the key-fault report

A platform invalidates a keystore entry for reasons that have nothing to
do with this app: the screen lock changed, a backup was restored,
biometrics were re-enrolled. Making that a full re-enrolment would cost
the member their place in the device list and tell them nothing useful,
so `POST /auth/device/key` lets a handset present a new public key and
keep its row.

**Messages already sent stay unreadable, and here that is a fact rather
than a policy.** They were sealed to content keys wrapped to the old
public key, and this server never held the private half — so it could not
re-seal them if it wanted to. The app clears what it cannot open.

`POST /auth/device/key-fault` is the handset saying it cannot open its
messages. It has to be reported rather than inferred: from the server a
handset with a lost private key looks perfectly healthy right up until a
message it cannot read. The Devices screen shows it in red.

## REST API

Everything is under `fellowship/v1` and everything requires HTTPS.

| Route | Auth | What |
| --- | --- | --- |
| `GET /auth/device/start` | none | Begin sign-in. Answers an authorization URL (Google) or a nonce (Apple). |
| `GET /auth/callback` | none | Browser leg. Redirects into the app with a one-time code. |
| `POST /auth/device/exchange` | none | Register the public key, mint the device token. |
| `POST /auth/device/push` | device | Update the FCM registration token. |
| `POST /auth/device/key` | device | Present a replacement public key. |
| `POST /auth/device/key-fault` | device | "I cannot open my messages." |
| `GET /auth/device/session` | device | Who am I. |
| `DELETE /auth/device` | device | Sign out (self-revoke). |
| `GET /messages?since=&limit=` | device | Sealed inbox, paged by message id. |
| `POST /messages` | device | Send. |
| `POST /messages/{id}/read` | device | Mark read. |
| `GET /directory` | device | Address book. |

Two sign-in flows meet at one exchange:

**Google (server-side).** `start` → browser → `callback` exchanges the
authorization code with Google, verifies the ID token, and redirects to
`link://auth?code=…` with a one-time device code → `exchange` spends it.
The browser is never trusted with the device token itself: it would land
in browser history, in any redirect logging in between, and in the app's
launch intent. The code is worthless two minutes later and worthless once
used.

**Apple (client-side).** `start` → the app runs the platform sheet with
the nonce it was given → `exchange` with the state and the ID token.
There is no browser leg and no client secret.

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

Address with `committee` (slug or id), `member_emails`, or neither for
everyone. Returns the message id or a `WP_Error`. There is an action form
too, `fellowship/send_message`, for callers that would rather not depend
on a function existing.

Unlike Reach's alerting API this one is **not** lock-screen constrained.
Alerts may carry no personal data because their text lands on a lock
screen; message bodies are sealed and never appear in a notification, so
a message may carry ordinary fellowship business.

## Conventions

`declare(strict_types=1)`, a namespaced `Fellowship\` PSR-4 autoloader, a
`FELLOWSHIP_KILL` kill switch, and a `fellowship/loaded` action. It
registers into Unity's container on `unity/loaded` and has no container
of its own, like Trumpet and Promises.

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
