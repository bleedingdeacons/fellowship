=== Fellowship ===
Contributors: thebleedingdeacons
Requires at least: 6.1
Tested up to: 6.7
Requires PHP: 8.1
Stable tag: 1.1.1
Build date: 2026/09/05 06:25:28
License: MIT (Modified)

Server side of the Link messaging app. Enrols handsets against Unity members by OAuth-verified email, exchanges a device public key, and delivers messages to individuals and committees as encrypted push notifications. Requires Unity and Scrutiny.

== Description ==

Fellowship is the WordPress half of a two-part messaging system. The other half is **Link**, a .NET MAUI app for Android and iOS.

A member installs Link and signs in with Google or Apple. Fellowship verifies the ID token, looks the address up in Unity, and enrols the handset only if it belongs to a member. At the same moment the handset generates a keypair in its platform keystore and sends the public half; the private half never leaves the device.

From then on, every message Fellowship sends that handset is sealed to that key. A fresh AES-256 content key per message, the body sealed under it with AES-256-GCM over gzip, the content key wrapped to the device with RSA-OAEP. What travels through Google's push infrastructure and lands in the notification tray is "New message" and nothing else.

Messages can be addressed to named members or to a whole committee, from the app or from the WordPress admin. Committees come from Unity and include their sub-committees.

**What the server can and cannot read.** Fellowship stores message bodies in plain text and can read them. That is deliberate: it is what makes committee broadcasts, the message log and GDPR audit possible. It is not end-to-end encryption and should not be described as such. What it does not hold is any handset's private key, so a payload it sealed and sent is one it cannot open afterwards — not even with the database and wp-config.php.

Every send and every directory read is audit-logged through Scrutiny.

== Installation ==

1. Install and activate Unity and Scrutiny first. Fellowship refuses to activate without them.
2. Activate Fellowship. Its tables are created on activation, and repaired on load if a later version adds one.
3. Under **Fellowship → Settings**, register the redirect URI shown there with your Google OAuth client, and paste in the client ID and secret.
4. Paste in a Firebase service-account JSON to enable push. Without it, messages are still delivered — handsets collect them on their next poll instead of being woken.
5. Decide whether members may send to a whole committee from the app. It is off by default.

== Frequently Asked Questions ==

= What happens if push is not configured? =

Messages are stored and delivered anyway. Link polls as well as listening, so push is the fast path rather than the reliable one. A phone in a tunnel catches up when it surfaces.

= A member has lost their phone. =

**Fellowship → Devices**, then Revoke. The token stops working immediately and the record of the device is kept. Remove deletes the row outright and is for tidying up test enrolments and erasure requests.

= A handset says it cannot read its messages. =

Its keystore entry has been invalidated — a changed screen lock, a restored backup, re-enrolled biometrics. Link reports this, the Devices screen shows it in red, and Settings presents a new public key without re-enrolling. Messages sent before that stay unreadable: they were sealed to a key that no longer exists anywhere, and this server never held the private half to re-seal them.

= Can I turn Fellowship off without deactivating it? =

Define `FELLOWSHIP_KILL` as true in wp-config.php. No routes, no admin pages, no push. Enrolled handsets are left alone.

== Changelog ==

= 1.0.0 =
* First release. Device enrolment by Google and Apple sign-in against Unity members, a per-device keypair exchanged at enrolment, hybrid-sealed push and poll delivery, messages to individuals and committees from the app and from WordPress, an admin message log, and device revocation.
