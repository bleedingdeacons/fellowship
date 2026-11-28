=== Fellowship ===
Contributors: thebleedingdeacons
Requires at least: 6.1
Tested up to: 7.1.1
Requires PHP: 8.4
Stable tag: 1.19.8
Build date: 2026/11/28 16:21:45
License: MIT (Modified)

Server side of the Link messaging app. Decides which members may use Link, signs what each phone carries to Link's Firebase back end, and runs Link's password sign-in and admin screens. Requires Unity and Scrutiny.

== Description ==

Fellowship is the WordPress half of a messaging system. The other half is **Link**, a .NET MAUI app for Android and iOS, and between them sits a Firebase project that carries the messages.

The member list stays in WordPress. A member signs in to Link with Google, Apple or a password, and Fellowship signs a short statement that this sign-in is a member; the phone carries it to Firebase to enrol. When a member sends, Fellowship signs which members the message reaches.

Messages are end-to-end encrypted. Each is sealed on the sending phone to each recipient device's public key: a fresh AES-256 content key per message, the body sealed under it with AES-256-GCM over gzip, the content key wrapped to the device with RSA-OAEP. Neither Fellowship nor Firebase holds a private key, so neither can read a message. What lands in the notification tray is "New message" and nothing else.

Messages can be addressed to named members, a committee or the GSRs, from the app or from the WordPress admin. Committees come from Unity and include their sub-committees. Every admin send and every directory read is audit-logged through Scrutiny.

== Installation ==

1. Install and activate Unity and Scrutiny first. Fellowship refuses to activate without them.
2. Activate Fellowship.
3. Under **Fellowship → Settings**, paste in the site's Firebase service-account JSON. Without it Link cannot sign in or send.
4. For the browser sign-in another plugin offers, such as Freedom's, register the redirect URI shown there with your Google OAuth client, and paste in the client ID and secret.
5. Decide whether members may send to a whole committee from the app. It is off by default.

== Frequently Asked Questions ==

= A member has lost their phone. =

**Fellowship → Devices**, then Revoke. The device stops working at once and its record is kept. Remove deletes the record and its inbox, and is for tidying up test enrolments and erasure requests.

= Can I turn Fellowship off without deactivating it? =

Define `FELLOWSHIP_KILL` as true in wp-config.php. No routes and no admin pages.

== Changelog ==

= 1.0.0 =
* First release. Device enrolment by Google and Apple sign-in against Unity members, a per-device keypair exchanged at enrolment, hybrid-sealed push and poll delivery, messages to individuals and committees from the app and from WordPress, an admin message log, and device revocation.
