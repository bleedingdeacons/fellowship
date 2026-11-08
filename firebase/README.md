# Link's back end on Firebase

Firestore rules and Cloud Functions for project `fellowship-510917`. It lives in
Fellowship's repo because the two have to agree: the Functions check what
Fellowship's `/attest/*` routes sign, and Fellowship's admin screens call the
`admin*` functions. None of this is in the plugin zip.

## What it holds, and what it doesn't

**The member list stays in WordPress.** Nothing about a member is copied here.
Fellowship decides who is a member and who a message reaches, and signs its answer
as opaque ids. The phone fetches it and passes it on as `data.attestation`, and the
Functions check the signature against the service account's public keys at Google.
They never call the site: its host challenges Google Cloud's shared addresses.

**Messages are end-to-end encrypted.** A phone asks who a message reaches, seals
one envelope per device, and hands them back. The server addresses the message
and never sees it.

| Google holds | Google doesn't hold |
| --- | --- |
| Ciphertext, device public keys, push tokens | Message subjects or bodies |
| Opaque member ids, so who messaged whom and when | Names, home groups, committees |
| A sign-in's address, only while it enrols | Addresses or passwords at rest |

A message records the kind of audience (`members`, `part`, `mixed`, `everyone`)
rather than which committees, because a committee's slug says what it is.

## Identity

Each device is its own Firebase user: the uid is the device id, with `memberId`
and `kind: 'device'` as claims, signed in with a custom token.

A person proves who they are only to enrol, replace a key or take over a device:
Google or Apple prove an address, and a Unity password arrives as a custom token
from Fellowship's `/auth/identity/password`, because the password stays in Unity.
That identity user is then deleted, so Firebase Auth keeps no addresses.

Revoking disables the user and marks the row. Firestore doesn't check token
revocation and an ID token lasts an hour, so the rules also read the device's
`status` and `tokensValidAfter`, which is what cuts a phone off on its next request.

## Running the tests

They need Node 22 and Java 21. From this directory:

```bash
npm --prefix functions ci
```
```bash
firebase emulators:exec --project demo-fellowship --only auth,firestore "npm --prefix functions test"
```

`demo-*` projects never touch a real one, and the tests need no credentials.

## Deploying

Nothing deploys automatically yet. From this directory, signed in to the Firebase
CLI as an owner of the project:

```bash
npx firebase-tools@15 deploy --only firestore,functions --project fellowship-510917 --non-interactive --force
```

`--force` also keeps the cleanup policy on old container images, so they don't
build up storage charges.

The Functions run as the service account Fellowship holds, and only a statement
signed with that account's key is believed. See `SERVICE_ACCOUNT` and
`ATTESTATION_AUDIENCE` in `src/config.ts`. Fellowship needs the account's JSON with
its `private_key_id`, which names the key Google publishes.

### What a new project needs first

Learned from the first deploy, on 2026-11-06. New Google organisations don't give
service accounts broad roles, so these two have to be granted by hand:

| Account | Role | Without it |
| --- | --- | --- |
| `<project number>-compute@developer.gserviceaccount.com` | Cloud Build Service Account | Every function fails to build. |
| `firebase-adminsdk-fbsvc@<project>.iam.gserviceaccount.com` | Eventarc Event Receiver | The Firestore triggers fail with `eventarc.events.receiveEvent` denied. |
| `firebase-adminsdk-fbsvc@<project>.iam.gserviceaccount.com` | Cloud Run Invoker | **Deploys cleanly, then every event is refused with a 403.** No pushes, no tick counts and no sweep, with nothing to say so except the function's request log. |

The CLI gives the compute account Eventarc Event Receiver and Cloud Run Invoker by
itself, which is easy to mistake for these grants. It isn't, because the Functions
don't run as that account.

**A deploy that fails leaves empty placeholder functions behind**, and they cause
two confusing failures on the next attempt:

- A placeholder for a trigger reads as an HTTPS function, and changing the type is
  refused. Delete it and deploy again.
- A phone function is made public only when it is created, so one updated from a
  placeholder stays private and answers 403 before reaching any code. Setting
  `invoker` doesn't help, because the CLI doesn't apply it to a callable on update.
  Delete it and deploy again.

### What WordPress checks

Fellowship reads Firestore and calls the admin Functions as the same service account.
A device's ID token is checked by `Devices/FirebaseDevices`, which makes the same
checks as the rules (a device's token, a live device, not from before it was cut off)
and then re-runs the member gate, which only WordPress can do. Firebase being
unreachable is never treated as a refusal.

`Sync/MemberWatch` cuts off devices whose member has gone. Deleting a member from
Unity removes their devices at once. A daily check revokes anyone else the gate now
refuses, unless that's more than three members and more than a quarter of those with
devices. **Then it does nothing and logs an error**, because revoking is final and a
bad member list shouldn't be able to cut off the fellowship.

### Checking it

A phone function with no token should answer 401 with `fellowship_unauthenticated`,
and an admin function with no token should answer a bare 403. A phone function with
a token but no statement from Fellowship answers `fellowship_bad_attestation`.
`adminResolve`, called as the service account with `{"memberIds": [<id>],
"audience": "members"}`, lists that member's live devices.

### SiteGround's anti-bot challenge

The site's host challenges requests it can't identify, with a `202` page redirecting
to `/.well-known/sgcaptcha/`, which a server can't complete. On 2026-11-07 it named
its reason as `y=ipr:<address>`: the reputation of the Google address a Function's
call came from, which no header changes. Identical calls got through from some
addresses and not others, and SiteGround offers no exemption for Google's changing
ones.

**So nothing here calls the site.** The phone, which reaches it, fetches Fellowship's
signed answer and hands it over. Fellowship still calls the admin Functions, which
is Google's side and isn't challenged.

### Deploying everything at once

All 15 functions rolling out together can fail some of them with `Quota exceeded for
total allowable CPU per project per region`. The failed ones keep serving their old
version. Deploy those again in groups of three.

### The kill switch

A budget only sends emails. `budgetAlert` is what stops the spending: it detaches
billing when actual spend reaches the budget, which puts the project back on Spark
and stops the Functions.

**Firing it has real costs.** Google warns that disabling billing can irretrievably
delete resources and that re-enabling it is manual, with no guarantee of recovery.
Notifications also lag behind spending, so some charges can still land after it
fires. It acts only on actual spend, never on a forecast.

**It runs as its own account**, `budget-kill-switch@`, which needs Billing Account
Administrator on the whole billing account. That role reaches beyond this project,
so it is kept away from `firebase-adminsdk-fbsvc@`, whose key is on the WordPress
server. The account has no key, so nothing outside Google can act as it.

It needs setting up by hand, in this order:

1. Create the `budget-kill-switch` service account. It must exist before a deploy.
2. Grant it **Billing Account Administrator** on the billing account, and on the
   project **Project Billing Manager**, **Eventarc Event Receiver** and **Cloud Run
   Invoker**. The billing account role doesn't reach the project, so it needs both.
3. Deploy.
4. Publish the check below, and don't go on until it says `ready`.
5. Create a budget scoped to this project alone, and connect it to the
   `budget-alerts` topic. This is `Fellowship kill switch`, at £5 a month.

**Don't connect the `£5 Monthly Budget Alert` budget.** Register shares this billing
account and that budget covers both, so Register's spending could detach billing
from Fellowship. It stays as an email alert for both projects.

**Credits are subtracted before the budget compares**, which is the default. So
while the free trial's credit is covering costs, spend stays at £0 and this won't
fire. It starts protecting real money once costs aren't covered by credit.

Without all of these the budget still emails, but nothing stops the spending.

**To test it without firing it**, publish `{"check": true}` to `budget-alerts`. The
function logs `Kill switch readiness check`, with `ready`, what's missing on the
project and the billing account, and any call that was refused.

**The check asks Google whether the permissions are held. It can't prove the detach
itself works**, because the only way to do that is to fire it.
