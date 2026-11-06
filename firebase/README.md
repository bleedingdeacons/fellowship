# Link's back end on Firebase

Firestore rules and Cloud Functions for project `fellowship-510917`. It lives in
Fellowship's repo because the two have to agree: the Functions ask Fellowship's
`/service/*` routes about members, and Fellowship's admin screens call the
`admin*` functions. None of this is in the plugin zip.

## What it holds, and what it doesn't

**The member list stays in WordPress.** Nothing about a member is copied here.
Functions ask Fellowship when they need an answer, and the answers are opaque ids.

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

`functions/.env.fellowship-510917` holds `FELLOWSHIP_SERVICE_URL`, the full address
of Fellowship's `/wp-json/fellowship/v1/service` on `/amber`. It has to match what
Fellowship's `rest_url()` produces exactly, because it's also the token's audience.

The Functions run as the service account Fellowship holds, because that's the
only caller its service routes accept. See `SERVICE_ACCOUNT` in `src/config.ts`.

### What a new project needs first

Learned from the first deploy, on 2026-11-06. New Google organisations don't give
service accounts broad roles, so these two have to be granted by hand:

| Account | Role | Without it |
| --- | --- | --- |
| `<project number>-compute@developer.gserviceaccount.com` | Cloud Build Service Account | Every function fails to build. |
| `firebase-adminsdk-fbsvc@<project>.iam.gserviceaccount.com` | Eventarc Event Receiver | The Firestore triggers fail with `eventarc.events.receiveEvent` denied. |

The CLI gives the compute account Eventarc Event Receiver by itself, which is easy
to mistake for the second grant. It isn't, because the Functions don't run as it.

**A deploy that fails leaves empty placeholder functions behind**, and they cause
two confusing failures on the next attempt:

- A placeholder for a trigger reads as an HTTPS function, and changing the type is
  refused. Delete it and deploy again.
- A phone function is made public only when it is created, so one updated from a
  placeholder stays private and answers 403 before reaching any code. Setting
  `invoker` doesn't help, because the CLI doesn't apply it to a callable on update.
  Delete it and deploy again.

### Checking it

A phone function with no token should answer 401 with `fellowship_unauthenticated`,
and an admin function with no token should answer a bare 403. `adminResolve`, called
as the service account with `{"everyone": true}`, proves the whole path to
Fellowship: the answer's `members` count comes from the real site, through a
Google-signed token.

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
2. Grant it **Billing Account Administrator** on the billing account, and
   **Eventarc Event Receiver** on the project.
3. Deploy.
4. Scope the budget to this project, and connect it to the `budget-alerts` topic.

Without all of these the budget still emails, but nothing stops the spending.

**To test it without firing it**, publish `{"check": true}` to `budget-alerts`. The
function logs `Kill switch readiness check`, with `ready` and anything `missing`.
