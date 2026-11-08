/** Where the Functions run. Firestore is here too, and cannot move. */
export const REGION = 'europe-west2';

/**
 * Who the Functions run as: the service account Fellowship holds. Fellowship signs
 * what a phone carries here with its key, and it is the only caller allowed to
 * invoke the admin functions.
 */
export const SERVICE_ACCOUNT = 'firebase-adminsdk-fbsvc@fellowship-510917.iam.gserviceaccount.com';

/** Who Fellowship signs a statement for. See AttestationSigner::audience(). */
export const ATTESTATION_AUDIENCE = 'fellowship-functions:fellowship-510917';

/** Fellowship signs for five minutes. Anything longer wasn't signed by it. */
export const ATTESTATION_MAX_LIFETIME_SECONDS = 300;

/**
 * Who the kill switch runs as. It holds Billing Account Administrator, the one
 * role here that reaches beyond this project, so it is kept away from the account
 * above, whose key sits on the WordPress server. It has no key of its own.
 */
export const KILL_SWITCH_ACCOUNT = 'budget-kill-switch@fellowship-510917.iam.gserviceaccount.com';

/** The billing account the kill switch's readiness check asks about. */
export const BILLING_ACCOUNT = 'billingAccounts/0119D8-80D310-ABF3B3';

/** Matches MAX_DEVICES_PER_MEMBER in Fellowship's DeviceAuthController. */
export const MAX_DEVICES_PER_MEMBER = 5;

/** Matches SEND_MAX and SEND_WINDOW in Fellowship's MessageController. */
export const SEND_MAX = 20;
export const SEND_WINDOW_SECONDS = 900;

/** How long after a sign-in its token may still prove a member. */
export const MAX_AUTH_AGE_SECONDS = 300;
export const CLOCK_SKEW_SECONDS = 60;

/**
 * A takeover cuts off tokens from before it, with a little room so the new
 * phone's own sign-in is not refused by a difference between clocks.
 */
export const TAKEOVER_SKEW_SECONDS = 5;

/** FCM refuses a data message over 4KB, and an envelope has to fit in one. */
export const ENVELOPE_MAX_LENGTH = 3900;

/** Firestore allows at most 30 values in an `in` query. */
export const IN_QUERY_LIMIT = 30;

export const PUBLIC_KEY_MIN_BITS = 2048;
export const PUBLIC_KEY_MAX_LENGTH = 4096;
export const LABEL_MAX_LENGTH = 200;
export const PUSH_TOKEN_MAX_LENGTH = 512;
