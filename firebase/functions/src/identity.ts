import { createHash } from 'node:crypto';
import * as logger from 'firebase-functions/logger';
import { HttpsError } from 'firebase-functions/v2/https';
import { CLOCK_SKEW_SECONDS, MAX_AUTH_AGE_SECONDS } from './config';
import { Caller, Deps, nowSeconds } from './deps';

/**
 * Proving who a member is, at enrolment and when replacing or taking over a key.
 *
 * Google and Apple prove an address, and a Unity password arrives as a custom token
 * Fellowship already minted. Nothing else counts: Firebase also mints anonymous
 * tokens and device tokens, and neither proves a person.
 *
 * Which member it is comes from Fellowship, signed, in `data.attestation`, for this
 * sign-in's uid. Fellowship refuses anybody who isn't a member before signing, so a
 * phone that has no statement has been told why already.
 */

const SIGN_IN_PROVIDERS_WITH_ADDRESS = ['google.com', 'apple.com'];

/** Which member this sign-in proves, and it can't be used again. Refuses anything stale, used or unknown. */
export async function proveMember(deps: Deps, caller: Caller | undefined, attestation: unknown): Promise<number> {
  const memberId = await identifyMember(deps, caller, attestation);

  await spendSignIn(deps, caller);

  return memberId;
}

/**
 * Which member this sign-in proves, leaving it unspent. For a caller that may
 * refuse for a reason of its own and leave the sign-in good for something else.
 * That caller must call spendSignIn before it changes anything.
 */
export async function identifyMember(deps: Deps, caller: Caller | undefined, attestation: unknown): Promise<number> {
  if (caller === undefined) {
    throw new HttpsError('unauthenticated', 'Sign in first.', { reason: 'fellowship_unauthenticated' });
  }

  const age = nowSeconds(deps) - Number(caller.token.auth_time);
  if (!Number.isFinite(age) || age < -CLOCK_SKEW_SECONDS || age > MAX_AUTH_AGE_SECONDS + CLOCK_SKEW_SECONDS) {
    throw badToken();
  }

  requirePerson(caller);

  const { memberId } = await deps.attestations.member(attestation, caller.uid);

  // A password sign-in already names its member, and Fellowship can't have meant another.
  if (caller.token.identity === 'password' && caller.token.memberId !== memberId) {
    throw badToken();
  }

  return memberId;
}

/**
 * The identity's work is done, so Firebase Auth keeps no address. Failing here
 * does not fail the member's sign-in, but it is logged, because it leaves an
 * address behind that this design promises not to keep.
 */
export async function discardIdentity(deps: Deps, caller: Caller | undefined): Promise<void> {
  if (caller === undefined) {
    return;
  }

  try {
    await deps.auth.deleteUser(caller.uid);
  } catch (error) {
    if ((error as { code?: string }).code !== 'auth/user-not-found') {
      logger.error('Could not delete a spent identity user', { error: String(error) });
    }
  }
}

/** Fellowship checks this too. Checked again so a device can never pass as a person. */
function requirePerson(caller: Caller): void {
  const { token } = caller;
  const provider = token.firebase?.sign_in_provider;

  if (provider !== undefined && SIGN_IN_PROVIDERS_WITH_ADDRESS.includes(provider)) {
    if (typeof token.email !== 'string' || token.email === '' || token.email_verified !== true) {
      throw badToken();
    }

    return;
  }

  if (provider === 'custom' && token.identity === 'password' && Number.isInteger(token.memberId)) {
    return;
  }

  throw badToken();
}

/**
 * Each sign-in works once. Without a nonce this is what stops a captured token
 * enrolling a second handset.
 *
 * <b>Keyed on the sign-in, not the token.</b> `auth_time` is when the person
 * signed in, and every ID token refreshed from that sign-in carries the same one,
 * whereas `iat` is new with each refresh. Keyed on `iat`, somebody holding the
 * refresh token could mint a fresh ID token for each device, up to the cap.
 *
 * Kept until identifyMember would refuse the sign-in as stale anyway, when the
 * daily sweep removes it.
 */
export async function spendSignIn(deps: Deps, caller: Caller | undefined): Promise<void> {
  const signedInAt = Number(caller?.token.auth_time);
  if (caller === undefined || !Number.isFinite(signedInAt)) {
    throw badToken();
  }

  const id = createHash('sha256').update(`${caller.uid}:${signedInAt}`).digest('hex');
  const expireAt = signedInAt + MAX_AUTH_AGE_SECONDS + 2 * CLOCK_SKEW_SECONDS;

  try {
    await deps.db.collection('spentIdentities').doc(id).create({ expireAt });
  } catch (error) {
    if ((error as { code?: number }).code === 6) {
      throw badToken();
    }

    throw error;
  }
}

function badToken(): HttpsError {
  return new HttpsError('unauthenticated', 'That sign-in could not be verified.', {
    reason: 'fellowship_bad_id_token',
  });
}
