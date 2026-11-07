import { createPublicKey, randomBytes } from 'node:crypto';
import { FieldValue } from 'firebase-admin/firestore';
import { HttpsError } from 'firebase-functions/v2/https';
import {
  LABEL_MAX_LENGTH,
  MAX_DEVICES_PER_MEMBER,
  PUBLIC_KEY_MAX_LENGTH,
  PUBLIC_KEY_MIN_BITS,
  PUSH_TOKEN_MAX_LENGTH,
  TAKEOVER_SKEW_SECONDS,
} from './config';
import { Caller, Deps, nowSeconds } from './deps';
import { discardIdentity, identifyMember, proveMember, spendSignIn } from './identity';

/**
 * Each device is its own Firebase user, with the device id as its uid and the
 * member id as a claim. That mirrors Fellowship's device token: one credential
 * per phone, which can be cut off without touching the member's other phones.
 */

export interface LiveDevice {
  deviceId: string;
  memberId: number;
}

type Data = Record<string, unknown>;

export async function enrol(deps: Deps, caller: Caller | undefined, data: Data) {
  const memberId = await proveMember(deps, caller);

  const publicKey = requirePublicKey(data.publicKey);
  const platform = requirePlatform(data.platform);
  const deviceId = `d_${randomBytes(16).toString('hex')}`;

  await deps.auth.createUser({ uid: deviceId });

  try {
    await deps.auth.setCustomUserClaims(deviceId, { memberId, kind: 'device' });

    const devices = deps.db.collection('devices');

    // In a transaction, so two sign-ins at once cannot both take the last place.
    await deps.db.runTransaction(async (tx) => {
      const live = await tx.get(devices.where('memberId', '==', memberId).where('status', '==', 'live'));
      if (live.size >= MAX_DEVICES_PER_MEMBER) {
        throw new HttpsError(
          'failed-precondition',
          `This member already has ${MAX_DEVICES_PER_MEMBER} devices enrolled. Remove one before adding another.`,
          { reason: 'fellowship_too_many_devices' },
        );
      }

      tx.create(devices.doc(deviceId), {
        memberId,
        platform,
        publicKey,
        label: optionalString(data.label, LABEL_MAX_LENGTH),
        pushToken: optionalString(data.pushToken, PUSH_TOKEN_MAX_LENGTH),
        status: 'live',
        keyFault: false,
        tokensValidAfter: 0,
        createdAt: FieldValue.serverTimestamp(),
        lastSeenAt: FieldValue.serverTimestamp(),
      });
    });
  } catch (error) {
    await deps.auth.deleteUser(deviceId).catch(() => undefined);
    throw error;
  }

  const token = await deps.auth.createCustomToken(deviceId);

  await discardIdentity(deps, caller);

  return { deviceId, memberId, token };
}

export async function replaceKey(deps: Deps, caller: Caller | undefined, data: Data) {
  const memberId = await proveMember(deps, caller);
  const publicKey = requirePublicKey(data.publicKey);
  const ref = await membersLiveDevice(deps, data.deviceId, memberId);

  await ref.update({ publicKey, keyFault: false, lastSeenAt: FieldValue.serverTimestamp() });
  await discardIdentity(deps, caller);

  return { deviceId: ref.id };
}

/**
 * Moves a device to the phone restoring a backup, and cuts the old phone off.
 *
 * The key has to match, so a backup from before a key replacement cannot take
 * the device back, and the device has to be live, so an admin's revoke stays
 * final. Link enrols as new when this refuses, with the same sign-in, because
 * an Apple or Google credential can't be presented twice. So the sign-in is only
 * spent once every check has passed.
 */
export async function takeOverDevice(deps: Deps, caller: Caller | undefined, data: Data) {
  const memberId = await identifyMember(deps, caller);
  const publicKey = requirePublicKey(data.publicKey);
  const moved: Data = {};

  if (data.platform !== undefined) {
    moved.platform = requirePlatform(data.platform);
  }

  if (data.label !== undefined) {
    moved.label = optionalString(data.label, LABEL_MAX_LENGTH);
  }

  const ref = await membersLiveDevice(deps, data.deviceId, memberId);

  const device = await ref.get();
  if (device.get('publicKey') !== publicKey) {
    throw new HttpsError('failed-precondition', 'That backup is for an older key.', {
      reason: 'fellowship_key_mismatch',
    });
  }

  await spendSignIn(deps, caller);

  await deps.auth.revokeRefreshTokens(ref.id);
  await ref.update({
    ...moved,
    tokensValidAfter: nowSeconds(deps) - TAKEOVER_SKEW_SECONDS,
    pushToken: optionalString(data.pushToken, PUSH_TOKEN_MAX_LENGTH),
    keyFault: false,
    lastSeenAt: FieldValue.serverTimestamp(),
  });

  const token = await deps.auth.createCustomToken(ref.id);

  await discardIdentity(deps, caller);

  return { deviceId: ref.id, memberId, token };
}

export async function signOut(deps: Deps, caller: Caller | undefined) {
  const device = await requireLiveDevice(deps, caller);

  await revokeDevice(deps, device.deviceId);

  return {};
}

/** The token stops working and the row stays, showing it existed. */
export async function revokeDevice(deps: Deps, deviceId: string): Promise<void> {
  await deps.db.collection('devices').doc(deviceId).update({
    status: 'revoked',
    pushToken: null,
    revokedAt: FieldValue.serverTimestamp(),
  });

  await cutOffUser(deps, deviceId);
}

/** Destroys the evidence the device ever existed, inbox included. */
export async function removeDevice(deps: Deps, deviceId: string): Promise<void> {
  await deps.db.recursiveDelete(deps.db.collection('devices').doc(deviceId));

  await deps.auth.deleteUser(deviceId).catch((error: { code?: string }) => {
    if (error.code !== 'auth/user-not-found') {
      throw error;
    }
  });
}

/**
 * The caller, if it is a live device. Firestore's rules make the same check for
 * direct reads. A callable has to make it here, because a revoked device's
 * token stays valid until it expires.
 */
export async function requireLiveDevice(deps: Deps, caller: Caller | undefined): Promise<LiveDevice> {
  if (caller === undefined || caller.token.kind !== 'device' || !Number.isInteger(caller.token.memberId)) {
    throw notSignedIn();
  }

  const device = await deps.db.collection('devices').doc(caller.uid).get();

  if (
    !device.exists
    || device.get('status') !== 'live'
    || Number(caller.token.auth_time) < Number(device.get('tokensValidAfter') ?? 0)
  ) {
    throw notSignedIn();
  }

  return { deviceId: caller.uid, memberId: caller.token.memberId as number };
}

async function membersLiveDevice(deps: Deps, deviceId: unknown, memberId: number) {
  if (typeof deviceId !== 'string' || deviceId === '' || deviceId.includes('/')) {
    throw new HttpsError('invalid-argument', 'Which device?', { reason: 'fellowship_bad_request' });
  }

  const ref = deps.db.collection('devices').doc(deviceId);
  const device = await ref.get();

  // The same answer whether it is somebody else's or does not exist, so ids
  // cannot be walked to learn which are real.
  if (!device.exists || device.get('memberId') !== memberId) {
    throw new HttpsError('not-found', 'No such device.', { reason: 'fellowship_no_such_device' });
  }

  if (device.get('status') !== 'live') {
    throw new HttpsError('failed-precondition', 'That device has been removed.', {
      reason: 'fellowship_device_revoked',
    });
  }

  return ref;
}

async function cutOffUser(deps: Deps, deviceId: string): Promise<void> {
  try {
    await deps.auth.updateUser(deviceId, { disabled: true });
    await deps.auth.revokeRefreshTokens(deviceId);
  } catch (error) {
    if ((error as { code?: string }).code !== 'auth/user-not-found') {
      throw error;
    }
  }
}

function requirePublicKey(value: unknown): string {
  const refused = new HttpsError('invalid-argument', 'That public key could not be read.', {
    reason: 'fellowship_bad_public_key',
  });

  if (typeof value !== 'string' || value === '' || value.length > PUBLIC_KEY_MAX_LENGTH) {
    throw refused;
  }

  const encoded = value.replace(/\s+/g, '');

  try {
    const key = createPublicKey({ key: Buffer.from(encoded, 'base64'), format: 'der', type: 'spki' });
    const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
    if (key.asymmetricKeyType !== 'rsa' || bits < PUBLIC_KEY_MIN_BITS) {
      throw refused;
    }
  } catch {
    throw refused;
  }

  return encoded;
}

function requirePlatform(value: unknown): string {
  if (value !== 'android' && value !== 'ios') {
    throw new HttpsError('invalid-argument', 'Unknown platform.', { reason: 'fellowship_bad_request' });
  }

  return value;
}

function optionalString(value: unknown, maxLength: number): string | null {
  return typeof value === 'string' && value !== '' ? value.slice(0, maxLength) : null;
}

function notSignedIn(): HttpsError {
  return new HttpsError('unauthenticated', 'This device is not signed in.', {
    reason: 'fellowship_unauthenticated',
  });
}
