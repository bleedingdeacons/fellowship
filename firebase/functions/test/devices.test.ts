import { beforeEach, describe, expect, test } from 'vitest';
import { enrol, removeDevice, replaceKey, requireLiveDevice, revokeDevice, signOut, takeOverDevice } from '../src/devices';
import {
  auth,
  db,
  deviceCaller,
  fake,
  googleCaller,
  newPublicKey,
  passwordCaller,
  reasonOf,
  resetEmulators,
  userExists,
} from './support';

beforeEach(resetEmulators);

async function enrolled(email = 'dave@example.org', publicKey = newPublicKey()) {
  const { deps } = fake();
  const result = await enrol(deps, await googleCaller(email), { publicKey, platform: 'android', pushToken: 'push-1' });

  return { deps, publicKey, ...result };
}

describe('enrolling', () => {
  test('a member signed in with Google gets a device and a token', async () => {
    const { deviceId, memberId, token } = await enrolled();

    expect(memberId).toBe(7);
    expect(token).not.toBe('');

    const device = await db.collection('devices').doc(deviceId).get();
    expect(device.get('status')).toBe('live');
    expect(device.get('memberId')).toBe(7);
    expect(device.get('pushToken')).toBe('push-1');

    const user = await auth.getUser(deviceId);
    expect(user.customClaims).toEqual({ memberId: 7, kind: 'device' });
  });

  test('a member signed in with a Unity password gets one too', async () => {
    const { deps } = fake();
    const result = await enrol(deps, await passwordCaller(8), { publicKey: newPublicKey(), platform: 'ios' });

    expect(result.memberId).toBe(8);
  });

  test('the identity is deleted afterwards, so Firebase keeps no address', async () => {
    const { deps } = fake();
    const caller = await googleCaller();

    await enrol(deps, caller, { publicKey: newPublicKey(), platform: 'android' });

    expect(await userExists(caller.uid)).toBe(false);
  });

  test('a device has no email address', async () => {
    const { deviceId } = await enrolled();

    expect((await auth.getUser(deviceId)).email).toBeUndefined();
  });

  test('somebody who is not a member is refused and nothing is created', async () => {
    const { deps } = fake();
    const caller = await googleCaller('stranger@example.org');

    expect(await reasonOf(enrol(deps, caller, { publicKey: newPublicKey(), platform: 'android' })))
      .toBe('fellowship_not_a_member');
    expect((await db.collection('devices').get()).size).toBe(0);
  });

  test.each([
    ['nobody signed in', undefined],
    ['an unverified address', { email_verified: false }],
    ['no address', { email: '' }],
    ['a stale sign-in', { auth_time: Math.floor(Date.now() / 1000) - 3600 }],
    ['an anonymous sign-in', { firebase: { sign_in_provider: 'anonymous', identities: {} } }],
  ])('%s is refused', async (_name, claims) => {
    const { deps } = fake();
    const caller = claims === undefined ? undefined : await googleCaller('dave@example.org', claims);
    const expected = claims === undefined ? 'fellowship_unauthenticated' : 'fellowship_bad_id_token';

    expect(await reasonOf(enrol(deps, caller, { publicKey: newPublicKey(), platform: 'android' }))).toBe(expected);
    expect((await db.collection('devices').get()).size).toBe(0);
  });

  test('a device cannot enrol another device', async () => {
    const { deps, deviceId } = await enrolled();

    expect(await reasonOf(enrol(deps, deviceCaller(deviceId, 7), { publicKey: newPublicKey(), platform: 'android' })))
      .toBe('fellowship_bad_id_token');
  });

  test('a sign-in works only once', async () => {
    const { deps } = fake();
    const caller = await googleCaller();

    await enrol(deps, caller, { publicKey: newPublicKey(), platform: 'android' });

    expect(await reasonOf(enrol(deps, caller, { publicKey: newPublicKey(), platform: 'android' })))
      .toBe('fellowship_bad_id_token');
  });

  test.each([
    ['nonsense', 'not a key'],
    ['empty', ''],
    ['too long', 'A'.repeat(5000)],
  ])('a public key that is %s is refused', async (_name, publicKey) => {
    const { deps } = fake();

    expect(await reasonOf(enrol(deps, await googleCaller(), { publicKey, platform: 'android' })))
      .toBe('fellowship_bad_public_key');
  });

  test('an unknown platform is refused', async () => {
    const { deps } = fake();

    expect(await reasonOf(enrol(deps, await googleCaller(), { publicKey: newPublicKey(), platform: 'windows' })))
      .toBe('fellowship_bad_request');
  });

  test('a sixth live device is refused, and leaves no user behind', async () => {
    const { deps } = fake();

    for (let i = 0; i < 5; i++) {
      await enrol(deps, await googleCaller(), { publicKey: newPublicKey(), platform: 'android' });
    }

    const before = (await auth.listUsers()).users.length;

    expect(await reasonOf(enrol(deps, await googleCaller(), { publicKey: newPublicKey(), platform: 'android' })))
      .toBe('fellowship_too_many_devices');
    expect((await db.collection('devices').get()).size).toBe(5);
    // Only the refused sign-in's own identity is new.
    expect((await auth.listUsers()).users.length).toBe(before + 1);
  });

  test('a revoked device does not count towards the cap', async () => {
    const { deps } = fake();
    const first = await enrol(deps, await googleCaller(), { publicKey: newPublicKey(), platform: 'android' });

    for (let i = 0; i < 4; i++) {
      await enrol(deps, await googleCaller(), { publicKey: newPublicKey(), platform: 'android' });
    }

    await revokeDevice(deps, first.deviceId);

    await expect(enrol(deps, await googleCaller(), { publicKey: newPublicKey(), platform: 'android' }))
      .resolves.toBeDefined();
  });
});

describe('replacing a key', () => {
  test('the new key is stored and the fault cleared', async () => {
    const { deps, deviceId } = await enrolled();
    await db.collection('devices').doc(deviceId).update({ keyFault: true });
    const publicKey = newPublicKey();

    await replaceKey(deps, await googleCaller(), { deviceId, publicKey });

    const device = await db.collection('devices').doc(deviceId).get();
    expect(device.get('publicKey')).toBe(publicKey);
    expect(device.get('keyFault')).toBe(false);
  });

  test('somebody else cannot replace it, and cannot tell it exists', async () => {
    const { deps, deviceId } = await enrolled();

    expect(await reasonOf(replaceKey(deps, await googleCaller('sue@example.org'), { deviceId, publicKey: newPublicKey() })))
      .toBe('fellowship_no_such_device');
  });

  test('a revoked device cannot have its key replaced', async () => {
    const { deps, deviceId } = await enrolled();
    await revokeDevice(deps, deviceId);

    expect(await reasonOf(replaceKey(deps, await googleCaller(), { deviceId, publicKey: newPublicKey() })))
      .toBe('fellowship_device_revoked');
  });
});

describe('taking over a device', () => {
  test('the new phone gets a token for the same device', async () => {
    const { deps, deviceId, publicKey } = await enrolled();

    const result = await takeOverDevice(deps, await googleCaller(), { deviceId, publicKey, pushToken: 'push-2' });

    expect(result.deviceId).toBe(deviceId);
    expect((await db.collection('devices').doc(deviceId).get()).get('pushToken')).toBe('push-2');
  });

  test('the old phone is cut off, even with a token that has not expired', async () => {
    const { deps, deviceId, publicKey } = await enrolled();
    const anHourAgo = Math.floor(Date.now() / 1000) - 3600;
    const oldPhone = deviceCaller(deviceId, 7, { auth_time: anHourAgo });

    await expect(requireLiveDevice(deps, oldPhone)).resolves.toBeDefined();

    await takeOverDevice(deps, await googleCaller(), { deviceId, publicKey });

    expect(await reasonOf(requireLiveDevice(deps, oldPhone))).toBe('fellowship_unauthenticated');
    await expect(requireLiveDevice(deps, deviceCaller(deviceId, 7))).resolves.toBeDefined();
  });

  test('a backup from before a key replacement cannot take it over', async () => {
    const { deps, deviceId, publicKey } = await enrolled();
    await replaceKey(deps, await googleCaller(), { deviceId, publicKey: newPublicKey() });

    expect(await reasonOf(takeOverDevice(deps, await googleCaller(), { deviceId, publicKey })))
      .toBe('fellowship_key_mismatch');
  });

  test('another member cannot take it over', async () => {
    const { deps, deviceId, publicKey } = await enrolled();

    expect(await reasonOf(takeOverDevice(deps, await googleCaller('sue@example.org'), { deviceId, publicKey })))
      .toBe('fellowship_no_such_device');
  });

  test('an admin revoke stays final', async () => {
    const { deps, deviceId, publicKey } = await enrolled();
    await revokeDevice(deps, deviceId);

    expect(await reasonOf(takeOverDevice(deps, await googleCaller(), { deviceId, publicKey })))
      .toBe('fellowship_device_revoked');
  });
});

describe('cutting a device off', () => {
  test('signing out revokes the calling device and keeps the row', async () => {
    const { deps, deviceId } = await enrolled();

    await signOut(deps, deviceCaller(deviceId, 7));

    const device = await db.collection('devices').doc(deviceId).get();
    expect(device.get('status')).toBe('revoked');
    expect(device.get('pushToken')).toBeNull();
    expect((await auth.getUser(deviceId)).disabled).toBe(true);
  });

  test('a revoked device is refused at once', async () => {
    const { deps, deviceId } = await enrolled();
    await revokeDevice(deps, deviceId);

    expect(await reasonOf(requireLiveDevice(deps, deviceCaller(deviceId, 7)))).toBe('fellowship_unauthenticated');
  });

  test('a token that is not a device token is refused', async () => {
    const { deps, deviceId } = await enrolled();

    expect(await reasonOf(requireLiveDevice(deps, await googleCaller()))).toBe('fellowship_unauthenticated');
    expect(await reasonOf(requireLiveDevice(deps, deviceCaller(deviceId, 7, { kind: 'other' })))).toBe('fellowship_unauthenticated');
  });

  test('removing a device takes its inbox and user with it', async () => {
    const { deps, deviceId } = await enrolled();
    const device = db.collection('devices').doc(deviceId);
    await device.collection('inbox').doc('m1').set({ k: 'k', p: 'p' });

    await removeDevice(deps, deviceId);

    expect((await device.get()).exists).toBe(false);
    expect((await device.collection('inbox').get()).size).toBe(0);
    expect(await userExists(deviceId)).toBe(false);
  });
});
