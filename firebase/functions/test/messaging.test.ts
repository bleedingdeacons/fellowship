import { Timestamp } from 'firebase-admin/firestore';
import { beforeEach, describe, expect, test } from 'vitest';
import { adminRemove, adminResolve, adminRevoke, adminRevokeMember, adminSend } from '../src/admin';
import { countReceipt, pushInboxEntry, sweep } from '../src/background';
import type { Deps } from '../src/deps';
import { enrol } from '../src/devices';
import { overBudget } from '../src/killSwitch';
import { newMessageId, resolveAudience, sendMessage } from '../src/messaging';
import { auth, db, deviceCaller, fake, googleCaller, newPublicKey, passwordCaller, reasonOf, resetEmulators } from './support';

beforeEach(resetEmulators);

async function deviceFor(deps: Deps, memberId: number, pushToken?: string): Promise<string> {
  const { deviceId } = await enrol(deps, await passwordCaller(memberId), {
    publicKey: newPublicKey(),
    platform: 'android',
    pushToken,
  });

  return deviceId;
}

const envelope = (deviceId: string) => ({ deviceId, k: 'wrapped-key', p: 'sealed-payload' });

describe('working out who a message reaches', () => {
  test('answers the live devices, with their keys', async () => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    const sue = await deviceFor(deps, 8);

    const answer = await resolveAudience(deps, deviceCaller(sender, 7), { memberIds: [8] });

    expect(answer.devices.map((device) => device.deviceId)).toEqual([sue]);
    expect(answer.devices[0].publicKey).not.toBe('');
    expect(answer.members).toBe(1);
    expect(answer.reachable).toBe(1);
  });

  test('counts a member with no device as unreachable', async () => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    await deviceFor(deps, 8);

    const answer = await resolveAudience(deps, deviceCaller(sender, 7), { memberIds: [8, 10] });

    expect(answer.members).toBe(2);
    expect(answer.reachable).toBe(1);
  });

  test('every phone a member has is included, and a revoked one is not', async () => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    const phone = await deviceFor(deps, 8);
    const tablet = await deviceFor(deps, 8);
    const old = await deviceFor(deps, 8);
    await adminRevoke(deps, { deviceId: old });

    const answer = await resolveAudience(deps, deviceCaller(sender, 7), { memberIds: [8] });

    expect(answer.devices.map((device) => device.deviceId).sort()).toEqual([phone, tablet].sort());
  });

  test('a phone always asks as a member, whatever it sends', async () => {
    const { deps, audiences } = fake();
    const sender = await deviceFor(deps, 7);

    await resolveAudience(deps, deviceCaller(sender, 7), {
      memberIds: [8],
      origin: 'admin',
      everyone: true,
      senderMemberId: 8,
    });

    expect(audiences[0].origin).toBe('member');
    expect(audiences[0].senderMemberId).toBe(7);
    expect(audiences[0].everyone).toBeUndefined();
  });

  test('more members than one query can hold are all found', async () => {
    const { deps } = fake({ admitted: Array.from({ length: 35 }, (_, i) => i + 100) });
    const sender = await deviceFor(deps, 100);
    await deviceFor(deps, 134);

    const answer = await resolveAudience(deps, deviceCaller(sender, 100), {
      memberIds: Array.from({ length: 35 }, (_, i) => i + 100),
    });

    expect(answer.members).toBe(34);
    expect(answer.reachable).toBe(1);
  });
});

describe('sending', () => {
  test('each device gets its envelope, and the server records who sent it', async () => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    const sue = await deviceFor(deps, 8);

    const { id } = await sendMessage(deps, deviceCaller(sender, 7), { id: newMessageId(Date.now()), memberIds: [8], envelopes: [envelope(sue)] });

    const entry = await db.collection('devices').doc(sue).collection('inbox').doc(String(id)).get();
    expect(entry.get('k')).toBe('wrapped-key');
    expect(entry.get('p')).toBe('sealed-payload');
    expect(entry.get('senderMemberId')).toBe(7);

    const message = await db.collection('messages').doc(String(id)).get();
    expect(message.get('recipientMemberIds')).toEqual([8]);
    expect(message.get('receivedCount')).toBe(0);
  });

  test('an id is a growing number, in the shape Link already uses', async () => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    const sue = await deviceFor(deps, 8);

    const first = await sendMessage(deps, deviceCaller(sender, 7), { id: newMessageId(Date.now()), memberIds: [8], envelopes: [envelope(sue)] });
    const entry = await db.collection('devices').doc(sue).collection('inbox').doc(String(first.id)).get();

    expect(Number.isSafeInteger(first.id)).toBe(true);
    expect(entry.get('seq')).toBe(first.id);
    expect(first.createdAt).toBeGreaterThan(0);

    // Well above anything Fellowship ever issued, so existing poll marks carry across.
    expect(first.id).toBeGreaterThan(1e12);

    await new Promise((resolve) => setTimeout(resolve, 5));

    const second = await sendMessage(deps, deviceCaller(sender, 7), { id: newMessageId(Date.now()), memberIds: [8], envelopes: [envelope(sue)] });

    expect(second.id).toBeGreaterThan(first.id);
  });

  test('resolving an audience issues the id to seal in', async () => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    const sue = await deviceFor(deps, 8);

    const answer = await resolveAudience(deps, deviceCaller(sender, 7), { memberIds: [8] });
    const { id } = await sendMessage(deps, deviceCaller(sender, 7), {
      id: answer.id,
      memberIds: [8],
      envelopes: [envelope(sue)],
    });

    expect(id).toBe(answer.id);
  });

  test.each([
    ['missing', undefined],
    ['not a number', '123'],
    ['from long ago', Date.UTC(2020, 0, 1) * 1024],
    ['from the future', (Date.now() + 86400000) * 1024],
    ['not whole', 1.5],
  ])('an id that is %s is refused', async (_name, id) => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    const sue = await deviceFor(deps, 8);

    expect(await reasonOf(sendMessage(deps, deviceCaller(sender, 7), { id, memberIds: [8], envelopes: [envelope(sue)] })))
      .toBe('fellowship_bad_message_id');
    expect((await db.collection('messages').get()).size).toBe(0);
  });

  test('an id already taken means sealing again', async () => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    const sue = await deviceFor(deps, 8);
    const id = newMessageId(Date.now());

    await sendMessage(deps, deviceCaller(sender, 7), { id, memberIds: [8], envelopes: [envelope(sue)] });

    expect(await reasonOf(sendMessage(deps, deviceCaller(sender, 7), { id, memberIds: [8], envelopes: [envelope(sue)] })))
      .toBe('fellowship_stale_audience');
  });

  test('ids stay safe for a very long time', () => {
    expect(Number.isSafeInteger(newMessageId(Date.UTC(2200, 0, 1)))).toBe(true);
  });

  test('a client cannot claim to be somebody else', async () => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    const sue = await deviceFor(deps, 8);

    const { id } = await sendMessage(deps, deviceCaller(sender, 7), { id: newMessageId(Date.now()),
      senderMemberId: 10,
      memberIds: [8],
      envelopes: [envelope(sue)],
    });

    expect((await db.collection('messages').doc(String(id)).get()).get('senderMemberId')).toBe(7);
  });

  test.each([
    ['leaves a device out', (sue: string, _other: string) => [envelope(sue)]],
    ['adds a device', (sue: string, other: string) => [envelope(sue), envelope(other), envelope('d_intruder')]],
    ['names a device twice', (sue: string, _other: string) => [envelope(sue), envelope(sue)]],
  ])('a client that %s is told the audience is stale', async (_name, envelopes) => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    const sue = await deviceFor(deps, 8);
    const other = await deviceFor(deps, 8);

    expect(await reasonOf(sendMessage(deps, deviceCaller(sender, 7), { id: newMessageId(Date.now()),
      memberIds: [8],
      envelopes: envelopes(sue, other),
    }))).toBe('fellowship_stale_audience');
    expect((await db.collection('messages').get()).size).toBe(0);
  });

  test('nobody with Link means nothing is sent', async () => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);

    expect(await reasonOf(sendMessage(deps, deviceCaller(sender, 7), { id: newMessageId(Date.now()), memberIds: [8], envelopes: [envelope('d_x')] })))
      .toBe('fellowship_no_reachable_members');
  });

  test.each([
    ['none', []],
    ['not a list', 'nonsense'],
    ['no key', [{ deviceId: 'd_x', p: 'p' }]],
    ['a path for a device', [{ deviceId: 'a/b', k: 'k', p: 'p' }]],
    ['too big for a push', [{ deviceId: 'd_x', k: 'k', p: 'p'.repeat(3900) }]],
  ])('envelopes that are %s are refused', async (_name, envelopes) => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    await deviceFor(deps, 8);

    expect(await reasonOf(sendMessage(deps, deviceCaller(sender, 7), { id: newMessageId(Date.now()), memberIds: [8], envelopes })))
      .toBe('fellowship_bad_envelope');
  });

  test('a revoked device cannot send', async () => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    await adminRevoke(deps, { deviceId: sender });

    expect(await reasonOf(sendMessage(deps, deviceCaller(sender, 7), { id: newMessageId(Date.now()), memberIds: [8], envelopes: [] })))
      .toBe('fellowship_unauthenticated');
  });

  test('a twenty-first send in the window is refused', async () => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    const sue = await deviceFor(deps, 8);
    const caller = deviceCaller(sender, 7);

    for (let i = 0; i < 20; i++) {
      await sendMessage(deps, caller, { id: newMessageId(Date.now()), memberIds: [8], envelopes: [envelope(sue)] });
    }

    expect(await reasonOf(sendMessage(deps, caller, { id: newMessageId(Date.now()), memberIds: [8], envelopes: [envelope(sue)] })))
      .toBe('fellowship_rate_limited');
  });

  test('nothing readable reaches Firestore or Firebase Auth', async () => {
    const { deps } = fake();
    const sender = await deviceFor(deps, 7);
    const google = await googleCaller('sue@example.org', {});
    const { deviceId: sue } = await enrol(deps, google, { publicKey: newPublicKey(), platform: 'android', label: 'Pixel' });

    await sendMessage(deps, deviceCaller(sender, 7), { id: newMessageId(Date.now()),
      memberIds: [8],
      committees: ['public-information'],
      envelopes: [envelope(sue)],
    });

    const stored: unknown[] = [];
    for (const collection of ['devices', 'messages', 'spentIdentities', 'rateLimits']) {
      for (const doc of (await db.collection(collection).get()).docs) {
        stored.push(doc.data());
      }
    }
    stored.push((await db.collection('devices').doc(sue).collection('inbox').get()).docs.map((doc) => doc.data()));

    const everything = JSON.stringify(stored);

    expect(everything).not.toContain('example.org');
    expect(everything).not.toContain('public-information');
    expect((await auth.listUsers()).users.filter((user) => user.email !== undefined)).toEqual([]);
  });
});

describe('the admin screens', () => {
  test('Compose can resolve and send to everyone', async () => {
    const { deps, audiences } = fake();
    const dave = await deviceFor(deps, 7);
    const sue = await deviceFor(deps, 8);

    const answer = await adminResolve(deps, { everyone: true });
    expect(audiences[0].origin).toBe('admin');
    expect(answer.reachable).toBe(2);

    const { id } = await adminSend(deps, { id: newMessageId(Date.now()), everyone: true, envelopes: [envelope(dave), envelope(sue)] });
    const message = await db.collection('messages').doc(String(id)).get();
    expect(message.get('senderMemberId')).toBe(0);
    expect(message.get('audience')).toBe('everyone');
  });

  test('revoking a member reaches all their live devices and keeps the rows', async () => {
    const { deps } = fake();
    const one = await deviceFor(deps, 8);
    const two = await deviceFor(deps, 8);
    const other = await deviceFor(deps, 7);

    await adminRevokeMember(deps, { memberId: 8 });

    expect((await db.collection('devices').doc(one).get()).get('status')).toBe('revoked');
    expect((await db.collection('devices').doc(two).get()).get('status')).toBe('revoked');
    expect((await db.collection('devices').doc(other).get()).get('status')).toBe('live');
  });

  test('erasure removes the devices altogether', async () => {
    const { deps } = fake();
    const one = await deviceFor(deps, 8);

    await adminRevokeMember(deps, { memberId: 8, remove: true });

    expect((await db.collection('devices').doc(one).get()).exists).toBe(false);
  });

  test('remove takes the row, and a bad id is refused', async () => {
    const { deps } = fake();
    const one = await deviceFor(deps, 8);

    await adminRemove(deps, { deviceId: one });

    expect((await db.collection('devices').doc(one).get()).exists).toBe(false);
    expect(await reasonOf(adminRemove(deps, { deviceId: 'a/b' }))).toBe('fellowship_bad_request');
    expect(await reasonOf(adminRevokeMember(deps, { memberId: 'x' }))).toBe('fellowship_bad_request');
  });
});

describe('pushing', () => {
  const entry = { k: 'wrapped-key', p: 'sealed-payload', senderMemberId: 7 };

  test('a push carries only what is sealed, plus opaque ids', async () => {
    const { deps, pushes } = fake();
    const sue = await deviceFor(deps, 8, 'push-token');

    await pushInboxEntry(deps, sue, 'm1', entry);

    expect(pushes[0].token).toBe('push-token');
    expect(pushes[0].data).toEqual({ v: '1', id: 'm1', s: '7', k: 'wrapped-key', p: 'sealed-payload' });
    expect(Object.keys(pushes[0])).not.toContain('notification');
  });

  test('a device with no token is left to poll', async () => {
    const { deps, pushes } = fake();
    const sue = await deviceFor(deps, 8);

    await pushInboxEntry(deps, sue, 'm1', entry);

    expect(pushes).toEqual([]);
  });

  test('a token FCM no longer recognises is cleared', async () => {
    const { deps } = fake({ pushError: 'messaging/registration-token-not-registered' });
    const sue = await deviceFor(deps, 8, 'push-token');

    await pushInboxEntry(deps, sue, 'm1', entry);

    expect((await db.collection('devices').doc(sue).get()).get('pushToken')).toBeNull();
  });

  test('any other failure keeps the token and does not throw', async () => {
    const { deps } = fake({ pushError: 'messaging/internal-error' });
    const sue = await deviceFor(deps, 8, 'push-token');

    await pushInboxEntry(deps, sue, 'm1', entry);

    expect((await db.collection('devices').doc(sue).get()).get('pushToken')).toBe('push-token');
  });
});

describe('receipts', () => {
  async function counts(before: object | undefined, after: object | undefined) {
    const { deps } = fake();
    const ref = db.collection('messages').doc('m1');
    await ref.set({ receivedCount: 0, readCount: 0 });

    await countReceipt(deps, 'm1', before, after);

    const message = await ref.get();

    return [message.get('receivedCount'), message.get('readCount')];
  }

  test.each([
    ['first received', undefined, { receivedAt: 1 }, [1, 0]],
    ['read without a received first', undefined, { readAt: 1 }, [1, 1]],
    ['read after received', { receivedAt: 1 }, { receivedAt: 1, readAt: 2 }, [0, 1]],
    ['written again', { receivedAt: 1, readAt: 2 }, { receivedAt: 1, readAt: 3 }, [0, 0]],
    ['deleted', { receivedAt: 1 }, undefined, [0, 0]],
  ])('%s', async (_name, before, after, expected) => {
    expect(await counts(before, after)).toEqual(expected);
  });
});

describe('the retention sweep', () => {
  const daysAgo = (days: number) => Timestamp.fromMillis(Date.now() - days * 86400000);

  test('removes what has passed the window, and keeps the rest', async () => {
    const { deps } = fake();
    await db.collection('config').doc('messaging').set({ retentionDays: 180 });
    const inbox = db.collection('devices').doc('d_1').collection('inbox');
    await inbox.doc('old').set({ createdAt: daysAgo(200) });
    await inbox.doc('new').set({ createdAt: daysAgo(10) });
    await db.collection('messages').doc('old').set({ createdAt: daysAgo(200) });
    await db.collection('messages').doc('old').collection('receipts').doc('8').set({ receivedAt: 1 });
    await db.collection('messages').doc('new').set({ createdAt: daysAgo(10) });

    await sweep(deps);

    expect((await inbox.get()).docs.map((doc) => doc.id)).toEqual(['new']);
    expect((await db.collection('messages').get()).docs.map((doc) => doc.id)).toEqual(['new']);
    expect((await db.collection('messages').doc('old').collection('receipts').get()).size).toBe(0);
  });

  test.each([
    ['no window set', undefined],
    ['a window of zero', { retentionDays: 0 }],
  ])('%s keeps messages indefinitely', async (_name, config) => {
    const { deps } = fake();
    if (config !== undefined) {
      await db.collection('config').doc('messaging').set(config);
    }
    await db.collection('messages').doc('old').set({ createdAt: daysAgo(4000) });

    await sweep(deps);

    expect((await db.collection('messages').doc('old').get()).exists).toBe(true);
  });

  test('forgets spent sign-ins once they have expired', async () => {
    const { deps } = fake();
    const now = Math.floor(Date.now() / 1000);
    await db.collection('spentIdentities').doc('old').set({ expireAt: now - 10 });
    await db.collection('spentIdentities').doc('new').set({ expireAt: now + 1000 });

    await sweep(deps);

    expect((await db.collection('spentIdentities').get()).docs.map((doc) => doc.id)).toEqual(['new']);
  });
});

describe('the kill switch', () => {
  test.each([
    ['at the budget', { costAmount: 5, budgetAmount: 5 }, true],
    ['past the budget', { costAmount: 7.5, budgetAmount: 5 }, true],
    ['under the budget', { costAmount: 4.99, budgetAmount: 5 }, false],
    ['with a forecast only', { budgetAmount: 5, alertThresholdExceeded: 1 }, false],
    ['with no budget', { costAmount: 5, budgetAmount: 0 }, false],
    ['with nothing', {}, false],
    ['with only a test request', { check: true }, false],
  ])('%s', (_name, alert, expected) => {
    expect(overBudget(alert)).toBe(expected);
  });
});
