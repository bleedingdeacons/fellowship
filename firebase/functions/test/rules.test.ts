import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  assertFails,
  assertSucceeds,
  initializeTestEnvironment,
  RulesTestEnvironment,
} from '@firebase/rules-unit-testing';
import { collection, doc, getDoc, getDocs, query, setDoc, updateDoc, where } from 'firebase/firestore';
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'vitest';
import { PROJECT } from './support';

let env: RulesTestEnvironment;

const NOW = Math.floor(Date.now() / 1000);

beforeAll(async () => {
  const [host, port] = String(process.env.FIRESTORE_EMULATOR_HOST).split(':');

  env = await initializeTestEnvironment({
    projectId: PROJECT,
    firestore: {
      host,
      port: Number(port),
      rules: readFileSync(resolve(__dirname, '../../firestore.rules'), 'utf8'),
    },
  });
});

afterAll(async () => {
  await env.cleanup();
});

beforeEach(async () => {
  await env.clearFirestore();

  await env.withSecurityRulesDisabled(async (context) => {
    const db = context.firestore();
    const device = (memberId: number, status: string, tokensValidAfter = 0) => ({
      memberId,
      status,
      tokensValidAfter,
      publicKey: 'key',
      pushToken: 'push',
      keyFault: false,
    });

    await setDoc(doc(db, 'devices/d_dave'), device(7, 'live'));
    await setDoc(doc(db, 'devices/d_sue'), device(8, 'live'));
    await setDoc(doc(db, 'devices/d_gone'), device(7, 'revoked'));
    await setDoc(doc(db, 'devices/d_moved'), device(7, 'live', NOW));
    await setDoc(doc(db, 'devices/d_dave/inbox/m1'), { k: 'k', p: 'p', senderMemberId: 8 });
    await setDoc(doc(db, 'devices/d_gone/inbox/m1'), { k: 'k', p: 'p', senderMemberId: 8 });
    await setDoc(doc(db, 'messages/m1'), { senderMemberId: 8, recipientMemberIds: [7], receivedCount: 0, readCount: 0 });
    await setDoc(doc(db, 'config/messaging'), { retentionDays: 180 });
    await setDoc(doc(db, 'spentIdentities/s1'), { expireAt: NOW });
    await setDoc(doc(db, 'rateLimits/d_dave'), { count: 1 });
  });
});

function as(deviceId: string, memberId: number, claims: Record<string, unknown> = {}) {
  return env.authenticatedContext(deviceId, { kind: 'device', memberId, auth_time: NOW - 60, ...claims }).firestore();
}

describe('a device', () => {
  test('reads itself and its inbox', async () => {
    const db = as('d_dave', 7);

    await assertSucceeds(getDoc(doc(db, 'devices/d_dave')));
    await assertSucceeds(getDoc(doc(db, 'devices/d_dave/inbox/m1')));
    await assertSucceeds(getDocs(collection(db, 'devices/d_dave/inbox')));
  });

  test('cannot read another device or its inbox', async () => {
    const db = as('d_dave', 7);

    await assertFails(getDoc(doc(db, 'devices/d_sue')));
    await assertFails(getDocs(collection(db, 'devices/d_sue/inbox')));
    await assertFails(getDocs(collection(db, 'devices')));
  });

  test('may change only its housekeeping', async () => {
    const db = as('d_dave', 7);

    await assertSucceeds(updateDoc(doc(db, 'devices/d_dave'), { pushToken: 'new', keyFault: true, lastSeenAt: NOW }));

    for (const change of [{ status: 'revoked' }, { memberId: 8 }, { publicKey: 'other' }, { tokensValidAfter: 1 }]) {
      await assertFails(updateDoc(doc(db, 'devices/d_dave'), change));
    }
  });

  test('cannot write to its inbox, or create a device or a message', async () => {
    const db = as('d_dave', 7);

    await assertFails(setDoc(doc(db, 'devices/d_dave/inbox/m2'), { k: 'k', p: 'p' }));
    await assertFails(setDoc(doc(db, 'devices/d_new'), { memberId: 7, status: 'live' }));
    await assertFails(setDoc(doc(db, 'messages/m2'), { senderMemberId: 7 }));
  });
});

describe('cutting a device off', () => {
  test('a revoked device reads nothing, with a token that has not expired', async () => {
    const db = as('d_gone', 7);

    await assertFails(getDoc(doc(db, 'devices/d_gone')));
    await assertFails(getDocs(collection(db, 'devices/d_gone/inbox')));
    await assertFails(updateDoc(doc(db, 'devices/d_gone'), { pushToken: 'new' }));
  });

  test('after a takeover the old phone reads nothing, and the new one does', async () => {
    await assertFails(getDoc(doc(as('d_moved', 7, { auth_time: NOW - 1 }), 'devices/d_moved')));
    await assertSucceeds(getDoc(doc(as('d_moved', 7, { auth_time: NOW + 1 }), 'devices/d_moved')));
  });
});

describe('who else is refused', () => {
  test('nobody signed in reads anything', async () => {
    const db = env.unauthenticatedContext().firestore();

    await assertFails(getDoc(doc(db, 'devices/d_dave')));
    await assertFails(getDoc(doc(db, 'messages/m1')));
  });

  test('a signed-in identity that is not a device reads nothing', async () => {
    const db = env.authenticatedContext('d_dave', { memberId: 7, auth_time: NOW }).firestore();

    await assertFails(getDoc(doc(db, 'devices/d_dave')));
  });

  test('a device-shaped token with no device reads nothing', async () => {
    await assertFails(getDoc(doc(as('d_nobody', 7), 'devices/d_nobody')));
  });

  test('nothing private can be read or written by a device', async () => {
    const db = as('d_dave', 7);

    await assertFails(getDoc(doc(db, 'config/messaging')));
    await assertFails(getDoc(doc(db, 'spentIdentities/s1')));
    await assertFails(getDoc(doc(db, 'rateLimits/d_dave')));
    await assertFails(setDoc(doc(db, 'rateLimits/d_dave'), { count: 0 }));
    await assertFails(setDoc(doc(db, 'config/messaging'), { retentionDays: 0 }));
  });
});

describe('messages and receipts', () => {
  test('a sender reads their own, and nobody else does', async () => {
    await assertSucceeds(getDoc(doc(as('d_sue', 8), 'messages/m1')));
    await assertSucceeds(getDocs(query(collection(as('d_sue', 8), 'messages'), where('senderMemberId', '==', 8))));
    await assertFails(getDoc(doc(as('d_dave', 7), 'messages/m1')));
    await assertFails(getDocs(collection(as('d_sue', 8), 'messages')));
  });

  test('a recipient writes their own receipt', async () => {
    const receipt = doc(as('d_dave', 7), 'messages/m1/receipts/7');

    await assertSucceeds(setDoc(receipt, { receivedAt: NOW }));
    await assertSucceeds(updateDoc(receipt, { readAt: NOW }));
  });

  test('nobody writes a receipt for somebody else, or for a message not addressed to them', async () => {
    await assertFails(setDoc(doc(as('d_dave', 7), 'messages/m1/receipts/8'), { receivedAt: NOW }));
    await assertFails(setDoc(doc(as('d_sue', 8), 'messages/m1/receipts/8'), { receivedAt: NOW }));
  });

  test('a receipt carries only its two times', async () => {
    await assertFails(setDoc(doc(as('d_dave', 7), 'messages/m1/receipts/7'), { receivedAt: NOW, extra: 'x' }));
  });

  test('a revoked device cannot write a receipt', async () => {
    await assertFails(setDoc(doc(as('d_gone', 7), 'messages/m1/receipts/7'), { receivedAt: NOW }));
  });

  test('a phone cannot read receipts or change the counts', async () => {
    await assertFails(getDoc(doc(as('d_sue', 8), 'messages/m1/receipts/7')));
    await assertFails(updateDoc(doc(as('d_sue', 8), 'messages/m1'), { readCount: 99 }));
  });
});

test('the emulator is what these ran against', () => {
  expect(process.env.FIRESTORE_EMULATOR_HOST).toBeTruthy();
});
