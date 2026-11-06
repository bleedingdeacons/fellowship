import { FieldValue } from 'firebase-admin/firestore';
import { HttpsError } from 'firebase-functions/v2/https';
import { ENVELOPE_MAX_LENGTH, IN_QUERY_LIMIT, SEND_MAX, SEND_WINDOW_SECONDS } from './config';
import { Caller, Deps, nowSeconds } from './deps';
import { requireLiveDevice } from './devices';
import type { AudienceQuery } from './fellowship';

/**
 * Sending a message end to end encrypted.
 *
 * The phone asks who a message reaches, seals one envelope to each device, and
 * hands the envelopes back. The server still does the addressing: it works the
 * audience out again and refuses a set that does not match, so a client cannot
 * add a device or quietly leave one out. It never sees the message.
 *
 * Nothing readable is stored. A message records the kind of audience rather than
 * which committees, because a committee's slug says what it is.
 */

export interface Reach {
  devices: { deviceId: string; memberId: number; publicKey: string }[];
  memberIds: number[];
}

interface Envelope {
  deviceId: string;
  k: string;
  p: string;
}

type Data = Record<string, unknown>;

export async function resolveAudience(deps: Deps, caller: Caller | undefined, data: Data) {
  const device = await requireLiveDevice(deps, caller);
  const reach = await reachOf(deps, memberAudience(device.memberId, data));

  return summary(reach);
}

export async function sendMessage(deps: Deps, caller: Caller | undefined, data: Data) {
  const device = await requireLiveDevice(deps, caller);

  await spendAllowance(deps, device.deviceId);

  const query = memberAudience(device.memberId, data);

  return deliver(deps, query, device.memberId, data.envelopes);
}

export async function reachOf(deps: Deps, query: AudienceQuery): Promise<Reach> {
  const memberIds = await deps.fellowship.audience(query);
  const db = deps.db.collection('devices');
  const devices: Reach['devices'] = [];

  for (let i = 0; i < memberIds.length; i += IN_QUERY_LIMIT) {
    const chunk = memberIds.slice(i, i + IN_QUERY_LIMIT);
    const snapshot = await db.where('memberId', 'in', chunk).where('status', '==', 'live').get();

    for (const doc of snapshot.docs) {
      devices.push({ deviceId: doc.id, memberId: doc.get('memberId'), publicKey: doc.get('publicKey') });
    }
  }

  return { devices, memberIds };
}

export function summary(reach: Reach) {
  const reached = new Set(reach.devices.map((device) => device.memberId));

  return {
    devices: reach.devices,
    members: reach.memberIds.length,
    reachable: reached.size,
  };
}

/**
 * Re-resolves and compares, then writes. Used by a handset and, with an admin
 * audience, by the Compose screen.
 */
export async function deliver(deps: Deps, query: AudienceQuery, senderMemberId: number, envelopes: unknown) {
  const sealed = requireEnvelopes(envelopes);
  const reach = await reachOf(deps, query);

  if (reach.devices.length === 0) {
    throw new HttpsError('failed-precondition', 'None of those members have Link yet.', {
      reason: 'fellowship_no_reachable_members',
    });
  }

  const expected = new Set(reach.devices.map((device) => device.deviceId));
  const offered = new Set(sealed.map((envelope) => envelope.deviceId));

  if (
    offered.size !== sealed.length
    || expected.size !== offered.size
    || [...expected].some((deviceId) => !offered.has(deviceId))
  ) {
    throw new HttpsError('failed-precondition', 'Who this message reaches has changed.', {
      reason: 'fellowship_stale_audience',
    });
  }

  const recipientMemberIds = [...new Set(reach.devices.map((device) => device.memberId))];
  const message = deps.db.collection('messages').doc();
  const writer = deps.db.bulkWriter();

  // The message first: a receipt is checked against it, and an inbox entry that
  // arrives first could be acknowledged before there is anything to count.
  await message.create({
    senderMemberId,
    audience: audienceKind(query),
    recipientMemberIds,
    recipientCount: recipientMemberIds.length,
    receivedCount: 0,
    readCount: 0,
    createdAt: FieldValue.serverTimestamp(),
  });

  for (const envelope of sealed) {
    writer.create(deps.db.collection('devices').doc(envelope.deviceId).collection('inbox').doc(message.id), {
      k: envelope.k,
      p: envelope.p,
      senderMemberId,
      createdAt: FieldValue.serverTimestamp(),
    });
  }

  await writer.close();

  return {
    id: message.id,
    members: reach.memberIds.length,
    reachable: recipientMemberIds.length,
  };
}

function memberAudience(senderMemberId: number, data: Data): AudienceQuery {
  return { origin: 'member', senderMemberId, ...audienceInput(data) };
}

export function audienceInput(data: Data): Pick<AudienceQuery, 'memberIds' | 'committees' | 'gsrs'> {
  const memberIds = Array.isArray(data.memberIds)
    ? data.memberIds.filter((id): id is number => Number.isInteger(id))
    : undefined;

  const committees = Array.isArray(data.committees)
    ? data.committees.filter((slug): slug is string => typeof slug === 'string')
    : undefined;

  return { memberIds, committees, gsrs: data.gsrs === true ? true : undefined };
}

function audienceKind(query: AudienceQuery): string {
  if (query.everyone === true) {
    return 'everyone';
  }

  const part = (query.committees?.length ?? 0) > 0 || query.gsrs === true;
  const named = (query.memberIds?.length ?? 0) > 0;

  if (part && named) {
    return 'mixed';
  }

  return part ? 'part' : 'members';
}

function requireEnvelopes(value: unknown): Envelope[] {
  const refused = new HttpsError('invalid-argument', 'That message could not be read.', {
    reason: 'fellowship_bad_envelope',
  });

  if (!Array.isArray(value) || value.length === 0) {
    throw refused;
  }

  return value.map((item: Record<string, unknown>) => {
    const { deviceId, k, p } = item ?? {};

    if (
      typeof deviceId !== 'string' || deviceId === '' || deviceId.includes('/')
      || typeof k !== 'string' || k === ''
      || typeof p !== 'string' || p === ''
      || k.length + p.length > ENVELOPE_MAX_LENGTH
    ) {
      throw refused;
    }

    return { deviceId, k, p };
  });
}

/** The same allowance as a send through Fellowship: 20 in 15 minutes. */
async function spendAllowance(deps: Deps, deviceId: string): Promise<void> {
  const ref = deps.db.collection('rateLimits').doc(deviceId);
  const now = nowSeconds(deps);

  await deps.db.runTransaction(async (tx) => {
    const doc = await tx.get(ref);
    const windowStart = Number(doc.get('windowStart') ?? 0);
    const inWindow = doc.exists && now - windowStart < SEND_WINDOW_SECONDS;
    const count = inWindow ? Number(doc.get('count') ?? 0) : 0;

    if (count >= SEND_MAX) {
      throw new HttpsError('resource-exhausted', 'Too many messages sent from this device. Please wait a few minutes.', {
        reason: 'fellowship_rate_limited',
      });
    }

    tx.set(ref, { windowStart: inWindow ? windowStart : now, count: count + 1 });
  });
}
