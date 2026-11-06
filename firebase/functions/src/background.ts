import { FieldValue, Timestamp } from 'firebase-admin/firestore';
import * as logger from 'firebase-functions/logger';
import { Deps, nowSeconds } from './deps';

/**
 * What runs without anybody calling it: pushes, the counts behind the ticks and
 * the retention sweep.
 */

const UNREGISTERED_CODES = [
  'messaging/registration-token-not-registered',
  'messaging/invalid-registration-token',
];

const SECONDS_IN_A_DAY = 86400;

/**
 * Pushes an inbox entry to its device.
 *
 * <b>Nothing readable goes through Google.</b> The sender's name and everything
 * else is inside the sealed payload. `s` is an opaque member id, which lets the
 * phone check the sealed sender against what the server recorded.
 *
 * A failed push is logged and left. The entry is safe in the inbox and the phone
 * polls, so push is the fast path rather than the reliable one.
 */
export async function pushInboxEntry(
  deps: Deps,
  deviceId: string,
  messageId: string,
  entry: { k: string; p: string; senderMemberId: number },
): Promise<void> {
  const device = deps.db.collection('devices').doc(deviceId);
  const token = (await device.get()).get('pushToken');

  if (typeof token !== 'string' || token === '') {
    return;
  }

  // Every value in an FCM data payload must be a string.
  const envelope = {
    v: '1',
    id: messageId,
    s: String(entry.senderMemberId),
    k: entry.k,
    p: entry.p,
  };

  try {
    await deps.push({
      token,
      data: envelope,
      // Wakes the app from Doze. At normal priority a data message can wait for
      // a maintenance window, which looks the same as not arriving.
      android: { priority: 'high' },
      apns: {
        // 5 is what APNs requires for a silent push; it rejects 10 without an alert.
        headers: { 'apns-priority': '5', 'apns-push-type': 'background' },
        payload: { aps: { contentAvailable: true }, ...envelope },
      },
    });
  } catch (error) {
    if (UNREGISTERED_CODES.includes((error as { code?: string }).code ?? '')) {
      await device.update({ pushToken: null });
      return;
    }

    logger.warn('A push failed; the phone will collect the message by polling', { error: String(error) });
  }
}

/** Keeps a message's counts in step with its receipts. Reading counts as receiving. */
export async function countReceipt(
  deps: Deps,
  messageId: string,
  before: { receivedAt?: unknown; readAt?: unknown } | undefined,
  after: { receivedAt?: unknown; readAt?: unknown } | undefined,
): Promise<void> {
  if (after === undefined) {
    return;
  }

  const update: Record<string, FieldValue> = {};

  if (!before?.receivedAt && !before?.readAt && (after.receivedAt || after.readAt)) {
    update.receivedCount = FieldValue.increment(1);
  }
  if (!before?.readAt && after.readAt) {
    update.readCount = FieldValue.increment(1);
  }

  if (Object.keys(update).length > 0) {
    await deps.db.collection('messages').doc(messageId).update(update);
  }
}

/**
 * Deletes what has passed the site's retention window, and spent sign-ins that
 * can no longer be replayed. With no window set, or zero, messages are kept.
 */
export async function sweep(deps: Deps): Promise<void> {
  const now = nowSeconds(deps);
  const writer = deps.db.bulkWriter();

  const spent = await deps.db.collection('spentIdentities').where('expireAt', '<', now).get();
  spent.docs.forEach((doc) => writer.delete(doc.ref));

  const config = await deps.db.collection('config').doc('messaging').get();
  const days = Number(config.get('retentionDays') ?? 0);

  if (days > 0) {
    const cutoff = Timestamp.fromMillis((now - days * SECONDS_IN_A_DAY) * 1000);

    const entries = await deps.db.collectionGroup('inbox').where('createdAt', '<', cutoff).get();
    entries.docs.forEach((doc) => writer.delete(doc.ref));

    const messages = await deps.db.collection('messages').where('createdAt', '<', cutoff).get();
    await Promise.all(messages.docs.map((doc) => deps.db.recursiveDelete(doc.ref)));
  }

  await writer.close();
}
