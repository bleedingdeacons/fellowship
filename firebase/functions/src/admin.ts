import { HttpsError } from 'firebase-functions/v2/https';
import { isAudienceKind, requireMemberIds } from './attestation';
import { Deps } from './deps';
import { removeDevice, revokeDevice } from './devices';
import { Audience, deliver, reachOf, summary } from './messaging';

/**
 * What Fellowship's admin screens call. Only its service account can invoke
 * these, which Cloud Run enforces before any of this runs.
 *
 * Compose seals in PHP, so these never see a message either. Fellowship works out
 * who it reaches, and sends the member ids and the kind of audience; with only
 * Fellowship able to call, they are taken as given.
 */

type Data = Record<string, unknown>;

export async function adminRevoke(deps: Deps, data: Data) {
  await revokeDevice(deps, requireDeviceId(data.deviceId));

  return {};
}

export async function adminRemove(deps: Deps, data: Data) {
  await removeDevice(deps, requireDeviceId(data.deviceId));

  return {};
}

/**
 * Cuts off every device of a member nobody should be reaching any more.
 * `remove` is for erasure: their devices and inboxes go altogether, rather than
 * staying as a record.
 */
export async function adminRevokeMember(deps: Deps, data: Data) {
  if (!Number.isInteger(data.memberId) || (data.memberId as number) <= 0) {
    throw new HttpsError('invalid-argument', 'Which member?', { reason: 'fellowship_bad_request' });
  }

  const devices = await deps.db.collection('devices').where('memberId', '==', data.memberId).get();

  for (const device of devices.docs) {
    if (data.remove === true) {
      await removeDevice(deps, device.id);
    } else if (device.get('status') === 'live') {
      await revokeDevice(deps, device.id);
    }
  }

  return { devices: devices.size };
}

export async function adminResolve(deps: Deps, data: Data) {
  return summary(deps, await reachOf(deps, adminAudience(data).memberIds));
}

export async function adminSend(deps: Deps, data: Data) {
  const senderMemberId = Number.isInteger(data.senderMemberId) ? (data.senderMemberId as number) : 0;

  return deliver(deps, adminAudience(data), senderMemberId, data.id, data.envelopes);
}

function adminAudience(data: Data): Audience {
  const memberIds = requireMemberIds(data.memberIds, () => new HttpsError(
    'invalid-argument',
    'That message would not reach anybody.',
    { reason: 'fellowship_no_recipients' },
  ));

  if (!isAudienceKind(data.audience)) {
    throw new HttpsError('invalid-argument', 'Choose who this message is for.', { reason: 'fellowship_no_audience' });
  }

  return { memberIds, kind: data.audience };
}

function requireDeviceId(value: unknown): string {
  if (typeof value !== 'string' || value === '' || value.includes('/')) {
    throw new HttpsError('invalid-argument', 'Which device?', { reason: 'fellowship_bad_request' });
  }

  return value;
}
