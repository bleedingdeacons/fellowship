import { initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';
import { getMessaging } from 'firebase-admin/messaging';
import { onDocumentCreated, onDocumentWritten } from 'firebase-functions/v2/firestore';
import { HttpsError, onCall, onRequest } from 'firebase-functions/v2/https';
import * as logger from 'firebase-functions/logger';
import { onMessagePublished } from 'firebase-functions/v2/pubsub';
import { onSchedule } from 'firebase-functions/v2/scheduler';
import * as admin from './admin';
import { countReceipt, pushInboxEntry, sweep as runSweep } from './background';
import { googleCertificates, verifiedAttestations } from './attestation';
import { KILL_SWITCH_ACCOUNT, REGION, SERVICE_ACCOUNT } from './config';
import { Deps } from './deps';
import * as devices from './devices';
import { BudgetAlert, checkReadiness, detachBilling, overBudget } from './killSwitch';
import * as messaging from './messaging';

initializeApp();

let cached: Deps | undefined;

function deps(): Deps {
  cached ??= {
    db: getFirestore(),
    auth: getAuth(),
    attestations: verifiedAttestations(googleCertificates(), () => Date.now()),
    push: (message) => getMessaging().send(message),
    now: () => Date.now(),
  };

  return cached;
}

// A low ceiling on instances is part of keeping this affordable: a runaway
// client slows down rather than running up a bill.
const common = {
  region: REGION,
  serviceAccount: SERVICE_ACCOUNT,
  memory: '256MiB',
  maxInstances: 5,
} as const;

const data = (request: { data: unknown }) => (request.data ?? {}) as Record<string, unknown>;

// ── What a phone calls ──

export const enrol = onCall(common, (request) => devices.enrol(deps(), request.auth, data(request)));
export const replaceKey = onCall(common, (request) => devices.replaceKey(deps(), request.auth, data(request)));
export const takeOverDevice = onCall(common, (request) => devices.takeOverDevice(deps(), request.auth, data(request)));
export const signOut = onCall(common, (request) => devices.signOut(deps(), request.auth));
export const resolveAudience = onCall(common, (request) => messaging.resolveAudience(deps(), request.auth, data(request)));
export const sendMessage = onCall(common, (request) => messaging.sendMessage(deps(), request.auth, data(request)));

// ── What Fellowship's admin screens call ──

function adminFunction(handler: (deps: Deps, data: Record<string, unknown>) => Promise<unknown>) {
  return onRequest({ ...common, invoker: SERVICE_ACCOUNT }, async (request, response) => {
    if (request.method !== 'POST') {
      response.status(405).json({ reason: 'fellowship_bad_request' });
      return;
    }

    try {
      response.json(await handler(deps(), (request.body ?? {}) as Record<string, unknown>));
    } catch (error) {
      if (error instanceof HttpsError) {
        const reason = (error.details as { reason?: string } | undefined)?.reason;

        response.status(error.httpErrorCode.status).json({ reason, message: error.message });
        return;
      }

      logger.error('An admin function failed', { error: String(error) });
      response.status(500).json({ reason: 'fellowship_internal' });
    }
  });
}

export const adminRevoke = adminFunction(admin.adminRevoke);
export const adminRemove = adminFunction(admin.adminRemove);
export const adminRevokeMember = adminFunction(admin.adminRevokeMember);
export const adminResolve = adminFunction(admin.adminResolve);
export const adminSend = adminFunction(admin.adminSend);

// ── What runs on its own ──

export const onInboxEntry = onDocumentCreated(
  { ...common, document: 'devices/{deviceId}/inbox/{messageId}' },
  async (event) => {
    const entry = event.data?.data();
    if (entry !== undefined) {
      await pushInboxEntry(deps(), event.params.deviceId, event.params.messageId, {
        k: entry.k,
        p: entry.p,
        senderMemberId: entry.senderMemberId,
      });
    }
  },
);

export const onReceipt = onDocumentWritten(
  { ...common, document: 'messages/{messageId}/receipts/{memberId}' },
  async (event) => {
    await countReceipt(deps(), event.params.messageId, event.data?.before.data(), event.data?.after.data());
  },
);

export const sweep = onSchedule(
  { ...common, schedule: 'every day 03:00', timeZone: 'Europe/London' },
  async () => {
    await runSweep(deps());
  },
);

// The budget publishes to this topic once it is connected in the console.
export const budgetAlert = onMessagePublished<BudgetAlert>(
  { ...common, serviceAccount: KILL_SWITCH_ACCOUNT, topic: 'budget-alerts' },
  async (event) => {
    const alert = event.data.message.json;
    const project = String(process.env.GCLOUD_PROJECT);

    if (alert.check === true) {
      await checkReadiness(project);
    } else if (overBudget(alert)) {
      await detachBilling(project);
    }
  },
);
