import { generateKeyPairSync } from 'node:crypto';
import { getApps, initializeApp } from 'firebase-admin/app';
import { DecodedIdToken, getAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';
import { HttpsError } from 'firebase-functions/v2/https';
import { Caller, Deps } from '../src/deps';
import type { AudienceQuery, Fellowship, MemberQuery } from '../src/fellowship';

export const PROJECT = 'demo-fellowship';

if (getApps().length === 0) {
  initializeApp({ projectId: PROJECT });
}

export const db = getFirestore();
export const auth = getAuth();

/** Clears both emulators, so each test starts from nothing. */
export async function resetEmulators(): Promise<void> {
  const firestore = process.env.FIRESTORE_EMULATOR_HOST;
  const identity = process.env.FIREBASE_AUTH_EMULATOR_HOST;

  await fetch(`http://${firestore}/emulator/v1/projects/${PROJECT}/databases/(default)/documents`, { method: 'DELETE' });
  await fetch(`http://${identity}/emulator/v1/projects/${PROJECT}/accounts`, {
    method: 'DELETE',
    headers: { Authorization: 'Bearer owner' },
  });
}

export function newPublicKey(): string {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

  return publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
}

export interface Fake {
  deps: Deps;
  pushes: Record<string, unknown>[];
  audiences: AudienceQuery[];
}

/**
 * Fellowship stood in for: `members` maps an address to a member id, and only
 * ids in `admitted` are let in. The audience is whatever a test names, with the
 * sender left out, as the real route does.
 */
export function fake(options: { admitted?: number[]; pushError?: string } = {}): Fake {
  const addresses: Record<string, number> = { 'dave@example.org': 7, 'sue@example.org': 8, 'pat@example.org': 10 };
  const admitted = options.admitted ?? [7, 8, 10];
  const pushes: Record<string, unknown>[] = [];
  const audiences: AudienceQuery[] = [];

  const fellowship: Fellowship = {
    async member(query: MemberQuery) {
      const memberId = query.memberId ?? addresses[query.email ?? ''] ?? 0;

      return { memberId, admitted: admitted.includes(memberId) };
    },
    async audience(query: AudienceQuery) {
      audiences.push(query);

      if (query.everyone === true) {
        return admitted.filter((id) => id !== query.senderMemberId);
      }

      return (query.memberIds ?? []).filter((id) => admitted.includes(id) && id !== query.senderMemberId);
    },
  };

  return {
    pushes,
    audiences,
    deps: {
      db,
      auth,
      fellowship,
      push: async (message) => {
        if (options.pushError !== undefined) {
          throw Object.assign(new Error('push failed'), { code: options.pushError });
        }

        pushes.push(message as unknown as Record<string, unknown>);

        return 'sent';
      },
      now: () => Date.now(),
    },
  };
}

function token(uid: string, claims: Record<string, unknown>): DecodedIdToken {
  const now = Math.floor(Date.now() / 1000);

  return {
    uid,
    sub: uid,
    aud: PROJECT,
    iss: `https://securetoken.google.com/${PROJECT}`,
    iat: now,
    exp: now + 3600,
    auth_time: now,
    firebase: { sign_in_provider: 'custom', identities: {} },
    ...claims,
  } as unknown as DecodedIdToken;
}

let identities = 0;

/** Somebody who has just signed in with Google, with a user the Auth emulator knows. */
export async function googleCaller(email = 'dave@example.org', claims: Record<string, unknown> = {}): Promise<Caller> {
  const uid = `google_${++identities}`;
  await auth.createUser({ uid });

  return {
    uid,
    token: token(uid, {
      email,
      email_verified: true,
      firebase: { sign_in_provider: 'google.com', identities: {} },
      ...claims,
    }),
  };
}

/** Somebody who has just signed in with the token Fellowship mints for a Unity password. */
export async function passwordCaller(memberId: number): Promise<Caller> {
  const uid = `pw_${memberId}_${++identities}`;
  await auth.createUser({ uid });

  return { uid, token: token(uid, { identity: 'password', memberId }) };
}

export function deviceCaller(deviceId: string, memberId: number, claims: Record<string, unknown> = {}): Caller {
  return { uid: deviceId, token: token(deviceId, { kind: 'device', memberId, ...claims }) };
}

/** The `reason` a refusal carries, which is what the app reads. */
export async function reasonOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof HttpsError) {
      return (error.details as { reason?: string } | undefined)?.reason;
    }

    throw error;
  }

  throw new Error('Expected a refusal, and nothing was refused.');
}

export async function userExists(uid: string): Promise<boolean> {
  return auth.getUser(uid).then(() => true, () => false);
}
