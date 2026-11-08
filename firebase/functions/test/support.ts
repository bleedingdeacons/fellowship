import { createSign, generateKeyPairSync } from 'node:crypto';
import { getApps, initializeApp } from 'firebase-admin/app';
import { DecodedIdToken, getAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';
import { HttpsError } from 'firebase-functions/v2/https';
import { verifiedAttestations } from '../src/attestation';
import { ATTESTATION_AUDIENCE, SERVICE_ACCOUNT } from '../src/config';
import { Caller, Deps } from '../src/deps';

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

/** Stands in for the service account's key, which only Fellowship and Google hold. */
const signingKey = generateKeyPairSync('rsa', { modulusLength: 2048 });
export const SIGNING_KID = 'test-key';

/** The certificates Google publishes for the account, as the Functions fetch them. */
export const certificates = async () => ({
  [SIGNING_KID]: signingKey.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
});

/** A statement signed as Fellowship signs one. Change anything with `claims`, or remove it with undefined. */
export function sign(claims: Record<string, unknown>, options: { kid?: string; key?: 'genuine' | 'forged' } = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = Object.fromEntries(
    Object.entries({ iss: SERVICE_ACCOUNT, aud: ATTESTATION_AUDIENCE, iat: now, exp: now + 300, ...claims })
      .filter(([, value]) => value !== undefined),
  );

  const head = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: options.kid ?? SIGNING_KID })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const key = options.key === 'forged' ? generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey : signingKey.privateKey;
  const signature = createSign('RSA-SHA256').update(`${head}.${body}`).sign(key).toString('base64url');

  return `${head}.${body}.${signature}`;
}

export interface Fake {
  deps: Deps;
  pushes: Record<string, unknown>[];
}

interface StandIn {
  addresses: Record<string, number>;
  admitted: number[];
}

/** What each fake's Fellowship admits, for the statements it signs. */
const standIns = new WeakMap<Deps, StandIn>();

/**
 * Fellowship stood in for: `addresses` maps an address to a member id, and only
 * ids in `admitted` are let in. It signs what the real routes would sign, with
 * the sender left out of an audience, and nothing for somebody it refuses.
 */
export function fake(options: { admitted?: number[]; pushError?: string } = {}): Fake {
  const pushes: Record<string, unknown>[] = [];

  const deps: Deps = {
    db,
    auth,
    attestations: verifiedAttestations(certificates, () => Date.now()),
    push: async (message) => {
      if (options.pushError !== undefined) {
        throw Object.assign(new Error('push failed'), { code: options.pushError });
      }

      pushes.push(message as unknown as Record<string, unknown>);

      return 'sent';
    },
    now: () => Date.now(),
  };

  standIns.set(deps, {
    addresses: { 'dave@example.org': 7, 'sue@example.org': 8, 'pat@example.org': 10 },
    admitted: options.admitted ?? [7, 8, 10],
  });

  return { pushes, deps };
}

/** `data` with what `/attest/member` would answer this caller, if anything. */
export function withMember(deps: Deps, caller: Caller | undefined, data: Record<string, unknown>): Record<string, unknown> {
  const standIn = standIns.get(deps);
  if (caller === undefined || standIn === undefined || 'attestation' in data) {
    return data;
  }

  const { token } = caller;
  const memberId = typeof token.memberId === 'number'
    ? token.memberId
    : standIn.addresses[String(token.email ?? '').toLowerCase()] ?? 0;

  if (!standIn.admitted.includes(memberId)) {
    return data;
  }

  return { ...data, attestation: sign({ kind: 'member', sub: caller.uid, memberId }) };
}

/** `data` with what `/attest/audience` would answer this device, if anything. */
export function withAudience(deps: Deps, caller: Caller | undefined, data: Record<string, unknown>): Record<string, unknown> {
  const standIn = standIns.get(deps);
  if (caller === undefined || standIn === undefined || 'attestation' in data) {
    return data;
  }

  const senderMemberId = Number(caller.token.memberId);
  const named = Array.isArray(data.memberIds) ? (data.memberIds as number[]) : [];
  const part = (Array.isArray(data.committees) && data.committees.length > 0) || data.gsrs === true;
  const memberIds = named.filter((id) => standIn.admitted.includes(id) && id !== senderMemberId);

  if (memberIds.length === 0) {
    return data;
  }

  const audience = part ? (named.length > 0 ? 'mixed' : 'part') : 'members';

  return { ...data, attestation: sign({ kind: 'audience', sub: caller.uid, senderMemberId, memberIds, audience }) };
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
