import { createPublicKey, createVerify, KeyObject } from 'node:crypto';
import * as logger from 'firebase-functions/logger';
import { HttpsError } from 'firebase-functions/v2/https';
import { ATTESTATION_AUDIENCE, ATTESTATION_MAX_LIFETIME_SECONDS, CLOCK_SKEW_SECONDS, SERVICE_ACCOUNT } from './config';

/**
 * What Fellowship has decided, signed, and carried here by the phone.
 *
 * The member list stays in WordPress, so only Fellowship can say whether a sign-in
 * is a member or who a message reaches. The Functions used to ask it, but its host
 * challenges calls from Google Cloud's shared addresses. So the phone asks
 * Fellowship's `/attest/*` routes and passes on what they sign. Nothing here calls
 * the site.
 *
 * A statement is a JWT signed RS256 by the service account Fellowship holds, which
 * is also who these Functions run as. It is checked against that account's public
 * keys at Google, and it is good for five minutes, for one sign-in or one device:
 * `sub` has to be the caller's own uid.
 */

export interface MemberStatement {
  memberId: number;
}

export interface AudienceStatement {
  senderMemberId: number;
  memberIds: number[];
  audience: AudienceKind;
}

export const AUDIENCE_KINDS = ['everyone', 'members', 'part', 'mixed'] as const;
export type AudienceKind = (typeof AUDIENCE_KINDS)[number];

export interface Attestations {
  /** Which member this sign-in is. */
  member(token: unknown, uid: string): Promise<MemberStatement>;
  /** Who this device's message reaches. */
  audience(token: unknown, deviceId: string): Promise<AudienceStatement>;
}

/** Key id to PEM, as Google publishes a service account's certificates. */
export type Certificates = (refresh: boolean) => Promise<Record<string, string>>;

/** More than a fellowship has members, so a list this long is a mistake. */
const MAX_MEMBER_IDS = 5000;

export function verifiedAttestations(
  certificates: Certificates,
  now: () => number,
  issuer: string = SERVICE_ACCOUNT,
  audience: string = ATTESTATION_AUDIENCE,
): Attestations {
  async function claims(token: unknown, kind: string, subject: string): Promise<Record<string, unknown>> {
    if (typeof token !== 'string') {
      throw badAttestation();
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      throw badAttestation();
    }

    const header = decode(parts[0]);
    const payload = decode(parts[1]);
    if (header?.alg !== 'RS256' || typeof header.kid !== 'string' || payload === undefined) {
      throw badAttestation();
    }

    const key = await keyFor(header.kid);
    const signature = Buffer.from(parts[2], 'base64url');
    const genuine = createVerify('RSA-SHA256').update(`${parts[0]}.${parts[1]}`).verify(key, signature);
    if (!genuine) {
      throw badAttestation();
    }

    const seconds = Math.floor(now() / 1000);
    const { iat, exp } = payload;

    if (
      payload.iss !== issuer
      || payload.aud !== audience
      || payload.kind !== kind
      || payload.sub !== subject
      || typeof iat !== 'number'
      || typeof exp !== 'number'
      || exp - iat > ATTESTATION_MAX_LIFETIME_SECONDS
      || iat > seconds + CLOCK_SKEW_SECONDS
      || exp < seconds - CLOCK_SKEW_SECONDS
    ) {
      throw badAttestation();
    }

    return payload;
  }

  async function keyFor(kid: string): Promise<KeyObject> {
    let pem = (await fetchCertificates(false))[kid];
    pem ??= (await fetchCertificates(true))[kid];

    if (pem === undefined) {
      throw badAttestation();
    }

    return createPublicKey(pem);
  }

  async function fetchCertificates(refresh: boolean): Promise<Record<string, string>> {
    try {
      return await certificates(refresh);
    } catch (error) {
      logger.error('Could not fetch the service account\'s public keys', { error: String(error) });

      throw new HttpsError('unavailable', 'Please try again.', { reason: 'fellowship_unavailable' });
    }
  }

  return {
    async member(token, uid) {
      const { memberId } = await claims(token, 'member', uid);

      if (!isMemberId(memberId)) {
        throw badAttestation();
      }

      return { memberId };
    },

    async audience(token, deviceId) {
      const statement = await claims(token, 'audience', deviceId);
      const memberIds = requireMemberIds(statement.memberIds, badAttestation);

      if (!isMemberId(statement.senderMemberId) || !isAudienceKind(statement.audience)) {
        throw badAttestation();
      }

      return { senderMemberId: statement.senderMemberId, memberIds, audience: statement.audience };
    },
  };
}

/**
 * The service account's certificates from Google, kept for as long as Google says.
 * Asked again early only when a key id isn't among them, at most once a minute.
 */
export function googleCertificates(account: string = SERVICE_ACCOUNT): Certificates {
  const url = `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(account)}`;
  let cached: Record<string, string> | undefined;
  let fetchedAt = 0;
  let expiresAt = 0;

  return async (refresh) => {
    const now = Date.now();
    const stale = cached === undefined || now >= expiresAt || (refresh && now - fetchedAt > 60_000);

    if (stale) {
      const response = await fetch(url, { signal: AbortSignal.timeout(10_000) });
      if (!response.ok) {
        throw new Error(`Google answered ${response.status}`);
      }

      const maxAge = /max-age=(\d+)/.exec(response.headers.get('cache-control') ?? '')?.[1];

      cached = (await response.json()) as Record<string, string>;
      fetchedAt = now;
      expiresAt = now + (maxAge === undefined ? 300 : Number(maxAge)) * 1000;
    }

    return cached as Record<string, string>;
  };
}

/** A non-empty list of member ids, each once. */
export function requireMemberIds(value: unknown, refused: () => HttpsError): number[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_MEMBER_IDS || !value.every(isMemberId)) {
    throw refused();
  }

  return [...new Set(value as number[])];
}

export function isAudienceKind(value: unknown): value is AudienceKind {
  return typeof value === 'string' && (AUDIENCE_KINDS as readonly string[]).includes(value);
}

function isMemberId(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function decode(part: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));

    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function badAttestation(): HttpsError {
  return new HttpsError('permission-denied', 'The intergroup\'s answer could not be checked. Please try again.', {
    reason: 'fellowship_bad_attestation',
  });
}
