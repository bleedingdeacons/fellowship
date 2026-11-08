import { HttpsError } from 'firebase-functions/v2/https';
import { describe, expect, test } from 'vitest';
import { verifiedAttestations } from '../src/attestation';
import { certificates, reasonOf, sign } from './support';

/**
 * What a phone carries from Fellowship. Signed here with a test key standing in for
 * the service account's, and checked against its public half, as the Functions check
 * the real one against Google's copy.
 */

const attestations = verifiedAttestations(certificates, () => Date.now());
const now = Math.floor(Date.now() / 1000);

const member = (claims: Record<string, unknown> = {}, options = {}) =>
  sign({ kind: 'member', sub: 'uid-1', memberId: 7, ...claims }, options);

const audience = (claims: Record<string, unknown> = {}) =>
  sign({ kind: 'audience', sub: 'd_abc', senderMemberId: 7, memberIds: [8, 10], audience: 'members', ...claims });

describe('a membership statement', () => {
  test('names the member when it is genuine and for this sign-in', async () => {
    expect(await attestations.member(member(), 'uid-1')).toEqual({ memberId: 7 });
  });

  test.each([
    ['missing', undefined],
    ['not a string', 42],
    ['not a JWT', 'abc'],
    ['for another sign-in', member({ sub: 'uid-2' })],
    ['about an audience', member({ kind: 'audience' })],
    ['for another project', member({ aud: 'fellowship-functions:somebody-else' })],
    ['from another account', member({ iss: 'someone@elsewhere.iam.gserviceaccount.com' })],
    ['expired', member({ iat: now - 900, exp: now - 600 })],
    ['from the future', member({ iat: now + 600, exp: now + 900 })],
    ['longer-lived than Fellowship signs', member({ exp: now + 3600 })],
    ['without an expiry', member({ exp: undefined })],
    ['with no member', member({ memberId: undefined })],
    ['with a member that is not a number', member({ memberId: '7' })],
    ['with member zero', member({ memberId: 0 })],
    ['signed with another key', member({}, { key: 'forged' })],
    ['signed with a key Google has never published', member({}, { kid: 'unknown' })],
  ])('is refused when %s', async (_name, token) => {
    expect(await reasonOf(attestations.member(token, 'uid-1'))).toBe('fellowship_bad_attestation');
  });

  test('is refused when signed with no algorithm at all', async () => {
    const [, body] = member().split('.');
    const head = Buffer.from(JSON.stringify({ alg: 'none', kid: 'test-key' })).toString('base64url');

    expect(await reasonOf(attestations.member(`${head}.${body}.`, 'uid-1'))).toBe('fellowship_bad_attestation');
  });

  test('is refused when its claims were changed after signing', async () => {
    const [head, , signature] = member().split('.');
    const body = Buffer.from(JSON.stringify({ kind: 'member', sub: 'uid-1', memberId: 8 })).toString('base64url');

    expect(await reasonOf(attestations.member(`${head}.${body}.${signature}`, 'uid-1'))).toBe('fellowship_bad_attestation');
  });
});

describe('an audience statement', () => {
  test('names who it reaches when genuine and for this device', async () => {
    expect(await attestations.audience(audience(), 'd_abc')).toEqual({
      senderMemberId: 7,
      memberIds: [8, 10],
      audience: 'members',
    });
  });

  test.each([
    ['for another device', audience({ sub: 'd_other' })],
    ['about a member', audience({ kind: 'member' })],
    ['reaching nobody', audience({ memberIds: [] })],
    ['with ids that are not ids', audience({ memberIds: [8, 'x'] })],
    ['with no sender', audience({ senderMemberId: undefined })],
    ['of an unknown kind', audience({ audience: 'galaxy' })],
  ])('is refused when %s', async (_name, token) => {
    expect(await reasonOf(attestations.audience(token, 'd_abc'))).toBe('fellowship_bad_attestation');
  });
});

describe('Google\'s keys', () => {
  test('are asked again once when a key id is new', async () => {
    const asked: boolean[] = [];
    const rotating = verifiedAttestations(async (refresh) => {
      asked.push(refresh);

      return refresh ? certificates() : {};
    }, () => Date.now());

    expect(await rotating.member(member(), 'uid-1')).toEqual({ memberId: 7 });
    expect(asked).toEqual([false, true]);
  });

  test('that cannot be fetched mean try again, not a refusal', async () => {
    const unreachable = verifiedAttestations(async () => {
      throw new Error('offline');
    }, () => Date.now());

    const error = await unreachable.member(member(), 'uid-1').catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(HttpsError);
    expect((error as HttpsError).code).toBe('unavailable');
  });
});
