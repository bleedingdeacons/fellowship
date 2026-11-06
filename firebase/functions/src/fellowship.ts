import { HttpsError } from 'firebase-functions/v2/https';
import { GoogleAuth } from 'google-auth-library';

/**
 * Fellowship's service routes: how the Functions ask about members.
 *
 * The member list stays in WordPress and nothing about a member is copied to
 * Firebase. Answers are opaque ids, so no name or address passes through here
 * on the way back. An email goes in only to ask whose it is.
 */

export interface MemberQuery {
  email?: string;
  memberId?: number;
}

export interface MemberAnswer {
  memberId: number;
  admitted: boolean;
}

export interface AudienceQuery {
  origin: 'member' | 'admin';
  senderMemberId?: number;
  memberIds?: number[];
  committees?: string[];
  gsrs?: boolean;
  everyone?: boolean;
}

export interface Fellowship {
  member(query: MemberQuery): Promise<MemberAnswer>;
  audience(query: AudienceQuery): Promise<number[]>;
}

const TIMEOUT_MS = 15000;

const STATUS_TO_CODE: Record<number, 'invalid-argument' | 'permission-denied' | 'unavailable'> = {
  400: 'invalid-argument',
  403: 'permission-denied',
};

/**
 * @param serviceUrl Fellowship's `/wp-json/fellowship/v1/service`, which is also
 *                   the audience of the token, so the two cannot disagree.
 */
export function httpFellowship(
  serviceUrl: string,
  idToken: (audience: string) => Promise<string> = googleIdToken,
): Fellowship {
  async function post(route: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    let response: Response;
    try {
      response = await fetch(`${serviceUrl}/${route}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${await idToken(serviceUrl)}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      throw new HttpsError('unavailable', 'The intergroup site could not be reached.', {
        reason: 'fellowship_unreachable',
      });
    }

    const answer = (await response.json().catch(() => ({}))) as Record<string, unknown>;

    if (!response.ok) {
      // Fellowship's own refusal goes back to the app unchanged, so it can say
      // the same thing it says today. Anything else is an outage.
      const code = STATUS_TO_CODE[response.status] ?? 'unavailable';
      throw new HttpsError(code, String(answer.message ?? 'The intergroup site refused.'), {
        reason: String(answer.code ?? 'fellowship_refused'),
      });
    }

    return answer;
  }

  return {
    async member(query) {
      const answer = await post('member', {
        email: query.email,
        member_id: query.memberId,
      });

      return { memberId: Number(answer.member_id ?? 0), admitted: answer.admitted === true };
    },

    async audience(query) {
      const answer = await post('audience', {
        origin: query.origin,
        sender_member_id: query.senderMemberId,
        member_ids: query.memberIds,
        committees: query.committees,
        gsrs: query.gsrs,
        everyone: query.everyone,
      });

      const ids = answer.member_ids;

      return Array.isArray(ids) ? ids.map(Number) : [];
    },
  };
}

async function googleIdToken(audience: string): Promise<string> {
  const client = await new GoogleAuth().getIdTokenClient(audience);

  // On Google's metadata server this asks with format=full, which is what puts
  // the email claim in the token. Fellowship refuses one without it.
  return client.idTokenProvider.fetchIdToken(audience);
}
