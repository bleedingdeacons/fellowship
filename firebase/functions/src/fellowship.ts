import * as logger from 'firebase-functions/logger';
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
  async function post(
    route: string,
    body: Record<string, unknown>,
  ): Promise<{ answer: Record<string, unknown>; response: Response }> {
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

    const text = await response.text().catch(() => '');
    const answer = jsonObject(text);

    if (!response.ok) {
      // Fellowship's own refusal goes back to the app unchanged, so it can say
      // the same thing it says today. Anything else is an outage.
      const code = STATUS_TO_CODE[response.status] ?? 'unavailable';
      throw new HttpsError(code, String(answer?.message ?? 'The intergroup site refused.'), {
        reason: String(answer?.code ?? 'fellowship_refused'),
      });
    }

    if (answer === null) {
      throw unreadable(route, response, text);
    }

    return { answer, response };
  }

  return {
    async member(query) {
      const { answer, response } = await post('member', {
        email: query.email,
        member_id: query.memberId,
      });

      if (typeof answer.admitted !== 'boolean') {
        throw unreadable('member', response, '');
      }

      return { memberId: Number(answer.member_id ?? 0), admitted: answer.admitted };
    },

    async audience(query) {
      const { answer, response } = await post('audience', {
        origin: query.origin,
        sender_member_id: query.senderMemberId,
        member_ids: query.memberIds,
        committees: query.committees,
        gsrs: query.gsrs,
        everyone: query.everyone,
      });

      const ids = answer.member_ids;

      if (!Array.isArray(ids)) {
        throw unreadable('audience', response, '');
      }

      return ids.map(Number);
    },
  };
}

function jsonObject(text: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(text);

    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/**
 * A success that isn't Fellowship's answer, such as a page from something in front
 * of the site. Reading it as "nobody" would tell a member they aren't one, so it
 * is an outage.
 *
 * @param text The body when it wasn't JSON. A JSON body from Fellowship's route
 *             holds member ids, so it is never logged.
 */
function unreadable(route: string, response: Response, text: string): HttpsError {
  logger.error('Fellowship answered something that could not be read', {
    route,
    status: response.status,
    url: response.url,
    redirected: response.redirected,
    contentType: response.headers.get('content-type'),
    server: response.headers.get('server'),
    start: text.slice(0, 200),
  });

  return new HttpsError('unavailable', 'The intergroup site could not be reached.', {
    reason: 'fellowship_unreadable_answer',
  });
}

async function googleIdToken(audience: string): Promise<string> {
  const client = await new GoogleAuth().getIdTokenClient(audience);

  // On Google's metadata server this asks with format=full, which is what puts
  // the email claim in the token. Fellowship refuses one without it.
  return client.idTokenProvider.fetchIdToken(audience);
}
