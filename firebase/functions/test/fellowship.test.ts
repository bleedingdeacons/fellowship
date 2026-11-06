import * as logger from 'firebase-functions/logger';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { httpFellowship, userAgent } from '../src/fellowship';

vi.mock('firebase-functions/logger', () => ({ error: vi.fn() }));

const SERVICE = 'https://example.org/wp-json/fellowship/v1/service';

function answers(status: number, body: string, contentType = 'application/json') {
  const fetched = vi.fn(async () => new Response(body, { status, headers: { 'content-type': contentType } }));

  vi.stubGlobal('fetch', fetched);

  return fetched;
}

const client = () => httpFellowship(SERVICE, async () => 'id-token');

async function reasonOf(call: Promise<unknown>): Promise<string | undefined> {
  try {
    await call;
  } catch (error) {
    return (error as { details?: { reason?: string } }).details?.reason;
  }

  throw new Error('It should have been refused.');
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('asking Fellowship', () => {
  test('an audience comes back as numbers, asked for with the token', async () => {
    const fetched = answers(200, '{"member_ids":[7,8]}');

    expect(await client().audience({ origin: 'admin', everyone: true })).toEqual([7, 8]);

    const [url, init] = fetched.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${SERVICE}/audience`);
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer id-token');
  });

  test('every request says what it is and what it wants back', async () => {
    const fetched = answers(200, '{"member_id":7,"admitted":true}');

    await client().member({ email: 'a@example.org' });

    const headers = (fetched.mock.calls[0] as unknown as [string, RequestInit])[1].headers as Record<string, string>;
    expect(headers['User-Agent']).toBe('Fellowship-Functions (rest@aa-bristol.org; https://example.org)');
    expect(headers.Accept).toBe('application/json');
  });

  test.each([
    ['/amber', 'https://aa-bristol.org/amber/wp-json/fellowship/v1/service', 'https://aa-bristol.org/amber'],
    ['live', 'https://aa-bristol.org/wp-json/fellowship/v1/service', 'https://aa-bristol.org'],
    ['a trailing slash', 'https://aa-bristol.org//wp-json/x', 'https://aa-bristol.org'],
    ['characters that would break the header', 'https://a.org/x(y);\r\nz/wp-json/x', 'https://a.org/xyz'],
    ['nothing', '', 'unknown'],
  ])('the deployment is named for %s', (_name, url, expected) => {
    expect(userAgent(url)).toBe(`Fellowship-Functions (rest@aa-bristol.org; ${expected})`);
  });

  test('a member comes back with whether they are admitted', async () => {
    answers(200, '{"member_id":7,"admitted":false}');

    expect(await client().member({ email: 'a@example.org' })).toEqual({ memberId: 7, admitted: false });
  });

  test("Fellowship's own refusal comes back unchanged", async () => {
    answers(400, '{"code":"fellowship_no_recipients","message":"That message would not reach anybody."}');

    expect(await reasonOf(client().audience({ origin: 'admin', memberIds: [1] }))).toBe('fellowship_no_recipients');
  });

  test('a refusal that is not JSON is still a refusal', async () => {
    answers(503, '<html>down</html>', 'text/html');

    expect(await reasonOf(client().audience({ origin: 'admin', everyone: true }))).toBe('fellowship_refused');
  });

  // Each of these used to read as nobody, or as not a member.
  test.each([
    ['a page', '<html>checking your browser</html>', 'text/html'],
    ['nothing', '', 'text/html'],
    ['a list', '[]', 'application/json'],
    ['JSON with no ids', '{"ok":true}', 'application/json'],
  ])('%s with a 200 is an outage rather than an empty audience', async (_name, body, type) => {
    answers(200, body, type);

    expect(await reasonOf(client().audience({ origin: 'admin', everyone: true }))).toBe('fellowship_unreadable_answer');
  });

  test.each([
    ['a page', '<html>checking your browser</html>', 'text/html'],
    ['JSON that does not say', '{"member_id":7}', 'application/json'],
  ])('%s with a 200 does not tell a member they are not one', async (_name, body, type) => {
    answers(200, body, type);

    expect(await reasonOf(client().member({ email: 'a@example.org' }))).toBe('fellowship_unreadable_answer');
  });

  test('an empty list from Fellowship is still an answer', async () => {
    answers(200, '{"member_ids":[]}');

    expect(await client().audience({ origin: 'admin', everyone: true })).toEqual([]);
  });

  test('what it logs never includes member ids', async () => {
    vi.mocked(logger.error).mockClear();

    answers(200, '{"ids":[424242]}');
    await reasonOf(client().audience({ origin: 'admin', everyone: true }));

    const written = JSON.stringify(vi.mocked(logger.error).mock.calls);

    expect(written).toContain('could not be read');
    expect(written).not.toContain('424242');
  });

  test('what it logs says what actually came back', async () => {
    vi.mocked(logger.error).mockClear();

    answers(200, '<html>checking your browser</html>', 'text/html');
    await reasonOf(client().audience({ origin: 'admin', everyone: true }));

    const details = vi.mocked(logger.error).mock.calls[0][1] as Record<string, unknown>;

    expect(details.status).toBe(200);
    expect(details.contentType).toBe('text/html');
    expect(details.start).toContain('checking your browser');
  });
});
