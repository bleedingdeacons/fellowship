import type { Auth, DecodedIdToken } from 'firebase-admin/auth';
import type { Firestore } from 'firebase-admin/firestore';
import type { Message } from 'firebase-admin/messaging';
import type { Attestations } from './attestation';

/** What the handlers reach for, passed in so tests can run on the emulators. */
export interface Deps {
  db: Firestore;
  auth: Auth;
  attestations: Attestations;
  push: (message: Message) => Promise<string>;
  now: () => number;
}

/** A callable's `request.auth`, or nothing when the caller is not signed in. */
export interface Caller {
  uid: string;
  token: DecodedIdToken;
}

export function nowSeconds(deps: Deps): number {
  return Math.floor(deps.now() / 1000);
}
