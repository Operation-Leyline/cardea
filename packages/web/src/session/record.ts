import { decodeJwt } from "jose";
import type { Provider } from "../providers.js";

/** How the current session was started. It decides how it is refreshed. */
export type SessionMethod = "password" | Provider;

/** The one thing written to localStorage. */
export interface StoredSession {
  version: 1;
  method: SessionMethod;
  /**
   * A provider sign-in made natively: its tokens came from the user pool's API,
   * so they are refreshed there and no hosted session goes with them.
   */
  native?: true;
  username: string;
  idToken: string;
  accessToken: string;
  refreshToken: string;
  /** Seconds this browser's clock was ahead of Cognito's when the tokens arrived. */
  clockDrift?: number;
}

/** The signed-in account as the app sees it. Tokens are fetched separately. */
export interface Session {
  /** Cognito `sub`. A change of subject is a change of account. */
  readonly subject: string;
  /** The product's user id (see `userIdClaim`). */
  readonly userId: string;
  readonly username: string;
  readonly email: string | null;
  readonly method: SessionMethod;
  /** ID token claims, for display and navigation. The API enforces access. */
  readonly claims: Readonly<Record<string, unknown>>;
  /** When the ID token expires, in epoch milliseconds. */
  readonly expiresAt: number;
}

/** Refresh this long before expiry so a token is still good when the API reads it. */
const EXPIRY_MARGIN_MS = 60_000;

export function toSession(record: StoredSession, userIdClaim: string): Session {
  const claims = decodeJwt(record.idToken);
  const subject = claims.sub as string;
  const userId = claims[userIdClaim];
  return {
    subject,
    userId: typeof userId === "string" && userId ? userId : subject,
    username: record.username,
    email: typeof claims.email === "string" ? claims.email : null,
    method: record.method,
    claims,
    expiresAt: (claims.exp ?? 0) * 1000,
  };
}

/** Cognito's internal username, when the ID token names it. */
export function usernameOf(idToken: string): string | undefined {
  const value = decodeJwt(idToken)["cognito:username"];
  return typeof value === "string" && value ? value : undefined;
}

export function subjectOf(record: StoredSession): string {
  return decodeJwt(record.idToken).sub as string;
}

/** Notes the clock difference on tokens that have just arrived, so a wrong device clock does not expire them. */
export function justIssued(record: StoredSession, now = Date.now()): StoredSession {
  const issued = decodeJwt(record.accessToken).iat;
  return { ...record, clockDrift: issued === undefined ? 0 : Math.floor(now / 1000) - issued };
}

/** Whether both tokens will still be good `marginMs` from now. */
export function isFresh(record: StoredSession, marginMs = EXPIRY_MARGIN_MS): boolean {
  const drift = typeof record.clockDrift === "number" ? record.clockDrift : 0;
  return [record.idToken, record.accessToken].every(
    (token) => ((decodeJwt(token).exp ?? 0) + drift) * 1000 > Date.now() + marginMs,
  );
}

/** Stored values outlive the code that wrote them; anything unexpected reads as signed out. */
export function parseRecord(raw: string | null): StoredSession | null {
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as Partial<StoredSession> | null;
    if (!value || value.version !== 1) return null;
    const strings = [value.method, value.username, value.idToken, value.accessToken, value.refreshToken];
    if (!strings.every((item) => typeof item === "string" && item)) return null;
    const record = value as StoredSession;
    const subject = decodeJwt(record.idToken).sub;
    decodeJwt(record.accessToken);
    return typeof subject === "string" && subject ? record : null;
  } catch {
    return null;
  }
}
