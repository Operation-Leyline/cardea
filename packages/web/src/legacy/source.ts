import type { SessionMethod } from "../session/record.js";

/** The app client whose old session is wanted. */
export interface LegacyClient {
  readonly clientId: string;
  readonly issuer: string;
}

/** Tokens as an app's earlier sign-in code saved them. Nothing here is trusted yet. */
export interface LegacySession {
  method: SessionMethod;
  idToken: string;
  accessToken: string;
  refreshToken: string;
  username?: string;
  /** The subject the old code recorded, which the tokens must then match. */
  subject?: string;
  /** Seconds this browser's clock was ahead of Cognito's, if the old code noted it. */
  clockDrift?: number;
}

/**
 * One place an app kept its session before adopting this package, so that the
 * people using it stay signed in.
 */
export interface LegacySessionSource {
  /** The saved tokens for this client, or `null` when there are none that can be read. */
  read(storage: Storage, client: LegacyClient): LegacySession | null;
  /** Removes everything the old code saved for this client. */
  clear(storage: Storage, client: LegacyClient): void;
}

export function isText(value: unknown): value is string {
  return typeof value === "string" && value !== "";
}

/** The `{ id_token, access_token, refresh_token, subject }` record that hosted sign-in code saved as JSON. */
export function readTokenJson(raw: string | null): Omit<LegacySession, "method"> | null {
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as Record<string, unknown> | null;
    const { id_token, access_token, refresh_token, subject } = value ?? {};
    if (!isText(id_token) || !isText(access_token) || !isText(refresh_token) || !isText(subject)) return null;
    return { idToken: id_token, accessToken: access_token, refreshToken: refresh_token, subject };
  } catch {
    return null;
  }
}
