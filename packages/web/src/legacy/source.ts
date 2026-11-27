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

/** The property names of a token record that old sign-in code saved as JSON. */
export interface TokenFields {
  readonly idToken: string;
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly subject: string;
}

/**
 * Reads one JSON token record. All four values must be there. A name not given
 * is the hosted token endpoint's, and `subject` for the signed-in subject.
 */
export function readTokenJson(raw: string | null, fields: Partial<TokenFields> = {}): Omit<LegacySession, "method"> | null {
  if (!raw) return null;
  const names: TokenFields = {
    idToken: fields.idToken ?? "id_token",
    accessToken: fields.accessToken ?? "access_token",
    refreshToken: fields.refreshToken ?? "refresh_token",
    subject: fields.subject ?? "subject",
  };
  try {
    const value = (JSON.parse(raw) ?? {}) as Record<string, unknown>;
    const [idToken, accessToken, refreshToken, subject] = [
      value[names.idToken],
      value[names.accessToken],
      value[names.refreshToken],
      value[names.subject],
    ];
    if (!isText(idToken) || !isText(accessToken) || !isText(refreshToken) || !isText(subject)) return null;
    return { idToken, accessToken, refreshToken, subject };
  } catch {
    return null;
  }
}
