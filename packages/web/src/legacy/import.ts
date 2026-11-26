import type { ResolvedConfig } from "../config.js";
import type { Verifier } from "../hosted/verify.js";
import { isFresh, justIssued, usernameOf, type SessionMethod, type StoredSession } from "../session/record.js";
import type { TokenSource } from "../session/refresh.js";
import type { LegacySession, LegacySessionSource } from "./source.js";

/** Removes every configured source's keys, so an old session can never come back. */
export function forgetLegacySessions(config: ResolvedConfig, storage: () => Storage): void {
  for (const source of config.importSession) {
    try {
      source.clear(storage(), config);
    } catch {
      // A browser that blocks storage has nothing to import either.
    }
  }
}

function readFrom(source: LegacySessionSource, config: ResolvedConfig, storage: () => Storage): LegacySession | null {
  try {
    return source.read(storage(), config);
  } catch {
    return null;
  }
}

export interface ImportDependencies {
  config: ResolvedConfig;
  storage: () => Storage;
  verify: Verifier;
  tokenSource: (method: SessionMethod) => TokenSource;
  /** Saves the session, unless something newer has happened in the meantime. */
  save: (record: StoredSession) => void;
}

/**
 * Takes over the first old session that verifies as this pool's and this
 * client's: signature, issuer, client, purpose and subject. There is no nonce
 * to check, and expiry is settled by refreshing at once.
 *
 * Nothing is saved if the old session disappears while this runs.
 *
 * A source that does not verify is left where it is. A refresh that fails ends
 * the old sign-in: every old key is removed and nothing is saved. Otherwise old
 * keys go only after the new session is saved.
 */
export async function importLegacySession(dependencies: ImportDependencies): Promise<void> {
  const { config, storage, verify, tokenSource, save } = dependencies;
  // A simulator's tokens cannot be verified against a real pool's keys.
  if (config.endpoint) return;
  for (const source of config.importSession) {
    const found = readFrom(source, config, storage);
    // A provider session needs the hosted domain to be refreshed.
    if (!found || (found.method !== "password" && !config.loginDomain)) continue;
    const { subject: recorded, username, ...tokens } = found;
    let record: StoredSession;
    let subject: string;
    try {
      subject = await verify(tokens, { allowExpired: true, ...(recorded ? { subject: recorded } : {}) });
      record = { version: 1, ...tokens, username: usernameOf(tokens.idToken) ?? username ?? subject };
    } catch {
      continue;
    }
    if (!isFresh(record)) {
      try {
        record = justIssued({ ...record, ...(await tokenSource(record.method)(record)) });
        await verify(record, { allowExpired: true, subject });
      } catch {
        forgetLegacySessions(config, storage);
        return;
      }
    }
    // Gone means signed out, or already taken over by another tab, while this one waited.
    if (readFrom(source, config, storage)?.refreshToken !== found.refreshToken) return;
    save(record);
    return;
  }
}
