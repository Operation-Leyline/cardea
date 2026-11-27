import type { ResolvedConfig } from "../config.js";
import { CardeaError } from "../errors.js";
import { tokensRejected, type Verifier } from "../hosted/verify.js";
import { isFresh, justIssued, usernameOf, type StoredSession } from "../session/record.js";
import { RefreshExpired, type TokenSource } from "../session/refresh.js";
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
  tokenSource: (record: StoredSession) => TokenSource;
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
 * A source that does not verify is left where it is. A refused refresh ends the
 * old sign-in: every old key is removed and nothing is saved. Any other failure
 * to reach a verdict, such as being offline or a server error, imports nothing,
 * keeps every key for the next start-up and throws `refresh-failed`. Otherwise
 * old keys go only after the new session is saved.
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
    const checks = { allowExpired: true, emailOptional: found.method === "password" };
    // Gone means signed out, or already taken over by another tab, while this one waited.
    const gone = () => readFrom(source, config, storage)?.refreshToken !== found.refreshToken;
    /** Gives up for now, without trying a later source in place of this one. */
    const postpone = () => {
      if (!gone()) throw new CardeaError("refresh-failed");
    };
    try {
      subject = await verify(tokens, { ...checks, ...(recorded ? { subject: recorded } : {}) });
      record = { version: 1, ...tokens, username: usernameOf(tokens.idToken) ?? username ?? subject };
    } catch (error) {
      if (tokensRejected(error)) continue;
      return postpone();
    }
    if (!isFresh(record)) {
      try {
        record = justIssued({ ...record, ...(await tokenSource(record)(record)) });
        await verify(record, { ...checks, subject });
      } catch (error) {
        if (!(error instanceof RefreshExpired)) return postpone();
        forgetLegacySessions(config, storage);
        return;
      }
    }
    if (gone()) return;
    save(record);
    return;
  }
}
