import { CardeaError } from "../errors.js";
import { isFresh, justIssued, subjectOf, type StoredSession } from "./record.js";
import type { SessionStore } from "./store.js";

export interface Tokens {
  idToken: string;
  accessToken: string;
  refreshToken: string;
}

/** Thrown by a token source when the refresh token no longer works. */
export class RefreshExpired extends Error {}

/** Gets new tokens for a saved session. Password and provider sessions differ. */
export type TokenSource = (record: StoredSession) => Promise<Tokens>;

/**
 * Hands out a saved session that is still usable, refreshing it when needed.
 * Concurrent callers share one request. A response that arrives after a
 * sign-out, a new sign-in or another tab's change is discarded.
 */
export function createRefresher(store: SessionStore, source: (record: StoredSession) => TokenSource) {
  let running: { raw: string; saved: Promise<string | null> } | null = null;

  /** Resolves with what it wrote to storage, or `null` when it wrote nothing. */
  async function refresh(raw: string, record: StoredSession): Promise<string | null> {
    try {
      const tokens = await source(record)(record);
      const next = justIssued({ ...record, ...tokens });
      if (subjectOf(next) !== subjectOf(record)) throw new CardeaError("token-verification-failed");
      if (store.read().raw !== raw) return null;
      store.save(next);
      return JSON.stringify(next);
    } catch (error) {
      if (store.read().raw !== raw) return null;
      if (error instanceof RefreshExpired) {
        store.remove("expired");
        return null;
      }
      // An outage keeps the session, so a later call can try again.
      throw new CardeaError("refresh-failed");
    }
  }

  return async function usable(): Promise<StoredSession | null> {
    store.sync();
    const { raw, record } = store.read();
    if (!raw || !record) return null;
    if (isFresh(record)) return record;
    if (running?.raw !== raw) {
      const saved = refresh(raw, record).finally(() => {
        if (running?.saved === saved) running = null;
      });
      running = { raw, saved };
    }
    const saved = await running.saved;
    store.sync();
    const latest = store.read();
    // A caller that asked on behalf of one account never receives another's tokens.
    if (!latest.record || subjectOf(latest.record) !== subjectOf(record)) return null;
    if (latest.raw === saved || isFresh(latest.record, 0)) return latest.record;
    // The same account was saved again, already stale: refresh that one.
    return latest.raw === raw ? null : usable();
  };
}
