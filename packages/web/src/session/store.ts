import { CardeaError } from "../errors.js";
import { parseRecord, toSession, type Session, type StoredSession } from "./record.js";

/** Whether this tab made a change, or another tab sharing the storage did. */
export type SessionOrigin = "thisTab" | "otherTab";

/**
 * A change of who is signed in. A token refresh for the same account is not one.
 * Clear account-bound caches on `signedOut` and `accountChanged`.
 */
export type SessionEvent =
  | { type: "signedIn"; session: Session; origin: SessionOrigin }
  | { type: "accountChanged"; session: Session; previous: Session; origin: SessionOrigin }
  | { type: "signedOut"; previous: Session; reason: "signedOut" | "expired"; origin: SessionOrigin };

export interface StoredState {
  readonly raw: string | null;
  readonly record: StoredSession | null;
}

function announce<T>(listeners: Set<(value: T) => void>, value: T): void {
  for (const listener of [...listeners]) {
    try {
      listener(value);
    } catch (error) {
      // One broken listener must not stop the others from clearing their state.
      queueMicrotask(() => {
        throw error;
      });
    }
  }
}

/**
 * The saved session in localStorage, and the account the app last heard about.
 * Every read and write goes through here, so changes made in this tab and in
 * others are reported the same way.
 */
export class SessionStore {
  private seen: { raw: string | null; session: Session | null };
  private readonly events = new Set<(event: SessionEvent) => void>();
  private readonly updates = new Set<(session: Session | null) => void>();

  constructor(
    private readonly storage: () => Storage,
    private readonly key: string,
    private readonly userIdClaim: string,
    private readonly target: Window | undefined,
  ) {
    const { raw, record } = this.read();
    this.seen = { raw, session: record ? toSession(record, userIdClaim) : null };
    target?.addEventListener("storage", this.onStorage);
  }

  read(): StoredState {
    let raw: string | null = null;
    try {
      raw = this.storage().getItem(this.key);
    } catch {
      // A browser that blocks storage has no saved session.
    }
    return { raw, record: parseRecord(raw) };
  }

  /** The account as last reported to listeners. */
  current(): Session | null {
    return this.seen.session;
  }

  /** Persist a session. Refusal is an error: a sign-in that cannot be saved did not happen. */
  save(record: StoredSession): void {
    try {
      this.storage().setItem(this.key, JSON.stringify(record));
    } catch {
      throw new CardeaError("storage-unavailable");
    }
    this.sync("thisTab");
  }

  remove(reason: "signedOut" | "expired"): void {
    try {
      this.storage().removeItem(this.key);
    } catch {
      // Nothing could have been saved either.
    }
    this.sync("thisTab", reason);
  }

  /** Compare storage with what listeners last heard, and report the difference. */
  sync(origin: SessionOrigin = "otherTab", reason: "signedOut" | "expired" = "signedOut"): void {
    const { raw, record } = this.read();
    if (raw === this.seen.raw) return;
    const previous = this.seen.session;
    const session = record ? toSession(record, this.userIdClaim) : null;
    this.seen = { raw, session };
    announce(this.updates, session);
    if (session && !previous) announce(this.events, { type: "signedIn", session, origin });
    else if (!session && previous) announce(this.events, { type: "signedOut", previous, reason, origin });
    else if (session && previous && session.subject !== previous.subject) {
      announce(this.events, { type: "accountChanged", session, previous, origin });
    }
  }

  subscribe(listener: (event: SessionEvent) => void): () => void {
    this.events.add(listener);
    return () => void this.events.delete(listener);
  }

  /** Any change to the saved session, including a refresh. */
  onUpdate(listener: (session: Session | null) => void): () => void {
    this.updates.add(listener);
    return () => void this.updates.delete(listener);
  }

  dispose(): void {
    this.target?.removeEventListener("storage", this.onStorage);
    this.events.clear();
    this.updates.clear();
  }

  private readonly onStorage = (event: StorageEvent): void => {
    // A null key means the whole storage was cleared.
    if (event.key === null || event.key === this.key) this.sync("otherTab");
  };
}
