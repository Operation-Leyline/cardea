import { decodeJwt } from "jose";
import type { ResolvedConfig } from "../config.js";
import { CardeaError, type CardeaErrorCode } from "../errors.js";
import type { ConfirmProviderSession } from "../hosted/callback.js";
import type { Verifier } from "../hosted/verify.js";
import { abortable } from "../link/proof.js";
import { usernameOf, type StoredSession } from "../session/record.js";
import type { ProviderSignInAdapter, SignInNonce } from "./adapter.js";
import { GoogleUnavailable, loadGoogle, requestCredential, type Credential } from "./credential.js";
import { exchangeTicket } from "./exchange.js";

export interface GoogleSignInOptions {
  /**
   * `popup`: draws Google's button in `container`; pressing it opens Google's
   * popup. `oneTap`: shows Google's One Tap prompt.
   */
  mode: "popup" | "oneTap";
  /** Required in popup mode: the element the button is drawn in. */
  container?: HTMLElement | undefined;
  /** Options for Google's button (theme, size, width). */
  button?: Record<string, unknown> | undefined;
  /**
   * Leave for the hosted sign-in when Google Identity Services cannot be used.
   * Defaults to true in popup mode, which the person asked for, and false for
   * One Tap, which a page may show on its own.
   */
  fallback?: boolean | undefined;
  /** Where a fallback redirect returns to. Defaults to the current page. */
  returnTo?: string | undefined;
  /** Gives up: removes the button or closes the prompt. */
  signal?: AbortSignal | undefined;
}

/** `dismissed`: the One Tap prompt was closed or skipped. */
export type NativeOutcome = { record: StoredSession } | "dismissed" | "redirect";

export interface NativeDependencies {
  config: ResolvedConfig;
  adapter: ProviderSignInAdapter | undefined;
  verify: Verifier;
  confirm: ConfirmProviderSession | undefined;
  /** Throws once someone has signed in or out since this sign-in began. */
  assertCurrent: () => void;
}

/** Asked again this long before a nonce runs out. */
const RENEW_EARLY_MS = 30_000;
/** Bounds on the wait, so that a wrong device clock neither spins nor outlives the nonce. */
const SHORTEST_WAIT_MS = 60_000;
const LONGEST_WAIT_MS = 9.5 * 60_000;

function lifetimeOf({ expiresAt }: SignInNonce): number {
  const remaining = new Date(expiresAt).getTime() - Date.now() - RENEW_EARLY_MS;
  return Math.min(LONGEST_WAIT_MS, Math.max(SHORTEST_WAIT_MS, remaining || 0));
}

/**
 * The person's Google ID token and the nonce it was asked with. A popup's
 * button is drawn again with a new nonce when the old one runs out.
 */
async function obtainToken(
  adapter: ProviderSignInAdapter,
  options: GoogleSignInOptions,
  signal: AbortSignal,
): Promise<string | "dismissed"> {
  // Loaded first: a blocked script asks the product for nothing.
  await abortable(signal, loadGoogle());
  for (;;) {
    if (signal.aborted) throw signal.reason;
    const challenge = await abortable(signal, adapter.createSignInNonce({ provider: "Google" }));
    const credential: Credential = await requestCredential({
      mode: options.mode,
      clientId: challenge.clientId,
      nonce: challenge.nonce,
      lifetimeMs: lifetimeOf(challenge),
      graceMs: RENEW_EARLY_MS,
      signal,
      container: options.container,
      button: options.button,
    });
    if (credential === "dismissed") return credential;
    if (credential === "expired") {
      if (options.mode === "oneTap") return "dismissed";
      continue;
    }
    // The server verifies the token. This only stops an answer to another request early.
    if (nonceOf(credential.idToken) !== challenge.nonce) throw new CardeaError("nonce-mismatch");
    return credential.idToken;
  }
}

function nonceOf(idToken: string): unknown {
  try {
    return decodeJwt(idToken).nonce;
  } catch {
    throw new CardeaError("proof-failed");
  }
}

/** Whether the product's error is the operation's `identityLinkRequired`. */
function asksToLink(error: unknown): boolean {
  const { name, code } = (error ?? {}) as { name?: unknown; code?: unknown };
  return [name, code].some((value) => typeof value === "string" && value.toLowerCase() === "identitylinkrequired");
}

/** Native Google sign-in up to a verified session that is not saved yet. */
export async function nativeGoogleSignIn(
  dependencies: NativeDependencies,
  options: GoogleSignInOptions,
  signal: AbortSignal,
): Promise<NativeOutcome> {
  const { config, adapter, verify, confirm, assertCurrent } = dependencies;
  const fallback = options.fallback ?? options.mode === "popup";
  // Nothing more is asked for once the caller has given up.
  const unlessAbandoned = <T>(work: () => Promise<T>): Promise<T> =>
    signal.aborted ? Promise.reject(signal.reason) : abortable(signal, work());
  if (signal.aborted) throw signal.reason;
  const unavailable = (): NativeOutcome => {
    if (fallback) return "redirect";
    throw new CardeaError("provider-unavailable");
  };
  // A simulator has no custom authentication flow.
  if (!adapter || config.endpoint) return unavailable();

  let idToken: string | "dismissed";
  try {
    idToken = await obtainToken(adapter, options, signal);
  } catch (error) {
    if (error instanceof GoogleUnavailable) return unavailable();
    throw error;
  }
  if (idToken === "dismissed") return idToken;

  assertCurrent();
  const begun = await unlessAbandoned(() =>
    adapter.beginProviderSignIn({ provider: "Google", idToken, appClientId: config.clientId }),
  ).catch((error: unknown) => {
    throw asksToLink(error) ? new CardeaError("link-required") : error;
  });
  // Raw causes can carry identity details, so they stop here.
  let stage: CardeaErrorCode = "token-exchange-failed";
  try {
    const tokens = await unlessAbandoned(() => exchangeTicket(config, begun.username, begun.ticket, signal));
    stage = "token-verification-failed";
    const subject = await unlessAbandoned(() => verify(tokens, {}));
    stage = "account-check-failed";
    await unlessAbandoned(async () => confirm?.({ idToken: tokens.idToken, subject }));
    const username = usernameOf(tokens.idToken) ?? begun.username;
    return { record: { version: 1, method: "Google", native: true, username, ...tokens } };
  } catch (error) {
    throw error instanceof CardeaError ? error : new CardeaError(stage);
  }
}
