import * as account from "./cognito/account.js";
import { authenticate, type AuthStep } from "./cognito/authenticate.js";
import { passwordTokenSource, tokensOf } from "./cognito/refresh.js";
import { createUser } from "./cognito/user.js";
import { resolveConfig, type CardeaConfig, type ResolvedConfig } from "./config.js";
import { authErrorCode, CardeaError } from "./errors.js";
import { discardAttempt, startAttempt } from "./hosted/attempt.js";
import { exchangeCallback, type ConfirmProviderSession } from "./hosted/callback.js";
import { logoutUrl } from "./hosted/logout.js";
import { providerTokenSource } from "./hosted/refresh.js";
import { createVerifier } from "./hosted/verify.js";
import { forgetLegacySessions, importLegacySession } from "./legacy/import.js";
import type { ProviderSignInAdapter } from "./native/adapter.js";
import { nativeGoogleSignIn, type GoogleSignInOptions } from "./native/google-sign-in.js";
import type { Provider } from "./providers.js";
import { justIssued, toSession, usernameOf, type Session, type StoredSession } from "./session/record.js";
import { createRefresher } from "./session/refresh.js";
import { SessionStore, type SessionEvent } from "./session/store.js";

export interface ClientOptions {
  /** Where sessions are kept. Default `localStorage`. */
  storage?: Storage;
  /** Where a provider attempt waits for its callback. Default `sessionStorage`. */
  attemptStorage?: Storage;
  /** How to leave the page. Default `location.assign`. */
  redirect?: (url: string) => void;
  confirmProviderSession?: ConfirmProviderSession;
  /** The product's API for native sign-in, which `signInWithGoogle` needs. */
  providerSignIn?: ProviderSignInAdapter;
}

/** What a view needs to decide what to draw. */
export interface AuthState {
  /** `loading` until `start` has restored a session or finished a callback. */
  readonly status: "loading" | "signedIn" | "signedOut";
  readonly session: Session | null;
  /** The last failure to restore or refresh the session. */
  readonly error: CardeaError | null;
}

export interface StartResult {
  /** Set after a provider callback: navigate here, replacing the history entry. */
  returnTo?: string;
  error?: CardeaError;
}

/** What `signInWithGoogle` came to. `redirecting`: the page is leaving for the hosted sign-in. */
export type GoogleSignInResult =
  | { status: "signedIn"; session: Session }
  | { status: "dismissed" }
  | { status: "redirecting" };

/** The outcome of one password sign-in step. */
export type SignInResult =
  | { status: "signedIn"; session: Session }
  | { status: "confirmationRequired"; email: string }
  | {
      status: "newPasswordRequired";
      /** Profile attributes the account still lacks; pass each to `completeNewPassword`. */
      requiredAttributes: readonly string[];
      completeNewPassword: (password: string, attributes?: Record<string, string>) => Promise<SignInResult>;
    }
  | { status: "totpRequired"; submitTotp: (code: string) => Promise<SignInResult> };

export interface CardeaClient {
  readonly config: ResolvedConfig;
  /** Restores the session, or finishes a provider callback. Runs once per client. */
  start(): Promise<StartResult>;
  getState(): AuthState;
  /** Every change of `getState`. */
  subscribeState(listener: () => void): () => void;
  /** Sign-in, sign-out and account change, from this tab or another. */
  subscribe(listener: (event: SessionEvent) => void): () => void;
  /** The saved session as it is now, without refreshing it. */
  currentSession(): Session | null;
  /** The session with usable tokens, refreshed if needed; `null` when signed out. */
  getSession(): Promise<Session | null>;
  getIdToken(): Promise<string | null>;
  getAccessToken(): Promise<string | null>;
  signUp(email: string, password: string, attributes?: Record<string, string>): Promise<{ confirmed: boolean }>;
  confirmSignUp(email: string, code: string): Promise<void>;
  resendConfirmationCode(email: string): Promise<void>;
  signIn(email: string, password: string): Promise<SignInResult>;
  /** Mails a reset code. Succeeds for unknown addresses too, so it reveals nothing. */
  requestPasswordReset(email: string): Promise<void>;
  resetPassword(email: string, code: string, password: string): Promise<void>;
  /** Leaves for the provider. `returnTo` defaults to the current page. */
  signInWithProvider(provider: Provider, options?: { returnTo?: string }): Promise<void>;
  /**
   * Signs in with Google without leaving the page, through Google Identity
   * Services and the pool's custom authentication flow. In popup mode this
   * resolves once the person has pressed the button and picked an account.
   * Google keeps one set of settings per page, so run one at a time, and not
   * beside a Google linking button.
   */
  signInWithGoogle(options: GoogleSignInOptions): Promise<GoogleSignInResult>;
  /**
   * Clears this browser's session. `hosted` also ends the hosted domain's
   * session by redirecting there; it defaults to true for provider sessions.
   */
  signOut(options?: { hosted?: boolean }): void;
  /** Stops listening to other tabs. */
  dispose(): void;
}

export function createCardeaClient(configuration: CardeaConfig, options: ClientOptions = {}): CardeaClient {
  const config = resolveConfig(configuration);
  // Read lazily: merely touching storage throws in some locked-down browsers.
  const storage = () => options.storage ?? window.localStorage;
  const attemptStorage = () => options.attemptStorage ?? window.sessionStorage;
  const redirect = options.redirect ?? ((url: string) => window.location.assign(url));
  const page = typeof window === "undefined" ? undefined : window;

  const store = new SessionStore(storage, config.sessionKey, config.generationKey, config.userIdClaim, page);
  const verify = createVerifier(config);
  const fromPassword = passwordTokenSource(config);
  const fromProvider = providerTokenSource(config, verify);
  // Native provider sessions hold tokens of the user pool's API, as password sessions do.
  const tokenSource = ({ method, native }: Pick<StoredSession, "method" | "native">) =>
    method === "password" || native ? fromPassword : fromProvider;
  const usable = createRefresher(store, tokenSource);
  const forgetLegacy = () => forgetLegacySessions(config, storage);
  // Once a session has been saved or ended, here or in another tab, an old one must not return.
  store.subscribe(forgetLegacy);

  // Sign-outs in this tab, counted even if storage refuses the shared mark.
  let signOuts = 0;
  /** A sign-in may save only if this is unchanged since it began. */
  const mark = () => `${signOuts}:${store.generation()}`;
  function assertCurrent(started: string, returnTo?: string): void {
    if (started !== mark()) throw new CardeaError("session-superseded", returnTo);
  }
  let ready = false;
  let failure: CardeaError | null = null;
  let starting: Promise<StartResult> | undefined;
  // Set once the client has decided about importing; it decides only once.
  let takeover: Promise<void> | undefined;
  let takingOver = false;
  const listeners = new Set<() => void>();

  const snapshot = (): AuthState => {
    const session = store.current();
    const status = !ready ? "loading" : session ? "signedIn" : "signedOut";
    return { status, session, error: failure };
  };
  let state = snapshot();
  const publish = () => {
    state = snapshot();
    for (const listener of [...listeners]) listener();
  };
  store.onUpdate(() => {
    failure = null;
    publish();
  });

  function accept(record: StoredSession, started: string, returnTo?: string): Session {
    assertCurrent(started, returnTo);
    ready = true;
    failure = null;
    discardAttempt(config, attemptStorage);
    store.supersede();
    store.save(justIssued(record));
    publish();
    return toSession(record, config.userIdClaim);
  }

  function signInResult(step: AuthStep, email: string, started: string): SignInResult {
    if (step.kind === "newPassword") {
      return {
        status: "newPasswordRequired",
        requiredAttributes: step.requiredAttributes,
        completeNewPassword: async (password, attributes) => {
          // Checked before sending: Cognito replaces the password even if the session is then refused.
          assertCurrent(started);
          return signInResult(await step.next(password, attributes), email, started);
        },
      };
    }
    if (step.kind === "totp") {
      return {
        status: "totpRequired",
        submitTotp: async (code) => signInResult(await step.next(code.replace(/\s/g, "")), email, started),
      };
    }
    const tokens = tokensOf(step.session);
    const username = usernameOf(tokens.idToken) ?? email;
    return { status: "signedIn", session: accept({ version: 1, method: "password", username, ...tokens }, started) };
  }

  function takeOverOldSession(): Promise<void> {
    return importLegacySession({
      config,
      storage,
      verify,
      tokenSource,
      save: (record) => {
        // A session saved while the import ran wins over it.
        if (!store.read().record) store.save(record);
      },
    });
  }

  /** The page's address, if a provider has just sent the person back to it. */
  function providerReturn(): URL | null {
    if (!page) return null;
    const url = new URL(page.location.href);
    const answered = ["code", "state", "error"].some((name) => url.searchParams.has(name));
    return url.pathname === config.callbackPath && answered ? url : null;
  }

  /** Rules out an import for the rest of this page's life. */
  function settleImport(): void {
    takeover ??= Promise.resolve();
  }

  function beginImport(): void {
    if (takeover) return;
    // A sign-in being finished wins over an old session, and so does a saved one.
    if (!config.importSession.length || providerReturn() || store.read().record) return settleImport();
    takingOver = true;
    takeover = takeOverOldSession().finally(() => (takingOver = false));
    // `start` reports the failure.
    takeover.catch(() => {});
  }

  /** The record for a caller, who may ask before an effect or the app has run `start`. */
  function afterImport(): Promise<StoredSession | null> {
    beginImport();
    // Without a wait, the account is the one saved as of this call.
    return takingOver ? takeover!.catch(() => {}).then(usableRecord) : usableRecord();
  }

  async function usableRecord(): Promise<StoredSession | null> {
    try {
      const record = await usable();
      // Finding nobody signed in does not settle an earlier failure.
      if (failure && record) {
        failure = null;
        publish();
      }
      return record;
    } catch (error) {
      failure = error instanceof CardeaError ? error : new CardeaError("refresh-failed");
      publish();
      throw failure;
    }
  }

  async function finishCallback(callback: URL): Promise<StartResult> {
    // Drop the code from the address bar before anything else can read it.
    window.history.replaceState(window.history.state, "", config.callbackPath);
    const started = mark();
    try {
      if (!config.loginDomain) throw new CardeaError("provider-unavailable", "/");
      const { record, returnTo } = await exchangeCallback(
        config,
        callback,
        attemptStorage,
        verify,
        options.confirmProviderSession,
        store.generation(),
      );
      accept(record, started, returnTo);
      return { returnTo };
    } catch (error) {
      const known = error instanceof CardeaError ? error : new CardeaError("token-exchange-failed", "/");
      return { returnTo: known.returnTo ?? "/", error: known };
    }
  }

  async function leaveFor(provider: Provider, returnTo?: string, signal?: AbortSignal): Promise<void> {
    const here = new URL(window.location.href);
    const target = returnTo ?? `${here.pathname}${here.search}${here.hash}`;
    const url = await startAttempt(config, provider, here, target, attemptStorage, store.generation());
    if (signal?.aborted) throw signal.reason;
    redirect(url);
  }

  async function signInWithGoogle(wanted: GoogleSignInOptions): Promise<GoogleSignInResult> {
    if (wanted.mode === "popup" && !wanted.container) throw new CardeaError("not-configured");
    const started = mark();
    const controller = new AbortController();
    const cancel = () => controller.abort(new CardeaError("sign-in-cancelled"));
    // A sign-in or sign-out elsewhere ends this one: it could not be saved.
    const unsubscribe = store.subscribe(() => controller.abort(new CardeaError("session-superseded")));
    wanted.signal?.addEventListener("abort", cancel, { once: true });
    if (wanted.signal?.aborted) cancel();
    try {
      const outcome = await nativeGoogleSignIn(
        {
          config,
          adapter: options.providerSignIn,
          verify,
          confirm: options.confirmProviderSession,
          assertCurrent: () => assertCurrent(started),
        },
        wanted,
        controller.signal,
      );
      // Given up at the last moment: nothing is saved and nobody is sent away.
      if (controller.signal.aborted) throw controller.signal.reason;
      if (outcome === "dismissed") return { status: "dismissed" };
      if (outcome === "redirect") {
        await leaveFor("Google", wanted.returnTo, controller.signal);
        return { status: "redirecting" };
      }
      settleImport();
      return { status: "signedIn", session: accept(outcome.record, started) };
    } finally {
      unsubscribe();
      wanted.signal?.removeEventListener("abort", cancel);
    }
  }

  async function run(): Promise<StartResult> {
    let result: StartResult = {};
    const callback = providerReturn();
    if (store.read().record) forgetLegacy();
    if (callback) {
      // Finishing it clears the address, so rule out an import first.
      settleImport();
      result = await finishCallback(callback);
    } else {
      // A reload of the emptied callback page has nothing to finish.
      if (window.location.pathname === config.callbackPath) result = { returnTo: "/" };
      try {
        beginImport();
        await takeover;
        await usableRecord();
      } catch (error) {
        failure = result.error = error as CardeaError;
      }
    }
    ready = true;
    publish();
    return result;
  }

  return {
    config,
    start: () => (starting ??= run()),
    getState: () => state,
    subscribeState(listener) {
      listeners.add(listener);
      return () => void listeners.delete(listener);
    },
    subscribe: (listener) => store.subscribe(listener),
    currentSession() {
      store.sync();
      return store.current();
    },
    async getSession() {
      const record = await afterImport();
      return record ? toSession(record, config.userIdClaim) : null;
    },
    getIdToken: async () => (await afterImport())?.idToken ?? null,
    getAccessToken: async () => (await afterImport())?.accessToken ?? null,
    async signUp(email, password, attributes = {}) {
      return { confirmed: await account.signUp(config, email.trim(), password, attributes) };
    },
    confirmSignUp: (email, code) => account.confirmSignUp(config, email.trim(), code.replace(/\s/g, "")),
    resendConfirmationCode: (email) => account.resendConfirmationCode(config, email.trim()),
    async signIn(email, password) {
      const address = email.trim();
      const started = mark();
      let step: AuthStep;
      try {
        step = await authenticate(createUser(config, address), address, password);
      } catch (error) {
        if (authErrorCode(error) !== "UserNotConfirmedException") throw error;
        return { status: "confirmationRequired", email: address };
      }
      return signInResult(step, address, started);
    },
    requestPasswordReset: (email) => account.requestPasswordReset(config, email.trim()),
    resetPassword: (email, code, password) =>
      account.resetPassword(config, email.trim(), code.replace(/\s/g, ""), password),
    signInWithProvider: (provider, { returnTo } = {}) => leaveFor(provider, returnTo),
    signInWithGoogle,
    signOut({ hosted } = {}) {
      const record = store.read().record;
      signOuts++;
      settleImport();
      store.supersede();
      ready = true;
      failure = null;
      discardAttempt(config, attemptStorage);
      forgetLegacy();
      store.remove("signedOut");
      publish();
      // Only the hosted flow leaves a hosted session behind.
      const leave = hosted ?? (record !== null && record.method !== "password" && !record.native);
      if (leave && config.loginDomain) redirect(logoutUrl(config, config.loginDomain, window.location.origin));
    },
    dispose() {
      store.dispose();
      listeners.clear();
    },
  };
}
