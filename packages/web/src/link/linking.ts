import { decodeJwt } from "jose";
import type { CardeaClient } from "../client.js";
import { sendResetCode } from "../cognito/account.js";
import { CardeaError } from "../errors.js";
import type { Provider } from "../providers.js";
import type { Session } from "../session/record.js";
import type { IdentityLinkAdapter, IdentityLinkChallenge, SignInMethod } from "./adapter.js";
import { appleProofSource } from "./apple.js";
import { googleProofSource } from "./google.js";
import type { ProofSource } from "./proof.js";

export interface LinkingOptions {
  client: CardeaClient;
  adapter: IdentityLinkAdapter;
  // The three provider settings are read each time a link is prepared.
  /** Return URL registered on the Apple Services ID. */
  appleRedirectUri?: string | undefined;
  /** Options for Google's button. */
  googleButton?: Record<string, unknown> | undefined;
  /** Replaces how a provider token is obtained, for tests or a native shell. */
  proofSources?: Partial<Record<Provider, ProofSource>> | undefined;
}

export interface ConfirmOptions {
  /** Required for Google: the element its button is drawn in. */
  container?: HTMLElement;
  signal?: AbortSignal;
}

/** A challenge that is ready for the person to confirm with the provider. */
export interface PreparedLink {
  readonly provider: Provider;
  readonly linkId: string;
  readonly expiresAt: Date;
  /**
   * Gets the provider's token and completes the link. After a failed completion,
   * calling again resends the same token, which the operation allows. For Apple,
   * call it straight from a click.
   */
  confirm(options?: ConfirmOptions): Promise<{ userId: string }>;
}

export interface Linking {
  prepareLink(provider: Provider): Promise<PreparedLink>;
  /**
   * `prepareLink` followed by `confirm`. Apple's popup can be blocked after the
   * wait in between; for Apple, prepare first and confirm from a click.
   */
  linkProvider(provider: Provider, options?: ConfirmOptions): Promise<{ userId: string }>;
  listSignInMethods(): Promise<SignInMethod[]>;
  unlinkSignInMethod(provider: Provider): Promise<void>;
  /**
   * "Set a password" is the forgot-password flow, sent to the signed-in address.
   * Unlike an anonymous reset, a refusal is reported.
   */
  requestPasswordSetup(): Promise<void>;
  completePasswordSetup(code: string, password: string): Promise<void>;
  /** Fires after a link, an unlink or a new password. */
  onMethodsChanged(listener: () => void): () => void;
}

export function createLinking(options: LinkingOptions): Linking {
  const { client, adapter } = options;
  function sourceFor(provider: Provider): ProofSource {
    const custom = options.proofSources?.[provider];
    if (custom) return custom;
    return provider === "Google" ? googleProofSource(options.googleButton) : appleProofSource(options.appleRedirectUri);
  }
  const listeners = new Set<() => void>();
  const changed = () => {
    for (const listener of [...listeners]) listener();
  };

  async function signedIn(): Promise<Session> {
    const session = await client.getSession();
    if (!session) throw new CardeaError("not-signed-in");
    return session;
  }

  /** Nothing begun for one account may finish, or show its result, under another. */
  function sameAccount(session: Session): void {
    if (client.currentSession()?.subject !== session.subject) throw new CardeaError("account-changed");
  }

  /** Waits for the provider, giving up at the deadline, on abort, or if the account changes. */
  async function obtainProof(
    source: ProofSource,
    challenge: IdentityLinkChallenge,
    deadline: number,
    confirm: ConfirmOptions,
  ): Promise<string> {
    const remaining = deadline - Date.now();
    if (!(remaining > 0)) throw new CardeaError("link-expired");
    const controller = new AbortController();
    const cancel = () => controller.abort(new CardeaError("proof-cancelled"));
    const timer = setTimeout(() => controller.abort(new CardeaError("link-expired")), remaining);
    const unsubscribe = client.subscribe(() => controller.abort(new CardeaError("account-changed")));
    confirm.signal?.addEventListener("abort", cancel, { once: true });
    if (confirm.signal?.aborted) cancel();
    try {
      // Called before any `await`, so a click still counts when the provider opens its popup.
      const idToken = await source.request({
        clientId: challenge.clientId,
        nonce: challenge.nonce,
        signal: controller.signal,
        ...(confirm.container ? { container: confirm.container } : {}),
      });
      // The server verifies the token. This only stops an answer to another request early.
      if (nonceOf(idToken) !== challenge.nonce) throw new CardeaError("nonce-mismatch");
      return idToken;
    } finally {
      clearTimeout(timer);
      unsubscribe();
      confirm.signal?.removeEventListener("abort", cancel);
    }
  }

  async function prepareLink(provider: Provider): Promise<PreparedLink> {
    const session = await signedIn();
    // The source that is loaded here is the one asked at confirmation.
    const source = sourceFor(provider);
    const [challenge] = await Promise.all([
      adapter.createIdentityLink({ provider, clientToken: crypto.randomUUID() }),
      source.load(),
    ]);
    sameAccount(session);
    const expiresAt = new Date(challenge.expiresAt);
    // Held in memory only, and only until the link completes.
    let proof: string | undefined;
    let result: { userId: string } | undefined;
    let running: Promise<{ userId: string }> | undefined;

    async function complete(confirm: ConfirmOptions) {
      sameAccount(session);
      if (!proof) proof = await obtainProof(source, challenge, expiresAt.getTime(), confirm);
      sameAccount(session);
      const completed = await adapter.completeIdentityLink({ linkId: challenge.linkId, idToken: proof });
      sameAccount(session);
      proof = undefined;
      if (completed.userId !== session.userId) throw new CardeaError("account-mismatch");
      result = completed;
      changed();
      return completed;
    }

    return {
      provider,
      linkId: challenge.linkId,
      expiresAt,
      confirm(confirm = {}) {
        if (result) return Promise.resolve(result);
        return (running ??= complete(confirm).finally(() => (running = undefined)));
      },
    };
  }

  function address(): string {
    const email = client.currentSession()?.email;
    if (!email) throw new CardeaError("not-signed-in");
    return email;
  }

  return {
    prepareLink,
    async linkProvider(provider, confirm = {}) {
      const prepared = await prepareLink(provider);
      return prepared.confirm(confirm);
    },
    async listSignInMethods() {
      const session = await signedIn();
      const methods = await adapter.listSignInMethods();
      sameAccount(session);
      return methods;
    },
    async unlinkSignInMethod(provider) {
      const session = await signedIn();
      await adapter.unlinkSignInMethod({ provider });
      sameAccount(session);
      changed();
    },
    requestPasswordSetup: async () => sendResetCode(client.config, address()),
    async completePasswordSetup(code, password) {
      await client.resetPassword(address(), code, password);
      changed();
    },
    onMethodsChanged(listener) {
      listeners.add(listener);
      return () => void listeners.delete(listener);
    },
  };
}

function nonceOf(idToken: string): unknown {
  try {
    return decodeJwt(idToken).nonce;
  } catch {
    throw new CardeaError("proof-failed");
  }
}
