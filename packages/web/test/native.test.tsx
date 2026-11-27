import { act, renderHook } from "@testing-library/react";
import { createElement, type ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { createCardeaClient, type ClientOptions, type ProviderSignInAdapter } from "../src/index.js";
import { CardeaProvider, useGoogleSignIn } from "../src/react/index.js";
import { ATTEMPT_KEY, authenticationResult, CognitoFailure, CONFIG, installFakeCognito, issueTokens, otherTabWrites, SESSION_KEY, storedSession } from "./fakes/cognito.js";
import { installFakeGoogle } from "./fakes/google.js";

const CUSTOM = {
  ChallengeName: "CUSTOM_CHALLENGE",
  Session: "cognito-session",
  ChallengeParameters: { challenge: "PROVIDER_TICKET", USERNAME: "user-ada" },
};

/** A pool that runs the custom flow, a product API and Google, all in this page. */
function setup(options: ClientOptions = {}) {
  const cognito = installFakeCognito();
  cognito.operations.InitiateAuth = async (body) => {
    if (body.AuthFlow === "CUSTOM_AUTH") return CUSTOM;
    return authenticationResult(await issueTokens(), false);
  };
  cognito.operations.RespondToAuthChallenge = async (body) =>
    body.ChallengeResponses.ANSWER === "ticket-1"
      ? authenticationResult(await issueTokens())
      : new CognitoFailure("NotAuthorizedException");
  let issued = 0;
  const adapter = {
    createSignInNonce: vi.fn<ProviderSignInAdapter["createSignInNonce"]>(async () => ({
      nonce: `nonce-${++issued}`,
      clientId: "google-client",
      expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    })),
    beginProviderSignIn: vi.fn<ProviderSignInAdapter["beginProviderSignIn"]>(async () => ({
      username: "user-ada",
      ticket: "ticket-1",
    })),
  };
  const google = installFakeGoogle();
  const redirect = vi.fn();
  const client = createCardeaClient(CONFIG, { providerSignIn: adapter, redirect, ...options });
  const container = document.createElement("div");
  return { cognito, adapter, google, redirect, client, container };
}

/** Starts a popup sign-in and waits for Google's button. */
async function popup(page: ReturnType<typeof setup>, extra: { signal?: AbortSignal } = {}) {
  const result = page.client.signInWithGoogle({ mode: "popup", container: page.container, ...extra });
  result.catch(() => {});
  await vi.waitFor(() => expect(page.google.buttons()).toBe(1));
  return { result };
}

describe("signing in with Google in a popup", () => {
  it("exchanges Google's token for a ticket and the ticket for a saved session", async () => {
    const page = setup();
    const { result } = await popup(page);
    expect(page.google.settings()).toMatchObject({ client_id: "google-client", nonce: "nonce-1", ux_mode: "popup" });
    expect(page.container.childElementCount).toBe(1);
    const idToken = await page.google.press();
    await expect(result).resolves.toMatchObject({ status: "signedIn", session: { subject: "ada", method: "Google" } });
    expect(page.adapter.beginProviderSignIn).toHaveBeenCalledWith({
      provider: "Google",
      idToken,
      appClientId: CONFIG.clientId,
    });
    expect(page.cognito.calls.map((call) => call.body)).toEqual([
      { AuthFlow: "CUSTOM_AUTH", ClientId: CONFIG.clientId, AuthParameters: { USERNAME: "user-ada" } },
      {
        ChallengeName: "CUSTOM_CHALLENGE",
        ClientId: CONFIG.clientId,
        Session: "cognito-session",
        ChallengeResponses: { USERNAME: "user-ada", ANSWER: "ticket-1" },
      },
    ]);
    expect(JSON.parse(localStorage.getItem(SESSION_KEY)!)).toMatchObject({ method: "Google", native: true });
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain(idToken);
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain("ticket-1");
    expect(page.container.childElementCount).toBe(0);
    expect(page.redirect).not.toHaveBeenCalled();
  });

  it("refreshes at the pool's API and signs out without the hosted domain", async () => {
    const page = setup();
    const { result } = await popup(page);
    await page.google.press();
    await result;
    const stored = JSON.parse(localStorage.getItem(SESSION_KEY)!);
    const stale = await issueTokens({ expiresIn: -60 });
    localStorage.setItem(SESSION_KEY, JSON.stringify({ ...stored, idToken: stale.id_token, accessToken: stale.access_token }));
    await expect(page.client.getSession()).resolves.toMatchObject({ method: "Google" });
    expect(page.cognito.calls.at(-1)!.body.AuthFlow).toBe("REFRESH_TOKEN_AUTH");
    expect(page.cognito.tokenRequests).toHaveLength(0);
    expect(JSON.parse(localStorage.getItem(SESSION_KEY)!).native).toBe(true);
    page.client.signOut();
    expect(localStorage.getItem(SESSION_KEY)).toBeNull();
    expect(page.redirect).not.toHaveBeenCalled();
  });

  it("draws the button again with a new nonce when the old one runs out", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const page = setup();
    const { result } = await popup(page);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await vi.waitFor(() => expect(page.google.settings().nonce).toBe("nonce-2"));
    expect(page.container.childElementCount).toBe(1);
    await page.google.press();
    await expect(result).resolves.toMatchObject({ status: "signedIn" });
  });

  it("keeps a pressed button's nonce until it runs out", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const page = setup();
    const listener = vi.fn();
    const result = page.client.signInWithGoogle({
      mode: "popup",
      container: page.container,
      button: { click_listener: listener },
    });
    await vi.waitFor(() => expect(page.google.buttons()).toBe(1));
    page.google.open();
    expect(listener).toHaveBeenCalledOnce();
    // Past the early renewal, before the expiry.
    await vi.advanceTimersByTimeAsync(9 * 60_000 + 45_000);
    expect(page.google.buttons()).toBe(1);
    await page.google.press();
    await expect(result).resolves.toMatchObject({ status: "signedIn" });
    expect(page.adapter.createSignInNonce).toHaveBeenCalledOnce();
  });

  it("renews a pressed button once its nonce has run out", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const page = setup();
    const { result } = await popup(page);
    page.google.open();
    await vi.advanceTimersByTimeAsync(10 * 60_000 + 1_000);
    await vi.waitFor(() => expect(page.google.settings().nonce).toBe("nonce-2"));
    await page.google.press();
    await expect(result).resolves.toMatchObject({ status: "signedIn" });
  });

  it.each(["beginProviderSignIn", "InitiateAuth", "RespondToAuthChallenge", "confirmProviderSession"])(
    "saves nothing when cancelled during %s",
    async (step) => {
      let release!: () => void;
      const held = new Promise<void>((resolve) => (release = resolve));
      const reached = vi.fn();
      let late: Promise<unknown> | undefined;
      const hold = <T,>(name: string, answer: () => T | Promise<T>): Promise<T> => {
        if (name !== step) return Promise.resolve(answer());
        reached();
        const answered = held.then(answer);
        late = answered;
        return answered;
      };
      const bodies: Promise<unknown>[] = [];
      const json = Response.prototype.json;
      vi.spyOn(Response.prototype, "json").mockImplementation(function (this: Response) {
        const body = json.call(this);
        bodies.push(body);
        return body;
      });
      const page = setup({ confirmProviderSession: () => hold("confirmProviderSession", () => {}) });
      page.adapter.beginProviderSignIn.mockImplementation(() =>
        hold("beginProviderSignIn", () => ({ username: "user-ada", ticket: "ticket-1" })),
      );
      for (const operation of ["InitiateAuth", "RespondToAuthChallenge"] as const) {
        const answer = page.cognito.operations[operation]!;
        page.cognito.operations[operation] = (body) => hold(operation, () => answer(body));
      }
      const controller = new AbortController();
      const { result } = await popup(page, { signal: controller.signal });
      await page.google.press();
      await vi.waitFor(() => expect(reached).toHaveBeenCalled());
      const calls = page.cognito.calls.length;
      controller.abort();
      await expect(result).rejects.toMatchObject({ code: "sign-in-cancelled" });
      release();
      // Lets the abandoned step run out: its answer arrives and is read, and
      // whatever would follow is started before the next turn of the event loop.
      await late;
      await new Promise((resolve) => setImmediate(resolve));
      await Promise.allSettled(bodies);
      await new Promise((resolve) => setImmediate(resolve));
      expect(localStorage.getItem(SESSION_KEY)).toBeNull();
      expect(page.cognito.calls).toHaveLength(calls);
    },
  );

  it.each([{}, { providerSignIn: undefined }])("does nothing for a caller who had already given up", async (options) => {
    const page = setup(options as ClientOptions);
    await expect(
      page.client.signInWithGoogle({ mode: "popup", container: page.container, signal: AbortSignal.abort() }),
    ).rejects.toMatchObject({ code: "sign-in-cancelled" });
    expect(page.redirect).not.toHaveBeenCalled();
    expect(page.google.buttons()).toBe(0);
  });

  it("refuses a token that carries another nonce", async () => {
    const page = setup();
    const { result } = await popup(page);
    await page.google.press("someone-elses-nonce");
    await expect(result).rejects.toMatchObject({ code: "nonce-mismatch" });
    expect(page.adapter.beginProviderSignIn).not.toHaveBeenCalled();
  });

  it.each(["name", "code"])("reports identityLinkRequired by its %s, without redirecting", async (field) => {
    const page = setup();
    page.adapter.beginProviderSignIn.mockRejectedValue(Object.assign(new Error("refused"), { [field]: "identityLinkRequired" }));
    const { result } = await popup(page);
    await page.google.press();
    await expect(result).rejects.toMatchObject({ code: "link-required" });
    expect(page.redirect).not.toHaveBeenCalled();
    expect(page.cognito.calls).toHaveLength(0);
  });

  it("passes the product's other errors through", async () => {
    const page = setup();
    const failure = new Error("rate limited");
    page.adapter.beginProviderSignIn.mockRejectedValue(failure);
    const { result } = await popup(page);
    await page.google.press();
    await expect(result).rejects.toBe(failure);
  });

  it.each([
    ["a refused ticket", () => new CognitoFailure("NotAuthorizedException"), "token-exchange-failed"],
    ["another challenge", () => ({ ChallengeName: "SOFTWARE_TOKEN_MFA", Session: "s" }), "challenge-unsupported"],
  ])("saves nothing after %s", async (_, answer, code) => {
    const page = setup();
    page.cognito.operations.RespondToAuthChallenge = answer;
    const { result } = await popup(page);
    await page.google.press();
    await expect(result).rejects.toMatchObject({ code });
    expect(localStorage.getItem(SESSION_KEY)).toBeNull();
  });

  it.each([
    ["a password challenge", { ...CUSTOM, ChallengeName: "PASSWORD_VERIFIER" }],
    ["somebody else's custom challenge", { ...CUSTOM, ChallengeParameters: { challenge: "OTHER" } }],
  ])("does not send the ticket to %s", async (_, challenge) => {
    const page = setup();
    page.cognito.operations.InitiateAuth = () => challenge;
    const { result } = await popup(page);
    await page.google.press();
    await expect(result).rejects.toMatchObject({ code: "challenge-unsupported" });
    expect(page.cognito.operationNames()).toEqual(["InitiateAuth"]);
  });

  it("verifies the tokens before saving them", async () => {
    const page = setup();
    page.cognito.operations.RespondToAuthChallenge = async () => authenticationResult(await issueTokens({ foreignKey: true }));
    const { result } = await popup(page);
    await page.google.press();
    await expect(result).rejects.toMatchObject({ code: "token-verification-failed" });
    expect(localStorage.getItem(SESSION_KEY)).toBeNull();
  });

  it("gives the product its last word", async () => {
    const confirmProviderSession = vi.fn(async () => {
      throw new Error("unknown here");
    });
    const page = setup({ confirmProviderSession });
    const { result } = await popup(page);
    await page.google.press();
    await expect(result).rejects.toMatchObject({ code: "account-check-failed" });
    expect(confirmProviderSession).toHaveBeenCalledWith({ idToken: expect.any(String), subject: "ada" });
    expect(localStorage.getItem(SESSION_KEY)).toBeNull();
  });

  it("is cancelled by its signal, removing the button", async () => {
    const page = setup();
    const controller = new AbortController();
    const { result } = await popup(page, { signal: controller.signal });
    controller.abort();
    await expect(result).rejects.toMatchObject({ code: "sign-in-cancelled" });
    expect(page.container.childElementCount).toBe(0);
  });

  it("is cancelled at once while the product has yet to answer", async () => {
    const page = setup();
    page.adapter.createSignInNonce.mockReturnValue(new Promise(() => {}));
    const controller = new AbortController();
    const result = page.client.signInWithGoogle({ mode: "popup", container: page.container, signal: controller.signal });
    await vi.waitFor(() => expect(page.adapter.createSignInNonce).toHaveBeenCalled());
    controller.abort();
    await expect(result).rejects.toMatchObject({ code: "sign-in-cancelled" });
    expect(page.google.buttons()).toBe(0);
  });

  it("gives way to a sign-in in another tab", async () => {
    const page = setup();
    const { result } = await popup(page);
    otherTabWrites(SESSION_KEY, await storedSession({ subject: "grace" }));
    await expect(result).rejects.toMatchObject({ code: "session-superseded" });
    expect(page.adapter.beginProviderSignIn).not.toHaveBeenCalled();
  });

  it("goes on when an old session expires meanwhile", async () => {
    // Saved before the page loads, as a returning visitor's is.
    localStorage.setItem(SESSION_KEY, await storedSession({ expiresIn: -60 }));
    const page = setup();
    const exchange = page.cognito.operations.InitiateAuth!;
    page.cognito.operations.InitiateAuth = (body) =>
      body.AuthFlow === "CUSTOM_AUTH" ? exchange(body) : new CognitoFailure("NotAuthorizedException");
    const { result } = await popup(page);
    // The SDK retries a refused refresh with back-off before giving up.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    let ended = false;
    const refresh = page.client.getSession().finally(() => (ended = true));
    while (!ended) await vi.advanceTimersByTimeAsync(1000);
    vi.useRealTimers();
    await expect(refresh).resolves.toBeNull();
    expect(localStorage.getItem(SESSION_KEY)).toBeNull();
    await page.google.press();
    await expect(result).resolves.toMatchObject({ status: "signedIn" });
  });

  it("goes on when an old session expires in another tab", async () => {
    localStorage.setItem(SESSION_KEY, await storedSession({ expiresIn: -60 }));
    const page = setup();
    const { result } = await popup(page);
    // An expiry removes the session and leaves the sign-in mark alone.
    otherTabWrites(SESSION_KEY, null);
    await page.google.press();
    await expect(result).resolves.toMatchObject({ status: "signedIn" });
  });

  it("gives way to a sign-out in another tab", async () => {
    localStorage.setItem(SESSION_KEY, await storedSession({ expiresIn: -60 }));
    const page = setup();
    const { result } = await popup(page);
    localStorage.setItem(SESSION_KEY.replace(".session.", ".generation."), "signed-out-elsewhere");
    otherTabWrites(SESSION_KEY, null);
    await expect(result).rejects.toMatchObject({ code: "session-superseded" });
  });

  it("needs somewhere to draw the button", async () => {
    const page = setup();
    await expect(page.client.signInWithGoogle({ mode: "popup" })).rejects.toMatchObject({ code: "not-configured" });
  });
});

describe("falling back to the redirect", () => {
  const redirected = (redirect: ReturnType<typeof vi.fn>) => new URL(redirect.mock.calls[0]![0]);

  async function expectRedirect(page: ReturnType<typeof setup>) {
    const result = await page.client.signInWithGoogle({ mode: "popup", container: page.container, returnTo: "/next" });
    expect(result).toEqual({ status: "redirecting" });
    expect(redirected(page.redirect).searchParams.get("identity_provider")).toBe("Google");
    expect(page.container.childElementCount).toBe(0);
  }

  it("when Google's script is blocked, asking the product for nothing", async () => {
    const page = setup();
    page.google.block();
    await expectRedirect(page);
    expect(page.adapter.createSignInNonce).not.toHaveBeenCalled();
  });

  it("when Google refuses to draw", async () => {
    const page = setup();
    page.google.break();
    await expectRedirect(page);
  });

  it("when the app has no native adapter", async () => {
    const page = setup({ providerSignIn: undefined } as unknown as ClientOptions);
    await expectRedirect(page);
  });

  it("not for a caller who gives up while it is prepared, whose attempt is never saved", async () => {
    const controller = new AbortController();
    const page = setup();
    page.google.block();
    sessionStorage.setItem(ATTEMPT_KEY, "another redirect's proof");
    const digest = crypto.subtle.digest.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, "digest").mockImplementation((...input) => {
      controller.abort();
      return digest(...input);
    });
    await expect(
      page.client.signInWithGoogle({ mode: "popup", container: page.container, signal: controller.signal }),
    ).rejects.toMatchObject({ code: "sign-in-cancelled" });
    expect(page.redirect).not.toHaveBeenCalled();
    expect(sessionStorage.getItem(ATTEMPT_KEY)).toBe("another redirect's proof");
  });

  it("not for a caller who gives up as the attempt is saved", async () => {
    const controller = new AbortController();
    const attemptStorage = {
      getItem: (key: string) => sessionStorage.getItem(key),
      removeItem: (key: string) => sessionStorage.removeItem(key),
      setItem: (key: string, value: string) => {
        sessionStorage.setItem(key, value);
        controller.abort();
      },
    } as Storage;
    const page = setup({ attemptStorage });
    page.google.block();
    await expect(
      page.client.signInWithGoogle({ mode: "popup", container: page.container, signal: controller.signal }),
    ).rejects.toMatchObject({ code: "sign-in-cancelled" });
    expect(page.redirect).not.toHaveBeenCalled();
  });

  it("only when asked to", async () => {
    const page = setup();
    page.google.block();
    await expect(
      page.client.signInWithGoogle({ mode: "popup", container: page.container, fallback: false }),
    ).rejects.toMatchObject({ code: "provider-unavailable" });
    expect(page.redirect).not.toHaveBeenCalled();
  });

  it("not when the product's API fails", async () => {
    const page = setup();
    const failure = new Error("down");
    page.adapter.createSignInNonce.mockRejectedValue(failure);
    await expect(page.client.signInWithGoogle({ mode: "popup", container: page.container })).rejects.toBe(failure);
    expect(page.redirect).not.toHaveBeenCalled();
  });
});

describe("One Tap", () => {
  async function oneTap(page: ReturnType<typeof setup>, extra: { fallback?: boolean } = {}) {
    const result = page.client.signInWithGoogle({ mode: "oneTap", ...extra });
    result.catch(() => {});
    await vi.waitFor(() => expect(page.google.prompted()).toBe(true));
    return { result };
  }

  it("signs in from the prompt", async () => {
    const page = setup();
    const { result } = await oneTap(page);
    await page.google.press();
    page.google.moment({ isDismissedMoment: () => true, getDismissedReason: () => "credential_returned" });
    await expect(result).resolves.toMatchObject({ status: "signedIn" });
    expect(page.google.cancelled()).toBe(0);
  });

  it.each([
    ["skipped", { isSkippedMoment: () => true }],
    ["dismissed", { isDismissedMoment: () => true, getDismissedReason: () => "cancel_called" }],
  ])("leaves the person on the page when the prompt is %s", async (_, moment) => {
    const page = setup();
    const { result } = await oneTap(page, { fallback: true });
    page.google.moment(moment);
    await expect(result).resolves.toEqual({ status: "dismissed" });
    expect(page.redirect).not.toHaveBeenCalled();
  });

  it("does not redirect on its own when the prompt cannot be shown", async () => {
    const page = setup();
    const { result } = await oneTap(page);
    page.google.moment({ isNotDisplayed: () => true });
    await expect(result).rejects.toMatchObject({ code: "provider-unavailable" });
    expect(page.redirect).not.toHaveBeenCalled();
  });

  it("redirects then if asked to", async () => {
    const page = setup();
    const { result } = await oneTap(page, { fallback: true });
    page.google.moment({ isNotDisplayed: () => true });
    await expect(result).resolves.toEqual({ status: "redirecting" });
  });
});

describe("useGoogleSignIn", () => {
  function render(page: ReturnType<typeof setup>) {
    const wrapper = ({ children }: { children: ReactNode }) => createElement(CardeaProvider, { client: page.client }, children);
    return renderHook(() => useGoogleSignIn(), { wrapper });
  }

  it("reports pending and the failure", async () => {
    const page = setup();
    const failure = new Error("down");
    page.adapter.createSignInNonce.mockRejectedValue(failure);
    const hook = render(page);
    await act(() => hook.result.current.signInWithGoogle({ mode: "popup", container: page.container }).catch(() => {}));
    expect(hook.result.current).toMatchObject({ pending: false, error: failure });
  });

  it("ends the attempt when the view goes away, reporting nothing", async () => {
    const page = setup();
    const hook = render(page);
    let result!: Promise<unknown>;
    act(() => {
      result = hook.result.current.signInWithGoogle({ mode: "popup", container: page.container });
      result.catch(() => {});
    });
    await vi.waitFor(() => expect(page.google.buttons()).toBe(1));
    expect(hook.result.current.pending).toBe(true);
    hook.unmount();
    await expect(result).rejects.toMatchObject({ code: "sign-in-cancelled" });
    expect(page.container.childElementCount).toBe(0);
  });

  it("replaces an earlier attempt with the next", async () => {
    const page = setup();
    const hook = render(page);
    const start = () => {
      let result!: Promise<unknown>;
      act(() => {
        result = hook.result.current.signInWithGoogle({ mode: "popup", container: page.container });
        result.catch(() => {});
      });
      return result;
    };
    const first = start();
    await vi.waitFor(() => expect(page.google.buttons()).toBe(1));
    const second = start();
    await expect(first).rejects.toMatchObject({ code: "sign-in-cancelled" });
    await vi.waitFor(() => expect(page.google.buttons()).toBe(2));
    expect(page.container.childElementCount).toBe(1);
    await act(() => page.google.press());
    await act(async () => {
      await expect(second).resolves.toMatchObject({ status: "signedIn" });
    });
    expect(hook.result.current.error).toBeNull();
  });
});
