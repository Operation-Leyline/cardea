import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { StrictMode, useEffect, useLayoutEffect, useState, type ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cognitoSdkSession, createCardeaClient, type IdentityLinkAdapter, type SignInMethod } from "../src/index.js";
import { CardeaProvider, useLinkProvider, useSession, useSignIn, useSignInMethods, type CardeaProviderProps } from "../src/react/index.js";
import { ATTEMPT_KEY, CognitoFailure, CONFIG, installFakeCognito, issueTokens, otherTabWrites, SESSION_KEY, storedSession } from "./fakes/cognito.js";

afterEach(cleanup);

const PASSWORD = "Correct-Horse-12";

function render<T>(hook: () => T, props: Partial<CardeaProviderProps> = {}) {
  const client = props.client ?? createCardeaClient(CONFIG, { redirect: () => {} });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <StrictMode>
      <CardeaProvider {...props} client={client}>
        {children}
      </CardeaProvider>
    </StrictMode>
  );
  return { client, ...renderHook(hook, { wrapper }) };
}

describe("useSession", () => {
  it("restores, then follows another tab and sign-out", async () => {
    installFakeCognito();
    localStorage.setItem(SESSION_KEY, await storedSession());
    const { result } = render(useSession);
    await waitFor(() => expect(result.current.status).toBe("signedIn"));
    const other = await storedSession({ subject: "grace" });
    act(() => otherTabWrites(SESSION_KEY, other));
    expect(result.current.session?.subject).toBe("grace");
    act(() => result.current.signOut());
    expect(result.current).toMatchObject({ status: "signedOut", session: null });
  });

  it.each([
    ["an effect", useEffect],
    ["a layout effect", useLayoutEffect],
  ])("gives a child that asks on mount, in %s, the token of a session being imported", async (_name, onMount) => {
    installFakeCognito();
    const old = await issueTokens();
    const root = `CognitoIdentityServiceProvider.${CONFIG.clientId}`;
    localStorage.setItem(`${root}.LastAuthUser`, "user-ada");
    localStorage.setItem(`${root}.user-ada.idToken`, old.id_token);
    localStorage.setItem(`${root}.user-ada.accessToken`, old.access_token);
    localStorage.setItem(`${root}.user-ada.refreshToken`, old.refresh_token);
    const client = createCardeaClient({ ...CONFIG, importSession: [cognitoSdkSession()] });
    const { result } = render(
      () => {
        const { getIdToken } = useSession();
        const [token, setToken] = useState<string | null>();
        onMount(() => void getIdToken().then(setToken), [getIdToken]);
        return token;
      },
      { client },
    );
    await waitFor(() => expect(result.current).toBe(old.id_token));
  });

  it("finishes a provider callback once and says where to go", async () => {
    const cognito = installFakeCognito();
    const redirect = vi.fn();
    await createCardeaClient(CONFIG, { redirect }).signInWithProvider("Google", { returnTo: "/settings" });
    const url = new URL(redirect.mock.calls[0][0]);
    cognito.onToken(async () => Response.json(await issueTokens({ nonce: url.searchParams.get("nonce")! })));
    window.history.replaceState(null, "", `/auth/callback?code=c&state=${url.searchParams.get("state")}`);
    const onRedirectComplete = vi.fn();
    const { result } = render(useSession, { onRedirectComplete });
    await waitFor(() => expect(result.current.status).toBe("signedIn"));
    await waitFor(() => expect(onRedirectComplete).toHaveBeenCalled());
    expect(onRedirectComplete.mock.calls).toEqual([[{ returnTo: "/settings" }]]);
    expect(cognito.tokenRequests).toHaveLength(1);
    expect(sessionStorage.getItem(ATTEMPT_KEY)).toBeNull();
  });
});

describe("useSignIn", () => {
  const both = () => ({ form: useSignIn(), session: useSession() });

  it("signs up, confirms, and signs in without asking for the password again", async () => {
    const cognito = installFakeCognito();
    const { result } = render(both);
    await act(() => result.current.form.signUp("ada@example.test", PASSWORD));
    expect(result.current.form).toMatchObject({ step: "confirmationRequired", email: "ada@example.test" });
    await act(() => result.current.form.resendCode());
    let signedIn: boolean | undefined;
    await act(async () => void (signedIn = await result.current.form.confirmSignUp("123456")));
    expect(signedIn).toBe(true);
    expect(result.current.form.step).toBe("credentials");
    expect(result.current.session.status).toBe("signedIn");
    expect(cognito.operationNames()).toEqual([
      "SignUp",
      "ResendConfirmationCode",
      "ConfirmSignUp",
      "InitiateAuth",
      "RespondToAuthChallenge",
    ]);
  });

  it("asks for the password again after confirming a sign-up that reset forgot", async () => {
    const cognito = installFakeCognito();
    cognito.operations.InitiateAuth = () => new CognitoFailure("UserNotConfirmedException");
    const { result } = render(both);
    await act(() => result.current.form.signIn("ada@example.test", PASSWORD));
    expect(result.current.form.step).toBe("confirmationRequired");
    act(() => result.current.form.reset());
    expect(result.current.form).toMatchObject({ step: "credentials", email: "" });
  });

  it("shows a challenge and answers it", async () => {
    const cognito = installFakeCognito();
    const normal = cognito.operations.RespondToAuthChallenge;
    cognito.operations.RespondToAuthChallenge = (body) =>
      body.ChallengeName === "PASSWORD_VERIFIER"
        ? { ChallengeName: "SOFTWARE_TOKEN_MFA", Session: "s", ChallengeParameters: {} }
        : normal(body);
    const { result } = render(both);
    await act(() => result.current.form.signIn("ada@example.test", PASSWORD));
    expect(result.current.form.step).toBe("totpRequired");
    await act(() => result.current.form.submitTotp("123456"));
    expect(result.current.session.status).toBe("signedIn");
    expect(result.current.form.step).toBe("credentials");
  });

  it("resets a password, and reports when the sign-in after it fails", async () => {
    const cognito = installFakeCognito();
    cognito.operations.InitiateAuth = () => new CognitoFailure("NotAuthorizedException");
    const { result } = render(both);
    await act(() => result.current.form.requestPasswordReset("ada@example.test"));
    expect(result.current.form.step).toBe("resetCodeSent");
    let signedIn: boolean | undefined;
    await act(async () => void (signedIn = await result.current.form.resetPassword("123456", PASSWORD)));
    expect(signedIn).toBe(false);
    expect(result.current.form).toMatchObject({ step: "credentials", error: null });
  });

  it("keeps a failure in error and rejects", async () => {
    const cognito = installFakeCognito();
    cognito.operations.InitiateAuth = () => new CognitoFailure("NotAuthorizedException");
    const { result } = render(both);
    await act(async () => {
      await expect(result.current.form.signIn("ada@example.test", "wrong")).rejects.toThrow();
    });
    expect(result.current.form).toMatchObject({ pending: false, error: { code: "NotAuthorizedException" } });
  });
});

describe("linking hooks", () => {
  function fakeAdapter() {
    const methods = new Map<string, SignInMethod[]>([
      ["ada", [{ type: "password" }]],
      ["grace", []],
    ]);
    const subject = () => JSON.parse(atob(JSON.parse(localStorage.getItem(SESSION_KEY)!).idToken.split(".")[1])).sub;
    const adapter: IdentityLinkAdapter = {
      createIdentityLink: async () => ({
        linkId: "l",
        nonce: "n",
        clientId: "c",
        expiresAt: new Date(Date.now() + 300_000),
      }),
      completeIdentityLink: async () => {
        methods.get(subject())!.push({ type: "provider", provider: "Google", email: "ada@gmail.test" });
        return { userId: subject() };
      },
      listSignInMethods: async () => [...methods.get(subject())!],
      unlinkSignInMethod: async ({ provider }) => {
        methods.set(subject(), methods.get(subject())!.filter((m) => m.type !== "provider" || m.provider !== provider));
      },
    };
    return adapter;
  }

  it("lists, links, unlinks, and never shows another account's methods", async () => {
    installFakeCognito();
    localStorage.setItem(SESSION_KEY, await storedSession());
    const token = (await issueTokens({ nonce: "n" })).id_token;
    const source = { load: async () => {}, request: async () => token };
    const adapter = fakeAdapter();
    const seen: unknown[] = [];
    const { result } = render(
      () => {
        const value = { methods: useSignInMethods(), link: useLinkProvider(), session: useSession() };
        seen.push([value.session.session?.subject, value.methods.methods?.length]);
        return value;
      },
      { linkAdapter: adapter, proofSources: { Google: source } },
    );
    await waitFor(() => expect(result.current.methods.hasPassword).toBe(true));
    await act(() => result.current.link.prepare("Google"));
    expect(result.current.link.status).toBe("ready");
    await act(() => result.current.link.confirm());
    expect(result.current.link.status).toBe("linked");
    await waitFor(() => expect(result.current.methods.methods).toHaveLength(2));
    await act(() => result.current.methods.unlink("Google"));
    await waitFor(() => expect(result.current.methods.methods).toHaveLength(1));

    const other = await storedSession({ subject: "grace" });
    act(() => otherTabWrites(SESSION_KEY, other));
    expect(result.current.link.status).toBe("idle");
    await waitFor(() => expect(result.current.methods.methods).toEqual([]));
    expect(seen).not.toContainEqual(["grace", 1]);
  });

  it("uses the provider settings as they are when a link is prepared, through to confirmation", async () => {
    installFakeCognito();
    localStorage.setItem(SESSION_KEY, await storedSession());
    const token = (await issueTokens({ nonce: "n" })).id_token;
    const source = () => ({ load: vi.fn(async () => {}), request: vi.fn(async () => token) });
    const [first, second, third] = [source(), source(), source()];
    const adapter = fakeAdapter();
    const client = createCardeaClient(CONFIG);
    let current = first;
    const { result, rerender } = renderHook(useLinkProvider, {
      wrapper: ({ children }) => (
        <CardeaProvider client={client} linkAdapter={adapter} proofSources={{ Google: current }}>
          {children}
        </CardeaProvider>
      ),
    });
    current = second;
    rerender();
    await act(() => result.current.prepare("Google"));
    // A change between preparing and confirming must not swap in a source that was never loaded.
    current = third;
    rerender();
    await act(() => result.current.confirm());
    expect(first.load).not.toHaveBeenCalled();
    expect(second.load).toHaveBeenCalledOnce();
    expect(second.request).toHaveBeenCalledOnce();
    expect(third.request).not.toHaveBeenCalled();
  });

  it("shows a failed link and refuses to confirm before preparing", async () => {
    installFakeCognito();
    localStorage.setItem(SESSION_KEY, await storedSession());
    const source = { load: async () => {}, request: async () => (await issueTokens({ nonce: "wrong" })).id_token };
    const { result } = render(useLinkProvider, { linkAdapter: fakeAdapter(), proofSources: { Google: source } });
    await act(async () => {
      await expect(result.current.confirm()).rejects.toMatchObject({ code: "attempt-invalid" });
      await expect(result.current.link("Google")).rejects.toMatchObject({ code: "nonce-mismatch" });
    });
    expect(result.current).toMatchObject({ status: "failed", provider: "Google" });
  });
});
