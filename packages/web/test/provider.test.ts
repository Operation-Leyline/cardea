import { describe, expect, it, vi } from "vitest";
import { createCardeaClient, safeReturnPath, type ClientOptions, type Provider } from "../src/index.js";
import { ATTEMPT_KEY, CONFIG, installFakeCognito, issueTokens, SESSION_KEY, storedSession, type TokenOptions } from "./fakes/cognito.js";

const RETURN = "/invitations/org/invite?token=synthetic#accept";

/** Leaves for the provider and returns what Cognito would send the browser back with. */
async function leave(options: ClientOptions = {}, provider: Provider = "Google") {
  const cognito = installFakeCognito();
  const redirect = vi.fn();
  const client = createCardeaClient(CONFIG, { redirect, ...options });
  await client.signInWithProvider(provider, { returnTo: RETURN });
  const authorization = new URL(redirect.mock.calls[0][0]);
  const query = new URLSearchParams({ code: "synthetic-code", state: authorization.searchParams.get("state")! });
  return { cognito, client, redirect, authorization, query, nonce: authorization.searchParams.get("nonce")! };
}

/** The page load that follows: a new client on the callback URL. */
function comeBack(query: URLSearchParams, options: ClientOptions = {}, config = CONFIG) {
  window.history.replaceState(null, "", `/auth/callback?${query}`);
  const client = createCardeaClient(config, { redirect: () => {}, ...options });
  return { client, result: client.start() };
}

function editAttempt(change: Record<string, unknown>) {
  const attempt = JSON.parse(sessionStorage.getItem(ATTEMPT_KEY)!);
  sessionStorage.setItem(ATTEMPT_KEY, JSON.stringify({ ...attempt, ...change }));
}

describe("leaving for a provider", () => {
  it("sends fresh state, nonce and an S256 challenge, remembered only in this tab", async () => {
    const first = await leave();
    const { authorization } = first;
    expect(authorization.origin + authorization.pathname).toBe(`${CONFIG.loginDomain}/oauth2/authorize`);
    expect(Object.fromEntries(authorization.searchParams)).toMatchObject({
      identity_provider: "Google",
      response_type: "code",
      scope: "openid email",
      client_id: CONFIG.clientId,
      redirect_uri: "https://app.example.test/auth/callback",
      code_challenge_method: "S256",
      prompt: "select_account",
    });
    const attempt = JSON.parse(sessionStorage.getItem(ATTEMPT_KEY)!);
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(attempt.verifier));
    expect(authorization.searchParams.get("code_challenge")).toBe(Buffer.from(digest).toString("base64url"));
    expect(authorization.href).not.toContain(attempt.verifier);
    expect(localStorage.length).toBe(0);
    const second = await leave();
    for (const name of ["state", "nonce", "code_challenge"]) {
      expect(second.authorization.searchParams.get(name)).not.toBe(authorization.searchParams.get(name));
    }
  });

  it("names Apple as Cognito does", async () => {
    const { authorization } = await leave({}, "Apple");
    expect(authorization.searchParams.get("identity_provider")).toBe("SignInWithApple");
    expect(authorization.searchParams.has("prompt")).toBe(false);
  });

  it("does not leave when the tab refuses to remember the attempt", async () => {
    const redirect = vi.fn();
    const refusing = { ...sessionStorage, setItem: () => { throw new Error("refused"); } } as unknown as Storage;
    const client = createCardeaClient(CONFIG, { redirect, attemptStorage: refusing });
    await expect(client.signInWithProvider("Google")).rejects.toMatchObject({ code: "storage-unavailable" });
    expect(redirect).not.toHaveBeenCalled();
  });
});

describe("coming back", () => {
  it("exchanges the code once, verifies, saves, and scrubs the address bar", async () => {
    const { cognito, query, nonce, authorization } = await leave();
    cognito.onToken(async () => Response.json(await issueTokens({ nonce })));
    const verifier = JSON.parse(sessionStorage.getItem(ATTEMPT_KEY)!).verifier;
    const { client, result } = comeBack(query);
    expect(client.getState().status).toBe("loading");
    expect(client.start()).toBe(result);
    await expect(result).resolves.toEqual({ returnTo: RETURN });
    expect(window.location.pathname + window.location.search).toBe("/auth/callback");
    expect(client.getState()).toMatchObject({ status: "signedIn", session: { method: "Google", subject: "ada" } });
    expect(cognito.tokenRequests).toHaveLength(1);
    expect(Object.fromEntries(cognito.tokenRequests[0])).toEqual({
      client_id: CONFIG.clientId,
      grant_type: "authorization_code",
      code: "synthetic-code",
      redirect_uri: authorization.searchParams.get("redirect_uri"),
      code_verifier: verifier,
    });
    expect(sessionStorage.length).toBe(0);

    // The same callback again finds no attempt, so no second exchange happens.
    localStorage.clear();
    const replay = await comeBack(query).result;
    expect(replay.error?.code).toBe("attempt-invalid");
    expect(cognito.tokenRequests).toHaveLength(1);
    expect(localStorage.length).toBe(0);
  });

  it("accepts an attempt just inside ten minutes and refuses one just outside", async () => {
    const young = await leave();
    young.cognito.onToken(async () => Response.json(await issueTokens({ nonce: young.nonce })));
    editAttempt({ createdAt: Date.now() - 9 * 60_000 - 50_000 });
    await expect(comeBack(young.query).result).resolves.toEqual({ returnTo: RETURN });

    localStorage.clear();
    const old = await leave();
    editAttempt({ createdAt: Date.now() - 10 * 60_000 - 1000 });
    const outcome = await comeBack(old.query).result;
    expect(outcome.error?.code).toBe("attempt-invalid");
    expect(old.cognito.tokenRequests).toHaveLength(0);
    expect(sessionStorage.length).toBe(0);
  });

  const tampering: [string, (query: URLSearchParams) => void][] = [
    ["no state", (query) => query.delete("state")],
    ["another state", (query) => query.set("state", "attacker")],
    ["two states", (query) => query.append("state", "attacker")],
    ["no code", (query) => query.delete("code")],
    ["two codes", (query) => query.append("code", "attacker")],
    ["an attempt from the future", () => editAttempt({ createdAt: Date.now() + 60_000 })],
    ["another origin's attempt", () => editAttempt({ redirectUri: "https://evil.example/auth/callback" })],
    ["another client's attempt", () => editAttempt({ clientId: "other" })],
    ["another domain's attempt", () => editAttempt({ domain: "https://other.example.test" })],
    ["a damaged verifier", () => editAttempt({ verifier: "short" })],
    ["an unreadable attempt", () => sessionStorage.setItem(ATTEMPT_KEY, "{")],
  ];
  it.each(tampering)("refuses %s without sending the code", async (_name, tamper) => {
    const { cognito, query } = await leave();
    tamper(query);
    const outcome = await comeBack(query).result;
    expect(outcome.error?.code).toBe("attempt-invalid");
    expect(cognito.tokenRequests).toHaveLength(0);
    expect(sessionStorage.length).toBe(0);
    expect(localStorage.length).toBe(0);
  });

  it("keeps the destination on refusal and repeats nothing the provider said", async () => {
    const { query } = await leave();
    query.delete("code");
    query.set("error", "access_denied");
    query.set("error_description", "private provider detail");
    const outcome = await comeBack(query).result;
    expect(outcome).toMatchObject({ returnTo: RETURN, error: { code: "provider-refused" } });
    expect(outcome.error?.message).not.toContain("private");
  });

  const forged: [string, TokenOptions][] = [
    ["a different nonce", { nonce: "someone-elses-nonce" }],
    ["no nonce", { nonce: "" }],
    ["a foreign signature", { foreignKey: true }],
    ["another issuer", { issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Other" }],
    ["another audience", { id: { aud: "other-client" } }],
    ["an expired token", { expiresIn: -120 }],
    ["an access token where the ID token belongs", { id: { token_use: "access" } }],
    ["no email", { id: { email: "" } }],
    ["an ID token where the access token belongs", { access: { token_use: "id" } }],
    ["an access token for another client", { access: { client_id: "other-client" } }],
    ["two different subjects", { access: { sub: "mallory" } }],
  ];
  it.each(forged)("saves nothing for %s", async (_name, options) => {
    const { cognito, query, nonce } = await leave();
    cognito.onToken(async () => Response.json(await issueTokens({ nonce, ...options })));
    const { client, result } = comeBack(query);
    await expect(result).resolves.toMatchObject({ error: { code: "token-verification-failed" } });
    expect(localStorage.length).toBe(0);
    expect(client.getState()).toMatchObject({ status: "signedOut", session: null });
  });

  it.each([
    ["a refused exchange", () => Response.json({ error: "invalid_grant" }, { status: 400 })],
    ["a response without tokens", () => Response.json({})],
  ])("reports %s", async (_name, response) => {
    const { cognito, query } = await leave();
    cognito.onToken(async () => response());
    await expect(comeBack(query).result).resolves.toMatchObject({ error: { code: "token-exchange-failed" } });
    expect(localStorage.length).toBe(0);
  });

  it("refuses a session with no refresh token", async () => {
    const { cognito, query, nonce } = await leave();
    cognito.onToken(async () => Response.json({ ...(await issueTokens({ nonce })), refresh_token: undefined }));
    await expect(comeBack(query).result).resolves.toMatchObject({ error: { code: "token-exchange-failed" } });
  });

  it("lets the product refuse the account before anything is saved", async () => {
    const { cognito, query, nonce } = await leave();
    cognito.onToken(async () => Response.json(await issueTokens({ nonce })));
    const confirmProviderSession = vi.fn().mockRejectedValue(new Error("unknown to the API"));
    await expect(comeBack(query, { confirmProviderSession }).result).resolves.toMatchObject({
      error: { code: "account-check-failed" },
    });
    expect(confirmProviderSession).toHaveBeenCalledWith({ idToken: expect.any(String), subject: "ada" });
    expect(localStorage.length).toBe(0);
  });

  it("yields to another tab that signed in during the exchange", async () => {
    const { cognito, query, nonce } = await leave();
    const other = await storedSession({ subject: "grace" });
    cognito.onToken(async () => {
      localStorage.setItem(SESSION_KEY, other);
      return Response.json(await issueTokens({ nonce }));
    });
    await expect(comeBack(query).result).resolves.toMatchObject({ error: { code: "session-superseded" } });
    expect(localStorage.getItem(SESSION_KEY)).toBe(other);
  });

  it("goes home without an error when the emptied callback page is reloaded", async () => {
    installFakeCognito();
    await expect(comeBack(new URLSearchParams()).result).resolves.toEqual({ returnTo: "/" });
  });
});

describe("return paths", () => {
  it.each([
    "https://evil.example/",
    "//evil.example/",
    "/\\evil.example/",
    "/.//evil.example/",
    "/auth/callback?code=old",
    "javascript:alert(1)",
    "relative",
    null,
  ])("sends %s home", (path) => {
    expect(safeReturnPath(path, window.location.origin)).toBe("/");
  });
});
