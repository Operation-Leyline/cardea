import { describe, expect, it, vi } from "vitest";
import { createCardeaClient, type SessionEvent } from "../src/index.js";
import { ATTEMPT_KEY, authenticationResult, CognitoFailure, CONFIG, deferred, installFakeCognito, issueTokens, otherTabWrites, SESSION_KEY, storedSession } from "./fakes/cognito.js";

async function signedIn(options: Parameters<typeof storedSession>[0] = {}) {
  const cognito = installFakeCognito();
  localStorage.setItem(SESSION_KEY, await storedSession(options));
  const redirect = vi.fn();
  const client = createCardeaClient(CONFIG, { redirect });
  const events: SessionEvent[] = [];
  client.subscribe((event) => events.push(event));
  return { cognito, client, events, redirect };
}

const STALE = { expiresIn: -10 };
const stored = () => localStorage.getItem(SESSION_KEY);

describe("restoring", () => {
  it("uses a fresh session without any request", async () => {
    const { cognito, client } = await signedIn();
    expect(client.getState().status).toBe("loading");
    await client.start();
    expect(client.getState()).toMatchObject({ status: "signedIn", session: { subject: "ada" } });
    expect(cognito.fetcher).not.toHaveBeenCalled();
  });

  it.each(["{", "null", '{"version":1}', '{"version":2}'])("reads %s as signed out", async (raw) => {
    installFakeCognito();
    localStorage.setItem(SESSION_KEY, raw);
    const client = createCardeaClient(CONFIG);
    await client.start();
    expect(client.getState().status).toBe("signedOut");
  });

  it("is signed out when the browser blocks storage", async () => {
    const blocked = { getItem: () => { throw new Error("blocked"); } } as unknown as Storage;
    const client = createCardeaClient(CONFIG, { storage: blocked });
    await client.start();
    await expect(client.getIdToken()).resolves.toBeNull();
  });
});

describe("refresh", () => {
  it("shares one request between concurrent callers and keeps the refresh token", async () => {
    const { cognito, client, events } = await signedIn(STALE);
    const tokens = await Promise.all([client.getIdToken(), client.getIdToken(), client.getAccessToken(), client.getSession()]);
    expect(cognito.operationNames()).toEqual(["InitiateAuth"]);
    expect(cognito.calls[0].body).toMatchObject({
      AuthFlow: "REFRESH_TOKEN_AUTH",
      AuthParameters: { REFRESH_TOKEN: "refresh-ada" },
    });
    expect(tokens[0]).toBe(tokens[1]);
    expect(JSON.parse(stored()!)).toMatchObject({ idToken: tokens[0], refreshToken: "refresh-ada" });
    // A refresh is not a change of account.
    expect(events).toEqual([]);
    expect(client.getState().session!.expiresAt).toBeGreaterThan(Date.now());
    await client.getIdToken();
    expect(cognito.calls).toHaveLength(1);
  });

  it("refreshes a provider session at the token endpoint and verifies the result", async () => {
    const { cognito, client } = await signedIn({ ...STALE, method: "Google" });
    cognito.onToken(async () => Response.json({ ...(await issueTokens()), refresh_token: undefined }));
    const [one, two] = await Promise.all([client.getIdToken(), client.getIdToken()]);
    expect(one).toBe(two);
    expect(cognito.tokenRequests).toHaveLength(1);
    expect(cognito.tokenRequests[0].get("grant_type")).toBe("refresh_token");
    expect(JSON.parse(stored()!).refreshToken).toBe("refresh-ada");
    expect(cognito.calls).toEqual([]);
  });

  it.each([
    ["another account's tokens", { subject: "mallory" }],
    ["a foreign signature", { foreignKey: true }],
  ])("saves nothing when a provider refresh returns %s", async (_name, options) => {
    const { cognito, client } = await signedIn({ ...STALE, method: "Google" });
    const before = stored();
    cognito.onToken(async () => Response.json(await issueTokens(options)));
    await expect(client.getIdToken()).rejects.toMatchObject({ code: "refresh-failed" });
    expect(stored()).toBe(before);
  });

  it("keeps the session through an outage and recovers", async () => {
    const { cognito, client } = await signedIn({ ...STALE, method: "Google" });
    cognito.onToken(async () => Promise.reject(new TypeError("offline")));
    const result = await client.start();
    expect(result.error?.code).toBe("refresh-failed");
    expect(client.getState()).toMatchObject({ status: "signedIn", error: { code: "refresh-failed" } });
    cognito.onToken(async () => Response.json(await issueTokens()));
    await expect(client.getIdToken()).resolves.toEqual(expect.any(String));
    expect(client.getState().error).toBeNull();
  });

  it("sends no refresh token anywhere once the hosted domain is no longer configured", async () => {
    const cognito = installFakeCognito();
    localStorage.setItem(SESSION_KEY, await storedSession({ method: "Google", expiresIn: -10 }));
    const { loginDomain: _unused, providers: _also, ...bare } = CONFIG;
    const client = createCardeaClient(bare);
    await expect(client.getIdToken()).rejects.toMatchObject({ code: "refresh-failed" });
    expect(cognito.fetcher).not.toHaveBeenCalled();
    expect(client.currentSession()?.subject).toBe("ada");
  });

  it("ends a provider session whose refresh token was revoked", async () => {
    const { cognito, client, events } = await signedIn({ ...STALE, method: "Apple" });
    cognito.onToken(async () => Response.json({ error: "invalid_grant" }, { status: 400 }));
    await expect(client.getIdToken()).resolves.toBeNull();
    expect(stored()).toBeNull();
    expect(events).toMatchObject([{ type: "signedOut", reason: "expired", origin: "thisTab" }]);
  });

  it("ends a password session whose refresh token expired", async () => {
    const { cognito, client, events } = await signedIn(STALE);
    cognito.operations.InitiateAuth = () => new CognitoFailure("NotAuthorizedException");
    // The SDK retries a refused refresh with back-off before giving up.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const token = client.getIdToken();
    let settled = false;
    void token.finally(() => (settled = true));
    while (!settled) await vi.advanceTimersByTimeAsync(1000);
    await expect(token).resolves.toBeNull();
    expect(events).toMatchObject([{ type: "signedOut", reason: "expired" }]);
  });

  it("does not bring a session back after sign-out", async () => {
    const { cognito, client } = await signedIn(STALE);
    const answer = deferred<unknown>();
    cognito.operations.InitiateAuth = () => answer.promise;
    const token = client.getIdToken();
    client.signOut();
    answer.resolve(authenticationResult(await issueTokens(), false));
    await expect(token).resolves.toBeNull();
    expect(stored()).toBeNull();
  });

  it("never hands a caller the tokens of an account that replaced theirs", async () => {
    const { cognito, client } = await signedIn(STALE);
    const answer = deferred<unknown>();
    cognito.operations.InitiateAuth = () => answer.promise;
    const token = client.getIdToken();
    const other = await storedSession({ subject: "grace" });
    otherTabWrites(SESSION_KEY, other);
    answer.resolve(authenticationResult(await issueTokens(), false));
    await expect(token).resolves.toBeNull();
    expect(stored()).toBe(other);
    expect(client.currentSession()?.subject).toBe("grace");
  });

  it("refreshes again when the same account is saved stale in the meantime", async () => {
    const { cognito, client } = await signedIn(STALE);
    const answer = deferred<unknown>();
    const normal = cognito.operations.InitiateAuth;
    cognito.operations.InitiateAuth = () => answer.promise;
    const token = client.getIdToken();
    otherTabWrites(SESSION_KEY, await storedSession({ ...STALE, id: { marker: "stale" } }));
    cognito.operations.InitiateAuth = normal;
    answer.resolve(authenticationResult(await issueTokens(), false));
    const result = await token;
    expect(result).toBe(JSON.parse(stored()!).idToken);
    expect(cognito.calls).toHaveLength(2);
  });

  it("does not loop or re-refresh when this device's clock is far ahead", async () => {
    const { cognito, client } = await signedIn(STALE);
    vi.useFakeTimers({ toFake: ["Date"] });
    // Cognito's clock, as the tokens show it, is two hours behind this device's.
    const behind = await issueTokens();
    vi.setSystemTime(Date.now() + 2 * 3600_000);
    cognito.operations.InitiateAuth = () => authenticationResult(behind, false);
    await expect(client.getIdToken()).resolves.toBe(behind.id_token);
    await expect(client.getIdToken()).resolves.toBe(behind.id_token);
    expect(cognito.calls).toHaveLength(1);
    expect(JSON.parse(stored()!).clockDrift).toBeGreaterThanOrEqual(7199);
  });

  it("takes the tokens another tab already refreshed", async () => {
    const { cognito, client } = await signedIn(STALE);
    const answer = deferred<unknown>();
    cognito.operations.InitiateAuth = () => answer.promise;
    const token = client.getIdToken();
    const fresh = await storedSession({ id: { marker: "other-tab" } });
    otherTabWrites(SESSION_KEY, fresh);
    answer.resolve(new CognitoFailure("InternalErrorException"));
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    let settled = false;
    void token.finally(() => (settled = true));
    while (!settled) await vi.advanceTimersByTimeAsync(1000);
    await expect(token).resolves.toBe(JSON.parse(fresh).idToken);
    expect(stored()).toBe(fresh);
  });
});

describe("changes in other tabs", () => {
  it("reports an account change, with both accounts", async () => {
    const { client, events } = await signedIn();
    await client.start();
    const listener = vi.fn();
    client.subscribeState(listener);
    otherTabWrites(SESSION_KEY, await storedSession({ subject: "grace" }));
    expect(events).toMatchObject([
      { type: "accountChanged", origin: "otherTab", previous: { subject: "ada" }, session: { subject: "grace" } },
    ]);
    expect(client.getState().session?.subject).toBe("grace");
    expect(listener).toHaveBeenCalled();
  });

  it("reports sign-out, then sign-in", async () => {
    const { client, events } = await signedIn();
    otherTabWrites(SESSION_KEY, null);
    otherTabWrites(SESSION_KEY, await storedSession());
    expect(events).toMatchObject([
      { type: "signedOut", reason: "signedOut", origin: "otherTab" },
      { type: "signedIn", origin: "otherTab" },
    ]);
    expect(client.currentSession()?.subject).toBe("ada");
  });

  it("reports cleared storage as sign-out", async () => {
    const { events } = await signedIn();
    otherTabWrites(null, null);
    expect(events).toMatchObject([{ type: "signedOut" }]);
  });

  it("stays quiet for another tab's refresh and for unrelated keys", async () => {
    const { events } = await signedIn();
    otherTabWrites(SESSION_KEY, await storedSession({ id: { marker: "refreshed" } }));
    otherTabWrites("theme", "dark");
    expect(events).toEqual([]);
  });

  it("notices a change on the next read even before the storage event arrives", async () => {
    const { client, events } = await signedIn();
    localStorage.setItem(SESSION_KEY, await storedSession({ subject: "grace" }));
    await client.getIdToken();
    expect(events).toMatchObject([{ type: "accountChanged" }]);
  });

  it("stops listening once disposed", async () => {
    const { client, events } = await signedIn();
    client.dispose();
    otherTabWrites(SESSION_KEY, null);
    expect(events).toEqual([]);
  });
});

describe("sign-out", () => {
  it("clears the session and any pending attempt, and stays on the page for a password session", async () => {
    const { client, events, redirect } = await signedIn();
    sessionStorage.setItem(ATTEMPT_KEY, "{}");
    localStorage.setItem("theme", "dark");
    client.signOut();
    expect(stored()).toBeNull();
    expect(sessionStorage.length).toBe(0);
    expect(localStorage.getItem("theme")).toBe("dark");
    expect(client.getState()).toEqual({ status: "signedOut", session: null, error: null });
    expect(events).toMatchObject([{ type: "signedOut", reason: "signedOut", origin: "thisTab" }]);
    expect(redirect).not.toHaveBeenCalled();
    await expect(client.getIdToken()).resolves.toBeNull();
  });

  it.each([
    ["a provider session", "Google", undefined],
    ["a request for it", "password", true],
  ])("also leaves the hosted session for %s", async (_name, method, hosted) => {
    const { client, redirect } = await signedIn({ method });
    client.signOut(hosted === undefined ? {} : { hosted });
    const url = new URL(redirect.mock.calls[0][0]);
    expect(url.origin + url.pathname).toBe(`${CONFIG.loginDomain}/logout`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: CONFIG.clientId,
      logout_uri: "https://app.example.test/",
    });
    expect(stored()).toBeNull();
  });
});
