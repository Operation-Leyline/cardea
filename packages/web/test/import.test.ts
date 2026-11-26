import { describe, expect, it, vi } from "vitest";
import {
  cognitoSdkSession,
  createCardeaClient,
  leylineGoogleSession,
  type CardeaConfig,
  type ClientOptions,
  type SessionEvent,
} from "../src/index.js";
import { authenticationResult, CognitoFailure, CONFIG, deferred, GENERATION_KEY, installFakeCognito, ISSUER, issueTokens, otherTabWrites, SESSION_KEY, storedSession, type TokenOptions } from "./fakes/cognito.js";

const SDK = `CognitoIdentityServiceProvider.${CONFIG.clientId}`;
const GOOGLE = `leyline.google.session.${CONFIG.clientId}.${ISSUER}`;
const EXPIRED = { expiresIn: -3600 };

/** What `amazon-cognito-identity-js` leaves in storage after a sign-in. */
async function saveSdk(options: TokenOptions & { prefix?: string; clientId?: string; user?: string } = {}) {
  const { prefix = "", clientId = CONFIG.clientId, user = "user-ada" } = options;
  const root = `${prefix}CognitoIdentityServiceProvider.${clientId}`;
  const tokens = await issueTokens(options);
  localStorage.setItem(`${root}.LastAuthUser`, user);
  localStorage.setItem(`${root}.${user}.idToken`, tokens.id_token);
  localStorage.setItem(`${root}.${user}.accessToken`, tokens.access_token);
  localStorage.setItem(`${root}.${user}.refreshToken`, tokens.refresh_token);
  localStorage.setItem(`${root}.${user}.clockDrift`, "0");
  return tokens;
}

/** The JSON record leyline-console and yoru-web keep for a Google sign-in. */
async function saveHosted(key: string, options: TokenOptions & { recorded?: string } = {}) {
  const tokens = await issueTokens(options);
  localStorage.setItem(key, JSON.stringify({ ...tokens, subject: options.recorded ?? options.subject ?? "ada" }));
  return tokens;
}

const SOURCES = {
  "the SDK's default storage": {
    source: cognitoSdkSession(),
    save: (options?: TokenOptions) => saveSdk(options),
    method: "password",
  },
  "the SDK layout under a prefix": {
    source: cognitoSdkSession({ prefix: "yoru.auth." }),
    save: (options?: TokenOptions) => saveSdk({ ...options, prefix: "yoru.auth." }),
    method: "password",
  },
  "leyline-console's Google session": {
    source: leylineGoogleSession(),
    save: (options?: TokenOptions) => saveHosted(GOOGLE, options),
    method: "Google",
  },
} as const;

function setup(importSession: CardeaConfig["importSession"], options: ClientOptions = {}, config: Partial<CardeaConfig> = {}) {
  const client = createCardeaClient({ ...CONFIG, ...config, importSession: importSession! }, { redirect: () => {}, ...options });
  const events: SessionEvent[] = [];
  client.subscribe((event) => events.push(event));
  return { client, events };
}

/** Stored keys, leaving out the sign-in generation mark. */
const keys = () => Object.keys(localStorage).filter((key) => key !== GENERATION_KEY).sort();
const saved = () => JSON.parse(localStorage.getItem(SESSION_KEY)!);

/** Answers a refresh from either endpoint. */
function refreshWith(cognito: ReturnType<typeof installFakeCognito>, answer: () => Promise<Response>) {
  cognito.onToken(answer);
  cognito.operations.InitiateAuth = async () => {
    const response = await answer();
    if (!response.ok) return new CognitoFailure("NotAuthorizedException");
    const body = await response.json();
    return authenticationResult(body, false);
  };
}

const refreshRequests = (cognito: ReturnType<typeof installFakeCognito>) =>
  cognito.calls.length + cognito.tokenRequests.length;

/** The SDK retries a refused refresh with back-off. */
async function throughBackoff<T>(work: Promise<T>): Promise<T> {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  let settled = false;
  void work.finally(() => (settled = true)).catch(() => {});
  while (!settled) await vi.advanceTimersByTimeAsync(1000);
  return work;
}

describe.each(Object.entries(SOURCES))("importing from %s", (_name, { source, save, method }) => {
  it("keeps the person signed in and removes the old keys", async () => {
    const cognito = installFakeCognito();
    const old = await save();
    localStorage.setItem("theme", "dark");
    const { client, events } = setup([source]);
    await expect(client.start()).resolves.toEqual({});
    expect(client.getState()).toMatchObject({ status: "signedIn", session: { subject: "ada", method } });
    expect(saved()).toMatchObject({ idToken: old.id_token, refreshToken: "refresh-ada", username: "user-ada" });
    expect(keys()).toEqual([SESSION_KEY, "theme"].sort());
    expect(events).toMatchObject([{ type: "signedIn" }]);
    expect(refreshRequests(cognito)).toBe(0);
  });

  it("refreshes an expired session at once", async () => {
    const cognito = installFakeCognito();
    const old = await save(EXPIRED);
    const { client } = setup([source]);
    await client.start();
    expect(refreshRequests(cognito)).toBe(1);
    expect(cognito.tokenRequests).toHaveLength(method === "Google" ? 1 : 0);
    expect(saved().idToken).not.toBe(old.id_token);
    expect(saved()).toMatchObject({ method, refreshToken: "refresh-ada" });
    expect(client.getState().status).toBe("signedIn");
    expect(keys()).toEqual([SESSION_KEY]);
  });

  it.each([
    ["is refused", async () => Response.json({ error: "invalid_grant" }, { status: 400 })],
    ["returns another account", async () => Response.json(await issueTokens({ subject: "mallory" }))],
    ["returns tokens the pool did not sign", async () => Response.json(await issueTokens({ foreignKey: true }))],
  ])("signs out and removes the old keys when the refresh %s", async (_case, answer) => {
    const cognito = installFakeCognito();
    await save(EXPIRED);
    refreshWith(cognito, answer);
    const { client, events } = setup([source]);
    // Only a refusal is retried; faking time otherwise would trip the request deadline.
    await (_case === "is refused" ? throughBackoff(client.start()) : client.start());
    expect(client.getState()).toMatchObject({ status: "signedOut", session: null });
    expect(keys()).toEqual([]);
    expect(events).toEqual([]);
  });

  it.each([
    ["another client", { id: { aud: "other-client" }, access: { client_id: "other-client" } }],
    ["another client's access token", { access: { client_id: "other-client" } }],
    ["another issuer", { issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Other" }],
    ["an unknown signing key", { foreignKey: true }],
  ])("never imports tokens for %s, fresh or expired", async (_case, options) => {
    for (const age of [{}, EXPIRED]) {
      localStorage.clear();
      const cognito = installFakeCognito();
      await save({ ...options, ...age });
      const before = keys();
      const { client } = setup([source]);
      await client.start();
      expect(client.getState().status).toBe("signedOut");
      expect(refreshRequests(cognito)).toBe(0);
      expect(keys()).toEqual(before);
    }
  });

  it("keeps the old keys when the new session cannot be saved", async () => {
    installFakeCognito();
    await save();
    const before = keys();
    const refusing: Storage = {
      get length() {
        return localStorage.length;
      },
      key: (index) => localStorage.key(index),
      getItem: (key) => localStorage.getItem(key),
      removeItem: (key) => localStorage.removeItem(key),
      clear: () => localStorage.clear(),
      setItem: () => {
        throw new Error("quota");
      },
    };
    const { client } = setup([source], { storage: refusing });
    await expect(client.start()).resolves.toMatchObject({ error: { code: "storage-unavailable" } });
    expect(client.getState().status).toBe("signedOut");
    expect(keys()).toEqual(before);
  });

  it("goes on reporting a failed save after a getter finds nobody signed in", async () => {
    installFakeCognito();
    await save();
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("quota");
    });
    const { client } = setup([source]);
    const token = client.getIdToken();
    await client.start();
    await expect(token).resolves.toBeNull();
    await expect(client.getIdToken()).resolves.toBeNull();
    expect(client.getState()).toMatchObject({ status: "signedOut", error: { code: "storage-unavailable" } });
    vi.restoreAllMocks();
  });
});

describe("unreadable old values", () => {
  it.each(["{", "null", "[]", '"text"', '{"id_token":"a"}', '{"id_token":"a","access_token":"b","refresh_token":"c","subject":"ada"}'])(
    "ignores the Google value %s",
    async (value) => {
      installFakeCognito();
      localStorage.setItem(GOOGLE, value);
      const { client } = setup([leylineGoogleSession()]);
      await expect(client.start()).resolves.toEqual({});
      expect(client.getState().status).toBe("signedOut");
      expect(keys()).toEqual([GOOGLE]);
    },
  );

  it.each([
    ["a damaged ID token", "idToken", "not-a-token"],
    ["a missing access token", "accessToken", null],
    ["no refresh token", "refreshToken", null],
  ])("ignores an SDK session with %s", async (_name, item, value) => {
    const cognito = installFakeCognito();
    await saveSdk(EXPIRED);
    const key = `${SDK}.user-ada.${item}`;
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
    const { client } = setup([cognitoSdkSession()]);
    await client.start();
    expect(client.getState().status).toBe("signedOut");
    expect(refreshRequests(cognito)).toBe(0);
  });

  it("refuses a Google record whose subject is not the tokens'", async () => {
    installFakeCognito();
    await saveHosted(GOOGLE, { recorded: "mallory" });
    const { client } = setup([leylineGoogleSession()]);
    await client.start();
    expect(client.getState().status).toBe("signedOut");
  });
});

describe("which old session is taken", () => {
  it("never reads keys named for another client or issuer", async () => {
    const cognito = installFakeCognito();
    await saveSdk({ clientId: "other-client" });
    await saveHosted(`leyline.google.session.other-client.${ISSUER}`);
    await saveHosted(`leyline.google.session.${CONFIG.clientId}.https://other.example.test`);
    const before = keys();
    const { client } = setup([leylineGoogleSession(), cognitoSdkSession()]);
    await client.start();
    expect(client.getState().status).toBe("signedOut");
    expect(cognito.fetcher).not.toHaveBeenCalled();
    expect(keys()).toEqual(before);
  });

  it("tries sources in order, then removes every configured one", async () => {
    installFakeCognito();
    await saveHosted(GOOGLE, { subject: "grace" });
    await saveSdk();
    await saveSdk({ user: "user-earlier" });
    await saveSdk({ clientId: "other-client" });
    const { client } = setup([leylineGoogleSession(), cognitoSdkSession()]);
    await client.start();
    expect(client.getState().session).toMatchObject({ subject: "grace", method: "Google" });
    expect(keys().filter((key) => !key.includes("other-client"))).toEqual([SESSION_KEY]);
    expect(keys().filter((key) => key.includes("other-client"))).toHaveLength(5);
  });

  it("moves on from a source that does not verify", async () => {
    installFakeCognito();
    await saveHosted(GOOGLE, { foreignKey: true });
    await saveSdk();
    const { client } = setup([leylineGoogleSession(), cognitoSdkSession()]);
    await client.start();
    expect(client.getState().session).toMatchObject({ subject: "ada", method: "password" });
  });

  it("takes yoru-web's Google tokens over the SDK's stale copy", async () => {
    const cognito = installFakeCognito();
    await saveSdk({ prefix: "yoru.auth.", ...EXPIRED });
    const current = await saveHosted("yoru.auth.googleSession");
    localStorage.setItem("yoru.auth.activeSubject", "ada");
    const { client } = setup([cognitoSdkSession({ prefix: "yoru.auth." })]);
    await client.start();
    expect(saved()).toMatchObject({ method: "Google", idToken: current.id_token });
    expect(refreshRequests(cognito)).toBe(0);
    expect(keys()).toEqual([SESSION_KEY, "yoru.auth.activeSubject"].sort());
  });

  it("honours the SDK's note that this device's clock is ahead", async () => {
    const cognito = installFakeCognito();
    await saveSdk({ expiresIn: -600 });
    localStorage.setItem(`${SDK}.user-ada.clockDrift`, "3600");
    const { client } = setup([cognitoSdkSession()]);
    await client.start();
    expect(client.getState().status).toBe("signedIn");
    expect(refreshRequests(cognito)).toBe(0);
  });

  it("does not try a Google session without a hosted domain to refresh it", async () => {
    installFakeCognito();
    await saveHosted(GOOGLE);
    const { client } = setup([leylineGoogleSession()], {}, { loginDomain: "" });
    await client.start();
    expect(client.getState().status).toBe("signedOut");
    expect(keys()).toEqual([GOOGLE]);
  });

  it("imports a password session whose ID token has no email, but not such a Google one", async () => {
    const cognito = installFakeCognito();
    const bare = { id: { email: undefined } };
    await saveHosted(GOOGLE, bare);
    await saveSdk({ ...bare, ...EXPIRED });
    refreshWith(cognito, async () => Response.json(await issueTokens(bare)));
    const { client } = setup([leylineGoogleSession(), cognitoSdkSession()]);
    await client.start();
    expect(client.getState().session).toMatchObject({ method: "password", email: null });
  });

  it("does nothing against a local simulator, or without the setting", async () => {
    const cognito = installFakeCognito();
    await saveSdk();
    const before = keys();
    await setup([cognitoSdkSession()], {}, { endpoint: "http://localhost:9229" }).client.start();
    await setup([]).client.start();
    expect(cognito.fetcher).not.toHaveBeenCalled();
    expect(keys()).toEqual(before);
  });
});

describe("an old session never comes back", () => {
  const sources = [cognitoSdkSession()];

  it("is removed unread when this package already has a session", async () => {
    const cognito = installFakeCognito();
    await saveSdk({ subject: "grace" });
    localStorage.setItem(SESSION_KEY, await storedSession());
    const { client } = setup(sources);
    await client.start();
    expect(client.getState().session?.subject).toBe("ada");
    expect(keys()).toEqual([SESSION_KEY]);
    expect(cognito.fetcher).not.toHaveBeenCalled();
  });

  it("is removed by a sign-out, even one before start", async () => {
    installFakeCognito();
    await saveSdk();
    setup(sources).client.signOut();
    expect(keys()).toEqual([]);
  });

  it.each([
    ["a getter found a session", true, (client: ReturnType<typeof setup>["client"]) => client.getIdToken()],
    ["start found a session", true, (client: ReturnType<typeof setup>["client"]) => client.start()],
    ["a sign-out before start", false, async (client: ReturnType<typeof setup>["client"]) => client.signOut()],
  ])("is not read later in the page's life, after %s", async (_name, signedIn, first) => {
    installFakeCognito();
    if (signedIn) localStorage.setItem(SESSION_KEY, await storedSession());
    const { client } = setup(sources);
    await first(client);
    if (signedIn) otherTabWrites(SESSION_KEY, null);
    // A tab still running the app's old build signs in afterwards.
    await saveSdk({ subject: "grace" });
    const before = keys();
    await expect(client.getIdToken()).resolves.toBeNull();
    await client.start();
    expect(client.getState().status).toBe("signedOut");
    expect(keys()).toEqual(before);
  });

  it("is removed when another tab signs out", async () => {
    installFakeCognito();
    localStorage.setItem(SESSION_KEY, await storedSession());
    setup(sources);
    await saveSdk();
    otherTabWrites(SESSION_KEY, null);
    expect(keys()).toEqual([]);
  });

  async function slowImport() {
    const cognito = installFakeCognito();
    await saveSdk(EXPIRED);
    const answer = deferred<unknown>();
    const asked = deferred<void>();
    cognito.operations.InitiateAuth = () => {
      asked.resolve();
      return answer.promise;
    };
    const { client, events } = setup(sources);
    const started = client.start();
    await asked.promise;
    const finish = async () => {
      answer.resolve(authenticationResult(await issueTokens(), false));
      await started;
    };
    return { cognito, client, events, finish };
  }

  it("is not saved after a sign-out during the import", async () => {
    const { client, finish } = await slowImport();
    client.signOut();
    await finish();
    expect(client.getState().status).toBe("signedOut");
    expect(keys()).toEqual([]);
  });

  it("is not saved after another tab took it over and signed out", async () => {
    const { client, finish } = await slowImport();
    // The other tab saved its session, removed the old keys, then signed out.
    for (const key of keys()) localStorage.removeItem(key);
    await finish();
    expect(client.getState().status).toBe("signedOut");
    expect(keys()).toEqual([]);
  });

  it("does not replace a session another tab saved during the import", async () => {
    const { client, finish } = await slowImport();
    const other = await storedSession({ subject: "grace" });
    otherTabWrites(SESSION_KEY, other);
    await finish();
    expect(localStorage.getItem(SESSION_KEY)).toBe(other);
    expect(client.getState().session?.subject).toBe("grace");
    expect(keys()).toEqual([SESSION_KEY]);
  });

  it("does not replace a session saved without removing the old keys", async () => {
    const { finish } = await slowImport();
    const other = await storedSession({ subject: "grace" });
    // A tab whose build does not import leaves the old keys where they are.
    localStorage.setItem(SESSION_KEY, other);
    await finish();
    expect(localStorage.getItem(SESSION_KEY)).toBe(other);
  });

  it("is taken over for a caller who asks before start, once", async () => {
    installFakeCognito();
    const old = await saveSdk();
    const { client, events } = setup(sources);
    await expect(client.getIdToken()).resolves.toBe(old.id_token);
    await client.start();
    expect(events).toMatchObject([{ type: "signedIn" }]);
    expect(events).toHaveLength(1);
  });

  it.each([
    ["before start and during it", true],
    ["only during it", false],
  ])("is left alone while a provider sign-in is being finished, with tokens asked %s", async (_name, askEarly) => {
    const cognito = installFakeCognito();
    const redirect = vi.fn();
    await createCardeaClient(CONFIG, { redirect }).signInWithProvider("Google");
    const url = new URL(redirect.mock.calls[0][0]);
    cognito.onToken(async () => Response.json(await issueTokens({ nonce: url.searchParams.get("nonce")! })));
    await saveSdk({ subject: "grace" });
    window.history.replaceState(null, "", `/auth/callback?code=c&state=${url.searchParams.get("state")}`);
    const { client, events } = setup(sources);
    // `during` is asked once start has cleared the address.
    const early = askEarly ? client.getIdToken() : Promise.resolve(null);
    const started = client.start();
    const during = client.getIdToken();
    await expect(early).resolves.toBeNull();
    await expect(during).resolves.toBeNull();
    await started;
    expect(events).toMatchObject([{ type: "signedIn", session: { subject: "ada" } }]);
    expect(events).toHaveLength(1);
    expect(keys()).toEqual([SESSION_KEY]);
  });

  it("makes callers wait while it is being taken over", async () => {
    const { client, finish, cognito } = await slowImport();
    const token = client.getIdToken();
    const session = client.getSession();
    await finish();
    await expect(token).resolves.toBe(saved().idToken);
    await expect(session).resolves.toMatchObject({ subject: "ada" });
    expect(cognito.calls).toHaveLength(1);
  });
});
