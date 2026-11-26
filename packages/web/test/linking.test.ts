import { describe, expect, it, vi } from "vitest";
import {
  createCardeaClient,
  createLinking,
  type IdentityLinkAdapter,
  type ProofRequest,
  type ProofSource,
} from "../src/index.js";
import { CognitoFailure, CONFIG, deferred, installFakeCognito, issueTokens, otherTabWrites, SESSION_KEY, storedSession } from "./fakes/cognito.js";

/** A provider token as the browser sees it: only the nonce is read here. */
async function proofToken(nonce: string) {
  return (await issueTokens({ nonce })).id_token;
}

async function setup() {
  const cognito = installFakeCognito();
  localStorage.setItem(SESSION_KEY, await storedSession());
  const client = createCardeaClient(CONFIG);
  const adapter = {
    createIdentityLink: vi.fn<IdentityLinkAdapter["createIdentityLink"]>(async () => ({
      linkId: "link-1",
      nonce: "challenge-nonce",
      clientId: "google-client",
      expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    })),
    completeIdentityLink: vi.fn<IdentityLinkAdapter["completeIdentityLink"]>(async () => ({ userId: "ada" })),
    listSignInMethods: vi.fn<IdentityLinkAdapter["listSignInMethods"]>(async () => [{ type: "password" }]),
    unlinkSignInMethod: vi.fn<IdentityLinkAdapter["unlinkSignInMethod"]>(async () => {}),
  };
  const source = {
    load: vi.fn(async () => {}),
    request: vi.fn(async ({ nonce }: ProofRequest) => proofToken(nonce)),
  } satisfies ProofSource;
  const linking = createLinking({ client, adapter, proofSources: { Google: source, Apple: source } });
  const changed = vi.fn();
  linking.onMethodsChanged(changed);
  return { cognito, client, adapter, source, linking, changed };
}

const switchAccount = async () => otherTabWrites(SESSION_KEY, await storedSession({ subject: "grace" }));

describe("linking a provider", () => {
  it("creates a challenge, gets a token carrying its nonce, and completes with it", async () => {
    const { adapter, source, linking, changed } = await setup();
    await expect(linking.linkProvider("Google")).resolves.toEqual({ userId: "ada" });
    expect(adapter.createIdentityLink).toHaveBeenCalledWith({
      provider: "Google",
      clientToken: expect.stringMatching(/^[0-9a-f-]{36}$/),
    });
    expect(source.request).toHaveBeenCalledWith(
      expect.objectContaining({ clientId: "google-client", nonce: "challenge-nonce" }),
    );
    const [completion] = adapter.completeIdentityLink.mock.calls[0];
    expect(completion).toEqual({ linkId: "link-1", idToken: await source.request.mock.results[0].value });
    expect(changed).toHaveBeenCalledOnce();
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain(completion.idToken);
  });

  it("asks the provider from within the caller's click", async () => {
    const { source, linking } = await setup();
    const prepared = await linking.prepareLink("Apple");
    expect(source.load).toHaveBeenCalled();
    expect(source.request).not.toHaveBeenCalled();
    const done = prepared.confirm();
    expect(source.request).toHaveBeenCalledOnce();
    await done;
  });

  it("refuses a token carrying another nonce, and asks again on retry", async () => {
    const { adapter, source, linking } = await setup();
    source.request.mockImplementationOnce(async () => proofToken("another-request"));
    const prepared = await linking.prepareLink("Google");
    await expect(prepared.confirm()).rejects.toMatchObject({ code: "nonce-mismatch" });
    expect(adapter.completeIdentityLink).not.toHaveBeenCalled();
    await expect(prepared.confirm()).resolves.toEqual({ userId: "ada" });
    expect(source.request).toHaveBeenCalledTimes(2);
  });

  it("retries a failed completion with the same token, even past the deadline", async () => {
    const { adapter, source, linking } = await setup();
    const timeout = new Error("timeout");
    adapter.completeIdentityLink.mockRejectedValueOnce(timeout);
    const prepared = await linking.prepareLink("Google");
    await expect(prepared.confirm()).rejects.toBe(timeout);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 10 * 60_000);
    // The session is refreshed independently of the challenge.
    localStorage.setItem(SESSION_KEY, await storedSession());
    await prepared.confirm();
    expect(source.request).toHaveBeenCalledOnce();
    expect(adapter.completeIdentityLink.mock.calls[1]).toEqual(adapter.completeIdentityLink.mock.calls[0]);
  });

  it("shares one completion between double clicks and repeats nothing afterwards", async () => {
    const { adapter, linking } = await setup();
    const prepared = await linking.prepareLink("Google");
    await Promise.all([prepared.confirm(), prepared.confirm()]);
    await prepared.confirm();
    expect(adapter.completeIdentityLink).toHaveBeenCalledOnce();
  });

  it("does not ask the provider once the challenge expired", async () => {
    const { adapter, source, linking } = await setup();
    adapter.createIdentityLink.mockResolvedValueOnce({
      linkId: "link-1",
      nonce: "n",
      clientId: "c",
      expiresAt: new Date(Date.now() - 1000),
    });
    const prepared = await linking.prepareLink("Google");
    await expect(prepared.confirm()).rejects.toMatchObject({ code: "link-expired" });
    expect(source.request).not.toHaveBeenCalled();
  });

  it.each([
    ["the deadline passes", "link-expired"],
    ["the caller aborts", "proof-cancelled"],
    ["another account signs in", "account-changed"],
  ])("stops waiting for the provider when %s", async (cause, code) => {
    const { adapter, source, linking } = await setup();
    const asked = deferred<void>();
    source.request.mockImplementationOnce(
      ({ signal }) =>
        new Promise<string>((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(signal.reason));
          asked.resolve();
        }),
    );
    const prepared = await linking.prepareLink("Google");
    const controller = new AbortController();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const done = expect(prepared.confirm({ signal: controller.signal })).rejects.toMatchObject({ code });
    await asked.promise;
    if (cause === "the deadline passes") await vi.advanceTimersByTimeAsync(5 * 60_000 + 1);
    if (cause === "the caller aborts") controller.abort();
    if (cause === "another account signs in") await switchAccount();
    await done;
    expect(adapter.completeIdentityLink).not.toHaveBeenCalled();
  });

  it("never completes one account's challenge as another", async () => {
    const { adapter, linking } = await setup();
    const prepared = await linking.prepareLink("Google");
    await switchAccount();
    await expect(prepared.confirm()).rejects.toMatchObject({ code: "account-changed" });
    expect(adapter.completeIdentityLink).not.toHaveBeenCalled();
  });

  it("refuses a result naming a different user", async () => {
    const { adapter, linking, changed } = await setup();
    adapter.completeIdentityLink.mockResolvedValueOnce({ userId: "mallory" });
    await expect(linking.linkProvider("Google")).rejects.toMatchObject({ code: "account-mismatch" });
    expect(changed).not.toHaveBeenCalled();
  });

  it("passes the product's own errors through", async () => {
    const { adapter, linking } = await setup();
    const conflict = Object.assign(new Error("conflict"), { reason: "identityAlreadyLinked" });
    adapter.createIdentityLink.mockRejectedValueOnce(conflict);
    await expect(linking.linkProvider("Google")).rejects.toBe(conflict);
  });

  it("needs a signed-in person", async () => {
    const { client, adapter, linking } = await setup();
    client.signOut();
    await expect(linking.linkProvider("Google")).rejects.toMatchObject({ code: "not-signed-in" });
    await expect(linking.listSignInMethods()).rejects.toMatchObject({ code: "not-signed-in" });
    expect(adapter.createIdentityLink).not.toHaveBeenCalled();
  });
});

describe("sign-in methods", () => {
  it("lists and unlinks through the adapter", async () => {
    const { adapter, linking, changed } = await setup();
    await expect(linking.listSignInMethods()).resolves.toEqual([{ type: "password" }]);
    await linking.unlinkSignInMethod("Apple");
    expect(adapter.unlinkSignInMethod).toHaveBeenCalledWith({ provider: "Apple" });
    expect(changed).toHaveBeenCalledOnce();
  });

  it("drops a list that arrives for a previous account", async () => {
    const { adapter, linking } = await setup();
    adapter.listSignInMethods.mockImplementationOnce(async () => {
      await switchAccount();
      return [{ type: "password" }];
    });
    await expect(linking.listSignInMethods()).rejects.toMatchObject({ code: "account-changed" });
  });

  it.each(["InvalidParameterException", "NotAuthorizedException", "UserNotFoundException"])(
    "reports %s to the signed-in person, but not to an anonymous reset",
    async (code) => {
      const { cognito, client, linking } = await setup();
      cognito.operations.ForgotPassword = () => new CognitoFailure(code);
      await expect(linking.requestPasswordSetup()).rejects.toMatchObject({ code });
      await expect(client.requestPasswordReset("ada@example.test")).resolves.toBeUndefined();
    },
  );

  it("sets a password through the forgot-password flow for the signed-in address", async () => {
    const { cognito, linking, changed } = await setup();
    await linking.requestPasswordSetup();
    await linking.completePasswordSetup("123456", "Correct-Horse-12");
    expect(cognito.operationNames()).toEqual(["ForgotPassword", "ConfirmForgotPassword"]);
    expect(cognito.calls.map((call) => call.body.Username)).toEqual(["ada@example.test", "ada@example.test"]);
    expect(changed).toHaveBeenCalledOnce();
  });
});
