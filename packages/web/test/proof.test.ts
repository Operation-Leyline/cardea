import { afterEach, describe, expect, it, vi } from "vitest";
import { appleProofSource, googleProofSource } from "../src/index.js";
import { APPLE_SCRIPT } from "../src/link/apple.js";
import { GOOGLE_SCRIPT } from "../src/link/google.js";
import { loadScript } from "../src/link/script.js";

afterEach(() => {
  document.head.innerHTML = "";
});

const request = (extra: Record<string, unknown> = {}) => ({
  clientId: "provider-client",
  nonce: "challenge-nonce",
  signal: new AbortController().signal,
  ...extra,
});
const script = (src: string) => document.querySelector<HTMLScriptElement>(`script[src="${src}"]`);

describe("script loading", () => {
  it("adds the script once, only when asked, and retries after a failure", async () => {
    expect(document.querySelector("script")).toBeNull();
    let library: object | undefined;
    const ready = () => library;
    const first = loadScript("https://provider.test/a.js", ready);
    const second = loadScript("https://provider.test/a.js", ready);
    expect(document.querySelectorAll("script")).toHaveLength(1);
    document.querySelector("script")!.onerror!(new Event("error"));
    await expect(first).rejects.toMatchObject({ code: "proof-failed" });
    await expect(second).rejects.toThrow();
    expect(document.querySelector("script")).toBeNull();
    const retry = loadScript("https://provider.test/a.js", ready);
    library = {};
    document.querySelector("script")!.onload!(new Event("load"));
    await expect(retry).resolves.toBe(library);
  });
});

describe("Google Identity Services", () => {
  it("draws Google's button with the nonce and resolves with the credential", async () => {
    const id = { initialize: vi.fn(), renderButton: vi.fn((parent: HTMLElement) => parent.append("button")) };
    const source = googleProofSource({ theme: "outline" });
    const loading = source.load();
    vi.stubGlobal("google", { accounts: { id } });
    script(GOOGLE_SCRIPT)!.onload!(new Event("load"));
    await loading;
    const container = document.createElement("div");
    const token = source.request(request({ container }));
    const options = id.initialize.mock.calls[0][0];
    expect(options).toMatchObject({ client_id: "provider-client", nonce: "challenge-nonce", auto_select: false });
    expect(id.renderButton).toHaveBeenCalledWith(container, expect.objectContaining({ theme: "outline" }));
    options.callback({ credential: "google-id-token" });
    await expect(token).resolves.toBe("google-id-token");
    expect(container.childNodes).toHaveLength(0);
  });

  it("needs a container, and removes the button on abort", async () => {
    vi.stubGlobal("google", { accounts: { id: { initialize: vi.fn(), renderButton: (p: HTMLElement) => p.append("b") } } });
    const source = googleProofSource();
    await source.load();
    await expect(source.request(request())).rejects.toMatchObject({ code: "proof-failed" });
    const container = document.createElement("div");
    const controller = new AbortController();
    const token = source.request(request({ container, signal: controller.signal }));
    controller.abort(new Error("stop"));
    await expect(token).rejects.toThrow("stop");
    expect(container.childNodes).toHaveLength(0);
  });
});

describe("Sign in with Apple JS", () => {
  function apple(respond: (state: string) => Promise<unknown>) {
    let state = "";
    const auth = {
      init: vi.fn((options: { state: string }) => (state = options.state)),
      signIn: vi.fn(() => respond(state)),
    };
    vi.stubGlobal("AppleID", { auth });
    return auth;
  }

  it("opens a popup carrying the nonce and returns the ID token", async () => {
    const auth = apple(async (state) => ({ authorization: { id_token: "apple-id-token", state } }));
    const source = appleProofSource();
    await source.load();
    expect(script(APPLE_SCRIPT)).toBeNull();
    const token = source.request(request());
    expect(auth.signIn).toHaveBeenCalledOnce();
    await expect(token).resolves.toBe("apple-id-token");
    expect(auth.init).toHaveBeenCalledWith(
      expect.objectContaining({
        clientId: "provider-client",
        nonce: "challenge-nonce",
        redirectURI: "https://app.example.test/",
        usePopup: true,
      }),
    );
  });

  it.each([
    ["an answer with another state", async () => ({ authorization: { id_token: "t", state: "other" } }), "proof-failed"],
    ["a closed popup", async () => Promise.reject({ error: "popup_closed_by_user" }), "proof-cancelled"],
    ["a provider error", async () => Promise.reject({ error: "invalid_client" }), "proof-failed"],
  ])("refuses %s", async (_name, respond, code) => {
    apple(respond);
    await expect(appleProofSource("https://app.example.test/apple").request(request())).rejects.toMatchObject({ code });
  });
});
