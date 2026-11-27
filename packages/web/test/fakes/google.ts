/** Google Identity Services as the page sees it, and a way to take it away. */
import { vi } from "vitest";
import { issueTokens } from "./cognito.js";

type Moment = Record<string, () => unknown>;

export function installFakeGoogle() {
  let settings: Record<string, any> = {};
  let drawn = 0;
  let listener: ((moment: Moment) => void) | undefined;
  let cancelled = 0;
  let broken = false;
  const id = {
    initialize: (options: Record<string, unknown>) => void (settings = options),
    renderButton: (parent: HTMLElement) => {
      if (broken) throw new Error("blocked");
      drawn++;
      parent.append(document.createElement("button"));
    },
    prompt: (report: (moment: Moment) => void) => void (listener = report),
    cancel: () => void cancelled++,
  };
  vi.stubGlobal("google", { accounts: { id } });

  return {
    settings: () => settings,
    buttons: () => drawn,
    prompted: () => listener !== undefined,
    cancelled: () => cancelled,
    moment: (moment: Moment) => listener!(moment),
    /** The person picks an account: Google answers with a token carrying the nonce. */
    async press(nonce: string = settings.nonce) {
      const idToken = (await issueTokens({ nonce })).id_token;
      settings.callback({ credential: idToken });
      return idToken;
    },
    /** An ad blocker: the script never arrives. */
    block() {
      vi.stubGlobal("google", undefined);
      vi.spyOn(document.head, "append").mockImplementation((...nodes) => {
        const script = nodes[0] as HTMLScriptElement;
        queueMicrotask(() => script.onerror?.(new Event("error")));
      });
    },
    break() {
      broken = true;
    },
  };
}
