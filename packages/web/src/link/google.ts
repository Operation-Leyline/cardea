import { CardeaError } from "../errors.js";
import { abortable, type ProofSource } from "./proof.js";
import { loadScript } from "./script.js";

export const GOOGLE_SCRIPT = "https://accounts.google.com/gsi/client";

/** The part of Google Identity Services used here. */
interface GoogleIdentity {
  initialize(options: Record<string, unknown>): void;
  renderButton(parent: HTMLElement, options: Record<string, unknown>): void;
}

function library(): GoogleIdentity | undefined {
  return (window as { google?: { accounts?: { id?: GoogleIdentity } } }).google?.accounts?.id;
}

/**
 * Google Identity Services. Google only issues a token after the person presses
 * Google's own button, so the caller gives it an element to draw in.
 * `button` is passed to `renderButton` (theme, size, width).
 */
export function googleProofSource(button: Record<string, unknown> = {}): ProofSource {
  return {
    async load() {
      await loadScript(GOOGLE_SCRIPT, library);
    },
    request({ clientId, nonce, signal, container }) {
      const google = library();
      if (!google || !container) return Promise.reject(new CardeaError("proof-failed"));
      if (signal.aborted) return Promise.reject(signal.reason);
      const credential = new Promise<string>((resolve, reject) => {
        google.initialize({
          client_id: clientId,
          nonce,
          // Linking is deliberate: the person picks the account every time.
          auto_select: false,
          ux_mode: "popup",
          callback: (response: { credential?: unknown }) =>
            typeof response.credential === "string"
              ? resolve(response.credential)
              : reject(new CardeaError("proof-failed")),
        });
        google.renderButton(container, { type: "standard", text: "continue_with", ...button });
      });
      return abortable(signal, credential).finally(() => container.replaceChildren());
    },
  };
}
