import { CardeaError } from "../errors.js";
import { randomValue } from "../random.js";
import { abortable, type ProofSource } from "./proof.js";
import { loadScript } from "./script.js";

export const APPLE_SCRIPT =
  "https://appleid.cdn-apple.com/appleauth/static/jsapi/appleid/1/en_US/appleid.auth.js";

/** The part of Sign in with Apple JS used here. */
interface AppleAuth {
  init(options: Record<string, unknown>): void;
  signIn(): Promise<{ authorization?: { id_token?: unknown; state?: unknown } }>;
}

function library(): AppleAuth | undefined {
  return (window as { AppleID?: { auth?: AppleAuth } }).AppleID?.auth;
}

const CANCELLED = ["popup_closed_by_user", "user_cancelled_authorize"];

/**
 * Sign in with Apple JS in a popup. `redirectUri` must be registered as a return
 * URL on the Services ID; it defaults to the page's origin followed by `/`.
 * Call `request` straight from a click, or the browser may block the popup.
 */
export function appleProofSource(redirectUri?: string): ProofSource {
  return {
    async load() {
      await loadScript(APPLE_SCRIPT, library);
    },
    request({ clientId, nonce, signal }) {
      const apple = library();
      if (!apple) return Promise.reject(new CardeaError("proof-failed"));
      if (signal.aborted) return Promise.reject(signal.reason);
      const state = randomValue();
      apple.init({
        clientId,
        nonce,
        state,
        scope: "email",
        redirectURI: redirectUri ?? `${window.location.origin}/`,
        usePopup: true,
      });
      // No `await` before this line: the popup needs the click that led here.
      const token = apple.signIn().then(
        ({ authorization }) => {
          if (authorization?.state !== state || typeof authorization.id_token !== "string") {
            throw new CardeaError("proof-failed");
          }
          return authorization.id_token;
        },
        (error: { error?: string } | undefined) => {
          throw new CardeaError(CANCELLED.includes(error?.error ?? "") ? "proof-cancelled" : "proof-failed");
        },
      );
      return abortable(signal, token);
    },
  };
}
