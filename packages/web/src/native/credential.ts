import { CardeaError } from "../errors.js";
import { GOOGLE_SCRIPT, googleLibrary, type PromptMoment } from "../link/google.js";
import { abortable } from "../link/proof.js";
import { loadScript } from "../link/script.js";

/** Google Identity Services cannot be used here: blocked, missing or refusing to show. */
export class GoogleUnavailable extends Error {}

/** What came of asking the person. `expired`: the nonce ran out first. */
export type Credential = { idToken: string } | "dismissed" | "expired";

export interface CredentialRequest {
  mode: "popup" | "oneTap";
  clientId: string;
  nonce: string;
  /** How long the nonce is worth waiting with, in milliseconds. */
  lifetimeMs: number;
  signal: AbortSignal;
  /** Where Google draws its button, in popup mode. */
  container?: HTMLElement | undefined;
  /** Options for Google's button. */
  button?: Record<string, unknown> | undefined;
}

export async function loadGoogle(): Promise<void> {
  try {
    await loadScript(GOOGLE_SCRIPT, googleLibrary);
  } catch {
    throw new GoogleUnavailable();
  }
}

/**
 * Asks Google for an ID token carrying the nonce: through its button, which
 * opens Google's popup, or through the One Tap prompt.
 */
export async function requestCredential(request: CredentialRequest): Promise<Credential> {
  const { mode, clientId, nonce, signal, container, button } = request;
  const google = googleLibrary();
  if (!google) throw new GoogleUnavailable();
  if (signal.aborted) throw signal.reason;
  // Google draws in an element of our own, so removing it leaves the caller's content alone.
  const host = mode === "popup" ? document.createElement("div") : undefined;
  if (host) container!.append(host);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let answered = false;
  const outcome = new Promise<Credential>((resolve, reject) => {
    timer = setTimeout(() => resolve("expired"), request.lifetimeMs);
    try {
      google.initialize({
        client_id: clientId,
        nonce,
        // The person picks the account every time.
        auto_select: false,
        ux_mode: "popup",
        callback: (response: { credential?: unknown }) => {
          answered = true;
          if (typeof response.credential === "string") resolve({ idToken: response.credential });
          else reject(new CardeaError("proof-failed"));
        },
      });
      if (host) {
        google.renderButton(host, { type: "standard", text: "signin_with", ...button });
        return;
      }
      google.prompt((moment: PromptMoment) => {
        // Reported only without FedCM; with it, an unavailable prompt is a skipped one.
        if (moment.isNotDisplayed?.()) reject(new GoogleUnavailable());
        else if (moment.isSkippedMoment?.()) resolve("dismissed");
        else if (moment.isDismissedMoment?.() && moment.getDismissedReason?.() !== "credential_returned") {
          resolve("dismissed");
        }
      });
    } catch {
      reject(new GoogleUnavailable());
    }
  });
  try {
    return await abortable(signal, outcome);
  } finally {
    clearTimeout(timer);
    host?.remove();
    // Closes a prompt nobody will listen to any more.
    if (!host && !answered) google.cancel?.();
  }
}
