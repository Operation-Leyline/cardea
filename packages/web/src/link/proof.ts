/** What a provider needs to issue an ID token for one linking challenge. */
export interface ProofRequest {
  clientId: string;
  nonce: string;
  signal: AbortSignal;
  /** Where Google draws its button. */
  container?: HTMLElement;
}

/** A way to get an ID token from a provider in this page. */
export interface ProofSource {
  /** Fetches the provider's script. Call before `request`. */
  load(): Promise<void>;
  /** Asks the person to confirm; resolves with the provider's ID token. */
  request(request: ProofRequest): Promise<string>;
}

/** Settles with the work, or rejects with the signal's reason, whichever comes first. */
export function abortable<T>(signal: AbortSignal, work: Promise<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
