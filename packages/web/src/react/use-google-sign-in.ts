import { useCallback, useEffect, useRef, useState } from "react";
import type { GoogleSignInOptions } from "../native/google-sign-in.js";
import { useCardea } from "./context.js";

/**
 * Native Google sign-in for one view. One attempt runs at a time: a new call, or
 * the view going away, ends the one before and removes its button or prompt.
 * `error` holds the last failure of an attempt that was not ended that way.
 *
 * ```tsx
 * const { signInWithGoogle, error } = useGoogleSignIn();
 * const button = useRef<HTMLDivElement>(null);
 * useEffect(() => {
 *   signInWithGoogle({ mode: "popup", container: button.current! }).catch(() => {});
 * }, [signInWithGoogle]);
 * ```
 */
export function useGoogleSignIn() {
  const { client } = useCardea();
  const [error, setError] = useState<unknown>(null);
  const [running, setRunning] = useState(0);
  const current = useRef<AbortController | null>(null);

  const cancel = useCallback(() => {
    current.current?.abort();
    current.current = null;
  }, []);
  useEffect(() => cancel, [client, cancel]);

  const signInWithGoogle = useCallback(
    async (options: GoogleSignInOptions) => {
      cancel();
      const own = new AbortController();
      current.current = own;
      const abort = () => own.abort();
      options.signal?.addEventListener("abort", abort, { once: true });
      if (options.signal?.aborted) abort();
      setError(null);
      setRunning((count) => count + 1);
      try {
        return await client.signInWithGoogle({ ...options, signal: own.signal });
      } catch (failure) {
        if (!own.signal.aborted) setError(failure);
        throw failure;
      } finally {
        options.signal?.removeEventListener("abort", abort);
        setRunning((count) => count - 1);
      }
    },
    [client, cancel],
  );

  /** `pending` is true while an attempt waits for the person or the network. */
  return { signInWithGoogle, cancel, error, pending: running > 0 };
}
