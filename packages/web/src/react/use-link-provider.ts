import { useCallback, useEffect, useRef, useState } from "react";
import { CardeaError } from "../errors.js";
import type { ConfirmOptions, PreparedLink } from "../link/linking.js";
import type { Provider } from "../providers.js";
import { useCardea, useLinking } from "./context.js";

export type LinkStatus = "idle" | "preparing" | "ready" | "linking" | "linked" | "failed";

interface View {
  status: LinkStatus;
  provider: Provider | null;
  error: unknown;
}

const IDLE: View = { status: "idle", provider: null, error: null };

/**
 * Adding a provider from settings: `prepare`, then `confirm` from a click (for
 * Google, with the element its button goes in). After a failure, `confirm`
 * retries the same request; `prepare` starts a new one.
 */
export function useLinkProvider() {
  const { client } = useCardea();
  const linking = useLinking();
  const [view, setView] = useState<View>(IDLE);
  const prepared = useRef<PreparedLink | null>(null);
  const abort = useRef<AbortController | null>(null);
  const generation = useRef(0);

  const cancel = useCallback(() => {
    generation.current++;
    abort.current?.abort();
    abort.current = null;
    prepared.current = null;
  }, []);

  const reset = useCallback(() => {
    cancel();
    setView(IDLE);
  }, [cancel]);

  useEffect(() => {
    const unsubscribe = client.subscribe(reset);
    return () => {
      unsubscribe();
      cancel();
    };
  }, [client, cancel, reset]);

  const prepare = useCallback(
    async (provider: Provider): Promise<PreparedLink> => {
      cancel();
      const started = generation.current;
      setView({ status: "preparing", provider, error: null });
      try {
        const link = await linking.prepareLink(provider);
        if (started !== generation.current) throw new CardeaError("proof-cancelled");
        prepared.current = link;
        setView({ status: "ready", provider, error: null });
        return link;
      } catch (error) {
        if (started === generation.current) setView({ status: "failed", provider, error });
        throw error;
      }
    },
    [linking, cancel],
  );

  const confirm = useCallback(async (options: Omit<ConfirmOptions, "signal"> = {}) => {
    const link = prepared.current;
    if (!link) throw new CardeaError("attempt-invalid");
    const started = generation.current;
    abort.current ??= new AbortController();
    // Started before any state update or `await`, to keep the click for the popup.
    const work = link.confirm({ ...options, signal: abort.current.signal });
    const { provider } = link;
    setView({ status: "linking", provider, error: null });
    try {
      const result = await work;
      if (started === generation.current) setView({ status: "linked", provider, error: null });
      return result;
    } catch (error) {
      if (started === generation.current) setView({ status: "failed", provider, error });
      throw error;
    }
  }, []);

  return {
    ...view,
    prepare,
    confirm,
    /** Both steps at once. Not for Apple, whose popup needs its own click. */
    link: useCallback(
      async (provider: Provider, options?: Omit<ConfirmOptions, "signal">) => {
        await prepare(provider);
        return confirm(options);
      },
      [prepare, confirm],
    ),
    reset,
  };
}
