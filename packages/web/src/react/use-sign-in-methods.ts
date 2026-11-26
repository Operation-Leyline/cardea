import { useCallback, useEffect, useRef, useState } from "react";
import type { SignInMethod } from "../link/adapter.js";
import type { Provider } from "../providers.js";
import { useLinking } from "./context.js";
import { useSession } from "./use-session.js";

interface Loaded {
  subject: string | null;
  methods: SignInMethod[] | null;
  error: unknown;
  loading: boolean;
}

/** The signed-in person's ways to sign in, reloaded when they or the account change. */
export function useSignInMethods() {
  const linking = useLinking();
  const subject = useSession().session?.subject ?? null;
  const [state, setState] = useState<Loaded>({ subject: null, methods: null, error: null, loading: false });
  const latest = useRef(0);

  const refresh = useCallback(async () => {
    const request = ++latest.current;
    if (!subject) return setState({ subject, methods: null, error: null, loading: false });
    setState((now) => ({
      subject,
      methods: now.subject === subject ? now.methods : null,
      error: null,
      loading: true,
    }));
    try {
      const methods = await linking.listSignInMethods();
      if (request === latest.current) setState({ subject, methods, error: null, loading: false });
    } catch (error) {
      if (request === latest.current) setState((now) => ({ ...now, error, loading: false }));
    }
  }, [linking, subject]);

  useEffect(() => {
    void refresh();
    const unsubscribe = linking.onMethodsChanged(() => void refresh());
    return () => {
      latest.current++;
      unsubscribe();
    };
  }, [linking, refresh]);

  // Never show one account's methods while another is signed in.
  const current = state.subject === subject;
  const methods = current ? state.methods : null;
  return {
    methods,
    loading: subject !== null && (!current || state.loading),
    error: current ? state.error : null,
    hasPassword: methods?.some((method) => method.type === "password") ?? false,
    refresh,
    unlink: useCallback((provider: Provider) => linking.unlinkSignInMethod(provider), [linking]),
    /** "Set a password": mails a code to the signed-in address. */
    requestPasswordSetup: linking.requestPasswordSetup,
    completePasswordSetup: linking.completePasswordSetup,
  };
}
