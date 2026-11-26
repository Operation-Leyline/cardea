import { createContext, useContext, useEffect, useLayoutEffect, useMemo, useRef, type ReactNode } from "react";
import type { CardeaClient, StartResult } from "../client.js";
import { CardeaError } from "../errors.js";
import type { IdentityLinkAdapter } from "../link/adapter.js";
import { createLinking, type Linking, type LinkingOptions } from "../link/linking.js";

interface Cardea {
  client: CardeaClient;
  linking: Linking | null;
}

const Context = createContext<Cardea | null>(null);
/** A callback is acted on once, even if the provider mounts again. */
const handled = new WeakSet<StartResult>();

export interface CardeaProviderProps extends Omit<LinkingOptions, "client" | "adapter"> {
  /** Create it once, outside the component. */
  client: CardeaClient;
  /** Needed for the sign-in method and linking hooks. */
  linkAdapter?: IdentityLinkAdapter;
  /** After a provider sign-in: navigate to `returnTo` and show `error`, if any. */
  onRedirectComplete?: (result: StartResult) => void;
  children?: ReactNode;
}

export function CardeaProvider(props: CardeaProviderProps) {
  const { client, linkAdapter, onRedirectComplete, children } = props;
  // The latest values are read through refs, so inline objects do not restart a link in progress.
  const latest = useRef(props);
  latest.current = props;

  const hasAdapter = linkAdapter !== undefined;
  const linking = useMemo(() => {
    if (!hasAdapter) return null;
    const adapter = () => latest.current.linkAdapter!;
    const { appleRedirectUri, googleButton, proofSources } = latest.current;
    return createLinking({
      client,
      adapter: {
        createIdentityLink: (input) => adapter().createIdentityLink(input),
        completeIdentityLink: (input) => adapter().completeIdentityLink(input),
        listSignInMethods: () => adapter().listSignInMethods(),
        unlinkSignInMethod: (input) => adapter().unlinkSignInMethod(input),
      },
      ...(appleRedirectUri ? { appleRedirectUri } : {}),
      ...(googleButton ? { googleButton } : {}),
      ...(proofSources ? { proofSources } : {}),
    });
  }, [client, hasAdapter]);

  // Layout effects run before any child's effects, so a child asking for a token
  // on mount already waits for a session being restored.
  useLayoutEffect(() => {
    void client.start();
  }, [client]);

  const notify = useRef(onRedirectComplete);
  notify.current = onRedirectComplete;
  useEffect(() => {
    let active = true;
    void client.start().then((result) => {
      if (!active || handled.has(result) || result.returnTo === undefined) return;
      handled.add(result);
      notify.current?.(result);
    });
    return () => {
      active = false;
    };
  }, [client]);

  const value = useMemo(() => ({ client, linking }), [client, linking]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useCardea(): Cardea {
  const value = useContext(Context);
  if (!value) throw new Error("Cardea hooks must be used inside CardeaProvider.");
  return value;
}

export function useLinking(): Linking {
  const { linking } = useCardea();
  if (!linking) throw new CardeaError("not-configured");
  return linking;
}
