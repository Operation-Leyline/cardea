import { useSyncExternalStore } from "react";
import type { AuthState } from "../client.js";
import { useCardea } from "./context.js";

const SERVER: AuthState = { status: "loading", session: null, error: null };

/** Who is signed in, and the calls that need nothing else. */
export function useSession() {
  const { client } = useCardea();
  const state = useSyncExternalStore(client.subscribeState, client.getState, () => SERVER);
  return {
    ...state,
    signOut: client.signOut,
    getIdToken: client.getIdToken,
    getAccessToken: client.getAccessToken,
    /** Tries again after a failed restore or refresh. */
    retry: client.getSession,
  };
}
