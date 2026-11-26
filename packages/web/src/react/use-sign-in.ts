import { useCallback, useEffect, useRef, useState } from "react";
import type { SignInResult } from "../client.js";
import { CardeaError } from "../errors.js";
import type { Provider } from "../providers.js";
import { useCardea } from "./context.js";

/** Which form to show. */
export type SignInStep =
  | "credentials"
  | "confirmationRequired"
  | "newPasswordRequired"
  | "totpRequired"
  | "resetCodeSent";

interface View {
  step: SignInStep;
  /** The address the current step is about. */
  email: string;
  /** Attributes `completeNewPassword` must also receive. */
  requiredAttributes: readonly string[];
}

const START: View = { step: "credentials", email: "", requiredAttributes: [] };
type Challenge = Extract<SignInResult, { status: "newPasswordRequired" | "totpRequired" }>;

/**
 * The sign-in, sign-up and recovery sequence. Each action rejects on failure
 * and also leaves the failure in `error`.
 */
export function useSignIn() {
  const { client } = useCardea();
  const [view, setView] = useState<View>(START);
  const [error, setError] = useState<unknown>(null);
  const [running, setRunning] = useState(0);
  const challenge = useRef<Challenge | null>(null);
  // Kept in memory until the code confirms the account, so it is not asked for twice.
  const chosen = useRef<string | null>(null);
  // Bumped by `reset`: an answer to an abandoned step changes nothing.
  const generation = useRef(0);
  const email = useRef("");

  const show = useCallback((step: SignInStep, address: string, requiredAttributes: readonly string[] = []) => {
    email.current = address;
    setView({ step, email: address, requiredAttributes });
  }, []);

  const reset = useCallback(() => {
    generation.current++;
    challenge.current = null;
    chosen.current = null;
    setError(null);
    show("credentials", "");
  }, [show]);

  useEffect(() => client.subscribe(reset), [client, reset]);

  const track = useCallback(async <T,>(work: (current: () => boolean) => Promise<T>): Promise<T> => {
    const started = generation.current;
    const current = () => started === generation.current;
    setError(null);
    setRunning((count) => count + 1);
    try {
      return await work(current);
    } catch (failure) {
      if (current()) setError(failure);
      throw failure;
    } finally {
      setRunning((count) => count - 1);
    }
  }, []);

  const apply = useCallback(
    (result: SignInResult, address: string, password: string | null) => {
      challenge.current = null;
      chosen.current = null;
      if (result.status === "signedIn") return show("credentials", "");
      if (result.status === "confirmationRequired") chosen.current = password;
      else challenge.current = result;
      show(result.status, address, result.status === "newPasswordRequired" ? result.requiredAttributes : []);
    },
    [show],
  );

  const attempt = useCallback(
    async (address: string, password: string, current: () => boolean) => {
      const result = await client.signIn(address, password);
      if (current()) apply(result, address, password);
      return result;
    },
    [client, apply],
  );

  const answer = useCallback(
    <S extends Challenge["status"]>(status: S, respond: (step: Extract<Challenge, { status: S }>) => Promise<SignInResult>) =>
      track(async (current) => {
        const step = challenge.current;
        if (step?.status !== status) throw new CardeaError("attempt-invalid");
        const result = await respond(step as Extract<Challenge, { status: S }>);
        if (current()) apply(result, email.current, null);
        return result;
      }),
    [track, apply],
  );

  return {
    ...view,
    error,
    pending: running > 0,
    providers: client.config.providers,
    reset,
    signIn: useCallback(
      (address: string, password: string) => track((current) => attempt(address.trim(), password, current)),
      [track, attempt],
    ),
    signUp: useCallback(
      (address: string, password: string, attributes?: Record<string, string>) =>
        track(async (current) => {
          const trimmed = address.trim();
          const { confirmed } = await client.signUp(trimmed, password, attributes);
          if (!current()) return;
          if (confirmed) return void (await attempt(trimmed, password, current));
          chosen.current = password;
          show("confirmationRequired", trimmed);
        }),
      [client, track, attempt, show],
    ),
    /** True once signed in; false when the account is confirmed but the form must take over. */
    confirmSignUp: useCallback(
      (code: string) =>
        track(async (current) => {
          const address = email.current;
          await client.confirmSignUp(address, code);
          const password = chosen.current;
          chosen.current = null;
          if (!current()) return false;
          if (password) {
            // A failure here is not a failed confirmation: the account is confirmed either way.
            try {
              return (await attempt(address, password, current)).status === "signedIn";
            } catch {
              /* the sign-in form takes it from here */
            }
          }
          if (current()) show("credentials", address);
          return false;
        }),
      [client, track, attempt, show],
    ),
    resendCode: useCallback(
      () => track(() => client.resendConfirmationCode(email.current)),
      [client, track],
    ),
    completeNewPassword: useCallback(
      (password: string, attributes?: Record<string, string>) =>
        answer("newPasswordRequired", (step) => step.completeNewPassword(password, attributes)),
      [answer],
    ),
    submitTotp: useCallback(
      (code: string) => answer("totpRequired", (step) => step.submitTotp(code)),
      [answer],
    ),
    requestPasswordReset: useCallback(
      (address: string) =>
        track(async (current) => {
          const trimmed = address.trim();
          await client.requestPasswordReset(trimmed);
          if (current()) show("resetCodeSent", trimmed);
        }),
      [client, track, show],
    ),
    /** True once signed in; false when the password changed but the form must take over. */
    resetPassword: useCallback(
      (code: string, password: string) =>
        track(async (current) => {
          const address = email.current;
          await client.resetPassword(address, code, password);
          if (!current()) return false;
          try {
            return (await attempt(address, password, current)).status === "signedIn";
          } catch {
            if (current()) show("credentials", address);
            return false;
          }
        }),
      [client, track, attempt, show],
    ),
    signInWithProvider: useCallback(
      (provider: Provider, options?: { returnTo?: string }) =>
        track(() => client.signInWithProvider(provider, options)),
      [client, track],
    ),
  };
}
