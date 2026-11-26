import { CognitoUserAttribute } from "amazon-cognito-identity-js";
import type { ResolvedConfig } from "../config.js";
import { authErrorCode } from "../errors.js";
import { createPool, createUser } from "./user.js";

/** Account operations that need no session: sign-up, confirmation and recovery. */

/** True when the pool confirmed the account at once and no code is needed. */
export function signUp(
  config: ResolvedConfig,
  email: string,
  password: string,
  attributes: Readonly<Record<string, string>>,
): Promise<boolean> {
  // Email is the sign-in alias and a required attribute; Cognito infers neither from the other.
  const list = Object.entries({ ...attributes, email }).map(
    ([Name, Value]) => new CognitoUserAttribute({ Name, Value }),
  );
  return new Promise((resolve, reject) => {
    createPool(config).signUp(email, password, list, [], (error, result) =>
      error ? reject(error) : resolve(Boolean(result?.userConfirmed)),
    );
  });
}

export function confirmSignUp(config: ResolvedConfig, email: string, code: string): Promise<void> {
  return new Promise((resolve, reject) => {
    // `false`: never take an alias over from an account that already holds it.
    createUser(config, email).confirmRegistration(code, false, (error) => (error ? reject(error) : resolve()));
  });
}

export function resendConfirmationCode(config: ResolvedConfig, email: string): Promise<void> {
  return new Promise((resolve, reject) => {
    createUser(config, email).resendConfirmationCode((error) => (error ? reject(error) : resolve()));
  });
}

/** Answers that would reveal whether an account exists or is eligible. */
const ELIGIBILITY = ["UserNotFoundException", "InvalidParameterException", "NotAuthorizedException"];

/** Starts the forgot-password flow and reports every refusal. */
export function sendResetCode(config: ResolvedConfig, email: string): Promise<void> {
  return new Promise((resolve, reject) => {
    createUser(config, email).forgotPassword({
      onSuccess: () => resolve(),
      inputVerificationCode: () => resolve(),
      onFailure: reject,
    });
  });
}

/** For someone not signed in: succeeds whether or not a code could be sent. */
export async function requestPasswordReset(config: ResolvedConfig, email: string): Promise<void> {
  try {
    await sendResetCode(config, email);
  } catch (error) {
    if (!ELIGIBILITY.includes(authErrorCode(error))) throw error;
  }
}

export function resetPassword(config: ResolvedConfig, email: string, code: string, password: string): Promise<void> {
  return new Promise((resolve, reject) => {
    createUser(config, email).confirmPassword(code, password, { onSuccess: () => resolve(), onFailure: reject });
  });
}
