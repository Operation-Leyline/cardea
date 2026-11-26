import { AuthenticationDetails, type CognitoUser, type CognitoUserSession } from "amazon-cognito-identity-js";
import { CardeaError } from "../errors.js";

/** Where a password sign-in stands after one exchange with Cognito. */
export type AuthStep =
  | { kind: "session"; session: CognitoUserSession }
  | {
      kind: "newPassword";
      requiredAttributes: readonly string[];
      next: (password: string, attributes?: Record<string, string>) => Promise<AuthStep>;
    }
  | { kind: "totp"; next: (code: string) => Promise<AuthStep> };

/**
 * Turns the SDK's callbacks into one step. The same `CognitoUser` carries the
 * challenge session, so each continuation closes over it.
 */
function step(user: CognitoUser, start: (callbacks: Parameters<CognitoUser["authenticateUser"]>[1]) => void) {
  return new Promise<AuthStep>((resolve, reject) => {
    const unsupported = () => reject(new CardeaError("challenge-unsupported"));
    const callbacks: Parameters<CognitoUser["authenticateUser"]>[1] = {
      onSuccess: (session) => resolve({ kind: "session", session }),
      onFailure: reject,
      // Not a failure: the password was right and Cognito wants it replaced.
      // Only the attributes it reports missing go back, because it refuses its
      // read-only ones.
      newPasswordRequired: (_current: unknown, missing: string[] = []) =>
        resolve({
          kind: "newPassword",
          requiredAttributes: missing,
          next: (password, attributes = {}) => {
            const wanted = Object.entries(attributes).filter(([name]) => missing.includes(name));
            return step(user, (next) =>
              user.completeNewPasswordChallenge(password, Object.fromEntries(wanted), next),
            );
          },
        }),
      totpRequired: () =>
        resolve({
          kind: "totp",
          next: (code) => step(user, (next) => user.sendMFACode(code, next, "SOFTWARE_TOKEN_MFA")),
        }),
      selectMFAType: () => user.sendMFASelectionAnswer("SOFTWARE_TOKEN_MFA", callbacks),
      mfaRequired: unsupported,
      mfaSetup: unsupported,
      customChallenge: unsupported,
    };
    start(callbacks);
  });
}

export function authenticate(user: CognitoUser, email: string, password: string): Promise<AuthStep> {
  return step(user, (callbacks) =>
    user.authenticateUser(new AuthenticationDetails({ Username: email, Password: password }), callbacks),
  );
}
