import { CognitoRefreshToken, type CognitoUserSession } from "amazon-cognito-identity-js";
import type { ResolvedConfig } from "../config.js";
import { authErrorCode } from "../errors.js";
import { RefreshExpired, type TokenSource, type Tokens } from "../session/refresh.js";
import { createUser } from "./user.js";

/** The SDK sets no deadline of its own, and a hung request would block every caller. */
const DEADLINE_MS = 20_000;

export function tokensOf(session: CognitoUserSession): Tokens {
  return {
    idToken: session.getIdToken().getJwtToken(),
    accessToken: session.getAccessToken().getJwtToken(),
    refreshToken: session.getRefreshToken().getToken(),
  };
}

/** Password sessions refresh through the Cognito API. */
export function passwordTokenSource(config: ResolvedConfig): TokenSource {
  return (record) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timeout")), DEADLINE_MS);
      const token = new CognitoRefreshToken({ RefreshToken: record.refreshToken });
      createUser(config, record.username).refreshSession(token, (error: unknown, session: CognitoUserSession) => {
        clearTimeout(timer);
        if (!error) return resolve(tokensOf(session));
        const gone = ["NotAuthorizedException", "UserNotFoundException"].includes(authErrorCode(error));
        reject(gone ? new RefreshExpired() : error);
      });
    });
}
