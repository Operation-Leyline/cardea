import type { ResolvedConfig } from "../config.js";
import { CardeaError, type CardeaErrorCode } from "../errors.js";
import { safeReturnPath } from "../return-path.js";
import { usernameOf, type StoredSession } from "../session/record.js";
import { consumeAttempt } from "./attempt.js";
import { requestTokens } from "./token-endpoint.js";
import type { Verifier } from "./verify.js";

/**
 * A product's last word before a provider session is saved, for example
 * "does my API know this user?". Throwing refuses the sign-in.
 */
export type ConfirmProviderSession = (candidate: { idToken: string; subject: string }) => Promise<void>;

/** Turns the returning URL into a verified session that is not saved yet. */
export async function exchangeCallback(
  config: ResolvedConfig,
  callback: URL,
  storage: () => Storage,
  verify: Verifier,
  confirm: ConfirmProviderSession | undefined,
): Promise<{ record: StoredSession; returnTo: string }> {
  let returnTo = "/";
  // The stage names the failure. Raw causes can carry identity details, so they stop here.
  let stage: CardeaErrorCode = "attempt-invalid";
  try {
    const attempt = consumeAttempt(config, callback, storage);
    returnTo = safeReturnPath(attempt.returnTo, callback.origin, config.callbackPath);
    if (callback.searchParams.has("error")) throw new CardeaError("provider-refused");
    const codes = callback.searchParams.getAll("code");
    if (codes.length !== 1 || !codes[0]) throw new CardeaError("attempt-invalid");
    stage = "token-exchange-failed";
    const tokens = await requestTokens(config, {
      grant_type: "authorization_code",
      code: codes[0],
      redirect_uri: attempt.redirectUri,
      code_verifier: attempt.verifier,
    });
    const { idToken, accessToken, refreshToken } = tokens;
    if (!refreshToken) throw new CardeaError(stage);
    stage = "token-verification-failed";
    const subject = await verify(tokens, { nonce: attempt.nonce });
    stage = "account-check-failed";
    await confirm?.({ idToken, subject });
    const username = usernameOf(idToken) ?? subject;
    return { record: { version: 1, method: attempt.provider, username, idToken, accessToken, refreshToken }, returnTo };
  } catch (error) {
    throw new CardeaError(error instanceof CardeaError ? error.code : stage, returnTo);
  }
}
