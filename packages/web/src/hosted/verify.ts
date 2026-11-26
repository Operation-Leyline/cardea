import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import type { ResolvedConfig } from "../config.js";
import { CardeaError } from "../errors.js";

/**
 * Checks both Cognito tokens against the pool's signing keys before they are
 * saved: signature, issuer, client, expiry, purpose, nonce and subject.
 * Returns the subject. `allowExpired` skips only the expiry check, for tokens
 * whose freshness is judged separately.
 */
export type Verifier = (
  tokens: { idToken: string; accessToken: string },
  expected: { nonce?: string; subject?: string; allowExpired?: boolean },
) => Promise<string>;

export function createVerifier(config: ResolvedConfig): Verifier {
  let keys: JWTVerifyGetKey | undefined;
  return async (tokens, expected) => {
    keys ??= createRemoteJWKSet(new URL(`${config.issuer}/.well-known/jwks.json`));
    const options = {
      issuer: config.issuer,
      algorithms: ["RS256"],
      // Judged at the epoch, nothing has expired yet.
      ...(expected.allowExpired ? { currentDate: new Date(0) } : {}),
    };
    const { payload: id } = await jwtVerify(tokens.idToken, keys, {
      ...options,
      audience: config.clientId,
      requiredClaims: ["exp", "iat", "sub", "email", "token_use"],
    });
    const { payload: access } = await jwtVerify(tokens.accessToken, keys, {
      ...options,
      requiredClaims: ["exp", "sub", "client_id", "token_use"],
    });
    if (
      !id.sub ||
      id.token_use !== "id" ||
      typeof id.email !== "string" ||
      !id.email ||
      (expected.nonce !== undefined && id.nonce !== expected.nonce) ||
      (expected.subject !== undefined && id.sub !== expected.subject) ||
      access.token_use !== "access" ||
      access.client_id !== config.clientId ||
      access.sub !== id.sub
    ) {
      throw new CardeaError("token-verification-failed");
    }
    return id.sub;
  };
}
