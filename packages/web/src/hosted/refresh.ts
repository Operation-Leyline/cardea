import type { ResolvedConfig } from "../config.js";
import { subjectOf } from "../session/record.js";
import type { TokenSource } from "../session/refresh.js";
import { requestTokens } from "./token-endpoint.js";
import type { Verifier } from "./verify.js";

/** Provider sessions refresh at the OAuth endpoint, and are verified before saving. */
export function providerTokenSource(config: ResolvedConfig, verify: Verifier): TokenSource {
  return async (record) => {
    const tokens = await requestTokens(config, { grant_type: "refresh_token", refresh_token: record.refreshToken });
    await verify(tokens, { subject: subjectOf(record) });
    return { ...tokens, refreshToken: tokens.refreshToken ?? record.refreshToken };
  };
}
