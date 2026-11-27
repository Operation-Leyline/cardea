import type { ResolvedConfig } from "../config.js";
import { CardeaError } from "../errors.js";
import type { Tokens } from "../session/refresh.js";

/** The public parameter the library's challenge carries. */
const CHALLENGE = "PROVIDER_TICKET";
const DEADLINE_MS = 20_000;

type Answer = Record<string, any>;

/** One unsigned call to the user pool's API, as a public client. */
async function call(config: ResolvedConfig, operation: string, body: object): Promise<Answer> {
  const region = config.userPoolId.split("_")[0];
  const response = await fetch(`https://cognito-idp.${region}.amazonaws.com/`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": `AWSCognitoIdentityProviderService.${operation}`,
    },
    body: JSON.stringify(body),
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
    referrerPolicy: "no-referrer",
    signal: AbortSignal.timeout(DEADLINE_MS),
  });
  const answer = (await response.json().catch(() => null)) as Answer | null;
  if (!response.ok || !answer) throw new CardeaError("token-exchange-failed");
  return answer;
}

/**
 * Cognito's custom authentication flow: start it for `username`, answer its one
 * challenge with the ticket, and take the tokens. Any other challenge is
 * refused, and the ticket is sent only to the library's own, and only while
 * `signal` has not given up.
 */
export async function exchangeTicket(
  config: ResolvedConfig,
  username: string,
  ticket: string,
  signal: AbortSignal,
): Promise<Tokens> {
  const started = await call(config, "InitiateAuth", {
    AuthFlow: "CUSTOM_AUTH",
    ClientId: config.clientId,
    AuthParameters: { USERNAME: username },
  });
  const parameters = started.ChallengeParameters;
  if (
    started.ChallengeName !== "CUSTOM_CHALLENGE" ||
    parameters?.challenge !== CHALLENGE ||
    typeof started.Session !== "string"
  ) {
    throw new CardeaError("challenge-unsupported");
  }
  if (signal.aborted) throw signal.reason;
  const finished = await call(config, "RespondToAuthChallenge", {
    ChallengeName: "CUSTOM_CHALLENGE",
    ClientId: config.clientId,
    Session: started.Session,
    ChallengeResponses: { USERNAME: parameters.USERNAME ?? username, ANSWER: ticket },
  });
  if (finished.ChallengeName) throw new CardeaError("challenge-unsupported");
  const { IdToken: idToken, AccessToken: accessToken, RefreshToken: refreshToken } = finished.AuthenticationResult ?? {};
  if ([idToken, accessToken, refreshToken].some((token) => typeof token !== "string" || !token)) {
    throw new CardeaError("token-exchange-failed");
  }
  return { idToken, accessToken, refreshToken };
}
