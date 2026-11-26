/**
 * A fake pool behind `fetch`: the Cognito API, the hosted token endpoint and
 * the signing keys, with real RS256 tokens. No network.
 */
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { vi } from "vitest";
import type { CardeaConfig } from "../../src/index.js";

export const CONFIG = {
  userPoolId: "us-east-1_Fixture",
  clientId: "web-client",
  loginDomain: "https://login.example.test",
  providers: ["Google", "Apple"],
} satisfies CardeaConfig;

export const ISSUER = `https://cognito-idp.us-east-1.amazonaws.com/${CONFIG.userPoolId}`;
export const SESSION_KEY = `cardea.auth.session.${ISSUER}.${CONFIG.clientId}`;
export const GENERATION_KEY = `cardea.auth.generation.${ISSUER}.${CONFIG.clientId}`;
export const ATTEMPT_KEY = `cardea.auth.attempt.${ISSUER}.${CONFIG.clientId}`;

const signing = await generateKeyPair("RS256");
const foreign = await generateKeyPair("RS256");
const jwk = { ...(await exportJWK(signing.publicKey)), kid: "pool-key", alg: "RS256", use: "sig" };

export interface TokenOptions {
  subject?: string;
  /** Seconds from now. */
  expiresIn?: number;
  nonce?: string;
  id?: Record<string, unknown>;
  access?: Record<string, unknown>;
  issuer?: string;
  /** Sign with a key the pool does not publish. */
  foreignKey?: boolean;
}

export async function issueTokens(options: TokenOptions = {}) {
  const { subject = "ada", expiresIn = 3600 } = options;
  const now = Math.floor(Date.now() / 1000);
  const sign = (claims: Record<string, unknown>) =>
    new SignJWT({ sub: subject, iss: options.issuer ?? ISSUER, iat: now, exp: now + expiresIn, ...claims })
      .setProtectedHeader({ alg: "RS256", kid: "pool-key" })
      .sign(options.foreignKey ? foreign.privateKey : signing.privateKey);
  return {
    id_token: await sign({
      aud: CONFIG.clientId,
      token_use: "id",
      email: `${subject}@example.test`,
      "cognito:username": `user-${subject}`,
      ...(options.nonce ? { nonce: options.nonce } : {}),
      ...options.id,
    }),
    access_token: await sign({ client_id: CONFIG.clientId, token_use: "access", ...options.access }),
    refresh_token: `refresh-${subject}`,
  };
}

/** The record the client writes to localStorage, for tests that start signed in. */
export async function storedSession(options: TokenOptions & { method?: string } = {}) {
  const tokens = await issueTokens(options);
  const subject = options.subject ?? "ada";
  return JSON.stringify({
    version: 1,
    method: options.method ?? "password",
    username: `user-${subject}`,
    idToken: tokens.id_token,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
  });
}

export class CognitoFailure {
  constructor(readonly code: string) {}
}

export function authenticationResult(tokens: Awaited<ReturnType<typeof issueTokens>>, refresh = true) {
  return {
    AuthenticationResult: {
      IdToken: tokens.id_token,
      AccessToken: tokens.access_token,
      ...(refresh ? { RefreshToken: tokens.refresh_token } : {}),
      ExpiresIn: 3600,
      TokenType: "Bearer",
    },
  };
}

type Handler = (body: any) => unknown;

export function installFakeCognito() {
  const calls: { operation: string; body: any }[] = [];
  const tokenRequests: URLSearchParams[] = [];
  const operations: Record<string, Handler> = {
    InitiateAuth: async (body) => {
      if (body.AuthFlow === "REFRESH_TOKEN_AUTH") {
        const subject = String(body.AuthParameters.REFRESH_TOKEN).replace("refresh-", "");
        return authenticationResult(await issueTokens({ subject }), false);
      }
      if (body.AuthFlow === "USER_PASSWORD_AUTH") return authenticationResult(await issueTokens());
      return {
        ChallengeName: "PASSWORD_VERIFIER",
        ChallengeParameters: {
          SRP_B: "ab".repeat(192),
          SALT: "cd".repeat(16),
          SECRET_BLOCK: btoa("secret-block"),
          USER_ID_FOR_SRP: "user-ada",
          USERNAME: "user-ada",
        },
      };
    },
    RespondToAuthChallenge: async () => authenticationResult(await issueTokens()),
    SignUp: () => ({ UserConfirmed: false, UserSub: "ada" }),
    ConfirmSignUp: () => ({}),
    ResendConfirmationCode: () => ({ CodeDeliveryDetails: {} }),
    ForgotPassword: () => ({ CodeDeliveryDetails: {} }),
    ConfirmForgotPassword: () => ({}),
  };
  let token: (body: URLSearchParams) => Promise<Response> = async () => Response.json(await issueTokens());

  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url === `${ISSUER}/.well-known/jwks.json`) return Response.json({ keys: [jwk] });
    if (url === `${CONFIG.loginDomain}/oauth2/token`) {
      const body = init!.body as URLSearchParams;
      tokenRequests.push(body);
      return token(body);
    }
    const headers = init?.headers as Record<string, string> | undefined;
    const operation = headers?.["X-Amz-Target"]?.split(".")[1];
    const handler = operation ? operations[operation] : undefined;
    if (!operation || !handler) throw new TypeError("unexpected request");
    const body = JSON.parse(String(init!.body));
    calls.push({ operation, body });
    const result = await handler(body);
    if (result instanceof Response) return result;
    if (result instanceof CognitoFailure) {
      return Response.json({ __type: result.code, message: result.code }, { status: 400 });
    }
    return Response.json(result);
  });
  vi.stubGlobal("fetch", fetcher);

  return {
    fetcher,
    calls,
    tokenRequests,
    operations,
    onToken(handler: typeof token) {
      token = handler;
    },
    operationNames: () => calls.map((call) => call.operation),
  };
}

/** A promise a test settles when it chooses. */
export function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

/** What a browser does in every other tab after one tab writes. */
export function otherTabWrites(key: string | null, value: string | null) {
  if (key === null) localStorage.clear();
  else if (value === null) localStorage.removeItem(key);
  else localStorage.setItem(key, value);
  window.dispatchEvent(new StorageEvent("storage", { key, newValue: value }));
}
