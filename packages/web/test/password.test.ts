import { describe, expect, it } from "vitest";
import { createCardeaClient, type SessionEvent, type SignInResult } from "../src/index.js";
import { authenticationResult, CognitoFailure, CONFIG, installFakeCognito, issueTokens, SESSION_KEY } from "./fakes/cognito.js";

const PASSWORD = "Correct-Horse-12";

function setup(config: Partial<typeof CONFIG> & { endpoint?: string } = {}) {
  const cognito = installFakeCognito();
  const client = createCardeaClient({ ...CONFIG, ...config }, { redirect: () => {} });
  const events: SessionEvent[] = [];
  client.subscribe((event) => events.push(event));
  return { cognito, client, events };
}

function expectStatus<S extends SignInResult["status"]>(result: SignInResult, status: S) {
  expect(result.status).toBe(status);
  return result as Extract<SignInResult, { status: S }>;
}

describe("password sign-in", () => {
  it("uses SRP and keeps only the session record in storage", async () => {
    const { cognito, client, events } = setup();
    const result = expectStatus(await client.signIn("  ada@example.test ", PASSWORD), "signedIn");
    expect(cognito.calls[0].body.AuthFlow).toBe("USER_SRP_AUTH");
    expect(cognito.calls[0].body.AuthParameters.USERNAME).toBe("ada@example.test");
    expect(JSON.stringify(cognito.calls)).not.toContain(PASSWORD);
    expect(result.session).toMatchObject({ subject: "ada", userId: "ada", method: "password", email: "ada@example.test" });
    expect(Object.keys(localStorage)).toEqual([SESSION_KEY]);
    expect(localStorage.getItem(SESSION_KEY)).not.toContain(PASSWORD);
    expect(client.getState()).toMatchObject({ status: "signedIn", session: { subject: "ada" } });
    expect(events.map((event) => event.type)).toEqual(["signedIn"]);
    await expect(client.getIdToken()).resolves.toEqual(expect.any(String));
  });

  it("uses USER_PASSWORD_AUTH only against a local endpoint, and offers no provider there", async () => {
    const { cognito, client } = setup({ endpoint: "http://localhost:9229" });
    await client.signIn("ada@example.test", PASSWORD);
    expect(cognito.calls[0].body.AuthFlow).toBe("USER_PASSWORD_AUTH");
    expect(String(cognito.fetcher.mock.calls[0][0])).toBe("http://localhost:9229");
    expect(client.config.providers).toEqual([]);
    await expect(client.signInWithProvider("Google")).rejects.toMatchObject({ code: "provider-unavailable" });
  });

  it("reads the product's user id from the configured claim", async () => {
    const cognito = installFakeCognito();
    cognito.operations.RespondToAuthChallenge = async () =>
      authenticationResult(await issueTokens({ id: { "custom:userId": "original-id" } }));
    const client = createCardeaClient({ ...CONFIG, userIdClaim: "custom:userId" });
    const result = expectStatus(await client.signIn("ada@example.test", PASSWORD), "signedIn");
    expect(result.session).toMatchObject({ subject: "ada", userId: "original-id" });
  });

  it("walks a temporary password through the new-password and TOTP challenges", async () => {
    const { cognito, client } = setup();
    cognito.operations.RespondToAuthChallenge = async (body) => {
      if (body.ChallengeName === "PASSWORD_VERIFIER") {
        return {
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          Session: "s1",
          ChallengeParameters: { userAttributes: '{"email_verified":"true"}', requiredAttributes: "[]" },
        };
      }
      if (body.ChallengeName === "NEW_PASSWORD_REQUIRED") {
        return { ChallengeName: "SOFTWARE_TOKEN_MFA", Session: "s2", ChallengeParameters: {} };
      }
      return authenticationResult(await issueTokens());
    };
    const first = expectStatus(await client.signIn("ada@example.test", "temporary"), "newPasswordRequired");
    expect(localStorage.length).toBe(0);
    const second = expectStatus(await first.completeNewPassword(PASSWORD), "totpRequired");
    expect(cognito.calls.at(-1)!.body.ChallengeResponses).not.toHaveProperty("userAttributes.email_verified");
    expectStatus(await second.submitTotp(" 123 456 "), "signedIn");
    expect(cognito.calls.at(-1)!.body.ChallengeResponses.SOFTWARE_TOKEN_MFA_CODE).toBe("123456");
    expect(client.currentSession()?.subject).toBe("ada");
  });

  it("does not sign in with a challenge answered after sign-out", async () => {
    const { cognito, client } = setup();
    cognito.operations.RespondToAuthChallenge = async (body) =>
      body.ChallengeName === "PASSWORD_VERIFIER"
        ? { ChallengeName: "SOFTWARE_TOKEN_MFA", Session: "s", ChallengeParameters: {} }
        : authenticationResult(await issueTokens());
    const challenge = expectStatus(await client.signIn("ada@example.test", PASSWORD), "totpRequired");
    client.signOut();
    await expect(challenge.submitTotp("123456")).rejects.toMatchObject({ code: "session-superseded" });
    expect(localStorage.length).toBe(0);
  });

  it("reports an unconfirmed account as a step, and a wrong password as Cognito's error", async () => {
    const { cognito, client } = setup();
    cognito.operations.InitiateAuth = () => new CognitoFailure("UserNotConfirmedException");
    await expect(client.signIn("ada@example.test", PASSWORD)).resolves.toEqual({
      status: "confirmationRequired",
      email: "ada@example.test",
    });
    cognito.operations.InitiateAuth = () => new CognitoFailure("NotAuthorizedException");
    await expect(client.signIn("ada@example.test", "wrong")).rejects.toMatchObject({ code: "NotAuthorizedException" });
    expect(localStorage.length).toBe(0);
  });
});

describe("sign-up and recovery", () => {
  it("signs up with the email attribute, confirms without forcing an alias, and resends", async () => {
    const { cognito, client } = setup();
    await expect(client.signUp(" Ada@Example.test ", PASSWORD, { name: "Ada" })).resolves.toEqual({ confirmed: false });
    await client.confirmSignUp("Ada@Example.test", " 123456 ");
    await client.resendConfirmationCode("Ada@Example.test");
    const [signUp, confirm] = cognito.calls;
    expect(signUp.body.UserAttributes).toEqual([
      { Name: "name", Value: "Ada" },
      { Name: "email", Value: "Ada@Example.test" },
    ]);
    expect(confirm.body).toMatchObject({ ConfirmationCode: "123456", ForceAliasCreation: false });
    expect(cognito.operationNames()).toEqual(["SignUp", "ConfirmSignUp", "ResendConfirmationCode"]);
  });

  it.each(["UserNotFoundException", "InvalidParameterException", "NotAuthorizedException"])(
    "does not reveal %s when asking for a reset code",
    async (code) => {
      const { cognito, client } = setup();
      cognito.operations.ForgotPassword = () => new CognitoFailure(code);
      await expect(client.requestPasswordReset("nobody@example.test")).resolves.toBeUndefined();
    },
  );

  it("keeps rate limits and bad reset codes as errors", async () => {
    const { cognito, client } = setup();
    cognito.operations.ForgotPassword = () => new CognitoFailure("LimitExceededException");
    await expect(client.requestPasswordReset("ada@example.test")).rejects.toMatchObject({ code: "LimitExceededException" });
    cognito.operations.ConfirmForgotPassword = () => new CognitoFailure("CodeMismatchException");
    await expect(client.resetPassword("ada@example.test", "000000", PASSWORD)).rejects.toMatchObject({
      code: "CodeMismatchException",
    });
  });
});

describe("configuration", () => {
  it.each([
    { userPoolId: "" },
    { clientId: "" },
    { loginDomain: "http://login.example.test" },
    { loginDomain: "https://login.example.test/path" },
  ])("refuses %o", (bad) => {
    expect(() => createCardeaClient({ ...CONFIG, ...bad })).toThrow(expect.objectContaining({ code: "not-configured" }));
  });

  it("scopes storage by prefix, issuer and client", () => {
    const client = createCardeaClient({ ...CONFIG, storagePrefix: "yoru.auth." });
    expect(client.config.sessionKey).toBe(`yoru.auth.session.${client.config.issuer}.web-client`);
  });
});
