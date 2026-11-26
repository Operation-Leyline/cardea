import { isText, readTokenJson, type LegacySessionSource } from "./source.js";

/**
 * The session `amazon-cognito-identity-js` saves in its default layout,
 * `CognitoIdentityServiceProvider.<clientId>.…`, optionally behind a key
 * `prefix` that the app's own storage wrapper added.
 *
 * With a prefix, `<prefix>googleSession` is also read. yoru-web keeps the
 * current tokens of a Google sign-in there (the SDK's copy goes stale, and
 * only the hosted token endpoint refreshes them).
 */
export function cognitoSdkSession({ prefix = "" }: { prefix?: string } = {}): LegacySessionSource {
  const root = (clientId: string) => `${prefix}CognitoIdentityServiceProvider.${clientId}.`;
  const hostedKey = prefix ? `${prefix}googleSession` : null;

  return {
    read(storage, { clientId }) {
      const hosted = hostedKey ? storage.getItem(hostedKey) : null;
      if (hosted !== null) {
        const tokens = readTokenJson(hosted);
        return tokens ? { method: "Google", ...tokens } : null;
      }
      const username = storage.getItem(`${root(clientId)}LastAuthUser`);
      if (!username) return null;
      const item = (name: string) => storage.getItem(`${root(clientId)}${username}.${name}`);
      const [idToken, accessToken, refreshToken] = [item("idToken"), item("accessToken"), item("refreshToken")];
      if (!isText(idToken) || !isText(accessToken) || !isText(refreshToken)) return null;
      const clockDrift = Number.parseInt(item("clockDrift") ?? "", 10) || 0;
      return { method: "password", username, idToken, accessToken, refreshToken, clockDrift };
    },
    clear(storage, { clientId }) {
      // Every user of this client, so no earlier account's refresh token stays behind.
      const keys = Array.from({ length: storage.length }, (_, index) => storage.key(index));
      for (const key of keys) {
        if (key?.startsWith(root(clientId))) storage.removeItem(key);
      }
      if (hostedKey) storage.removeItem(hostedKey);
    },
  };
}
