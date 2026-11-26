import { readTokenJson, type LegacyClient, type LegacySessionSource } from "./source.js";

/** leyline-console's Google session, saved under `leyline.google.session.<clientId>.<issuer>`. */
export function leylineGoogleSession(): LegacySessionSource {
  const key = ({ clientId, issuer }: LegacyClient) => `leyline.google.session.${clientId}.${issuer}`;
  return {
    read(storage, client) {
      const tokens = readTokenJson(storage.getItem(key(client)));
      return tokens ? { method: "Google", ...tokens } : null;
    },
    clear(storage, client) {
      storage.removeItem(key(client));
    },
  };
}
