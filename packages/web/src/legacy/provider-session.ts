import type { Provider } from "../providers.js";
import { readTokenJson, type LegacyClient, type LegacySessionSource, type TokenFields } from "./source.js";

/** Where an app's earlier code kept the tokens of a provider sign-in. */
export interface ProviderSessionOptions {
  /**
   * The storage key: a pattern in which `{clientId}` and `{issuer}` stand for
   * this client's, or a function of them.
   */
  key: string | ((client: LegacyClient) => string);
  /** The record's property names, where they differ from `id_token`, `access_token`, `refresh_token` and `subject`. */
  fields?: Partial<TokenFields>;
  /** The provider the saved sign-in used. */
  provider?: Provider;
}

function fromPattern(pattern: string): (client: LegacyClient) => string {
  return (client) => pattern.replace(/\{(clientId|issuer)\}/g, (_, name: keyof LegacyClient) => client[name]);
}

/** A provider sign-in saved as one JSON record under one storage key. */
export function providerSession({ key, fields, provider = "Google" }: ProviderSessionOptions): LegacySessionSource {
  const keyFor = typeof key === "string" ? fromPattern(key) : key;
  return {
    read(storage, client) {
      const tokens = readTokenJson(storage.getItem(keyFor(client)), fields);
      return tokens ? { method: provider, ...tokens } : null;
    },
    clear(storage, client) {
      storage.removeItem(keyFor(client));
    },
  };
}
