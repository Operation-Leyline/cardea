import { CognitoUser, CognitoUserPool, type ICognitoStorage } from "amazon-cognito-identity-js";
import type { ResolvedConfig } from "../config.js";

/**
 * The SDK keeps tokens in whatever storage it is given. It gets one that lives
 * only as long as the operation, so the session store is the single saved copy.
 */
function memoryStorage(): ICognitoStorage {
  const values = new Map<string, string>();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => void values.set(key, value),
    removeItem: (key) => void values.delete(key),
    clear: () => values.clear(),
  };
}

export function createPool(config: ResolvedConfig, storage = memoryStorage()): CognitoUserPool {
  return new CognitoUserPool({
    UserPoolId: config.userPoolId,
    ClientId: config.clientId,
    ...(config.endpoint ? { endpoint: config.endpoint } : {}),
    Storage: storage,
    AdvancedSecurityDataCollectionFlag: false,
  });
}

export function createUser(config: ResolvedConfig, username: string): CognitoUser {
  const storage = memoryStorage();
  const user = new CognitoUser({ Username: username, Pool: createPool(config, storage), Storage: storage });
  // The simulator's client does not support SRP.
  if (config.endpoint) user.setAuthenticationFlowType("USER_PASSWORD_AUTH");
  return user;
}
