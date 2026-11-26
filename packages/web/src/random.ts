export function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/** 32 random bytes as 43 URL-safe characters: state, nonce and PKCE verifier. */
export function randomValue(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}
