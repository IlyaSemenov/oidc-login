const loopbackHostnames = new Set(["localhost", "127.0.0.1", "[::1]"])

/**
 * Checks that an issuer URL is safe to sign in through: HTTPS, or plain HTTP on a loopback host for local development.
 *
 * `createOidcLogin` accepts plain HTTP only for such URLs, so validate issuer URLs that users enter with this function.
 */
export function isSecureIssuerUrl(value: string): boolean {
  if (!URL.canParse(value)) {
    return false
  }

  const url = new URL(value)
  return url.protocol === "https:" || (url.protocol === "http:" && isLoopbackHostname(url.hostname))
}

/** Checks whether a hostname points to the local machine. */
export function isLoopbackHostname(hostname: string): boolean {
  return loopbackHostnames.has(hostname) || hostname.endsWith(".localhost")
}
