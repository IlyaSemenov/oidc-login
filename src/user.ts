/** User that an OpenID Connect sign-in returns. */
export interface OidcUser {
  /** Subject identifier, unique and stable within the issuer. */
  sub: string
  email?: string
  /** Whether the provider verified `email`; `undefined` when it does not say. */
  emailVerified?: boolean
  /** Display name: the `name` claim, or `preferred_username` without it. */
  name?: string
  /** Claims of the ID token as the provider sent them. */
  claims: Record<string, unknown>
  /** UserInfo response as the provider sent it, when the sign-in requested it. */
  userinfo?: Record<string, unknown>
}

/** Standard claims of the user, with values of unexpected types dropped. */
export interface StandardClaims {
  email?: string
  email_verified?: boolean
  name?: string
  preferred_username?: string
}

/** Reads standard claims from an untrusted claims object. */
export function readStandardClaims(claims: Record<string, unknown> | undefined): StandardClaims {
  return {
    email: readString(claims?.email),
    email_verified: typeof claims?.email_verified === "boolean" ? claims.email_verified : undefined,
    name: readString(claims?.name),
    preferred_username: readString(claims?.preferred_username),
  }
}

/** Builds the user from the ID token claims, filling missing claims from UserInfo. */
export function createOidcUser(
  claims: { sub: string } & Record<string, unknown>,
  userinfo?: Record<string, unknown>,
): OidcUser {
  const fromToken = readStandardClaims(claims)
  const fromUserinfo = readStandardClaims(userinfo)
  const email = fromToken.email ?? fromUserinfo.email
  return {
    sub: claims.sub,
    email,
    // `email_verified` describes the email of the same response, so a response with another email cannot verify it.
    emailVerified:
      email === undefined
        ? undefined
        : (getEmailVerified(fromToken, email) ?? getEmailVerified(fromUserinfo, email)),
    name:
      fromToken.name ??
      fromToken.preferred_username ??
      fromUserinfo.name ??
      fromUserinfo.preferred_username,
    claims,
    userinfo,
  }
}

function getEmailVerified(claims: StandardClaims, email: string): boolean | undefined {
  return claims.email === email ? claims.email_verified : undefined
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined
}
