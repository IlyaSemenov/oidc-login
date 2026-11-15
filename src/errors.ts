/**
 * Stage of the sign-in that failed.
 *
 * - `discovery_failed`: the issuer metadata could not be fetched or is invalid.
 * - `authorization_failed`: the provider redirected back with an error, such as `access_denied`.
 * - `callback_failed`: the callback does not match the flow, or the code exchange or ID token validation failed.
 * - `userinfo_failed`: the UserInfo request failed.
 */
export type OidcLoginErrorCode =
  | "discovery_failed"
  | "authorization_failed"
  | "callback_failed"
  | "userinfo_failed"

/** Failure of an OpenID Connect sign-in; the original error is in `cause`. */
export class OidcLoginError extends Error {
  override name = "OidcLoginError"

  /** Stage of the sign-in that failed. */
  readonly code: OidcLoginErrorCode

  /** OAuth error code that the provider returned with `authorization_failed`, such as `access_denied`. */
  readonly error?: string

  constructor(
    code: OidcLoginErrorCode,
    options: { cause?: unknown; error?: string; message?: string } = {},
  ) {
    super(options.message ?? `OpenID Connect sign-in failed: ${code}.`, { cause: options.cause })
    this.code = code
    this.error = options.error
  }
}
