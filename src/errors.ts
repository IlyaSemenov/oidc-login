/**
 * Stage of a login or of a check of the provider settings that failed.
 *
 * - `discovery_failed`: the issuer metadata could not be fetched or is invalid.
 * - `authorization_failed`: the provider redirected back with an error, such as `access_denied`.
 * - `callback_failed`: the callback does not match the flow, or the code exchange or ID token validation failed.
 * - `userinfo_failed`: the UserInfo request failed.
 * - `client_rejected`: `checkClient` found that the provider rejects the client: its ID or secret is wrong, or it may not use the authorization code flow.
 * - `client_check_failed`: `checkClient` could not tell whether the provider accepts the client.
 */
export type OidcLoginErrorCode =
  | "discovery_failed"
  | "authorization_failed"
  | "callback_failed"
  | "userinfo_failed"
  | "client_rejected"
  | "client_check_failed"

/** Failure of an OpenID Connect login or of a check of the provider settings; the original error is in `cause`. */
export class OidcLoginError extends Error {
  override name = "OidcLoginError"

  /** Stage that failed. */
  readonly code: OidcLoginErrorCode

  /** OAuth error code that the provider returned, such as `access_denied` with `authorization_failed` or `invalid_client` with `client_rejected`. */
  readonly error?: string

  constructor(
    code: OidcLoginErrorCode,
    options: { cause?: unknown; error?: string; message?: string } = {},
  ) {
    super(options.message ?? `OpenID Connect request failed: ${code}.`, { cause: options.cause })
    this.code = code
    this.error = options.error
  }
}
