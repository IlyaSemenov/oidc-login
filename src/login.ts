import * as client from "openid-client"

import { OidcLoginError } from "./errors"
import { isLoopbackHostname } from "./issuer-url"
import type { OidcUser } from "./user"
import { createOidcUser, readStandardClaims } from "./user"

/** Fetch API-compatible function that sends the HTTP requests to the provider. */
export type OidcFetch = (url: string, init: RequestInit) => Promise<Response>

/**
 * When the sign-in requests the UserInfo endpoint.
 *
 * - `auto`: when the ID token has no `email` or no `email_verified`.
 * - `always`: on every sign-in.
 * - `never`: never; the user has only the ID token claims.
 */
export type OidcUserinfoMode = "auto" | "always" | "never"

/** How a client with a secret authenticates to the token endpoint. */
export type OidcClientAuthentication = "client_secret_basic" | "client_secret_post"

/** Issuer metadata that `discover` returns: a plain JSON object. */
export interface OidcIssuerMetadata {
  issuer: string
  [key: string]: unknown
}

/** Options of `createOidcLogin`. */
export interface OidcLoginOptions {
  /** Issuer URL: HTTPS, or plain HTTP on a loopback host. */
  issuerUrl: string | URL
  clientId: string
  /** Client secret; omit it for a public client. */
  clientSecret?: string
  /** How to send the client secret; `client_secret_basic` by default, as OAuth defines. */
  clientAuthentication?: OidcClientAuthentication
  /** Scopes to request besides `openid`, `email`, and `profile`. */
  scope?: readonly string[]
  /** When to request the UserInfo endpoint; `auto` by default. */
  userinfo?: OidcUserinfoMode
  /** Sends the HTTP requests to the provider instead of the global `fetch`, such as to a test issuer. */
  fetch?: OidcFetch
  /**
   * Issuer metadata that `discover` returned for the same issuer URL, to use instead of fetching it.
   *
   * If the supplied metadata fails discovery validation, such as when it belongs to another issuer URL, the instance fetches fresh metadata from the provider.
   */
  metadata?: OidcIssuerMetadata
}

/**
 * State of a started sign-in that `finish` needs.
 *
 * Store it between `start` and `finish` where only the user's browser session can read it, such as in a signed and encrypted cookie: it holds the PKCE verifier.
 * It is a plain JSON object.
 */
export interface OidcLoginFlow {
  redirectUri: string
  state: string
  nonce: string
  codeVerifier: string
}

/** Started sign-in. */
export interface OidcLoginStart {
  /** Authorization URL to redirect the browser to. */
  url: string
  flow: OidcLoginFlow
}

/** OpenID Connect sign-in through one provider. */
export interface OidcLogin {
  /** Starts a sign-in that returns to `redirectUri`, which must have no query or fragment. */
  start: (options: { redirectUri: string | URL; loginHint?: string }) => Promise<OidcLoginStart>
  /**
   * Finishes the sign-in with the query of the request to the redirect URI.
   *
   * Pass the full callback URL, its query string, or its parameters.
   */
  finish: (flow: OidcLoginFlow, callback: URL | URLSearchParams | string) => Promise<OidcUser>
  /**
   * Fetches the issuer metadata, unless the instance has it, and returns it.
   *
   * Pass the result as the `metadata` option to create an instance that does not fetch it again.
   */
  discover: () => Promise<OidcIssuerMetadata>
  /**
   * Checks that the provider accepts the client ID and secret, without a user.
   *
   * It exchanges a made-up authorization code for `redirectUri` and resolves when the provider rejects only the code.
   */
  checkClient: (options: { redirectUri: string | URL }) => Promise<void>
}

const defaultScope = ["openid", "email", "profile"]

/**
 * Creates an OpenID Connect login handler for one provider: the authorization code flow with PKCE, state, and nonce.
 *
 * The instance fetches the issuer metadata once, on first use, unless valid `metadata` is supplied; after a failed fetch, the next call fetches it again.
 * Methods reject with `OidcLoginError` when the sign-in fails, and with `TypeError` for invalid arguments.
 */
export function createOidcLogin({
  issuerUrl,
  clientId,
  clientSecret,
  clientAuthentication = "client_secret_basic",
  scope = [],
  userinfo = "auto",
  fetch,
  metadata,
}: OidcLoginOptions): OidcLogin {
  const issuer = new URL(issuerUrl)
  // openid-client rejects plain HTTP unless allowed explicitly; it is allowed only for local development.
  const insecure = issuer.protocol === "http:" && isLoopbackHostname(issuer.hostname)
  const settings: IssuerSettings = {
    issuer,
    insecure,
    clientId,
    clientSecret,
    clientAuthentication,
    fetch,
  }
  let configuration: Promise<client.Configuration> | undefined

  const getConfiguration = () => {
    configuration ??= (
      metadata
        ? // Metadata that fails the checks of discovery, such as of another issuer URL, is fetched again.
          discover(settings, metadata).catch(() => discover(settings))
        : discover(settings)
    ).catch((cause: unknown) => {
      configuration = undefined
      throw new OidcLoginError("discovery_failed", { cause })
    })
    return configuration
  }

  return {
    async start({ redirectUri, loginHint }) {
      const redirectUrl = parseRedirectUri(redirectUri)
      const config = await getConfiguration()
      const codeVerifier = client.randomPKCECodeVerifier()
      const flow: OidcLoginFlow = {
        redirectUri: redirectUrl.href,
        state: client.randomState(),
        nonce: client.randomNonce(),
        codeVerifier,
      }

      const url = client.buildAuthorizationUrl(config, {
        redirect_uri: flow.redirectUri,
        scope: [...new Set([...defaultScope, ...scope])].join(" "),
        state: flow.state,
        nonce: flow.nonce,
        code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
        code_challenge_method: "S256",
        ...(loginHint === undefined ? {} : { login_hint: loginHint }),
      })

      return { url: url.href, flow }
    },

    async finish(flow, callback) {
      const config = await getConfiguration()

      // openid-client takes `redirect_uri` of the token request from the callback URL, so the URL is rebuilt from the flow: behind a proxy, the application may see its own URL differently.
      const callbackUrl = new URL(flow.redirectUri)
      callbackUrl.search = new URLSearchParams(
        callback instanceof URL || (typeof callback === "string" && URL.canParse(callback))
          ? new URL(callback).search
          : callback,
      ).toString()

      const tokens = await client
        .authorizationCodeGrant(config, callbackUrl, {
          pkceCodeVerifier: flow.codeVerifier,
          expectedState: flow.state,
          expectedNonce: flow.nonce,
          idTokenExpected: true,
        })
        .catch((cause: unknown) => {
          throw cause instanceof client.AuthorizationResponseError
            ? new OidcLoginError("authorization_failed", { cause, error: cause.error })
            : new OidcLoginError("callback_failed", { cause })
        })

      // `idTokenExpected` makes openid-client reject a response without an ID token.
      const claims = tokens.claims()!
      const standardClaims = readStandardClaims(claims)
      const needsUserinfo =
        userinfo === "always" ||
        (userinfo === "auto" &&
          (!standardClaims.email || standardClaims.email_verified === undefined))
      if (!needsUserinfo) {
        return createOidcUser(claims)
      }

      const userinfoResponse = await client
        .fetchUserInfo(config, tokens.access_token, claims.sub)
        .catch((cause: unknown) => {
          throw new OidcLoginError("userinfo_failed", { cause })
        })
      return createOidcUser(claims, { ...userinfoResponse })
    },

    async discover() {
      const { supportsPKCE: _, ...metadata } = (await getConfiguration()).serverMetadata()
      return metadata
    },

    async checkClient({ redirectUri }) {
      const redirectUrl = parseRedirectUri(redirectUri)
      const config = await getConfiguration()

      // Providers authenticate the client before they look at the code, so the error tells whether the client is accepted.
      const failure = await client
        .genericGrantRequest(config, "authorization_code", {
          code: client.randomState(),
          redirect_uri: redirectUrl.href,
          code_verifier: client.randomPKCECodeVerifier(),
        })
        .then(
          () => undefined,
          (cause: unknown) => cause,
        )

      const error = await readOAuthError(failure)
      if (error === "invalid_grant") {
        return
      }

      const rejected =
        // `unauthorized_client` means that the client may not use the authorization code flow, so logins fail as well.
        error === "invalid_client" ||
        error === "unauthorized_client" ||
        // A provider answers a failed client authentication with 401 and a challenge, which may name no error.
        (error === undefined &&
          failure instanceof client.WWWAuthenticateChallengeError &&
          failure.status === 401)
      throw new OidcLoginError(rejected ? "client_rejected" : "client_check_failed", {
        cause: failure,
        error,
      })
    },
  }
}

/**
 * Parses the redirect URI of a sign-in.
 *
 * It must have no query or fragment: openid-client sends the redirect URI of the token request without its query, which would not match the authorization request.
 */
function parseRedirectUri(redirectUri: string | URL): URL {
  const redirectUrl = new URL(redirectUri)
  // `search` and `hash` are empty for a bare `?` or `#`, which openid-client drops as well.
  if (/[?#]/.test(redirectUrl.href)) {
    throw new TypeError("The redirect URI must have no query or fragment.")
  }
  return redirectUrl
}

/** Reads the OAuth error code of a failed token request from its JSON body or its `WWW-Authenticate` challenge. */
async function readOAuthError(failure: unknown): Promise<string | undefined> {
  if (failure instanceof client.ResponseBodyError) {
    return failure.error
  }
  if (failure instanceof client.WWWAuthenticateChallengeError) {
    // oauth4webapi throws on the challenge before it reads the body, which may hold the error code.
    // A copy is read to keep the body of `cause` for the caller, such as its `error_description`.
    const body: unknown = await failure.response
      .clone()
      .json()
      .catch(() => undefined)
    if (body && typeof body === "object" && "error" in body && typeof body.error === "string") {
      return body.error
    }
    return failure.cause.find(challenge => challenge.parameters.error)?.parameters.error
  }
}

/** Settings of the issuer and the client that the configuration of an instance needs. */
interface IssuerSettings {
  issuer: URL
  /** Whether plain HTTP is allowed: the issuer is a plain HTTP URL on a loopback host. */
  insecure: boolean
  clientId: string
  clientSecret?: string
  clientAuthentication: OidcClientAuthentication
  fetch?: OidcFetch
}

/**
 * Fetches the issuer metadata, or takes `metadata` that `discover` returned earlier, and creates the configuration from it.
 *
 * Cached metadata goes through openid-client discovery as its response, so that it gets the same checks and the provider-specific handling that openid-client keeps in its private state, such as for the issuer of Microsoft Entra ID.
 */
async function discover(
  { issuer, insecure, clientId, clientSecret, clientAuthentication, fetch }: IssuerSettings,
  metadata?: OidcIssuerMetadata,
): Promise<client.Configuration> {
  const config = await client.discovery(
    issuer,
    clientId,
    clientSecret,
    getClientAuth(clientSecret, clientAuthentication),
    {
      ...(metadata
        ? { [client.customFetch]: async () => Response.json(metadata) }
        : fetch
          ? { [client.customFetch]: fetch }
          : {}),
      ...(insecure ? { execute: [client.allowInsecureRequests] } : {}),
    },
  )
  if (metadata) {
    // The configuration keeps the fetch of discovery, which only returns `metadata`.
    config[client.customFetch] = fetch ?? ((url, options) => globalThis.fetch(url, options))
  }

  if (!hasValidEndpoints(config.serverMetadata(), insecure)) {
    throw new Error("The issuer metadata has an invalid endpoint.")
  }

  return config
}

/** Selects how openid-client authenticates the client: a client without a secret is public. */
function getClientAuth(
  clientSecret: string | undefined,
  clientAuthentication: OidcClientAuthentication,
): client.ClientAuth {
  return clientSecret === undefined
    ? client.None()
    : clientAuthentication === "client_secret_basic"
      ? client.ClientSecretBasic(clientSecret)
      : client.ClientSecretPost(clientSecret)
}

/**
 * Checks the endpoints of the issuer metadata.
 *
 * openid-client accepts metadata with missing or invalid endpoints, but then the sign-in fails later with a generic error.
 */
function hasValidEndpoints(metadata: Record<string, unknown>, insecure: boolean): boolean {
  const { authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri } = metadata
  return (
    [authorization_endpoint, token_endpoint].every(endpoint => isEndpointUrl(endpoint, insecure)) &&
    // These receive the access token or provide the keys of the ID token, so they need the same protection.
    [userinfo_endpoint, jwks_uri].every(
      endpoint => endpoint === undefined || isEndpointUrl(endpoint, insecure),
    )
  )
}

/**
 * Checks that an endpoint from the issuer metadata is an absolute URL with an allowed protocol.
 *
 * A plain HTTP issuer on a loopback host may name HTTPS endpoints or plain HTTP endpoints on loopback hosts, so that the client secret and tokens do not leave the machine unencrypted.
 */
function isEndpointUrl(value: unknown, insecure: boolean): boolean {
  if (typeof value !== "string" || !URL.canParse(value)) {
    return false
  }

  const { protocol, hostname } = new URL(value)
  return protocol === "https:" || (insecure && protocol === "http:" && isLoopbackHostname(hostname))
}
