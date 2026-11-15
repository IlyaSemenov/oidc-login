import { describe, expect, test } from "bun:test"

import type { OidcLoginOptions } from "oidc-login"
import { createOidcLogin, OidcLoginError } from "oidc-login"
import type { GetTestOidcUser } from "oidc-test-issuer"
import { createTestOidcIssuer, defaultTestOidcUser } from "oidc-test-issuer"

const origin = "https://app.example.com"
const redirectUri = `${origin}/auth/callback`

/** Rewrites a response of the issuer to imitate a misbehaving provider. */
type Intercept = (request: Request, response: Response) => Response | Promise<Response>

function createLogin({
  getUser,
  intercept = (_request, response) => response,
  ...options
}: Partial<OidcLoginOptions> & { getUser?: GetTestOidcUser; intercept?: Intercept } = {}) {
  const issuer = createTestOidcIssuer({ basePath: "/oidc", getUser })
  const login = createOidcLogin({
    issuerUrl: issuer.getIssuerUrl(origin),
    clientId: "client-1",
    clientSecret: "secret-1",
    fetch: async (url, init) => {
      // The issuer and the interceptor each read their own copy of the request body.
      return await intercept(new Request(url, init), await issuer.fetch(new Request(url, init)))
    },
    ...options,
  })
  return { issuer, login }
}

/** Rewrites the JSON body of the responses of an issuer endpoint. */
function rewriteJson(
  path: string,
  rewrite: (body: Record<string, unknown>) => Record<string, unknown>,
): Intercept {
  return async (request, response) =>
    new URL(request.url).pathname === `/oidc${path}`
      ? Response.json(rewrite((await response.json()) as Record<string, unknown>))
      : response
}

/** Starts a sign-in and follows the authorization URL to the callback URL. */
async function authorize({ issuer, login }: ReturnType<typeof createLogin>, loginHint?: string) {
  const { url, flow } = await login.start({ redirectUri, loginHint })
  const response = await issuer.fetch(new Request(url))
  return { flow, callbackUrl: new URL(response.headers.get("location")!) }
}

describe("sign-in", () => {
  test("returns the user of the ID token", async () => {
    const context = createLogin()
    const { flow, callbackUrl } = await authorize(context)

    const user = await context.login.finish(flow, callbackUrl)

    expect(user).toMatchObject({
      sub: defaultTestOidcUser.sub,
      email: defaultTestOidcUser.claims.email,
      emailVerified: true,
      name: defaultTestOidcUser.claims.name,
      claims: { iss: `${origin}/oidc`, aud: "client-1" },
      userinfo: undefined,
    })
  })

  test.each([
    ["URL", (url: URL) => url],
    ["URL string", (url: URL) => url.href],
    ["query string", (url: URL) => url.search],
    ["parameters", (url: URL) => url.searchParams],
  ] as const)("accepts the callback as %s", async (_form, toCallback) => {
    const context = createLogin()
    const { flow, callbackUrl } = await authorize(context, "7")

    const user = await context.login.finish(flow, toCallback(callbackUrl))

    expect(user.sub).toBe("test-oidc-user-000007")
  })

  test("returns to the redirect URI with the flow state", async () => {
    const { flow, callbackUrl } = await authorize(createLogin())

    expect(callbackUrl.origin + callbackUrl.pathname).toBe(redirectUri)
    expect(callbackUrl.searchParams.get("state")).toBe(flow.state)
  })

  test.each([
    `${redirectUri}?tenant=1`,
    `${redirectUri}?`,
    `${redirectUri}#`,
    new URL(`${redirectUri}?`),
  ])("rejects the redirect URI %s with a query or fragment", async uri => {
    const { login } = createLogin()

    await expect(login.start({ redirectUri: uri })).rejects.toBeInstanceOf(TypeError)
  })

  test.each(["state", "nonce", "codeVerifier"] as const)(
    "rejects a callback for a flow with another %s",
    async field => {
      const context = createLogin()
      const { flow, callbackUrl } = await authorize(context)

      const error = await context.login
        .finish({ ...flow, [field]: "other" }, callbackUrl)
        .catch((error: unknown) => error)

      expect(error).toBeInstanceOf(OidcLoginError)
      expect(error).toMatchObject({ code: "callback_failed" })
    },
  )

  test("rejects a token response without an ID token", async () => {
    const context = createLogin({
      intercept: rewriteJson("/token", body => ({ ...body, id_token: undefined })),
    })
    const { flow, callbackUrl } = await authorize(context)

    await expect(context.login.finish(flow, callbackUrl)).rejects.toMatchObject({
      code: "callback_failed",
    })
  })

  test("reports the error that the provider returned", async () => {
    const context = createLogin({ getUser: () => undefined })
    const { flow, callbackUrl } = await authorize(context)

    const error = await context.login.finish(flow, callbackUrl).catch((error: unknown) => error)

    expect(error).toMatchObject({ code: "authorization_failed", error: "access_denied" })
  })
})

describe("client authentication", () => {
  /** Finishes a sign-in and returns the credentials of its token request. */
  async function captureTokenRequest(options: Partial<OidcLoginOptions>) {
    const tokenRequests: Request[] = []
    const context = createLogin({
      ...options,
      intercept: (request, response) => {
        if (new URL(request.url).pathname === "/oidc/token") {
          tokenRequests.push(request)
        }
        return response
      },
    })
    const { flow, callbackUrl } = await authorize(context)
    await context.login.finish(flow, callbackUrl)

    const [request] = tokenRequests
    return {
      authorization: request!.headers.get("authorization"),
      body: new URLSearchParams(await request!.text()),
    }
  }

  test("sends the client secret in the Basic authorization header by default", async () => {
    const { authorization, body } = await captureTokenRequest({})

    // OAuth clients form-encode the credentials before Base64.
    const [scheme, encoded] = authorization!.split(" ")
    const credentials = atob(encoded!).split(":").map(decodeURIComponent)
    expect(scheme).toBe("Basic")
    expect(credentials).toEqual(["client-1", "secret-1"])
    expect(body.has("client_secret")).toBe(false)
  })

  test("sends the client secret in the body with client_secret_post", async () => {
    const { authorization, body } = await captureTokenRequest({
      clientAuthentication: "client_secret_post",
    })

    expect(authorization).toBeNull()
    expect(body.get("client_secret")).toBe("secret-1")
  })
})

describe("client check", () => {
  const challenge = { "www-authenticate": 'Basic realm="oidc"' }

  /** Answers token requests with an OAuth error instead of the issuer. */
  function rejectTokenRequest(
    status: number,
    body: object,
    headers?: Record<string, string>,
  ): Intercept {
    return (request, response) =>
      new URL(request.url).pathname === "/oidc/token"
        ? Response.json(body, { status, headers })
        : response
  }

  /** Rejects token requests whose client credentials differ from `client-1:secret-1`, as a provider that checks the secret does. */
  const authenticateClient: Intercept = async (request, response) => {
    if (new URL(request.url).pathname !== "/oidc/token") {
      return response
    }

    const body = new URLSearchParams(await request.text())
    const [, encoded] = request.headers.get("authorization")?.split(" ") ?? []
    // OAuth clients form-encode the credentials before Base64.
    const credentials = encoded
      ? atob(encoded).split(":").map(decodeURIComponent)
      : [body.get("client_id"), body.get("client_secret")]
    return credentials.join(":") === "client-1:secret-1"
      ? response
      : Response.json({ error: "invalid_client" }, { status: 401, headers: challenge })
  }

  test.each(["client_secret_basic", "client_secret_post"] as const)(
    "resolves when the provider accepts the client with %s",
    async clientAuthentication => {
      const { login } = createLogin({ clientAuthentication, intercept: authenticateClient })

      await login.checkClient({ redirectUri })
    },
  )

  test.each(["client_secret_basic", "client_secret_post"] as const)(
    "rejects a wrong client secret with %s",
    async clientAuthentication => {
      const { login } = createLogin({
        clientAuthentication,
        clientSecret: "wrong",
        intercept: authenticateClient,
      })

      await expect(login.checkClient({ redirectUri })).rejects.toMatchObject({
        code: "client_rejected",
        error: "invalid_client",
      })
    },
  )

  test.each([
    ["unauthorized_client in the body", 400, { error: "unauthorized_client" }, undefined],
    ["unauthorized_client with a challenge", 401, { error: "unauthorized_client" }, challenge],
  ])("rejects the client when the provider answers %s", async (_kind, status, body, headers) => {
    const { login } = createLogin({ intercept: rejectTokenRequest(status, body, headers) })

    await expect(login.checkClient({ redirectUri })).rejects.toMatchObject({
      code: "client_rejected",
      error: "unauthorized_client",
    })
  })

  test("rejects the client on a challenge without an error code", async () => {
    const { login } = createLogin({ intercept: rejectTokenRequest(401, {}, challenge) })

    const error = await login.checkClient({ redirectUri }).catch((error: unknown) => error)

    expect(error).toMatchObject({ code: "client_rejected" })
    expect((error as OidcLoginError).error).toBeUndefined()
  })

  test("keeps the body of a challenge response readable in the cause", async () => {
    const body = { error: "invalid_request", error_description: "Missing parameter." }
    const { login } = createLogin({ intercept: rejectTokenRequest(401, body, challenge) })

    const error = await login.checkClient({ redirectUri }).catch((error: unknown) => error)

    const { cause } = error as OidcLoginError
    expect(await (cause as { response: Response }).response.json()).toEqual(body)
  })

  test.each([
    ["in the body", 400, undefined],
    ["with a challenge", 401, challenge],
  ])("reports an inconclusive answer %s", async (_kind, status, headers) => {
    const { login } = createLogin({
      intercept: rejectTokenRequest(status, { error: "invalid_request" }, headers),
    })

    await expect(login.checkClient({ redirectUri })).rejects.toMatchObject({
      code: "client_check_failed",
      error: "invalid_request",
    })
  })
})

describe("UserInfo", () => {
  const getUser: GetTestOidcUser = () => ({
    sub: "user-1",
    claims: { preferred_username: "user1" },
    userinfoClaims: { email: "user-1@example.com", email_verified: false },
  })

  test("fills claims that the ID token lacks", async () => {
    const context = createLogin({ getUser })
    const { flow, callbackUrl } = await authorize(context)

    const user = await context.login.finish(flow, callbackUrl)

    expect(user).toMatchObject({
      sub: "user-1",
      email: "user-1@example.com",
      emailVerified: false,
      name: "user1",
      userinfo: { sub: "user-1", email: "user-1@example.com" },
    })
  })

  test("is not requested in the never mode", async () => {
    const context = createLogin({ getUser, userinfo: "never" })
    const { flow, callbackUrl } = await authorize(context)

    const user = await context.login.finish(flow, callbackUrl)

    expect(user.email).toBeUndefined()
    expect(user.userinfo).toBeUndefined()
  })

  test("is requested in the always mode when the ID token is complete", async () => {
    const context = createLogin({ userinfo: "always" })
    const { flow, callbackUrl } = await authorize(context)

    const user = await context.login.finish(flow, callbackUrl)

    expect(user.userinfo).toMatchObject({ sub: defaultTestOidcUser.sub })
  })

  test("does not verify an email with the verification of another email", async () => {
    const context = createLogin({
      getUser: () => ({
        sub: "user-1",
        claims: { email: "old@example.com" },
        userinfoClaims: { email: "new@example.com", email_verified: true },
      }),
    })
    const { flow, callbackUrl } = await authorize(context)

    const user = await context.login.finish(flow, callbackUrl)

    expect(user).toMatchObject({ email: "old@example.com", emailVerified: undefined })
  })

  test("rejects a response for another subject", async () => {
    const context = createLogin({
      getUser,
      intercept: rewriteJson("/userinfo", body => ({ ...body, sub: "user-2" })),
    })
    const { flow, callbackUrl } = await authorize(context)

    await expect(context.login.finish(flow, callbackUrl)).rejects.toMatchObject({
      code: "userinfo_failed",
    })
  })
})

describe("discovery", () => {
  test("accepts a plain HTTP issuer on a loopback host", async () => {
    const issuer = createTestOidcIssuer({ basePath: "/oidc" })
    const login = createOidcLogin({
      issuerUrl: issuer.getIssuerUrl("http://app.localhost:3000"),
      clientId: "client-1",
      fetch: (url, init) => issuer.fetch(new Request(url, init)),
    })

    await login.discover()
  })

  test("fetches the issuer metadata again after a failure", async () => {
    const issuer = createTestOidcIssuer({ basePath: "/oidc" })
    let available = false
    const login = createOidcLogin({
      issuerUrl: issuer.getIssuerUrl(origin),
      clientId: "client-1",
      fetch: async (url, init) =>
        available ? issuer.fetch(new Request(url, init)) : new Response(null, { status: 503 }),
    })

    await expect(login.discover()).rejects.toMatchObject({ code: "discovery_failed" })
    available = true
    await login.discover()
  })

  test.each([
    ["missing", undefined],
    ["numeric", 42],
    ["relative", "/authorize"],
    ["plain HTTP", "http://app.example.com/oidc/authorize"],
  ])("rejects metadata with a %s authorization endpoint", async (_kind, endpoint) => {
    const { login } = createLogin({
      intercept: rewriteJson("/.well-known/openid-configuration", body => ({
        ...body,
        authorization_endpoint: endpoint,
      })),
    })

    await expect(login.start({ redirectUri })).rejects.toMatchObject({ code: "discovery_failed" })
  })

  describe("of a loopback issuer", () => {
    /** Creates a login through a plain HTTP issuer on a loopback host whose metadata `rewrite` changes. */
    function createLoopbackLogin(
      rewrite: (body: Record<string, unknown>) => Record<string, unknown>,
    ) {
      const issuer = createTestOidcIssuer({ basePath: "/oidc" })
      const intercept = rewriteJson("/.well-known/openid-configuration", rewrite)
      return createOidcLogin({
        issuerUrl: issuer.getIssuerUrl("http://app.localhost:3000"),
        clientId: "client-1",
        fetch: async (url, init) =>
          await intercept(new Request(url, init), await issuer.fetch(new Request(url, init))),
      })
    }

    test.each(["authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"])(
      "rejects a plain HTTP %s on a non-loopback host",
      async endpoint => {
        const login = createLoopbackLogin(body => ({
          ...body,
          [endpoint]: "http://idp.example.com/oidc/endpoint",
        }))

        await expect(login.discover()).rejects.toMatchObject({ code: "discovery_failed" })
      },
    )

    test.each([
      ["an HTTPS endpoint on another host", "https://idp.example.com/oidc/token"],
      ["a plain HTTP endpoint on another loopback host", "http://127.0.0.1:3001/oidc/token"],
    ])("accepts %s", async (_kind, tokenEndpoint) => {
      const login = createLoopbackLogin(body => ({ ...body, token_endpoint: tokenEndpoint }))

      await login.discover()
    })

    test("accepts metadata without UserInfo and JWKS endpoints", async () => {
      const login = createLoopbackLogin(body => ({
        ...body,
        userinfo_endpoint: undefined,
        jwks_uri: undefined,
      }))

      await login.discover()
    })
  })

  test("rejects a plain HTTP issuer on another host", async () => {
    const issuer = createTestOidcIssuer({ basePath: "/oidc" })
    const login = createOidcLogin({
      issuerUrl: issuer.getIssuerUrl("http://app.example.com"),
      clientId: "client-1",
      fetch: (url, init) => issuer.fetch(new Request(url, init)),
    })

    await expect(login.discover()).rejects.toMatchObject({ code: "discovery_failed" })
  })
})
