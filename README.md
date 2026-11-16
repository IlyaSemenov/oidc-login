# oidc-login

"Sign in with SSO" for web applications through any OpenID Connect provider, such as Keycloak, Microsoft Entra ID, Google, or Yandex.
It wraps [openid-client](https://github.com/panva/openid-client) into 2 calls: start the sign-in and finish it on the callback.

## Install

```sh
npm install oidc-login
```

## Usage

Configure the login handler with your provider settings:

```ts
import { createOidcLogin } from "oidc-login"

const login = createOidcLogin({
  issuerUrl: "https://keycloak.example.com/realms/company",
  clientId: "tracker",
  clientSecret: process.env.OIDC_CLIENT_SECRET,
})
```

When the user clicks the sign-in button, start the sign-in, store the flow in the user's session, and redirect the browser to the provider:

```ts
const { url, flow } = await login.start({ redirectUri: "https://app.example.com/auth/callback" })
session.oidcFlow = flow
return redirect(url)
```

The redirect URI must have no query or fragment.
Store the flow where only the user's browser session can read it, such as in a signed and encrypted cookie: it holds the PKCE verifier.
It is a plain JSON object.

When the provider redirects the browser back to the redirect URI, finish the sign-in with the flow and the callback URL:

```ts
const user = await login.finish(session.oidcFlow, request.url)
delete session.oidcFlow
```

`finish` also accepts the query string of the callback or its parameters, such as `location.search` that a client-side callback page sends to the server.
It returns the user:

```ts
user.sub // "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
user.email // "jane@example.com"
user.emailVerified // true, false, or undefined when the provider does not say
user.name // "Jane Doe"
user.claims // ID token claims
user.userinfo // UserInfo response, if requested
```

Identify the user by `sub` within the issuer: the provider may change the email.
Before you link the sign-in to an existing account by email, check `emailVerified`, or trust the provider to verify emails.

Reuse the instance for the same provider settings: it fetches the issuer metadata once, on first use.

## Cache the issuer metadata

To avoid fetching the issuer metadata in every process or on every sign-in, cache what `discover` returns and pass it as `metadata`:

```ts
const metadata = await createOidcLogin({ issuerUrl, clientId }).discover()
await cache.set(issuerUrl, metadata)

const login = createOidcLogin({
  issuerUrl,
  clientId,
  clientSecret,
  metadata: await cache.get(issuerUrl),
})
```

The metadata is a plain JSON object.
Keep it per issuer URL and refresh it from time to time: the provider may change its endpoints.

## Handle errors

`start` and `finish` reject with `OidcLoginError`, whose `code` names the failed stage:

- `discovery_failed`: the issuer URL is wrong or the provider is unavailable.
- `authorization_failed`: the provider redirected back with an error in `error`, such as `access_denied` when the user cancels.
- `callback_failed`: the callback does not belong to the flow, or the provider rejected the code.
- `userinfo_failed`: the UserInfo request failed.

The original error is in `cause`.
Invalid arguments, such as a redirect URI with a query, reject with `TypeError`.

## Check the provider settings

Call `discover` to check that the issuer URL points to a working provider, such as when an administrator saves the settings:

```ts
await createOidcLogin({ issuerUrl, clientId }).discover()
```

The issuer URL must use HTTPS; plain HTTP works only on loopback hosts, such as `localhost`, for local development.
Validate a URL that users enter with `isSecureIssuerUrl`.

Call `checkClient` with your redirect URI to check the client ID and secret as well, without signing anyone in:

```ts
await createOidcLogin({ issuerUrl, clientId, clientSecret }).checkClient({ redirectUri })
```

It exchanges a made-up code and expects the provider to reject only the code.
When the provider rejects the client, it rejects with `OidcLoginError` with the `client_rejected` code; when the response of the provider is inconclusive, with `client_check_failed`.
The OAuth error of the provider, if any, is in `error`.

The provider sees each check as a failed code exchange: it may log it as an error and count it against its rate limits.
Call `checkClient` when an administrator checks the settings, not as a periodic health check.

## Options

- `scope`: scopes to request besides `openid`, `email`, and `profile`.
- `userinfo`: when to request the UserInfo endpoint.
  `auto`, the default, requests it when the ID token has no `email` or `email_verified`; `email` requests it only when the ID token has no `email`, for an application that does not use `emailVerified`; `always` requests it on every sign-in; `never` uses only the ID token.
- `clientSecret`: omit it for a public client.
- `clientAuthentication`: how to send the client secret to the token endpoint.
  `client_secret_basic`, the default, sends it in the `Authorization` header; `client_secret_post` sends it in the request body, for providers that accept only that.
- `fetch`: sends the HTTP requests to the provider instead of the global `fetch`.

## Test the sign-in

Pass the handler of [oidc-test-issuer](https://github.com/IlyaSemenov/oidc-test-issuer) as `fetch` to run the whole sign-in in a unit test, without a server:

```ts
import { createTestOidcIssuer } from "oidc-test-issuer"

const issuer = createTestOidcIssuer({ basePath: "/oidc" })
const login = createOidcLogin({
  issuerUrl: issuer.getIssuerUrl("https://app.example.com"),
  clientId: "client-1",
  fetch: issuer.fetch,
})

const { url, flow } = await login.start({ redirectUri: "https://app.example.com/auth/callback" })
const user = await login.finish(flow, await issuer.authorize(url))
```

`issuer.authorize` opens the authorization URL instead of a browser and returns the callback URL.
