# oidc-login

## 1.3.0

### Minor Changes

- 7492cea: Add the `email` mode of the `userinfo` option, which requests UserInfo only when the ID token has no email, for applications that do not use `emailVerified`.

## 1.2.0

### Minor Changes

- 35bb2e5: `discover` returns the issuer metadata, and the `metadata` option reuses it, such as from a cache shared by several processes, without fetching it again.

## 1.1.1

### Patch Changes

- 2d25663: Reject the metadata of a plain HTTP issuer on a loopback host that names a plain HTTP endpoint on a non-loopback host.
  Discovery also rejects a UserInfo endpoint or JWKS URI that is not a valid URL with an allowed protocol.

## 1.1.0

### Minor Changes

- 330a705: Add `checkClient` to check that the provider accepts the client ID and secret, without signing anyone in.

## 1.0.0

### Major Changes

- de0d3e8: Initial release.
