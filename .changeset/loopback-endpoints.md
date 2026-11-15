---
"oidc-login": patch
---

Reject the metadata of a plain HTTP issuer on a loopback host that names a plain HTTP endpoint on a non-loopback host.
Discovery also rejects a UserInfo endpoint or JWKS URI that is not a valid URL with an allowed protocol.
