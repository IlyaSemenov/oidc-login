---
"oidc-login": minor
---

`discover` returns the issuer metadata, and the `metadata` option reuses it, such as from a cache shared by several processes, without fetching it again.
