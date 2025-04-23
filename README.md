# registry_auth

a heavily modified fork of https://github.com/adxgun/registry-auth/

- removed all non-std dependencies
- X.509 certificate is not needed anymore
- provide `LoadPrivateKey` for loading private key file in PEM format
- auto-generate JWK fingerprint when `TokenKeyID` is not provided
- provide `Handler` instead of `AuthServer` which listen and serve TLS
  - `(*Handler).HandleToken` for docker-style `GET /token` with optional HTTP Basic auth
  - `(*Handler).HandleOAuth2Token` for OAuth2-style `POST /token` with `grant_type=password`
- `HandlerConfig` could configure `service` allowlist
- `Authenticator.Authenticate` now has `service` parameter
- `Authorizer.Authorize` now has to deal with multiple resource scopes
- `AuthorizationRequest` now has `Context` field, which is the HTTP request context
- `AuthorizationRequest` now has `IP` field, which parsed from the HTTP request RemoteAddr field and excluded link-local unicast address ranges
- `DefaultAuthenticator` & `DefaultAuthorizor` removed
- `TokenGenerator` interface removed
- `jti` (JWT ID) claim is optional, and we don't have any tracking mechanism, removed
- `server_test.go` removed, don't bother maintain it

reference server implementation available at https://github.com/zhangyoufu/registry_auth_server/

## References

- [Distribution Registry Token Authentication](https://distribution.github.io/distribution/spec/auth/)
- [RFC 7638 JSON Web Key (JWK) Thumbprint](https://datatracker.ietf.org/doc/html/rfc7638)
- [RFC 8032 Edwards-Curve Digital Signature Algorithm (EdDSA)](https://datatracker.ietf.org/doc/html/rfc8032)
