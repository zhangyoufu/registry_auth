package registry_auth

import "encoding/json"

// https://distribution.github.io/distribution/spec/auth/jwt/

type jwtHeader struct {
	// Must be equal to JWT as recommended by Section 5.1 RFC7519
	Type string `json:"typ"`

	// Identifies the signing algorithm used to produce the signature.
	Algorithm string `json:"alg"`

	// Represents the ID of the key which was used to sign the token.
	KeyID string `json:"kid,omitempty"`

	// Represents the public key used to sign the token, compliant with RFC7517
	JWK *json.RawMessage `json:"jwk,omitempty"`

	// X.509 Certificate Chain
	// Represents the chain of certificates used to sign the token.
	X5C []string `json:"x5c,omitempty"`
}

type jwtClaims struct {
	// standard registered claims

	// The issuer of the token, typically the fqdn of the authorization server.
	Issuer string `json:"iss"`

	// The subject of the token; the name or id of the client which requested it.
	// This should be empty (`""`) if the client did not authenticate.
	Subject string `json:"sub"`

	// The intended audience of the token; the name or id of the service which
	// will verify the token to authorize the client/subject.
	Audience string `json:"aud"`

	// The token should only be considered valid up to this specified date and time.
	Expiration int64 `json:"exp"`

	// The token should not be considered valid before this specified date and time.
	NotBefore int64 `json:"nbf"`

	// Specifies the date and time which the Authorization server generated this token.
	IssuedAt int64 `json:"iat"`

	// A unique identifier for this token.
	// Can be used by the intended audience to prevent replays of the token.
	JWTID string `json:"jti,omitempty"`

	// private claim unique to this authorization server specification

	// An array of authorized resource scopes.
	Access Scope `json:"access"`
}
