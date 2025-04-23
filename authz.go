package registry_auth

import "context"

// Authorizer should be implemented to perform authorization.
// req.Actions should be checked against the user's authorized action on the repository,
// this function should return the list of authorized actions and a nil error. an empty list must be returned
// if requesting user is unauthorized
type Authorizer interface {
	Authorize(req *AuthorizationRequest) (Scope, error)
}

// AuthorizationRequest provides necessary data for access control.
type AuthorizationRequest struct {
	// Context provides the HTTP request context.
	Context context.Context

	// IP provides the source IP address from which the authorization request
	// originated. It holds one of the following formats:
	// - An IPv4 address in dotted-decimal notation (e.g., "192.0.2.1").
	// - An IPv6 address, excluding any scope zone identifier (e.g., "2001:db8::1").
	// - An empty string (""), indicating not available/applicable.
	//
	// Link-local unicast addresses (IPv4 169.254.0.0/16 and IPv6 fe80::/64)
	// require a scope zone (interface identifier, e.g., "%eth0") for proper
	// interpretation, as they are only unique within a specific network segment
	// (link). However, some access control engines may not be able to process
	// IP addresses with scope zones.[1] Consequently, to prevent potential
	// misinterpretation or incorrect policy matching, source IP addresses
	// falling within these link-local unicast CIDRs are ignored and stored
	// as an empty string in this field.
	//
	// [1]: https://github.com/ory/ladon/blob/1d16bb356d68220899c40d8b4a81120af55a6482/condition_cidr.go#L33-L51
	IP string

	// Service is usually the FQDN of the registry, aka. the RP (Resource
	// Provider). Corresponds to `aud` (Audience) claim in JWT. This field
	// is guaranteed to be non-empty.
	Service string

	// Authenticated username. Empty for anonymous requests. Corresponds to
	// `sub` (Subject) claim in JWT.
	Username string

	// An array of requested resource scopes. This field is guaranteed to be
	// non-empty for anonymous requests.
	Scope Scope
}
