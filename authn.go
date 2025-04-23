package registry_auth

// Authenticator should be implemented to perform authentication.
// An implementation should return a non-nil error when authentication is not successful, otherwise
// a nil error should be returned
type Authenticator interface {
	Authenticate(service, username, password string) error
}
