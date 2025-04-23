package registry_auth

import (
	"context"
	"crypto"
	_ "crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

type HandlerConfig struct {
	// Authenticator authenticate access requests. Currently only username/password is supported.
	Authenticator Authenticator

	// Authorizer authorize access requests with fine-grained scope.
	Authorizer Authorizer

	// Services stores a allowlist for service. Every incoming request carries a service field, which is also stored in JWT `aud` (Audience) claim later on. Empty service is never allowed. Leave this field nil means allow any service.
	Services map[string]struct{}

	// TokenSigner sign tokens. Expected to be one of *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey.
	TokenSigner crypto.Signer

	// TokenKeyID provieds JWT `kid` (KeyID) claim. Empty means generate JWK fingerprint from TokenSigner as TokenKeyID.
	TokenKeyID string

	// TokenIssuer should match what is configured in distribution auth.token.issuer.
	TokenIssuer string

	// TokenExpire determine the valid duration for every new signed JWT.
	TokenExpire time.Duration
}

type Handler struct {
	cfg HandlerConfig
}

func NewHandler(cfg HandlerConfig) (*Handler, error) {
	if cfg.Authenticator == nil {
		return nil, errors.New("Authenticator is required")
	}
	if cfg.Authorizer == nil {
		return nil, errors.New("Authorizer is required")
	}
	if cfg.TokenSigner == nil {
		return nil, errors.New("TokenSigner is required")
	}
	if cfg.TokenKeyID == "" {
		// https://github.com/distribution/distribution/pull/4471/files#diff-5c6c1d35b25cbb712df0aad3a56ecd791177fdb15bba77a468e6b0d317614811R50-R55
		keyID, err := getJWKThumbprint(cfg.TokenSigner.Public(), crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("failed to generate TokenKeyID: %w", err)
		}
		cfg.TokenKeyID = keyID
	}
	if cfg.TokenIssuer == "" {
		return nil, errors.New("TokenIssuer is required")
	}
	if cfg.TokenExpire == 0 {
		cfg.TokenExpire = 5 * time.Minute
	}
	if cfg.TokenExpire < 60*time.Second {
		return nil, errors.New("TokenExpire is too short")
	}
	return &Handler{cfg: cfg}, nil
}

func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	service := r.Form.Get("service")
	if service == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if h.cfg.Services != nil {
		if _, ok := h.cfg.Services[service]; !ok {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
	}
	username := ""
	if r.Header.Get("Authorization") != "" {
		_username, password, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := h.cfg.Authenticator.Authenticate(service, _username, password); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		username = _username
	}
	scope := Scope{}
	for _, item := range r.Form["scope"] {
		scope = append(scope, parseScope(item)...)
	}
	if username == "" && len(scope) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token, _, err := h.authorize(r.Context(), r.RemoteAddr, service, username, scope)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"token":"` + token + `"}`))
}

type oauth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	Scope        Scope  `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
	IssuedAt     string `json:"issued_at,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (h *Handler) HandleOAuth2Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	service := r.PostForm.Get("service")
	if service == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if h.cfg.Services != nil {
		if _, ok := h.cfg.Services[service]; !ok {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
	}
	if r.PostForm.Get("grant_type") != "password" {
		// "password" is supported by this implementation.
		// "refresh_token" is not supported by this implementation.
		// "authorization_code" is reserved for future use.
		http.Error(w, "unprocessable entity", http.StatusUnprocessableEntity)
		return
	}
	accessType := r.PostForm.Get("access_type")
	if accessType != "" && accessType != "online" {
		http.Error(w, "unprocessable entity", http.StatusUnprocessableEntity)
		return
	}
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	if err := h.cfg.Authenticator.Authenticate(service, username, password); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	scope := parseScope(r.PostForm.Get("scope"))
	token, access, err := h.authorize(r.Context(), r.RemoteAddr, service, username, scope)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	body, err := json.Marshal(oauth2TokenResponse{
		AccessToken: token,
		Scope:       access,
		ExpiresIn:   h.cfg.TokenExpire.Milliseconds() / 1000,
	})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func (h *Handler) authorize(ctx context.Context, remoteAddr, service, username string, scope Scope) (string, Scope, error) {
	// assume non-empty service check by caller

	// parse source IP
	addr, err := netip.ParseAddr(remoteAddr)
	if err != nil {
		if addr_port, err := netip.ParseAddrPort(remoteAddr); err == nil {
			addr = addr_port.Addr()
		}
	}
	if addr.IsLinkLocalUnicast() {
		// Link-local addresses are not guaranteed unique across interfaces.
		// Some access control engine does not support interface name / IPv6
		// address scope zone. To prevent potential misinterpretation or
		// incorrect policy matching, source IP addresses falling within
		// link-local unicast ranges are ignored and stored as an empty
		// string in the IP field.
		addr = netip.Addr{}
	}
	ip := ""
	if addr.IsValid() {
		ip = addr.WithZone("").String()
	}

	// authorize
	access, err := h.cfg.Authorizer.Authorize(&AuthorizationRequest{
		Context:  ctx,
		IP:       ip,
		Service:  service,
		Username: username,
		Scope:    scope,
	})
	if err != nil {
		return "", nil, err
	}

	// generate token
	alg, hash, err := getAlgHash(h.cfg.TokenSigner, 0)
	if err != nil {
		return "", nil, err
	}
	header, err := json.Marshal(jwtHeader{
		Type:      "JWT",
		Algorithm: alg,
		KeyID:     h.cfg.TokenKeyID,
	})
	if err != nil {
		return "", nil, err
	}
	now := time.Now()
	claim, err := json.Marshal(jwtClaims{
		Issuer:     h.cfg.TokenIssuer,
		Subject:    username,
		Audience:   service,
		Expiration: now.Add(h.cfg.TokenExpire).Unix(),
		NotBefore:  now.Add(-10 * time.Second).Unix(), // -10s for time error
		IssuedAt:   now.Unix(),
		Access:     access,
	})
	if err != nil {
		return "", nil, err
	}
	payload := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claim)
	sig, err := sign([]byte(payload), h.cfg.TokenSigner, hash)
	if err != nil {
		return "", nil, err
	}
	token := payload + "." + base64.RawURLEncoding.EncodeToString(sig)

	return token, access, nil
}
