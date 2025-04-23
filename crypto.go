package registry_auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// Attempt to parse the given private key file.
func LoadPrivateKey(path string) (crypto.Signer, error) {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	keyPEMBlock, _ := pem.Decode(keyPEM)
	// https://github.com/golang/go/blob/c889004615b40535ebd5054cbcf2deebdb3a299a/src/crypto/tls/tls.go#L308
	if keyPEMBlock.Type != "PRIVATE KEY" && !strings.HasSuffix(keyPEMBlock.Type, " PRIVATE KEY") {
		return nil, fmt.Errorf("unexpected PEM block in private key file: %s", keyPEMBlock.Type)
	}
	// https://github.com/golang/go/blob/c889004615b40535ebd5054cbcf2deebdb3a299a/src/crypto/tls/tls.go#L364-L384
	if key, err := x509.ParsePKCS1PrivateKey(keyPEMBlock.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(keyPEMBlock.Bytes); err == nil {
		switch _key := key.(type) {
		case *rsa.PrivateKey:
			return _key, nil
		case *ecdsa.PrivateKey:
			return _key, nil
		case ed25519.PrivateKey:
			return _key, nil
		default:
			return nil, fmt.Errorf("unsupported private key type: %T", key)
		}
	}
	if key, err := x509.ParseECPrivateKey(keyPEMBlock.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("failed to parse private key")
}

// RFC 7638 JSON Web Key (JWK) Thumbprint
func getJWKThumbprint(publicKey crypto.PublicKey, hash crypto.Hash) (string, error) {
	h := hash.New()
	switch _publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		_, _ = fmt.Fprintf(h, `{"e":"%s","kty":"RSA","n":"%s"}`,
			base64.RawURLEncoding.EncodeToString(big.NewInt(int64(_publicKey.E)).Bytes()),
			base64.RawURLEncoding.EncodeToString(_publicKey.N.Bytes()),
		)
	case *ecdsa.PublicKey:
		_, _ = fmt.Fprintf(h, `{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
			_publicKey.Params().Name,
			base64.RawURLEncoding.EncodeToString(_publicKey.X.Bytes()),
			base64.RawURLEncoding.EncodeToString(_publicKey.Y.Bytes()),
		)
	case ed25519.PublicKey:
		_, _ = fmt.Fprintf(h, `{"crv":"Ed25519","kty":"OTP","x":"%s"}`,
			base64.RawURLEncoding.EncodeToString(_publicKey),
		)
	default:
		return "", fmt.Errorf("unsupported key type: %T", publicKey)
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// determine hash and alg
func getAlgHash(privateKey crypto.Signer, hash crypto.Hash) (string, crypto.Hash, error) {
	var alg string
	switch _privateKey := privateKey.(type) {
	case *rsa.PrivateKey:
		if hash == 0 {
			hash = crypto.SHA256
		}
		switch hash {
		case crypto.SHA256:
			alg = "RS256"
		case crypto.SHA384:
			alg = "RS384"
		case crypto.SHA512:
			alg = "RS512"
		default:
			return "", 0, fmt.Errorf("unsupported hash algorithm for RSA JWK: %s", hash)
		}
	case *ecdsa.PrivateKey:
		switch _privateKey.Curve {
		case elliptic.P256():
			alg = "ES256"
			hash = crypto.SHA256
		case elliptic.P384():
			alg = "ES384"
			hash = crypto.SHA384
		case elliptic.P521():
			alg = "ES512"
			hash = crypto.SHA512
		default:
			return "", 0, fmt.Errorf("unsupported curve for ECDSA JWK: %s", _privateKey.Params().Name)
		}
	case ed25519.PrivateKey:
		alg = "EdDSA"
		hash = 0
	default:
		return "", 0, fmt.Errorf("unsupported key type: %T", privateKey)
	}
	return alg, hash, nil
}

func sign(data []byte, signer crypto.Signer, hash crypto.Hash) ([]byte, error) {
	switch privateKey := signer.(type) {
	case *rsa.PrivateKey:
		h := hash.New()
		_, _ = h.Write(data)
		return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, h.Sum(nil))
	case *ecdsa.PrivateKey:
		h := hash.New()
		_, _ = h.Write(data)
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
		if err != nil {
			return nil, err
		}
		l := (privateKey.Params().BitSize + 7) >> 3
		sig := make([]byte, l*2)
		r.FillBytes(sig[:l])
		s.FillBytes(sig[l:])
		return sig, nil
	case ed25519.PrivateKey:
		return privateKey.Sign(rand.Reader, data, crypto.Hash(0))
	default:
		return nil, fmt.Errorf("unsupported key type: %T", privateKey)
	}
}
