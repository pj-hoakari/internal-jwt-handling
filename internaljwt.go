package internaljwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

const (
	TokenUseTenantAccess = "tenant_access"
	TokenUseEventAccess  = "event_access"
	TokenUseService      = "service"
	TokenUseRegistration = "registration"
)

const (
	Algorithm = "ES256"
	KeyType   = "EC"
	Curve     = "P-256"
	KeyUse    = "sig"
)

type Claims struct {
	jwt.RegisteredClaims
	TokenUse string `json:"token_use"`
	ClientID string `json:"client_id"`
	// Txn correlates every hop of one processing chain.
	Txn string `json:"txn"`
	// Scope is the scope of the external token, copied over unchanged.
	Scope string `json:"scope,omitempty"`
	// SourceJTI is carried in the src_jti claim and is the jti of the token
	// this one was converted from: the external token at an entrance
	// conversion, the context token at a service re-issue.
	SourceJTI string `json:"src_jti,omitempty"`
	// OriginSub is the user a user-origin service token was re-issued for. It
	// is for audit only and must not feed authorization decisions.
	OriginSub string `json:"origin_sub,omitempty"`
	// TenantPublicID is carried in the tenant_id JWT claim. Its value is the
	// tenant's 16-character hexadecimal public ID,
	TenantPublicID string `json:"tenant_id,omitempty"`
	// EventPublicID is carried in the event_id JWT claim and is the event's
	// 16-character hexadecimal public ID.
	EventPublicID string `json:"event_id,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is one P-256 public key of the JWKS.
type JWK struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

const uncompressedP256Length = 65

// NewJWK describes an ES256 verification key as a JWK.
func NewJWK(keyID string, key *ecdsa.PublicKey) (JWK, error) {
	if keyID == "" {
		return JWK{}, errors.New("key ID is required")
	}

	if key == nil {
		return JWK{}, errors.New("public key is required")
	}

	if key.Curve != elliptic.P256() {
		return JWK{}, fmt.Errorf("unsupported curve %q: internal JWT keys are P-256", CurveName(key.Curve))
	}

	encoded, err := key.Bytes()
	if err != nil {
		return JWK{}, fmt.Errorf("encode public key: %w", err)
	}

	if len(encoded) != uncompressedP256Length {
		return JWK{}, fmt.Errorf("unexpected P-256 public key length %d", len(encoded))
	}

	return JWK{
		KeyType:   KeyType,
		Curve:     Curve,
		KeyID:     keyID,
		Use:       KeyUse,
		Algorithm: Algorithm,
		X:         base64.RawURLEncoding.EncodeToString(encoded[1:33]),
		Y:         base64.RawURLEncoding.EncodeToString(encoded[33:]),
	}, nil
}

// CurveName names an elliptic curve for an error message.
// A nil curve is possible on a key that was never initialized.
func CurveName(curve elliptic.Curve) string {
	if curve == nil {
		return ""
	}

	return curve.Params().Name
}
