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

const (
	uncompressedP256Length = 65
	p256CoordinateLength   = 32
)

// Errors NewJWK and PublicKey return.
var (
	ErrMissingKeyID         = errors.New("key ID is required")
	ErrMissingKey           = errors.New("public key is required")
	ErrUnsupportedCurve     = errors.New("unsupported curve: internal JWT keys are P-256")
	ErrUnexpectedKeyLength  = errors.New("unexpected P-256 public key length")
	ErrEncodeKey            = errors.New("encode public key")
	ErrUnsupportedKeyType   = errors.New("unsupported key type: internal JWT keys are EC keys")
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm: internal JWTs are signed with ES256")
	ErrUnsupportedKeyUse    = errors.New("unsupported key use: internal JWT keys are signature keys")
	ErrDecodeCoordinate     = errors.New("decode JWK coordinate")
	ErrInvalidPublicKey     = errors.New("invalid P-256 public key")
)

// NewJWK describes an ES256 verification key as a JWK.
func NewJWK(keyID string, key *ecdsa.PublicKey) (JWK, error) {
	if keyID == "" {
		return JWK{}, ErrMissingKeyID
	}

	if key == nil {
		return JWK{}, ErrMissingKey
	}

	if key.Curve != elliptic.P256() {
		return JWK{}, fmt.Errorf("%w: got %q", ErrUnsupportedCurve, CurveName(key.Curve))
	}

	encoded, err := key.Bytes()
	if err != nil {
		return JWK{}, fmt.Errorf("%w: %w", ErrEncodeKey, err)
	}

	if len(encoded) != uncompressedP256Length {
		return JWK{}, fmt.Errorf("%w: got %d, want %d", ErrUnexpectedKeyLength, len(encoded), uncompressedP256Length)
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

// PublicKey is the verification key a JWK describes.
func PublicKey(key JWK) (*ecdsa.PublicKey, error) {
	if key.KeyID == "" {
		return nil, ErrMissingKeyID
	}

	if key.KeyType != KeyType {
		return nil, fmt.Errorf("%w: got %q", ErrUnsupportedKeyType, key.KeyType)
	}

	if key.Curve != Curve {
		return nil, fmt.Errorf("%w: got %q", ErrUnsupportedCurve, key.Curve)
	}

	if key.Algorithm != Algorithm {
		return nil, fmt.Errorf("%w: got %q", ErrUnsupportedAlgorithm, key.Algorithm)
	}

	if key.Use != KeyUse {
		return nil, fmt.Errorf("%w: got %q", ErrUnsupportedKeyUse, key.Use)
	}

	x, err := coordinate("x", key.X)
	if err != nil {
		return nil, err
	}

	y, err := coordinate("y", key.Y)
	if err != nil {
		return nil, err
	}

	encoded := make([]byte, 0, uncompressedP256Length)
	encoded = append(encoded, 4)
	encoded = append(encoded, x...)
	encoded = append(encoded, y...)

	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPublicKey, err)
	}

	return publicKey, nil
}

// coordinate decodes one base64url coordinate of a P-256 public key.
func coordinate(name, encoded string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w %q: %w", ErrDecodeCoordinate, name, err)
	}

	if len(decoded) != p256CoordinateLength {
		return nil, fmt.Errorf("%w: coordinate %q is %d bytes, want %d", ErrUnexpectedKeyLength, name, len(decoded), p256CoordinateLength)
	}

	return decoded, nil
}

// CurveName names an elliptic curve for an error message.
// A nil curve is possible on a key that was never initialized.
func CurveName(curve elliptic.Curve) string {
	if curve == nil {
		return ""
	}

	return curve.Params().Name
}
