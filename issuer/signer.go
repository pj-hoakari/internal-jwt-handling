package issuer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

// Key and signing errors signer returns.
var (
	ErrKeyProvider         = errors.New("load signing keys")
	ErrMissingSigningKeyID = errors.New("signing key ID is required")
	ErrMissingSigningKey   = errors.New("signing key is required")
	ErrDuplicateKeyID      = errors.New("duplicate key ID")
	ErrDescribeKey         = errors.New("describe key as JWK")
	ErrGenerateID          = errors.New("generate identifier")
	ErrSign                = errors.New("sign internal JWT")
)

// signer signs claim sets with ES256 under the key a KeyProvider supplies and
// publishes the verification keys as a JWKS. It knows nothing of what the
// claims mean.
type signer struct {
	issuerID string
	keys     KeyProvider
}

// registeredClaims builds the standard claims of a token this signer issues,
// with a fresh UUIDv7 as jti.
func (s *signer) registeredClaims(audience, subject string, now, expiresAt time.Time) (jwt.RegisteredClaims, error) {
	jti, err := uuid.NewV7()
	if err != nil {
		return jwt.RegisteredClaims{}, fmt.Errorf("%w jti: %w", ErrGenerateID, err)
	}

	return jwt.RegisteredClaims{
		Issuer:    s.issuerID,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        jti.String(),
	}, nil
}

// sign signs the claims with the key currently in force and names that key in the kid header.
func (s *signer) sign(ctx context.Context, claims jwt.Claims) (string, error) {
	keys, err := s.keys.Current(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrKeyProvider, err)
	}

	if keys.Signing.KeyID == "" {
		return "", ErrMissingSigningKeyID
	}

	if keys.Signing.Key == nil {
		return "", ErrMissingSigningKey
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keys.Signing.KeyID

	signed, err := token.SignedString(keys.Signing.Key)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSign, err)
	}

	return signed, nil
}

// jwks describes the signing key and the published keys as a JWKS.
func (s *signer) jwks(ctx context.Context) (internaljwt.JWKS, error) {
	keys, err := s.keys.Current(ctx)
	if err != nil {
		return internaljwt.JWKS{}, fmt.Errorf("%w: %w", ErrKeyProvider, err)
	}

	if keys.Signing.Key == nil {
		return internaljwt.JWKS{}, ErrMissingSigningKey
	}

	jwks := internaljwt.JWKS{Keys: make([]internaljwt.JWK, 0, len(keys.Published)+1)}
	seen := make(map[string]struct{}, len(keys.Published)+1)

	signing, err := internaljwt.NewJWK(keys.Signing.KeyID, &keys.Signing.Key.PublicKey)
	if err != nil {
		return internaljwt.JWKS{}, fmt.Errorf("%w: signing key %q: %w", ErrDescribeKey, keys.Signing.KeyID, err)
	}

	jwks.Keys = append(jwks.Keys, signing)
	seen[signing.KeyID] = struct{}{}

	for _, published := range keys.Published {
		// A kid must name one key.
		// A duplicate would leave a verifier picking between two keys for the same identifier
		if _, duplicate := seen[published.KeyID]; duplicate {
			return internaljwt.JWKS{}, fmt.Errorf("%w in JWKS: %q", ErrDuplicateKeyID, published.KeyID)
		}

		key, err := internaljwt.NewJWK(published.KeyID, published.Key)
		if err != nil {
			return internaljwt.JWKS{}, fmt.Errorf("%w: published key %q: %w", ErrDescribeKey, published.KeyID, err)
		}

		jwks.Keys = append(jwks.Keys, key)
		seen[published.KeyID] = struct{}{}
	}

	return jwks, nil
}
