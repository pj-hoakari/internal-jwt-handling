package issuer

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

// Claim set errors: the wire form and the checks every context token passes.
// The binding claims a token_use requires and forbids are checked by
// internaljwt.ValidateBinding. A binding check that ran on the context token
// rather than on the input's own fields is wrapped as "context token: ...".
var (
	ErrAudienceCount = errors.New("an internal JWT names exactly one audience")

	ErrContextMissingExpiry    = errors.New("context token exp is required")
	ErrContextExpired          = errors.New("context token has expired")
	ErrContextAudienceMismatch = errors.New("context token audience does not name the calling service")
)

// signedClaims is the wire form of the claim set.
type signedClaims struct {
	Issuer         string           `json:"iss,omitempty"`
	Subject        string           `json:"sub,omitempty"`
	Audience       string           `json:"aud"`
	ExpiresAt      *jwt.NumericDate `json:"exp,omitempty"`
	NotBefore      *jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt       *jwt.NumericDate `json:"iat,omitempty"`
	ID             string           `json:"jti,omitempty"`
	TokenUse       string           `json:"token_use"`
	ClientID       string           `json:"client_id"`
	Txn            string           `json:"txn"`
	Scope          string           `json:"scope,omitempty"`
	SourceJTI      string           `json:"src_jti,omitempty"`
	OriginSub      string           `json:"origin_sub,omitempty"`
	TenantPublicID string           `json:"tenant_id,omitempty"`
	EventPublicID  string           `json:"event_id,omitempty"`
}

func (c signedClaims) GetIssuer() (string, error)  { return c.Issuer, nil }
func (c signedClaims) GetSubject() (string, error) { return c.Subject, nil }
func (c signedClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings{c.Audience}, nil
}
func (c signedClaims) GetExpirationTime() (*jwt.NumericDate, error) { return c.ExpiresAt, nil }
func (c signedClaims) GetNotBefore() (*jwt.NumericDate, error)      { return c.NotBefore, nil }
func (c signedClaims) GetIssuedAt() (*jwt.NumericDate, error)       { return c.IssuedAt, nil }

// newSignedClaims puts the claim set into its wire form.
func newSignedClaims(claims internaljwt.Claims) (signedClaims, error) {
	if len(claims.Audience) != 1 {
		return signedClaims{}, fmt.Errorf("%w, got %d", ErrAudienceCount, len(claims.Audience))
	}

	return signedClaims{
		Issuer:         claims.Issuer,
		Subject:        claims.Subject,
		Audience:       claims.Audience[0],
		ExpiresAt:      claims.ExpiresAt,
		NotBefore:      claims.NotBefore,
		IssuedAt:       claims.IssuedAt,
		ID:             claims.ID,
		TokenUse:       claims.TokenUse,
		ClientID:       claims.ClientID,
		Txn:            claims.Txn,
		Scope:          claims.Scope,
		SourceJTI:      claims.SourceJTI,
		OriginSub:      claims.OriginSub,
		TenantPublicID: claims.TenantPublicID,
		EventPublicID:  claims.EventPublicID,
	}, nil
}

// validateContextToken checks what every context token must satisfy before
// it is re-issued: it is still valid, and it was addressed to the service now calling.
func validateContextToken(context internaljwt.Claims, callerService string, now time.Time) error {
	if context.ExpiresAt == nil {
		return ErrContextMissingExpiry
	}

	if !context.ExpiresAt.After(now) {
		return ErrContextExpired
	}

	if !slices.Contains(context.Audience, callerService) {
		return fmt.Errorf("%w: audience %v, caller %q", ErrContextAudienceMismatch, context.Audience, callerService)
	}

	return nil
}
