package jwtgen

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

type uncheckedAudience jwt.ClaimStrings

func (a uncheckedAudience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}

	return json.Marshal([]string(a))
}

type uncheckedClaims struct {
	Issuer         string            `json:"iss,omitempty"`
	Subject        string            `json:"sub,omitempty"`
	Audience       uncheckedAudience `json:"aud,omitempty"`
	ExpiresAt      *jwt.NumericDate  `json:"exp,omitempty"`
	NotBefore      *jwt.NumericDate  `json:"nbf,omitempty"`
	IssuedAt       *jwt.NumericDate  `json:"iat,omitempty"`
	ID             string            `json:"jti,omitempty"`
	TokenUse       string            `json:"token_use"`
	ClientID       string            `json:"client_id"`
	Txn            string            `json:"txn"`
	Scope          string            `json:"scope,omitempty"`
	SourceJTI      string            `json:"src_jti,omitempty"`
	OriginSub      string            `json:"origin_sub,omitempty"`
	TenantPublicID string            `json:"tenant_id,omitempty"`
	EventPublicID  string            `json:"event_id,omitempty"`
}

func (c uncheckedClaims) GetIssuer() (string, error)  { return c.Issuer, nil }
func (c uncheckedClaims) GetSubject() (string, error) { return c.Subject, nil }
func (c uncheckedClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings(c.Audience), nil
}
func (c uncheckedClaims) GetExpirationTime() (*jwt.NumericDate, error) { return c.ExpiresAt, nil }
func (c uncheckedClaims) GetNotBefore() (*jwt.NumericDate, error)      { return c.NotBefore, nil }
func (c uncheckedClaims) GetIssuedAt() (*jwt.NumericDate, error)       { return c.IssuedAt, nil }

func newUncheckedClaims(claims internaljwt.Claims) uncheckedClaims {
	return uncheckedClaims{
		Issuer:         claims.Issuer,
		Subject:        claims.Subject,
		Audience:       uncheckedAudience(claims.Audience),
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
	}
}
