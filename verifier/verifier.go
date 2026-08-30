// Package verifier verifies internal JWTs against the Service Gateway's keys.
package verifier

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

// DefaultLeeway is the clock skew tolerated on exp, nbf, and iat.
const DefaultLeeway = 30 * time.Second

// tokenTypeJWT is the typ header every internal JWT carries.
const tokenTypeJWT = "JWT"

var (
	ErrMissingIssuerID    = errors.New("issuer ID is required")
	ErrMissingAudience    = errors.New("audience is required")
	ErrMissingKeyResolver = errors.New("key resolver is required")
	ErrNegativeLeeway     = errors.New("leeway must not be negative")
	ErrMissingClock       = errors.New("clock is required")

	ErrMissingToken        = errors.New("token is required")
	ErrInvalidToken        = errors.New("invalid internal JWT")
	ErrUnexpectedTokenType = errors.New("unexpected JWT typ header: an internal JWT is a JWT")
	ErrMissingKeyID        = errors.New("JWT kid header is required")
	ErrUnknownKey          = errors.New("no verification key for the JWT kid")

	ErrAudienceCount    = errors.New("an internal JWT names exactly one audience")
	ErrMissingClaim     = errors.New("missing claim")
	ErrForbiddenClaim   = errors.New("forbidden claim")
	ErrClientIDMismatch = errors.New("a service token's client_id and sub name the same service")
)

// KeyResolver finds the verification key a token's kid names.
// *jwks.Cache satisfies it.
type KeyResolver interface {
	Key(ctx context.Context, keyID string) (*ecdsa.PublicKey, error)
}

// Option adjusts a Verifier.
type Option func(*Verifier)

// WithLeeway sets the clock skew tolerated on exp, nbf, and iat.
func WithLeeway(d time.Duration) Option {
	return func(v *Verifier) {
		v.leeway = d
	}
}

// WithClock sets the clock every time claim is read against.
func WithClock(now func() time.Time) Option {
	return func(v *Verifier) {
		v.now = now
	}
}

// Verifier verifies the internal JWTs one service receives.
type Verifier struct {
	issuerID string
	audience string
	keys     KeyResolver
	leeway   time.Duration
	now      func() time.Time
	parser   *jwt.Parser
}

// New creates a Verifier that accepts tokens issued by issuerID and addressed
// to audience, verified with the keys the resolver hands out.
func New(issuerID, audience string, keys KeyResolver, opts ...Option) (*Verifier, error) {
	if issuerID == "" {
		return nil, ErrMissingIssuerID
	}

	if audience == "" {
		return nil, ErrMissingAudience
	}

	if keys == nil {
		return nil, ErrMissingKeyResolver
	}

	verifier := &Verifier{
		issuerID: issuerID,
		audience: audience,
		keys:     keys,
		leeway:   DefaultLeeway,
		now:      time.Now,
		parser:   nil,
	}

	for _, opt := range opts {
		opt(verifier)
	}

	if verifier.leeway < 0 {
		return nil, fmt.Errorf("%w, got %s", ErrNegativeLeeway, verifier.leeway)
	}

	if verifier.now == nil {
		return nil, ErrMissingClock
	}

	verifier.parser = jwt.NewParser(
		jwt.WithValidMethods([]string{internaljwt.Algorithm}),
		jwt.WithIssuer(verifier.issuerID),
		jwt.WithAudience(verifier.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(verifier.leeway),
		jwt.WithTimeFunc(verifier.now),
	)

	return verifier, nil
}

// Verify parses the token, checks its signature and every claim, and returns
// the claim set it carries.
func (v *Verifier) Verify(ctx context.Context, token string) (internaljwt.Claims, error) {
	if token == "" {
		return internaljwt.Claims{}, ErrMissingToken
	}

	var claims internaljwt.Claims

	if _, err := v.parser.ParseWithClaims(token, &claims, v.keyFunc(ctx)); err != nil {
		return internaljwt.Claims{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	if err := validateRegisteredClaims(claims); err != nil {
		return internaljwt.Claims{}, err
	}

	if err := validateCommonClaims(claims); err != nil {
		return internaljwt.Claims{}, err
	}

	if err := internaljwt.ValidateBinding(claims.TokenUse, claims.TenantPublicID, claims.EventPublicID); err != nil {
		return internaljwt.Claims{}, err
	}

	if err := validateOriginClaims(claims); err != nil {
		return internaljwt.Claims{}, err
	}

	return claims, nil
}

// keyFunc checks the token type and looks up the verification key the
// token's kid names.
func (v *Verifier) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if err := validateTokenType(token); err != nil {
			return nil, err
		}

		keyID, ok := token.Header["kid"].(string)
		if !ok || keyID == "" {
			return nil, ErrMissingKeyID
		}

		key, err := v.keys.Key(ctx, keyID)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnknownKey, err)
		}

		return key, nil
	}
}

// validateTokenType checks the typ header the spec fixes at JWT.
func validateTokenType(token *jwt.Token) error {
	tokenType, ok := token.Header["typ"].(string)
	if !ok {
		return fmt.Errorf("%w: missing", ErrUnexpectedTokenType)
	}

	if !strings.EqualFold(tokenType, tokenTypeJWT) {
		return fmt.Errorf("%w: %q", ErrUnexpectedTokenType, tokenType)
	}

	return nil
}

// validateRegisteredClaims checks the registered claims golang-jwt does not check itself.
// iss, aud, exp, nbf, and iat are checked by the parser.
func validateRegisteredClaims(claims internaljwt.Claims) error {
	if claims.Subject == "" {
		return missingClaim("sub")
	}

	if claims.ID == "" {
		return missingClaim("jti")
	}

	if claims.NotBefore == nil {
		return missingClaim("nbf")
	}

	// golang-jwt validates iat when it is present but never requires it.
	if claims.IssuedAt == nil {
		return missingClaim("iat")
	}

	if len(claims.Audience) != 1 {
		return fmt.Errorf("%w, got %d", ErrAudienceCount, len(claims.Audience))
	}

	return nil
}

// validateCommonClaims checks the claims every internal JWT carries.
func validateCommonClaims(claims internaljwt.Claims) error {
	if claims.TokenUse == "" {
		return missingClaim("token_use")
	}

	if claims.ClientID == "" {
		return missingClaim("client_id")
	}

	if claims.Txn == "" {
		return missingClaim("txn")
	}

	return nil
}

func missingClaim(name string) error {
	return fmt.Errorf("%w: %s", ErrMissingClaim, name)
}

func forbiddenClaim(name string) error {
	return fmt.Errorf("%w: %s", ErrForbiddenClaim, name)
}
