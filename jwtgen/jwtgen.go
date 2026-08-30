package jwtgen

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"
)

const (
	DefaultKeyID     = "test-key"
	DefaultTTL       = 2 * time.Minute
	DefaultSubject   = "test-subject"
	DefaultClientID  = "test-client"
	DefaultCaller    = "test-caller"
	DefaultSourceJTI = "test-source-jti"
)

// Errors Generate returns beside those of the issuer package.
var (
	ErrGenerateKey        = errors.New("generate signing key")
	ErrOriginSubForbidden = errors.New("origin sub is only valid for a service token")
	ErrTxnForbidden       = errors.New("txn is only valid for a service token: an external token conversion starts a new chain")
)

// Config describes the internal JWT to mint.
type Config struct {
	Issuer         string
	Audience       string
	TokenUse       string
	TenantPublicID string
	EventPublicID  string
	Scope          string
	// OriginSub is the origin user of a user-origin service token.
	OriginSub string
	// Txn fixes the processing chain identifier of a service token, which
	// passes through from the context token. Blank mints a UUIDv7. An
	// external token conversion always starts a new chain, so Txn is
	// rejected there.
	Txn string
	// Subject is sub of an external token conversion, and the calling service of a service token.
	// Blank falls back to DefaultSubject or DefaultCaller.
	Subject string
	// KeyID is the kid of the signing key. Blank falls back to DefaultKeyID.
	KeyID string
	// TTL is the token lifetime. Zero falls back to DefaultTTL.
	TTL time.Duration
}

// Output is a minted token, the claims it carries, and the JWKS that verifies it.
type Output struct {
	Token  string             `json:"token"`
	Claims internaljwt.Claims `json:"claims"`
	JWKS   internaljwt.JWKS   `json:"jwks"`
}

// Generate mints one internal JWT under a fresh signing key. Tokens that must
// verify against one JWKS come from one Generator instead.
func Generate(config Config) (Output, error) {
	generator, err := NewGenerator(config.KeyID)
	if err != nil {
		return Output{}, err
	}

	return generator.Generate(config)
}

// Generator mints internal JWTs under one signing key.
type Generator struct {
	keyID string
	key   *ecdsa.PrivateKey
}

// NewGenerator creates a signing key named keyID. Blank falls back to DefaultKeyID.
func NewGenerator(keyID string) (*Generator, error) {
	if keyID == "" {
		keyID = DefaultKeyID
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGenerateKey, err)
	}

	return &Generator{keyID: keyID, key: key}, nil
}

// KeyID is the kid the generator signs under.
func (g *Generator) KeyID() string {
	return g.keyID
}

// Generate mints one internal JWT. config.KeyID is ignored in favour of the generator's key.
func (g *Generator) Generate(config Config) (Output, error) {
	if config.OriginSub != "" && config.TokenUse != internaljwt.TokenUseService {
		return Output{}, ErrOriginSubForbidden
	}

	if config.Txn != "" && config.TokenUse != internaljwt.TokenUseService {
		return Output{}, ErrTxnForbidden
	}

	ttl := config.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}

	iss, err := issuer.New(config.Issuer, g.keyProvider(), issuer.WithTTL(ttl))
	if err != nil {
		return Output{}, err
	}

	ctx := context.Background()

	issued, err := g.issue(ctx, iss, config, ttl)
	if err != nil {
		return Output{}, err
	}

	jwks, err := iss.JWKS(ctx)
	if err != nil {
		return Output{}, err
	}

	return Output{Token: issued.Token, Claims: issued.Claims, JWKS: jwks}, nil
}

// JWKS is the document that verifies every token the generator minted.
func (g *Generator) JWKS() (internaljwt.JWKS, error) {
	key, err := internaljwt.NewJWK(g.keyID, &g.key.PublicKey)
	if err != nil {
		return internaljwt.JWKS{}, err
	}

	return internaljwt.JWKS{Keys: []internaljwt.JWK{key}}, nil
}

func (g *Generator) keyProvider() issuer.KeyProvider {
	return staticKeyProvider{keys: issuer.KeySet{
		Signing:   issuer.SigningKey{KeyID: g.keyID, Key: g.key},
		Published: nil,
	}}
}

func (g *Generator) issue(ctx context.Context, iss *issuer.Issuer, config Config, ttl time.Duration) (issuer.Issued, error) {
	if config.TokenUse != internaljwt.TokenUseService {
		return iss.IssueFromExternal(ctx, issuer.ExternalTokenInput{
			Audience:        config.Audience,
			TokenUse:        config.TokenUse,
			Subject:         orDefault(config.Subject, DefaultSubject),
			ClientID:        DefaultClientID,
			Scope:           config.Scope,
			SourceJTI:       DefaultSourceJTI,
			SourceExpiresAt: time.Now().Add(ttl),
			TenantPublicID:  config.TenantPublicID,
			EventPublicID:   config.EventPublicID,
		})
	}

	caller := orDefault(config.Subject, DefaultCaller)

	if config.OriginSub == "" {
		return iss.IssueMachineOriginService(ctx, issuer.MachineOriginServiceInput{
			Audience:      config.Audience,
			CallerService: caller,
			Context:       machineOriginContext(config, caller, ttl),
		})
	}

	// A user-origin re-issue is derived from the context token the calling
	// service received. The one built here already carries origin_sub, so
	// the value passes through as on any later hop.
	context := serviceContext(config, caller, ttl)
	context.Scope = config.Scope
	context.SourceJTI = DefaultSourceJTI
	context.OriginSub = config.OriginSub
	context.TenantPublicID = config.TenantPublicID
	context.EventPublicID = config.EventPublicID

	return iss.IssueUserOriginService(ctx, issuer.UserOriginServiceInput{
		Audience:      config.Audience,
		CallerService: caller,
		Context:       context,
	})
}

// machineOriginContext is the context token of a machine-origin call. A new
// machine origin presents none and gets a fresh txn; a fixed txn is carried
// in from a previous hop, which is what a context token is.
func machineOriginContext(config Config, caller string, ttl time.Duration) *internaljwt.Claims {
	if config.Txn == "" {
		return nil
	}

	context := serviceContext(config, caller, ttl)

	return &context
}

// serviceContext is a service token the calling service holds, addressed to
// it and carrying the chain identifier the re-issue passes through.
func serviceContext(config Config, caller string, ttl time.Duration) internaljwt.Claims {
	now := time.Now()

	return internaljwt.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   caller,
			Audience:  jwt.ClaimStrings{caller},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        DefaultSourceJTI,
		},
		TokenUse:       internaljwt.TokenUseService,
		ClientID:       caller,
		Txn:            orDefault(config.Txn, newTxn()),
		Scope:          "",
		SourceJTI:      "",
		OriginSub:      "",
		TenantPublicID: "",
		EventPublicID:  "",
	}
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}

// staticKeyProvider hands out one key set.
type staticKeyProvider struct {
	keys issuer.KeySet
}

func (p staticKeyProvider) Current(context.Context) (issuer.KeySet, error) {
	return p.keys, nil
}
