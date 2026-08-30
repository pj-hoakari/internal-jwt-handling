package issuer

import (
	"context"
	"errors"
	"time"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

// DefaultTTL is the lifetime of an internal JWT.
const DefaultTTL = 120 * time.Second

// Configuration errors New returns.
var (
	ErrMissingIssuerID    = errors.New("issuer ID is required")
	ErrMissingKeyProvider = errors.New("key provider is required")
	ErrNonPositiveTTL     = errors.New("TTL must be positive")
	ErrMissingClock       = errors.New("clock is required")
)

// ErrMissingAudience reports an issue input that names no destination.
var ErrMissingAudience = errors.New("audience is required")

// Issuer issues internal JWTs: it converts verified external tokens into
// internal ones and re-issues service tokens hop by hop. The claim derivation of
// each origin lives beside its input type; the signing is the signer's.
type Issuer struct {
	signer *signer
	ttl    time.Duration
	// now is time.Now in production and is replaced in tests to control iat, nbf, and exp.
	now func() time.Time
}

// Option adjusts an Issuer at construction.
type Option func(*Issuer)

// WithTTL replaces DefaultTTL with a custom lifetime for the internal JWTs.
func WithTTL(ttl time.Duration) Option {
	return func(i *Issuer) {
		i.ttl = ttl
	}
}

// WithClock replaces the clock the issuer reads iat, nbf, and exp from.
func WithClock(now func() time.Time) Option {
	return func(i *Issuer) {
		i.now = now
	}
}

// New builds an issuer that signs with the keys the provider supplies and names itself with issuerID.
func New(issuerID string, keys KeyProvider, opts ...Option) (*Issuer, error) {
	if issuerID == "" {
		return nil, ErrMissingIssuerID
	}

	if keys == nil {
		return nil, ErrMissingKeyProvider
	}

	issuer := &Issuer{
		signer: &signer{issuerID: issuerID, keys: keys},
		ttl:    DefaultTTL,
		now:    time.Now,
	}

	for _, opt := range opts {
		opt(issuer)
	}

	if issuer.ttl <= 0 {
		return nil, ErrNonPositiveTTL
	}

	if issuer.now == nil {
		return nil, ErrMissingClock
	}

	return issuer, nil
}

// Issued is a signed internal JWT together with the claims it carries.
type Issued struct {
	Token  string
	Claims internaljwt.Claims
}

// IssueFromExternal converts a verified external token into an internal JWT.
func (i *Issuer) IssueFromExternal(ctx context.Context, input ExternalTokenInput) (Issued, error) {
	claims, err := i.externalTokenClaims(input, i.now())
	if err != nil {
		return Issued{}, err
	}

	return i.issue(ctx, claims)
}

// IssueUserOriginService re-issues a user-origin call as a service token for
// the next hop.
func (i *Issuer) IssueUserOriginService(ctx context.Context, input UserOriginServiceInput) (Issued, error) {
	claims, err := i.userOriginServiceClaims(input, i.now())
	if err != nil {
		return Issued{}, err
	}

	return i.issue(ctx, claims)
}

// IssueMachineOriginService issues a service token for a call no user started.
func (i *Issuer) IssueMachineOriginService(ctx context.Context, input MachineOriginServiceInput) (Issued, error) {
	claims, err := i.machineOriginServiceClaims(input, i.now())
	if err != nil {
		return Issued{}, err
	}

	return i.issue(ctx, claims)
}

// JWKS is the document the gateway publishes its verification keys in.
func (i *Issuer) JWKS(ctx context.Context) (internaljwt.JWKS, error) {
	return i.signer.jwks(ctx)
}

// issue puts the claim set into its wire form and signs it.
func (i *Issuer) issue(ctx context.Context, claims internaljwt.Claims) (Issued, error) {
	signable, err := newSignedClaims(claims)
	if err != nil {
		return Issued{}, err
	}

	token, err := i.signer.sign(ctx, signable)
	if err != nil {
		return Issued{}, err
	}

	return Issued{Token: token, Claims: claims}, nil
}
