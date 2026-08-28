package issuer

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

// DefaultTTL is the lifetime of an internal JWT.
const DefaultTTL = 120 * time.Second

// Issuer signs internal JWTs.
type Issuer struct {
	issuerID string
	keys     KeyProvider
	ttl      time.Duration
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
		return nil, errors.New("issuer ID is required")
	}

	if keys == nil {
		return nil, errors.New("key provider is required")
	}

	issuer := &Issuer{
		issuerID: issuerID,
		keys:     keys,
		ttl:      DefaultTTL,
		now:      time.Now,
	}

	for _, opt := range opts {
		opt(issuer)
	}

	if issuer.ttl <= 0 {
		return nil, errors.New("TTL must be positive")
	}

	if issuer.now == nil {
		return nil, errors.New("clock is required")
	}

	return issuer, nil
}

// Issued is a signed internal JWT together with the claims it carries.
type Issued struct {
	Token  string
	Claims internaljwt.Claims
}

// EntranceInput describes the conversion of a verified external token into an internal one.
type EntranceInput struct {
	Audience        string
	TokenUse        string // tenant_access, event_access, or registration
	Subject         string
	ClientID        string
	Scope           string // copied from the external token
	SourceJTI       string // copied from the external token
	SourceExpiresAt time.Time
	TenantPublicID  string
	EventPublicID   string
}

// UserOriginServiceInput describes the re-issue of a user-origin call for the next hop.
type UserOriginServiceInput struct {
	Audience      string
	CallerService string
	Context       internaljwt.Claims
}

// MachineOriginServiceInput describes a machine-origin call.
type MachineOriginServiceInput struct {
	Audience      string
	CallerService string
	Context       *internaljwt.Claims
}

// IssueEntrance converts a verified external token into an internal JWT.
func (i *Issuer) IssueEntrance(ctx context.Context, input EntranceInput) (Issued, error) {
	if err := validateEntrance(input); err != nil {
		return Issued{}, err
	}

	txn, err := uuid.NewV7()
	if err != nil {
		return Issued{}, fmt.Errorf("generate txn: %w", err)
	}

	now := i.now()

	if !input.SourceExpiresAt.After(now) {
		return Issued{}, errors.New("source token expiry must be in the future")
	}

	expiresAt := now.Add(i.ttl)
	if input.SourceExpiresAt.Before(expiresAt) {
		expiresAt = input.SourceExpiresAt
	}

	registered, err := i.registeredClaims(input.Audience, input.Subject, now, expiresAt)
	if err != nil {
		return Issued{}, err
	}

	return i.sign(ctx, internaljwt.Claims{
		RegisteredClaims: registered,
		TokenUse:         input.TokenUse,
		ClientID:         input.ClientID,
		Txn:              txn.String(),
		Scope:            input.Scope,
		SourceJTI:        input.SourceJTI,
		OriginSub:        "",
		TenantPublicID:   input.TenantPublicID,
		EventPublicID:    input.EventPublicID,
	})
}

// IssueUserOriginService re-issues a user-origin call as a service token for
// the next hop.
func (i *Issuer) IssueUserOriginService(ctx context.Context, input UserOriginServiceInput) (Issued, error) {
	now := i.now()

	if err := validateUserOriginService(input, now); err != nil {
		return Issued{}, err
	}

	originSub := input.Context.OriginSub
	if originSub == "" {
		originSub = input.Context.Subject
	}

	registered, err := i.registeredClaims(input.Audience, input.CallerService, now, now.Add(i.ttl))
	if err != nil {
		return Issued{}, err
	}

	return i.sign(ctx, internaljwt.Claims{
		RegisteredClaims: registered,
		TokenUse:         internaljwt.TokenUseService,
		ClientID:         input.CallerService,
		Txn:              input.Context.Txn,
		Scope:            input.Context.Scope,
		SourceJTI:        input.Context.ID,
		OriginSub:        originSub,
		TenantPublicID:   input.Context.TenantPublicID,
		EventPublicID:    input.Context.EventPublicID,
	})
}

// IssueMachineOriginService issues a service token for a call no user started.
func (i *Issuer) IssueMachineOriginService(ctx context.Context, input MachineOriginServiceInput) (Issued, error) {
	now := i.now()

	if err := validateMachineOriginService(input, now); err != nil {
		return Issued{}, err
	}

	txn, err := machineOriginTxn(input.Context)
	if err != nil {
		return Issued{}, err
	}

	registered, err := i.registeredClaims(input.Audience, input.CallerService, now, now.Add(i.ttl))
	if err != nil {
		return Issued{}, err
	}

	return i.sign(ctx, internaljwt.Claims{
		RegisteredClaims: registered,
		TokenUse:         internaljwt.TokenUseService,
		ClientID:         input.CallerService,
		Txn:              txn,
		Scope:            "",
		SourceJTI:        "",
		OriginSub:        "",
		TenantPublicID:   "",
		EventPublicID:    "",
	})
}

// JWKS is the document the gateway publishes its verification keys in.
func (i *Issuer) JWKS(ctx context.Context) (internaljwt.JWKS, error) {
	keys, err := i.keys.Current(ctx)
	if err != nil {
		return internaljwt.JWKS{}, fmt.Errorf("load signing keys: %w", err)
	}

	if keys.Signing.Key == nil {
		return internaljwt.JWKS{}, errors.New("signing key is required")
	}

	jwks := internaljwt.JWKS{Keys: make([]internaljwt.JWK, 0, len(keys.Published)+1)}
	seen := make(map[string]struct{}, len(keys.Published)+1)

	signing, err := internaljwt.NewJWK(keys.Signing.KeyID, &keys.Signing.Key.PublicKey)
	if err != nil {
		return internaljwt.JWKS{}, fmt.Errorf("describe signing key: %w", err)
	}

	jwks.Keys = append(jwks.Keys, signing)
	seen[signing.KeyID] = struct{}{}

	for _, published := range keys.Published {
		// A kid must name one key.
		// A duplicate would leave a verifier picking between two keys for the same identifier
		if _, duplicate := seen[published.KeyID]; duplicate {
			return internaljwt.JWKS{}, fmt.Errorf("duplicate JWKS key ID %q", published.KeyID)
		}

		key, err := internaljwt.NewJWK(published.KeyID, published.Key)
		if err != nil {
			return internaljwt.JWKS{}, fmt.Errorf("describe published key %q: %w", published.KeyID, err)
		}

		jwks.Keys = append(jwks.Keys, key)
		seen[published.KeyID] = struct{}{}
	}

	return jwks, nil
}

// registeredClaims builds the claims every internal JWT shares.
func (i *Issuer) registeredClaims(audience, subject string, now, expiresAt time.Time) (jwt.RegisteredClaims, error) {
	jti, err := uuid.NewV7()
	if err != nil {
		return jwt.RegisteredClaims{}, fmt.Errorf("generate jti: %w", err)
	}

	return jwt.RegisteredClaims{
		Issuer:    i.issuerID,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        jti.String(),
	}, nil
}

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
		return signedClaims{}, fmt.Errorf("an internal JWT names exactly one audience, got %d", len(claims.Audience))
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

// sign signs the claims with the key currently in force and names that key in the kid header.
func (i *Issuer) sign(ctx context.Context, claims internaljwt.Claims) (Issued, error) {
	signable, err := newSignedClaims(claims)
	if err != nil {
		return Issued{}, err
	}

	keys, err := i.keys.Current(ctx)
	if err != nil {
		return Issued{}, fmt.Errorf("load signing key: %w", err)
	}

	if keys.Signing.KeyID == "" {
		return Issued{}, errors.New("signing key ID is required")
	}

	if keys.Signing.Key == nil {
		return Issued{}, errors.New("signing key is required")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, signable)
	token.Header["kid"] = keys.Signing.KeyID

	signed, err := token.SignedString(keys.Signing.Key)
	if err != nil {
		return Issued{}, fmt.Errorf("sign internal JWT: %w", err)
	}

	return Issued{Token: signed, Claims: claims}, nil
}

// machineOriginTxn keeps the chain identifier of a machine-origin call.
func machineOriginTxn(context *internaljwt.Claims) (string, error) {
	if context != nil {
		return context.Txn, nil
	}

	txn, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("generate txn: %w", err)
	}

	return txn.String(), nil
}

// validateEntrance checks the input of an entrance conversion against the
// claims its token_use requires and forbids
func validateEntrance(input EntranceInput) error {
	if input.Audience == "" {
		return errors.New("audience is required")
	}

	if input.Subject == "" {
		return errors.New("subject is required")
	}

	if input.ClientID == "" {
		return errors.New("client ID is required")
	}

	if input.Scope == "" {
		return errors.New("scope is required for an entrance conversion")
	}

	if input.SourceJTI == "" {
		return errors.New("source jti is required for an entrance conversion")
	}

	if input.SourceExpiresAt.IsZero() {
		return errors.New("source token expiry is required for an entrance conversion")
	}

	return validateEntranceBinding(input)
}

// validateEntranceBinding checks the tenant_id and event_id an entrance
// conversion must and must not carry.
func validateEntranceBinding(input EntranceInput) error {
	if input.TokenUse == internaljwt.TokenUseService {
		return errors.New("service tokens are re-issued from a context token, not converted at an entrance")
	}

	return validateBinding(input.TokenUse, input.TenantPublicID, input.EventPublicID)
}

// validateBinding checks the binding claims a token_use requires and forbids.
func validateBinding(tokenUse, tenantPublicID, eventPublicID string) error {
	switch tokenUse {
	case internaljwt.TokenUseTenantAccess:
		if tenantPublicID == "" {
			return errors.New("tenant public ID is required for tenant_access")
		}

		if eventPublicID != "" {
			return errors.New("tenant_access must not carry an event public ID")
		}
	case internaljwt.TokenUseEventAccess:
		if tenantPublicID == "" {
			return errors.New("tenant public ID is required for event_access")
		}

		if eventPublicID == "" {
			return errors.New("event public ID is required for event_access")
		}
	case internaljwt.TokenUseRegistration:
		if tenantPublicID != "" || eventPublicID != "" {
			return errors.New("registration must not carry a tenant or event public ID")
		}
	case internaljwt.TokenUseService:
		if eventPublicID != "" && tenantPublicID == "" {
			return errors.New("a service token carrying an event public ID must carry a tenant public ID")
		}
	default:
		return fmt.Errorf("unsupported token use %q", tokenUse)
	}

	return nil
}

func validateContextToken(context internaljwt.Claims, callerService string, now time.Time) error {
	if context.ExpiresAt == nil {
		return errors.New("context token exp is required")
	}

	if !context.ExpiresAt.After(now) {
		return errors.New("context token has expired")
	}

	if !slices.Contains(context.Audience, callerService) {
		return fmt.Errorf("context token audience %v does not name the calling service %q", context.Audience, callerService)
	}

	return nil
}

func validateUserOriginService(input UserOriginServiceInput, now time.Time) error {
	if input.Audience == "" {
		return errors.New("audience is required")
	}

	if input.CallerService == "" {
		return errors.New("caller service is required")
	}

	if err := validateContextToken(input.Context, input.CallerService, now); err != nil {
		return err
	}

	if err := validateUserOriginContextUse(input.Context); err != nil {
		return err
	}

	if input.Context.Scope == "" {
		return errors.New("context token scope is required for a user-origin re-issue")
	}

	if input.Context.Txn == "" {
		return errors.New("context token txn is required")
	}

	if input.Context.SourceJTI == "" {
		return errors.New("context token src_jti is required for a user-origin re-issue")
	}

	if input.Context.ID == "" {
		return errors.New("context token jti is required")
	}

	if input.Context.Subject == "" {
		return errors.New("context token subject is required")
	}

	return nil
}

func validateUserOriginContextUse(context internaljwt.Claims) error {
	switch context.TokenUse {
	case internaljwt.TokenUseTenantAccess, internaljwt.TokenUseEventAccess, internaljwt.TokenUseRegistration:
	case internaljwt.TokenUseService:
		if context.OriginSub == "" {
			return errors.New("a service context token without origin_sub is not user-origin")
		}
	default:
		return fmt.Errorf("unsupported context token use %q", context.TokenUse)
	}

	if err := validateBinding(context.TokenUse, context.TenantPublicID, context.EventPublicID); err != nil {
		return fmt.Errorf("context token: %w", err)
	}

	return nil
}

func validateMachineOriginService(input MachineOriginServiceInput, now time.Time) error {
	if input.Audience == "" {
		return errors.New("audience is required")
	}

	if input.CallerService == "" {
		return errors.New("caller service is required")
	}

	// A new machine origin presents no context token at all.
	if input.Context == nil {
		return nil
	}

	if err := validateContextToken(*input.Context, input.CallerService, now); err != nil {
		return err
	}

	if input.Context.Txn == "" {
		return errors.New("context token txn is required")
	}

	if input.Context.TokenUse != internaljwt.TokenUseService {
		return fmt.Errorf("a machine-origin context token must be a service token, got %q", input.Context.TokenUse)
	}

	if input.Context.Scope != "" || input.Context.SourceJTI != "" || input.Context.OriginSub != "" {
		return errors.New("a machine-origin context token must carry none of scope, src_jti, and origin_sub")
	}

	if input.Context.TenantPublicID != "" || input.Context.EventPublicID != "" {
		return errors.New("a machine-origin context token must carry neither tenant nor event public ID")
	}

	return nil
}
