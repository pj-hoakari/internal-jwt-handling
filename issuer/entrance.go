package issuer

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

// Input errors IssueEntrance returns.
var (
	ErrMissingSubject      = errors.New("subject is required")
	ErrMissingClientID     = errors.New("client ID is required")
	ErrMissingScope        = errors.New("scope is required for an entrance conversion")
	ErrMissingSourceJTI    = errors.New("source jti is required for an entrance conversion")
	ErrMissingSourceExpiry = errors.New("source token expiry is required for an entrance conversion")
	ErrSourceExpired       = errors.New("source token expiry must be in the future")
	ErrEntranceService     = errors.New("service tokens are re-issued from a context token, not converted at an entrance")
)

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

// entranceClaims derives the claim set of an entrance conversion. It starts a
// new processing chain, so txn is fresh, and its lifetime never outlives the
// external token it was converted from.
func (i *Issuer) entranceClaims(input EntranceInput, now time.Time) (internaljwt.Claims, error) {
	if err := validateEntrance(input); err != nil {
		return internaljwt.Claims{}, err
	}

	txn, err := uuid.NewV7()
	if err != nil {
		return internaljwt.Claims{}, fmt.Errorf("%w txn: %w", ErrGenerateID, err)
	}

	if !input.SourceExpiresAt.After(now) {
		return internaljwt.Claims{}, ErrSourceExpired
	}

	expiresAt := now.Add(i.ttl)
	if input.SourceExpiresAt.Before(expiresAt) {
		expiresAt = input.SourceExpiresAt
	}

	registered, err := i.signer.registeredClaims(input.Audience, input.Subject, now, expiresAt)
	if err != nil {
		return internaljwt.Claims{}, err
	}

	return internaljwt.Claims{
		RegisteredClaims: registered,
		TokenUse:         input.TokenUse,
		ClientID:         input.ClientID,
		Txn:              txn.String(),
		Scope:            input.Scope,
		SourceJTI:        input.SourceJTI,
		OriginSub:        "",
		TenantPublicID:   input.TenantPublicID,
		EventPublicID:    input.EventPublicID,
	}, nil
}

// validateEntrance checks the input of an entrance conversion against the
// claims its token_use requires and forbids
func validateEntrance(input EntranceInput) error {
	if input.Audience == "" {
		return ErrMissingAudience
	}

	if input.Subject == "" {
		return ErrMissingSubject
	}

	if input.ClientID == "" {
		return ErrMissingClientID
	}

	if input.Scope == "" {
		return ErrMissingScope
	}

	if input.SourceJTI == "" {
		return ErrMissingSourceJTI
	}

	if input.SourceExpiresAt.IsZero() {
		return ErrMissingSourceExpiry
	}

	return validateEntranceBinding(input)
}

// validateEntranceBinding checks the tenant_id and event_id an entrance
// conversion must and must not carry.
func validateEntranceBinding(input EntranceInput) error {
	if input.TokenUse == internaljwt.TokenUseService {
		return ErrEntranceService
	}

	return validateBinding(input.TokenUse, input.TenantPublicID, input.EventPublicID)
}
