package issuer

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

// Input errors IssueUserOriginService and IssueMachineOriginService return.
var (
	ErrMissingCallerService = errors.New("caller service is required")

	// Context token of a user-origin re-issue.
	ErrContextMissingTxn       = errors.New("context token txn is required")
	ErrContextMissingJTI       = errors.New("context token jti is required")
	ErrContextMissingSubject   = errors.New("context token subject is required")
	ErrContextMissingScope     = errors.New("context token scope is required for a user-origin re-issue")
	ErrContextMissingSourceJTI = errors.New("context token src_jti is required for a user-origin re-issue")
	ErrContextNotUserOrigin    = errors.New("a service context token without origin_sub is not user-origin")

	// Context token of a machine-origin re-issue.
	ErrMachineContextNotService     = errors.New("a machine-origin context token must be a service token")
	ErrMachineContextCarriesOrigin  = errors.New("a machine-origin context token must carry none of scope, src_jti, and origin_sub")
	ErrMachineContextCarriesBinding = errors.New("a machine-origin context token must carry neither tenant nor event public ID")
)

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

// userOriginServiceClaims derives the claim set of a user-origin re-issue.
// The chain identifier, scope, and binding claims pass through from the
// context token; origin_sub is set from the context token's sub on the first re-issue.
func (i *Issuer) userOriginServiceClaims(input UserOriginServiceInput, now time.Time) (internaljwt.Claims, error) {
	if err := validateUserOriginService(input, now); err != nil {
		return internaljwt.Claims{}, err
	}

	originSub := input.Context.OriginSub
	if originSub == "" {
		originSub = input.Context.Subject
	}

	registered, err := i.signer.registeredClaims(input.Audience, input.CallerService, now, now.Add(i.ttl))
	if err != nil {
		return internaljwt.Claims{}, err
	}

	return internaljwt.Claims{
		RegisteredClaims: registered,
		TokenUse:         internaljwt.TokenUseService,
		ClientID:         input.CallerService,
		Txn:              input.Context.Txn,
		Scope:            input.Context.Scope,
		SourceJTI:        input.Context.ID,
		OriginSub:        originSub,
		TenantPublicID:   input.Context.TenantPublicID,
		EventPublicID:    input.Context.EventPublicID,
	}, nil
}

// machineOriginServiceClaims derives the claim set of a machine-origin call.
// Only txn passes through from a context token; a new machine origin starts a chain.
func (i *Issuer) machineOriginServiceClaims(input MachineOriginServiceInput, now time.Time) (internaljwt.Claims, error) {
	if err := validateMachineOriginService(input, now); err != nil {
		return internaljwt.Claims{}, err
	}

	txn, err := machineOriginTxn(input.Context)
	if err != nil {
		return internaljwt.Claims{}, err
	}

	registered, err := i.signer.registeredClaims(input.Audience, input.CallerService, now, now.Add(i.ttl))
	if err != nil {
		return internaljwt.Claims{}, err
	}

	return internaljwt.Claims{
		RegisteredClaims: registered,
		TokenUse:         internaljwt.TokenUseService,
		ClientID:         input.CallerService,
		Txn:              txn,
		Scope:            "",
		SourceJTI:        "",
		OriginSub:        "",
		TenantPublicID:   "",
		EventPublicID:    "",
	}, nil
}

// machineOriginTxn keeps the chain identifier of a machine-origin call.
func machineOriginTxn(context *internaljwt.Claims) (string, error) {
	if context != nil {
		return context.Txn, nil
	}

	txn, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("%w txn: %w", ErrGenerateID, err)
	}

	return txn.String(), nil
}

func validateUserOriginService(input UserOriginServiceInput, now time.Time) error {
	if input.Audience == "" {
		return ErrMissingAudience
	}

	if input.CallerService == "" {
		return ErrMissingCallerService
	}

	if err := validateContextToken(input.Context, input.CallerService, now); err != nil {
		return err
	}

	if err := validateUserOriginContextUse(input.Context); err != nil {
		return err
	}

	if input.Context.Scope == "" {
		return ErrContextMissingScope
	}

	if input.Context.Txn == "" {
		return ErrContextMissingTxn
	}

	if input.Context.SourceJTI == "" {
		return ErrContextMissingSourceJTI
	}

	if input.Context.ID == "" {
		return ErrContextMissingJTI
	}

	if input.Context.Subject == "" {
		return ErrContextMissingSubject
	}

	return nil
}

func validateUserOriginContextUse(context internaljwt.Claims) error {
	switch context.TokenUse {
	case internaljwt.TokenUseTenantAccess, internaljwt.TokenUseEventAccess, internaljwt.TokenUseRegistration:
	case internaljwt.TokenUseService:
		if context.OriginSub == "" {
			return ErrContextNotUserOrigin
		}
	default:
		return fmt.Errorf("context token: %w %q", internaljwt.ErrUnsupportedTokenUse, context.TokenUse)
	}

	if err := internaljwt.ValidateBinding(context.TokenUse, context.TenantPublicID, context.EventPublicID); err != nil {
		return fmt.Errorf("context token: %w", err)
	}

	return nil
}

func validateMachineOriginService(input MachineOriginServiceInput, now time.Time) error {
	if input.Audience == "" {
		return ErrMissingAudience
	}

	if input.CallerService == "" {
		return ErrMissingCallerService
	}

	// A new machine origin presents no context token at all.
	if input.Context == nil {
		return nil
	}

	if err := validateContextToken(*input.Context, input.CallerService, now); err != nil {
		return err
	}

	if input.Context.Txn == "" {
		return ErrContextMissingTxn
	}

	if input.Context.TokenUse != internaljwt.TokenUseService {
		return fmt.Errorf("%w, got %q", ErrMachineContextNotService, input.Context.TokenUse)
	}

	if input.Context.Scope != "" || input.Context.SourceJTI != "" || input.Context.OriginSub != "" {
		return ErrMachineContextCarriesOrigin
	}

	if input.Context.TenantPublicID != "" || input.Context.EventPublicID != "" {
		return ErrMachineContextCarriesBinding
	}

	return nil
}
