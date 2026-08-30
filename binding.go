package internaljwt

import (
	"errors"
	"fmt"
)

// Binding errors ValidateBinding returns.
var (
	ErrUnsupportedTokenUse       = errors.New("unsupported token use")
	ErrMissingTenantPublicID     = errors.New("tenant public ID is required")
	ErrMissingEventPublicID      = errors.New("event public ID is required")
	ErrForbiddenEventPublicID    = errors.New("must not carry an event public ID")
	ErrRegistrationBinding       = errors.New("registration must not carry a tenant or event public ID")
	ErrServiceEventWithoutTenant = errors.New("a service token carrying an event public ID must carry a tenant public ID")
)

// ValidateBinding checks the tenant_id and event_id a token_use requires and
// forbids. The issuing and the verifying side share the rule.
func ValidateBinding(tokenUse, tenantPublicID, eventPublicID string) error {
	switch tokenUse {
	case TokenUseTenantAccess:
		if tenantPublicID == "" {
			return fmt.Errorf("%w for %s", ErrMissingTenantPublicID, tokenUse)
		}

		if eventPublicID != "" {
			return fmt.Errorf("%s %w", tokenUse, ErrForbiddenEventPublicID)
		}
	case TokenUseEventAccess:
		if tenantPublicID == "" {
			return fmt.Errorf("%w for %s", ErrMissingTenantPublicID, tokenUse)
		}

		if eventPublicID == "" {
			return fmt.Errorf("%w for %s", ErrMissingEventPublicID, tokenUse)
		}
	case TokenUseRegistration:
		if tenantPublicID != "" || eventPublicID != "" {
			return ErrRegistrationBinding
		}
	case TokenUseService:
		if eventPublicID != "" && tenantPublicID == "" {
			return ErrServiceEventWithoutTenant
		}
	default:
		return fmt.Errorf("%w %q", ErrUnsupportedTokenUse, tokenUse)
	}

	return nil
}
