package internaljwt

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Token uses an internal JWT carries in its token_use claim.
const (
	TokenUseTenantAccess = "tenant_access"
	TokenUseEventAccess  = "event_access"
	TokenUseService      = "service"
	TokenUseRegistration = "registration"
)

// Claims is the claim set of an internal JWT.
type Claims struct {
	jwt.RegisteredClaims
	TokenUse string `json:"token_use"`
	ClientID string `json:"client_id"`
	// Txn correlates every hop of one processing chain.
	Txn string `json:"txn"`
	// Scope is the scope of the external token, copied over unchanged.
	Scope string `json:"scope,omitempty"`
	// SourceJTI is carried in the src_jti claim and is the jti of the token
	// this one was converted from: the external token at an external token
	// conversion, the context token at a service re-issue.
	SourceJTI string `json:"src_jti,omitempty"`
	// OriginSub is the user a user-origin service token was re-issued for. It
	// is for audit only and must not feed authorization decisions.
	OriginSub string `json:"origin_sub,omitempty"`
	// TenantPublicID is carried in the tenant_id JWT claim. Its value is the
	// tenant's 16-character hexadecimal public ID.
	TenantPublicID string `json:"tenant_id,omitempty"`
	// EventPublicID is carried in the event_id JWT claim and is the event's
	// 16-character hexadecimal public ID.
	EventPublicID string `json:"event_id,omitempty"`
}

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
