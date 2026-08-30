package verifier

import (
	"fmt"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

// validateOriginClaims checks the scope, src_jti, and origin_sub the token's origin requires and forbids.
func validateOriginClaims(claims internaljwt.Claims) error {
	switch claims.TokenUse {
	case internaljwt.TokenUseTenantAccess, internaljwt.TokenUseEventAccess, internaljwt.TokenUseRegistration:
		return validateExternalOriginClaims(claims)
	case internaljwt.TokenUseService:
		return validateServiceClaims(claims)
	default:
		// Unreachable: ValidateBinding rejects an unsupported token_use first.
		return fmt.Errorf("%w %q", internaljwt.ErrUnsupportedTokenUse, claims.TokenUse)
	}
}

// validateExternalOriginClaims checks a token converted from an external one.
func validateExternalOriginClaims(claims internaljwt.Claims) error {
	if claims.Scope == "" {
		return missingClaim("scope")
	}

	if claims.SourceJTI == "" {
		return missingClaim("src_jti")
	}

	if claims.OriginSub != "" {
		return forbiddenClaim("origin_sub")
	}

	return nil
}

// validateServiceClaims checks a service token of either origin.
func validateServiceClaims(claims internaljwt.Claims) error {
	if err := validateServiceOriginClaims(claims); err != nil {
		return err
	}

	if claims.ClientID != claims.Subject {
		return fmt.Errorf("%w: client_id %q, sub %q", ErrClientIDMismatch, claims.ClientID, claims.Subject)
	}

	return nil
}

// validateServiceOriginClaims distinguishes the two origins of a service token by origin_sub.
//
// A user-origin re-issue carries the scope and src_jti of its context token.
// A machine-origin one carries no origin claim at all, and its authorization rests on the gateway's edge policy.
func validateServiceOriginClaims(claims internaljwt.Claims) error {
	if claims.OriginSub == "" {
		return validateMachineOriginClaims(claims)
	}

	if claims.Scope == "" {
		return missingClaim("scope")
	}

	if claims.SourceJTI == "" {
		return missingClaim("src_jti")
	}

	return nil
}

// validateMachineOriginClaims checks that a machine-origin service token
// carries none of the claims a user origin brings with it, tenant and event
// context included.
func validateMachineOriginClaims(claims internaljwt.Claims) error {
	if claims.Scope != "" {
		return forbiddenClaim("scope")
	}

	if claims.SourceJTI != "" {
		return forbiddenClaim("src_jti")
	}

	if claims.TenantPublicID != "" {
		return forbiddenClaim("tenant_id")
	}

	return nil
}
