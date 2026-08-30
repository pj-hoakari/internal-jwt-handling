package internaljwt

import (
	"errors"
	"testing"
)

const (
	testTenantPublicID = "0123456789abcdef"
	testEventPublicID  = "fedcba9876543210"
)

func TestValidateBindingAcceptsEveryTokenUse(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		tokenUse       string
		tenantPublicID string
		eventPublicID  string
	}{
		"tenant access carries a tenant": {
			tokenUse: TokenUseTenantAccess, tenantPublicID: testTenantPublicID, eventPublicID: "",
		},
		"event access carries a tenant and an event": {
			tokenUse: TokenUseEventAccess, tenantPublicID: testTenantPublicID, eventPublicID: testEventPublicID,
		},
		"registration carries neither": {
			tokenUse: TokenUseRegistration, tenantPublicID: "", eventPublicID: "",
		},
		"machine-origin service carries neither": {
			tokenUse: TokenUseService, tenantPublicID: "", eventPublicID: "",
		},
		"user-origin service carries a tenant": {
			tokenUse: TokenUseService, tenantPublicID: testTenantPublicID, eventPublicID: "",
		},
		"user-origin service carries a tenant and an event": {
			tokenUse: TokenUseService, tenantPublicID: testTenantPublicID, eventPublicID: testEventPublicID,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if err := ValidateBinding(test.tokenUse, test.tenantPublicID, test.eventPublicID); err != nil {
				t.Fatalf("ValidateBinding: %v", err)
			}
		})
	}
}

func TestValidateBindingRejectsAMisboundTokenUse(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		tokenUse       string
		tenantPublicID string
		eventPublicID  string
		want           error
	}{
		"tenant access without a tenant": {
			tokenUse: TokenUseTenantAccess, tenantPublicID: "", eventPublicID: "",
			want: ErrMissingTenantPublicID,
		},
		"tenant access with an event": {
			tokenUse: TokenUseTenantAccess, tenantPublicID: testTenantPublicID, eventPublicID: testEventPublicID,
			want: ErrForbiddenEventPublicID,
		},
		"event access without a tenant": {
			tokenUse: TokenUseEventAccess, tenantPublicID: "", eventPublicID: testEventPublicID,
			want: ErrMissingTenantPublicID,
		},
		"event access without an event": {
			tokenUse: TokenUseEventAccess, tenantPublicID: testTenantPublicID, eventPublicID: "",
			want: ErrMissingEventPublicID,
		},
		"registration with a tenant": {
			tokenUse: TokenUseRegistration, tenantPublicID: testTenantPublicID, eventPublicID: "",
			want: ErrRegistrationBinding,
		},
		"registration with an event": {
			tokenUse: TokenUseRegistration, tenantPublicID: "", eventPublicID: testEventPublicID,
			want: ErrRegistrationBinding,
		},
		"service with an event but no tenant": {
			tokenUse: TokenUseService, tenantPublicID: "", eventPublicID: testEventPublicID,
			want: ErrServiceEventWithoutTenant,
		},
		"unknown token use": {
			tokenUse: "unknown", tenantPublicID: "", eventPublicID: "",
			want: ErrUnsupportedTokenUse,
		},
		"empty token use": {
			tokenUse: "", tenantPublicID: "", eventPublicID: "",
			want: ErrUnsupportedTokenUse,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := ValidateBinding(test.tokenUse, test.tenantPublicID, test.eventPublicID)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateBinding = %v, want %v", err, test.want)
			}
		})
	}
}
