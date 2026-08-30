package verifier

import (
	"errors"
	"strings"
	"testing"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

// serviceClaims is a machine-origin service token, which carries neither the
// origin claims nor a tenant or event binding.
func serviceClaims() internaljwt.Claims {
	claims := validClaims()
	claims.TokenUse = internaljwt.TokenUseService
	claims.Subject = "tolo-observation"
	claims.ClientID = "tolo-observation"
	claims.Scope = ""
	claims.SourceJTI = ""
	claims.OriginSub = ""
	claims.TenantPublicID = ""
	claims.EventPublicID = ""

	return claims
}

// userOriginServiceClaims is a service token re-issued for a user-origin call.
func userOriginServiceClaims() internaljwt.Claims {
	claims := serviceClaims()
	claims.Scope = testScope
	claims.SourceJTI = "src-jti-1"
	claims.OriginSub = "user-1"
	claims.TenantPublicID = testTenantPublicID

	return claims
}

func TestVerifyRejectsAMisboundToken(t *testing.T) {
	t.Parallel()

	signer := newSigner(t)

	tests := map[string]struct {
		claims func() internaljwt.Claims
		want   error
	}{
		"tenant_access without a tenant": {
			claims: func() internaljwt.Claims {
				claims := validClaims()
				claims.TenantPublicID = ""

				return claims
			},
			want: internaljwt.ErrMissingTenantPublicID,
		},
		"tenant_access with an event": {
			claims: func() internaljwt.Claims {
				claims := validClaims()
				claims.EventPublicID = testEventPublicID

				return claims
			},
			want: internaljwt.ErrForbiddenEventPublicID,
		},
		"event_access without an event": {
			claims: func() internaljwt.Claims {
				claims := validClaims()
				claims.TokenUse = internaljwt.TokenUseEventAccess

				return claims
			},
			want: internaljwt.ErrMissingEventPublicID,
		},
		"registration with a tenant": {
			claims: func() internaljwt.Claims {
				claims := validClaims()
				claims.TokenUse = internaljwt.TokenUseRegistration

				return claims
			},
			want: internaljwt.ErrRegistrationBinding,
		},
		"service with an event but no tenant": {
			claims: func() internaljwt.Claims {
				claims := userOriginServiceClaims()
				claims.TenantPublicID = ""
				claims.EventPublicID = testEventPublicID

				return claims
			},
			want: internaljwt.ErrServiceEventWithoutTenant,
		},
		"an unknown token use": {
			claims: func() internaljwt.Claims {
				claims := validClaims()
				claims.TokenUse = "unknown"

				return claims
			},
			want: internaljwt.ErrUnsupportedTokenUse,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			verifier := newVerifier(t, signer.keys, fixedClock())

			_, err := verifier.Verify(t.Context(), signer.sign(t, test.claims()))
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify = %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifyRejectsAnInvalidOriginClaim(t *testing.T) {
	t.Parallel()

	signer := newSigner(t)

	tests := map[string]struct {
		claims func() internaljwt.Claims
		want   error
		detail string
	}{
		"an entrance conversion without scope": {
			claims: func() internaljwt.Claims {
				claims := validClaims()
				claims.Scope = ""

				return claims
			},
			want: ErrMissingClaim, detail: "scope",
		},
		"an entrance conversion without src_jti": {
			claims: func() internaljwt.Claims {
				claims := validClaims()
				claims.SourceJTI = ""

				return claims
			},
			want: ErrMissingClaim, detail: "src_jti",
		},
		"an entrance conversion carrying origin_sub": {
			claims: func() internaljwt.Claims {
				claims := validClaims()
				claims.OriginSub = "user-1"

				return claims
			},
			want: ErrForbiddenClaim, detail: "origin_sub",
		},
		"a registration without scope": {
			claims: func() internaljwt.Claims {
				claims := validClaims()
				claims.TokenUse = internaljwt.TokenUseRegistration
				claims.TenantPublicID = ""
				claims.Scope = ""

				return claims
			},
			want: ErrMissingClaim, detail: "scope",
		},
		"a user-origin service token without scope": {
			claims: func() internaljwt.Claims {
				claims := userOriginServiceClaims()
				claims.Scope = ""

				return claims
			},
			want: ErrMissingClaim, detail: "scope",
		},
		"a user-origin service token without src_jti": {
			claims: func() internaljwt.Claims {
				claims := userOriginServiceClaims()
				claims.SourceJTI = ""

				return claims
			},
			want: ErrMissingClaim, detail: "src_jti",
		},
		"a machine-origin service token carrying scope": {
			claims: func() internaljwt.Claims {
				claims := serviceClaims()
				claims.Scope = testScope

				return claims
			},
			want: ErrForbiddenClaim, detail: "scope",
		},
		"a machine-origin service token carrying src_jti": {
			claims: func() internaljwt.Claims {
				claims := serviceClaims()
				claims.SourceJTI = "src-jti-1"

				return claims
			},
			want: ErrForbiddenClaim, detail: "src_jti",
		},
		"a machine-origin service token carrying a tenant": {
			claims: func() internaljwt.Claims {
				claims := serviceClaims()
				claims.TenantPublicID = testTenantPublicID

				return claims
			},
			want: ErrForbiddenClaim, detail: "tenant_id",
		},
		"a machine-origin service token carrying an event alone": {
			claims: func() internaljwt.Claims {
				claims := serviceClaims()
				claims.EventPublicID = testEventPublicID

				return claims
			},
			want: internaljwt.ErrServiceEventWithoutTenant, detail: "",
		},
		"a service token whose client_id is not its sub": {
			claims: func() internaljwt.Claims {
				claims := serviceClaims()
				claims.ClientID = "tolo-notification"

				return claims
			},
			want: ErrClientIDMismatch, detail: "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			verifier := newVerifier(t, signer.keys, fixedClock())

			_, err := verifier.Verify(t.Context(), signer.sign(t, test.claims()))
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify = %v, want %v", err, test.want)
			}

			if test.detail != "" && !strings.Contains(err.Error(), test.detail) {
				t.Fatalf("Verify = %v, want it to name %q", err, test.detail)
			}
		})
	}
}

func TestVerifyAcceptsAServiceTokenOfEitherOrigin(t *testing.T) {
	t.Parallel()

	signer := newSigner(t)

	tests := map[string]internaljwt.Claims{
		"machine origin":            serviceClaims(),
		"user origin":               userOriginServiceClaims(),
		"user origin with an event": eventBoundUserOriginServiceClaims(),
	}

	for name, claims := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			verifier := newVerifier(t, signer.keys, fixedClock())

			if _, err := verifier.Verify(t.Context(), signer.sign(t, claims)); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func eventBoundUserOriginServiceClaims() internaljwt.Claims {
	claims := userOriginServiceClaims()
	claims.EventPublicID = testEventPublicID

	return claims
}
