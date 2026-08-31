package internaljwt_test

import (
	"testing"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

func TestContextWithClaimsRoundTrips(t *testing.T) {
	t.Parallel()

	want := internaljwt.Claims{
		TokenUse:       internaljwt.TokenUseTenantAccess,
		ClientID:       "tolo-web",
		Txn:            "txn-1",
		Scope:          "tenant.read",
		TenantPublicID: "0123456789abcdef",
	}

	claims, found := internaljwt.ClaimsFromContext(internaljwt.ContextWithClaims(t.Context(), want))
	if !found {
		t.Fatal("the context carries no claims")
	}

	if claims.TokenUse != want.TokenUse || claims.ClientID != want.ClientID ||
		claims.Txn != want.Txn || claims.Scope != want.Scope ||
		claims.TenantPublicID != want.TenantPublicID {
		t.Fatalf("claims = %+v, want %+v", claims, want)
	}
}

func TestClaimsFromContextWithoutClaims(t *testing.T) {
	t.Parallel()

	claims, found := internaljwt.ClaimsFromContext(t.Context())
	if found {
		t.Fatalf("a bare context reported claims %+v", claims)
	}
}

func TestContextWithClaimsCarriesTheZeroValue(t *testing.T) {
	t.Parallel()

	// The zero value is a value like any other: found tells a handler whether
	// a token was verified, not whether the claims say anything.
	if _, found := internaljwt.ClaimsFromContext(internaljwt.ContextWithClaims(t.Context(), internaljwt.Claims{})); !found {
		t.Fatal("the context carries no claims")
	}
}
