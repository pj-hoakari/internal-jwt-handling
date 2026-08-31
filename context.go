package internaljwt

import "context"

// claimsContextKey names the claims verified for the call in progress.
type claimsContextKey struct{}

// ContextWithClaims returns a context carrying claims verified for the call.
func ContextWithClaims(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// ClaimsFromContext returns the claims verified for the call in progress.
func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(Claims)

	return claims, ok
}
