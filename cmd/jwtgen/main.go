// Command jwtgen mints an ES256 internal JWT and the JWKS that verifies it.
package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"os"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/jwtgen"
)

func main() {
	issuerID := flag.String("issuer", "service-gateway", "internal JWT issuer (the Service Gateway's issuer identifier)")
	audience := flag.String("audience", "", "internal JWT audience (the destination service)")
	tokenUse := flag.String("token-use", internaljwt.TokenUseTenantAccess, "token use: tenant_access, event_access, service, or registration")
	tenantPublicID := flag.String("tenant-public-id", "", "tenant public ID (16-character hex; required for tenant_access and event_access, optional for a user-origin service token)")
	eventPublicID := flag.String("event-public-id", "", "event public ID (16-character hex; required for event_access, optional for a user-origin service token)")
	scope := flag.String("scope", "", "space-delimited scopes (required for tenant_access, event_access, registration, and a user-origin service token)")
	originSub := flag.String("origin-sub", "", "origin user ID; turns a service token into a user-origin re-issue")
	subject := flag.String("subject", "", "sub of the token; the calling service for a service token")
	txn := flag.String("txn", "", "fixed processing chain identifier (service tokens only; blank mints a UUIDv7)")
	kid := flag.String("kid", jwtgen.DefaultKeyID, "JWK key ID")
	ttl := flag.Duration("ttl", jwtgen.DefaultTTL, "token lifetime")

	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	output, err := jwtgen.Generate(jwtgen.Config{
		Issuer:         *issuerID,
		Audience:       *audience,
		TokenUse:       *tokenUse,
		TenantPublicID: *tenantPublicID,
		EventPublicID:  *eventPublicID,
		Scope:          *scope,
		OriginSub:      *originSub,
		Subject:        *subject,
		Txn:            *txn,
		KeyID:          *kid,
		TTL:            *ttl,
	})
	if err != nil {
		logger.Error("generate token failed", "error", err)
		os.Exit(1)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(output); err != nil {
		logger.Error("encode output failed", "error", err)
		os.Exit(1)
	}
}
