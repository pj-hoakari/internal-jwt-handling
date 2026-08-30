package jwtgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"
)

// verify checks the token against the JWKS the way a receiving service would.
func verify(t *testing.T, output Output, audience string) internaljwt.Claims {
	t.Helper()

	if len(output.JWKS.Keys) != 1 {
		t.Fatalf("JWKS holds %d keys, want 1", len(output.JWKS.Keys))
	}

	key := publicKeyFromJWK(t, output.JWKS.Keys[0])

	var claims internaljwt.Claims

	parsed, err := jwt.ParseWithClaims(output.Token, &claims, func(token *jwt.Token) (any, error) {
		if token.Header["kid"] != output.JWKS.Keys[0].KeyID {
			return nil, errors.New("kid does not name the JWKS key")
		}

		return key, nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithAudience(audience), jwt.WithIssuer("service-gateway"))
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	if !parsed.Valid {
		t.Fatal("token is not valid")
	}

	return claims
}

func publicKeyFromJWK(t *testing.T, key internaljwt.JWK) *ecdsa.PublicKey {
	t.Helper()

	x, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}

	y, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		t.Fatalf("decode y: %v", err)
	}

	encoded := append([]byte{4}, x...)
	encoded = append(encoded, y...)

	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	return publicKey
}

func TestGenerateMintsEveryTokenUse(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		config Config
		check  func(t *testing.T, claims internaljwt.Claims)
	}{
		"tenant_access": {
			config: Config{
				Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseTenantAccess,
				TenantPublicID: "0123456789abcdef", Scope: "events.read",
			},
			check: func(t *testing.T, claims internaljwt.Claims) {
				t.Helper()

				if claims.Subject != DefaultSubject || claims.ClientID != DefaultClientID {
					t.Errorf("sub/client_id = %q/%q", claims.Subject, claims.ClientID)
				}

				if claims.Scope != "events.read" || claims.SourceJTI != DefaultSourceJTI || claims.TenantPublicID != "0123456789abcdef" {
					t.Errorf("unexpected claims: %+v", claims)
				}

				if claims.OriginSub != "" || claims.EventPublicID != "" {
					t.Errorf("tenant_access carries origin_sub or event_id: %+v", claims)
				}
			},
		},
		"event_access": {
			config: Config{
				Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseEventAccess,
				TenantPublicID: "0123456789abcdef", EventPublicID: "fedcba9876543210", Scope: "events.read",
			},
			check: func(t *testing.T, claims internaljwt.Claims) {
				t.Helper()

				if claims.TenantPublicID != "0123456789abcdef" || claims.EventPublicID != "fedcba9876543210" {
					t.Errorf("unexpected binding: %+v", claims)
				}
			},
		},
		"registration": {
			config: Config{
				Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseRegistration, Scope: "tenant.claim",
			},
			check: func(t *testing.T, claims internaljwt.Claims) {
				t.Helper()

				if claims.TenantPublicID != "" || claims.EventPublicID != "" || claims.Scope != "tenant.claim" {
					t.Errorf("unexpected claims: %+v", claims)
				}
			},
		},
		"machine-origin service": {
			config: Config{Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseService},
			check: func(t *testing.T, claims internaljwt.Claims) {
				t.Helper()

				if claims.Subject != DefaultCaller || claims.ClientID != DefaultCaller {
					t.Errorf("sub/client_id = %q/%q, want the caller", claims.Subject, claims.ClientID)
				}

				if claims.Scope != "" || claims.SourceJTI != "" || claims.OriginSub != "" || claims.TenantPublicID != "" {
					t.Errorf("machine-origin service carries origin claims: %+v", claims)
				}
			},
		},
		"user-origin service": {
			config: Config{
				Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseService,
				OriginSub: "user-1", Scope: "events.read", TenantPublicID: "0123456789abcdef", Subject: "tolo-observation",
			},
			check: func(t *testing.T, claims internaljwt.Claims) {
				t.Helper()

				if claims.Subject != "tolo-observation" || claims.ClientID != "tolo-observation" {
					t.Errorf("sub/client_id = %q/%q, want the caller", claims.Subject, claims.ClientID)
				}

				if claims.OriginSub != "user-1" || claims.Scope != "events.read" || claims.SourceJTI != DefaultSourceJTI || claims.TenantPublicID != "0123456789abcdef" {
					t.Errorf("unexpected claims: %+v", claims)
				}
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			output, err := Generate(test.config)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}

			claims := verify(t, output, "tenant-management")

			if claims.TokenUse != test.config.TokenUse {
				t.Errorf("token_use = %q, want %q", claims.TokenUse, test.config.TokenUse)
			}

			if claims.Txn == "" || claims.ID == "" {
				t.Errorf("txn or jti is missing: %+v", claims)
			}

			if output.JWKS.Keys[0].KeyID != DefaultKeyID {
				t.Errorf("kid = %q, want %q", output.JWKS.Keys[0].KeyID, DefaultKeyID)
			}

			if output.Claims.ID != claims.ID {
				t.Error("Output.Claims does not describe the token")
			}

			test.check(t, claims)
		})
	}
}

func TestGenerateHonoursKeyIDAndTTL(t *testing.T) {
	t.Parallel()

	before := time.Now()

	output, err := Generate(Config{
		Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseService, KeyID: "key-2", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	claims := verify(t, output, "tenant-management")

	if output.JWKS.Keys[0].KeyID != "key-2" {
		t.Errorf("kid = %q, want key-2", output.JWKS.Keys[0].KeyID)
	}

	if remaining := claims.ExpiresAt.Sub(before); remaining < 59*time.Minute || remaining > 61*time.Minute {
		t.Errorf("token lives %v, want about an hour", remaining)
	}
}

func TestGeneratorSharesOneKey(t *testing.T) {
	t.Parallel()

	generator, err := NewGenerator("shared")
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}

	first, err := generator.Generate(Config{Issuer: "service-gateway", Audience: "a", TokenUse: internaljwt.TokenUseService})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	second, err := generator.Generate(Config{Issuer: "service-gateway", Audience: "b", TokenUse: internaljwt.TokenUseService})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	jwks, err := generator.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	if first.JWKS.Keys[0] != jwks.Keys[0] || second.JWKS.Keys[0] != jwks.Keys[0] {
		t.Fatal("tokens of one generator are not verified by one key")
	}

	verify(t, Output{Token: second.Token, Claims: second.Claims, JWKS: jwks}, "b")
}

func TestGenerateFixesTxnOfServiceTokens(t *testing.T) {
	t.Parallel()

	const txn = "01900000-0000-7000-8000-000000000001"

	tests := map[string]Config{
		"machine-origin": {Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseService, Txn: txn},
		"user-origin": {
			Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseService,
			OriginSub: "user-1", Scope: "events.read", Txn: txn,
		},
	}

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			output, err := Generate(config)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}

			claims := verify(t, output, "tenant-management")

			if claims.Txn != txn {
				t.Errorf("txn = %q, want %q", claims.Txn, txn)
			}

			if config.OriginSub == "" && (claims.Scope != "" || claims.SourceJTI != "" || claims.OriginSub != "") {
				t.Errorf("a machine-origin service token with a fixed txn carries origin claims: %+v", claims)
			}
		})
	}
}

func TestGenerateRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		config Config
		want   error
	}{
		"origin sub on tenant_access": {
			config: Config{Issuer: "gw", Audience: "a", TokenUse: internaljwt.TokenUseTenantAccess, TenantPublicID: "0123456789abcdef", Scope: "s", OriginSub: "u"},
			want:   ErrOriginSubForbidden,
		},
		"txn on tenant_access": {
			config: Config{Issuer: "gw", Audience: "a", TokenUse: internaljwt.TokenUseTenantAccess, TenantPublicID: "0123456789abcdef", Scope: "s", Txn: "t"},
			want:   ErrTxnForbidden,
		},
		"tenant_access without tenant": {
			config: Config{Issuer: "gw", Audience: "a", TokenUse: internaljwt.TokenUseTenantAccess, Scope: "s"},
			want:   issuer.ErrMissingTenantPublicID,
		},
		"tenant_access without scope": {
			config: Config{Issuer: "gw", Audience: "a", TokenUse: internaljwt.TokenUseTenantAccess, TenantPublicID: "0123456789abcdef"},
			want:   issuer.ErrMissingScope,
		},
		"user-origin service without scope": {
			config: Config{Issuer: "gw", Audience: "a", TokenUse: internaljwt.TokenUseService, OriginSub: "u"},
			want:   issuer.ErrContextMissingScope,
		},
		"unknown token use": {
			config: Config{Issuer: "gw", Audience: "a", TokenUse: "other", Scope: "s"},
			want:   issuer.ErrUnsupportedTokenUse,
		},
		"empty issuer": {
			config: Config{Issuer: "", Audience: "a", TokenUse: internaljwt.TokenUseService},
			want:   issuer.ErrMissingIssuerID,
		},
		"empty audience": {
			config: Config{Issuer: "gw", Audience: "", TokenUse: internaljwt.TokenUseService},
			want:   issuer.ErrMissingAudience,
		},
		"negative TTL": {
			config: Config{Issuer: "gw", Audience: "a", TokenUse: internaljwt.TokenUseService, TTL: -time.Second},
			want:   issuer.ErrNonPositiveTTL,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := Generate(test.config); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}
