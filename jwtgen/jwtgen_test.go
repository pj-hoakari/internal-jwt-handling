package jwtgen

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"
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
			want:   internaljwt.ErrMissingTenantPublicID,
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
			want:   internaljwt.ErrUnsupportedTokenUse,
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

var errUnknownTestKey = errors.New("no such test key")

type staticResolver struct {
	keys map[string]*ecdsa.PublicKey
}

func (r staticResolver) Key(_ context.Context, keyID string) (*ecdsa.PublicKey, error) {
	key, ok := r.keys[keyID]
	if !ok {
		return nil, errUnknownTestKey
	}

	return key, nil
}

func verifierFor(t *testing.T, jwks internaljwt.JWKS, audience string) *verifier.Verifier {
	t.Helper()

	keys := make(map[string]*ecdsa.PublicKey, len(jwks.Keys))

	for _, jwk := range jwks.Keys {
		key, err := internaljwt.PublicKey(jwk)
		if err != nil {
			t.Fatalf("public key %q: %v", jwk.KeyID, err)
		}

		keys[jwk.KeyID] = key
	}

	verify, err := verifier.New("service-gateway", audience, staticResolver{keys: keys})
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}

	return verify
}

func signedInput(t *testing.T, token string) string {
	t.Helper()

	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		t.Fatalf("token holds %d segments, want 3", len(segments))
	}

	header, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	return string(header) + "." + string(payload)
}

func newTestKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return key
}

func TestNewGeneratorWithKeySignsWithTheInjectedKey(t *testing.T) {
	t.Parallel()

	key := newTestKey(t, elliptic.P256())

	generator, err := NewGeneratorWithKey("gateway-key", key)
	if err != nil {
		t.Fatalf("NewGeneratorWithKey: %v", err)
	}

	if generator.KeyID() != "gateway-key" {
		t.Errorf("KeyID = %q, want gateway-key", generator.KeyID())
	}

	jwks, err := generator.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	if len(jwks.Keys) != 1 || jwks.Keys[0].KeyID != "gateway-key" {
		t.Fatalf("JWKS does not name the injected key: %+v", jwks)
	}

	published, err := internaljwt.PublicKey(jwks.Keys[0])
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	if !published.Equal(&key.PublicKey) {
		t.Fatal("JWKS does not carry the public half of the injected key")
	}

	output, err := generator.Generate(Config{
		Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseService,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if output.JWKS.Keys[0] != jwks.Keys[0] {
		t.Error("Generate publishes a key other than the injected one")
	}

	claims, err := verifierFor(t, jwks, "tenant-management").Verify(context.Background(), output.Token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if claims.ID != output.Claims.ID || claims.TokenUse != internaljwt.TokenUseService {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

func TestNewGeneratorWithKeyDefaultsTheKeyID(t *testing.T) {
	t.Parallel()

	generator, err := NewGeneratorWithKey("", newTestKey(t, elliptic.P256()))
	if err != nil {
		t.Fatalf("NewGeneratorWithKey: %v", err)
	}

	if generator.KeyID() != DefaultKeyID {
		t.Errorf("KeyID = %q, want %q", generator.KeyID(), DefaultKeyID)
	}
}

func TestNewGeneratorWithKeyRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		key  *ecdsa.PrivateKey
		want error
	}{
		"no key":       {key: nil, want: ErrMissingSigningKey},
		"P-384 key":    {key: newTestKey(t, elliptic.P384()), want: internaljwt.ErrUnsupportedCurve},
		"P-521 key":    {key: newTestKey(t, elliptic.P521()), want: internaljwt.ErrUnsupportedCurve},
		"uninit curve": {key: &ecdsa.PrivateKey{}, want: internaljwt.ErrUnsupportedCurve},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewGeneratorWithKey("k", test.key); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestSignUncheckedMatchesTheIssuedWireForm(t *testing.T) {
	t.Parallel()

	generator, err := NewGenerator("wire")
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}

	tests := map[string]Config{
		"tenant_access": {
			Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseTenantAccess,
			TenantPublicID: "0123456789abcdef", Scope: "events.read",
		},
		"machine-origin service": {
			Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseService,
		},
		"user-origin service": {
			Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseService,
			OriginSub: "user-1", Scope: "events.read", TenantPublicID: "0123456789abcdef",
		},
	}

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			output, err := generator.Generate(config)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}

			token, err := generator.SignUnchecked(output.Claims)
			if err != nil {
				t.Fatalf("SignUnchecked: %v", err)
			}

			if signedInput(t, token) != signedInput(t, output.Token) {
				t.Errorf("re-signed payload %q, issued payload %q", signedInput(t, token), signedInput(t, output.Token))
			}

			verify := verifierFor(t, output.JWKS, "tenant-management")

			issued, err := verify.Verify(context.Background(), output.Token)
			if err != nil {
				t.Fatalf("Verify the issued token: %v", err)
			}

			signed, err := verify.Verify(context.Background(), token)
			if err != nil {
				t.Fatalf("Verify the re-signed token: %v", err)
			}

			if !reflect.DeepEqual(issued, signed) {
				t.Errorf("re-signed claims %+v, issued claims %+v", signed, issued)
			}

			if signed.ID != output.Claims.ID || signed.Txn != output.Claims.Txn || signed.Subject != output.Claims.Subject {
				t.Errorf("re-signed claims do not carry what was handed in: %+v", signed)
			}
		})
	}
}

func TestSignUncheckedMintsTokensTheVerifierRejects(t *testing.T) {
	t.Parallel()

	generator, err := NewGenerator("unchecked")
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}

	service, err := generator.Generate(Config{
		Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseService,
	})
	if err != nil {
		t.Fatalf("Generate the service token: %v", err)
	}

	tenant, err := generator.Generate(Config{
		Issuer: "service-gateway", Audience: "tenant-management", TokenUse: internaljwt.TokenUseTenantAccess,
		TenantPublicID: "0123456789abcdef", Scope: "events.read",
	})
	if err != nil {
		t.Fatalf("Generate the tenant_access token: %v", err)
	}

	jwks, err := generator.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	scopedMachineOrigin := service.Claims
	scopedMachineOrigin.Scope = "events.read"

	tenantlessTenantAccess := tenant.Claims
	tenantlessTenantAccess.TenantPublicID = ""

	mismatchedClientID := service.Claims
	mismatchedClientID.ClientID = "another-service"

	tests := map[string]struct {
		claims internaljwt.Claims
		want   error
	}{
		"scope on a machine-origin service token": {claims: scopedMachineOrigin, want: verifier.ErrForbiddenClaim},
		"tenant_access without a tenant":          {claims: tenantlessTenantAccess, want: internaljwt.ErrMissingTenantPublicID},
		"service whose client_id is not its sub":  {claims: mismatchedClientID, want: verifier.ErrClientIDMismatch},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			token, err := generator.SignUnchecked(test.claims)
			if err != nil {
				t.Fatalf("SignUnchecked: %v", err)
			}

			if _, err := verifierFor(t, jwks, "tenant-management").Verify(context.Background(), token); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestSignUncheckedHeaderNamesTheGeneratorKey(t *testing.T) {
	t.Parallel()

	generator, err := NewGeneratorWithKey("header-key", newTestKey(t, elliptic.P256()))
	if err != nil {
		t.Fatalf("NewGeneratorWithKey: %v", err)
	}

	token, err := generator.SignUnchecked(internaljwt.Claims{})
	if err != nil {
		t.Fatalf("SignUnchecked: %v", err)
	}

	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		t.Fatalf("token holds %d segments, want 3", len(segments))
	}

	raw, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}

	var header map[string]string

	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}

	want := map[string]string{"alg": internaljwt.Algorithm, "kid": "header-key", "typ": "JWT"}
	if !reflect.DeepEqual(header, want) {
		t.Errorf("header = %v, want %v", header, want)
	}
}
