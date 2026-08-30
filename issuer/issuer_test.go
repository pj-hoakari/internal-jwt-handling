package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

// fixedNow is the clock every test issues at, so that iat, nbf, and exp are
// exact values a test can compare against.
var fixedNow = time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)

// staticKeyProvider hands out one key set, or the failure a provider may
// return.
type staticKeyProvider struct {
	keys KeySet
	err  error
}

func (p staticKeyProvider) Current(context.Context) (KeySet, error) {
	if p.err != nil {
		return KeySet{}, p.err
	}

	return p.keys, nil
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return key
}

// newTestIssuer builds an issuer with one signing key and a frozen clock.
func newTestIssuer(t *testing.T, opts ...Option) *Issuer {
	t.Helper()

	provider := staticKeyProvider{
		keys: KeySet{
			Signing:   SigningKey{KeyID: "signing-1", Key: newTestKey(t)},
			Published: nil,
		},
		err: nil,
	}

	options := append([]Option{WithClock(func() time.Time { return fixedNow })}, opts...)

	issuer, err := New("service-gateway", provider, options...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return issuer
}

// verify parses an issued token the way a destination service does: it takes
// the verification key from the issuer's JWKS by the kid in the header and
// checks the ES256 signature. It returns the parsed claims and the raw payload
// so that a test can also assert which claims are absent from the JSON.
func verify(t *testing.T, issuer *Issuer, audience, token string) (internaljwt.Claims, map[string]any) {
	t.Helper()

	jwks, err := issuer.JWKS(t.Context())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	keys := make(map[string]*ecdsa.PublicKey, len(jwks.Keys))
	for _, key := range jwks.Keys {
		keys[key.KeyID] = publicKeyFromJWK(t, key)
	}

	var claims internaljwt.Claims

	parser := jwt.NewParser(
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer("service-gateway"),
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithTimeFunc(func() time.Time { return fixedNow }),
	)

	parsed, err := parser.ParseWithClaims(token, &claims, func(token *jwt.Token) (any, error) {
		keyID, ok := token.Header["kid"].(string)
		if !ok || keyID == "" {
			return nil, errors.New("JWT kid is required")
		}

		key, ok := keys[keyID]
		if !ok {
			return nil, errors.New("unknown JWT key ID")
		}

		return key, nil
	})
	if err != nil {
		t.Fatalf("parse issued token: %v", err)
	}

	if !parsed.Valid {
		t.Fatal("the issued token did not verify")
	}

	if typ, _ := parsed.Header["typ"].(string); typ != "JWT" {
		t.Fatalf("typ header = %v, want JWT", parsed.Header["typ"])
	}

	raw := payload(t, token)

	// One token names one audience, and aud is written as that plain string
	// rather than as a one-element array (internal_jwt.md「共通必須クレーム」).
	got, ok := raw["aud"].(string)
	if !ok {
		t.Fatalf("aud = %#v, want the single string %q", raw["aud"], audience)
	}

	if got != audience {
		t.Fatalf("aud = %q, want %q", got, audience)
	}

	return claims, raw
}

func publicKeyFromJWK(t *testing.T, key internaljwt.JWK) *ecdsa.PublicKey {
	t.Helper()

	if key.KeyType != "EC" || key.Curve != "P-256" || key.Algorithm != "ES256" || key.Use != "sig" {
		t.Fatalf("unexpected JWK: %+v", key)
	}

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
		t.Fatalf("parse JWK public key: %v", err)
	}

	return publicKey
}

// payload decodes the JWT payload so that a test can assert on the claim names
// that are present, not only on the values the claim struct holds.
func payload(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	claims := map[string]any{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	return claims
}

func assertAbsent(t *testing.T, claims map[string]any, names ...string) {
	t.Helper()

	for _, name := range names {
		if value, ok := claims[name]; ok {
			t.Errorf("claim %q must be omitted, got %v", name, value)
		}
	}
}

func assertPresent(t *testing.T, claims map[string]any, names ...string) {
	t.Helper()

	for _, name := range names {
		value, ok := claims[name]
		if !ok {
			t.Errorf("claim %q is missing", name)

			continue
		}

		switch value := value.(type) {
		case string:
			if value == "" {
				t.Errorf("claim %q is empty", name)
			}
		case float64, bool:
		default:
			// An array, an object, or a null is never a claim value of the
			// internal JWT; counting one as present would hide, for instance,
			// an aud that was written as an array.
			t.Errorf("claim %q = %#v, want a string or a number", name, value)
		}
	}
}

func assertUUIDv7(t *testing.T, value, name string) {
	t.Helper()

	if len(value) != 36 || value[14] != '7' {
		t.Errorf("%s = %q, want a UUIDv7", name, value)
	}
}

func TestIssueFromExternal(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input ExternalTokenInput
		// absent lists the claims this token_use must not carry.
		absent []string
	}{
		"tenant access": {
			input: ExternalTokenInput{
				Audience:        "tolo-tenant-management",
				TokenUse:        internaljwt.TokenUseTenantAccess,
				Subject:         "user-1",
				ClientID:        "admin-ui",
				Scope:           "tenant.write events.read",
				SourceJTI:       "external-jti-1",
				SourceExpiresAt: fixedNow.Add(15 * time.Minute),
				TenantPublicID:  "0123456789abcdef",
				EventPublicID:   "",
			},
			absent: []string{"origin_sub", "event_id"},
		},
		"event access": {
			input: ExternalTokenInput{
				Audience:        "tolo-observation",
				TokenUse:        internaljwt.TokenUseEventAccess,
				Subject:         "user-2",
				ClientID:        "staff-app",
				Scope:           "events.write",
				SourceJTI:       "external-jti-2",
				SourceExpiresAt: fixedNow.Add(10 * time.Minute),
				TenantPublicID:  "0123456789abcdef",
				EventPublicID:   "fedcba9876543210",
			},
			absent: []string{"origin_sub"},
		},
		"registration": {
			input: ExternalTokenInput{
				Audience:        "tolo-tenant-management",
				TokenUse:        internaljwt.TokenUseRegistration,
				Subject:         "user-3",
				ClientID:        "admin-ui",
				Scope:           "tenant.claim",
				SourceJTI:       "external-jti-3",
				SourceExpiresAt: fixedNow.Add(5 * time.Minute),
				TenantPublicID:  "",
				EventPublicID:   "",
			},
			absent: []string{"origin_sub", "tenant_id", "event_id"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			issuer := newTestIssuer(t)

			issued, err := issuer.IssueFromExternal(t.Context(), test.input)
			if err != nil {
				t.Fatalf("IssueFromExternal: %v", err)
			}

			claims, raw := verify(t, issuer, test.input.Audience, issued.Token)

			if claims.Issuer != "service-gateway" {
				t.Errorf("iss = %q, want service-gateway", claims.Issuer)
			}

			if claims.Subject != test.input.Subject {
				t.Errorf("sub = %q, want %q", claims.Subject, test.input.Subject)
			}

			if claims.TokenUse != test.input.TokenUse {
				t.Errorf("token_use = %q, want %q", claims.TokenUse, test.input.TokenUse)
			}

			if claims.ClientID != test.input.ClientID {
				t.Errorf("client_id = %q, want %q", claims.ClientID, test.input.ClientID)
			}

			if claims.Scope != test.input.Scope {
				t.Errorf("scope = %q, want %q", claims.Scope, test.input.Scope)
			}

			if claims.SourceJTI != test.input.SourceJTI {
				t.Errorf("src_jti = %q, want %q", claims.SourceJTI, test.input.SourceJTI)
			}

			if claims.TenantPublicID != test.input.TenantPublicID {
				t.Errorf("tenant_id = %q, want %q", claims.TenantPublicID, test.input.TenantPublicID)
			}

			if claims.EventPublicID != test.input.EventPublicID {
				t.Errorf("event_id = %q, want %q", claims.EventPublicID, test.input.EventPublicID)
			}

			if !claims.IssuedAt.Time.Equal(fixedNow) || !claims.NotBefore.Time.Equal(fixedNow) {
				t.Errorf("iat/nbf = %v/%v, want %v", claims.IssuedAt, claims.NotBefore, fixedNow)
			}

			if want := fixedNow.Add(DefaultTTL); !claims.ExpiresAt.Time.Equal(want) {
				t.Errorf("exp = %v, want %v", claims.ExpiresAt, want)
			}

			assertUUIDv7(t, claims.ID, "jti")
			assertUUIDv7(t, claims.Txn, "txn")
			assertPresent(t, raw, "iss", "sub", "aud", "iat", "nbf", "exp", "jti", "txn", "token_use", "client_id", "scope", "src_jti")
			assertAbsent(t, raw, test.absent...)

			if issued.Claims.ID != claims.ID || issued.Claims.Txn != claims.Txn {
				t.Error("the returned claims do not match the signed token")
			}
		})
	}
}

func TestIssueFromExternalCapsExpiryAtTheSourceToken(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		sourceExpiresAt time.Time
		want            time.Time
	}{
		"source expires first": {
			sourceExpiresAt: fixedNow.Add(30 * time.Second),
			want:            fixedNow.Add(30 * time.Second),
		},
		"source expires later": {
			sourceExpiresAt: fixedNow.Add(15 * time.Minute),
			want:            fixedNow.Add(DefaultTTL),
		},
		"source expires exactly at the TTL": {
			sourceExpiresAt: fixedNow.Add(DefaultTTL),
			want:            fixedNow.Add(DefaultTTL),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			issuer := newTestIssuer(t)

			input := validExternalTokenInput()
			input.SourceExpiresAt = test.sourceExpiresAt

			issued, err := issuer.IssueFromExternal(t.Context(), input)
			if err != nil {
				t.Fatalf("IssueFromExternal: %v", err)
			}

			claims, _ := verify(t, issuer, input.Audience, issued.Token)
			if !claims.ExpiresAt.Time.Equal(test.want) {
				t.Fatalf("exp = %v, want %v", claims.ExpiresAt, test.want)
			}
		})
	}
}

func validExternalTokenInput() ExternalTokenInput {
	return ExternalTokenInput{
		Audience:        "tolo-tenant-management",
		TokenUse:        internaljwt.TokenUseTenantAccess,
		Subject:         "user-1",
		ClientID:        "admin-ui",
		Scope:           "tenant.write",
		SourceJTI:       "external-jti-1",
		SourceExpiresAt: fixedNow.Add(15 * time.Minute),
		TenantPublicID:  "0123456789abcdef",
		EventPublicID:   "",
	}
}

func TestIssueFromExternalRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*ExternalTokenInput){
		"empty audience":               func(i *ExternalTokenInput) { i.Audience = "" },
		"empty subject":                func(i *ExternalTokenInput) { i.Subject = "" },
		"empty client ID":              func(i *ExternalTokenInput) { i.ClientID = "" },
		"empty scope":                  func(i *ExternalTokenInput) { i.Scope = "" },
		"empty source jti":             func(i *ExternalTokenInput) { i.SourceJTI = "" },
		"zero source expiry":           func(i *ExternalTokenInput) { i.SourceExpiresAt = time.Time{} },
		"source already expired":       func(i *ExternalTokenInput) { i.SourceExpiresAt = fixedNow.Add(-time.Second) },
		"source expiring now":          func(i *ExternalTokenInput) { i.SourceExpiresAt = fixedNow },
		"tenant_access without tenant": func(i *ExternalTokenInput) { i.TenantPublicID = "" },
		"tenant_access with event":     func(i *ExternalTokenInput) { i.EventPublicID = "fedcba9876543210" },
		"event_access without event": func(i *ExternalTokenInput) {
			i.TokenUse = internaljwt.TokenUseEventAccess
			i.EventPublicID = ""
		},
		"event_access without tenant": func(i *ExternalTokenInput) {
			i.TokenUse = internaljwt.TokenUseEventAccess
			i.TenantPublicID = ""
			i.EventPublicID = "fedcba9876543210"
		},
		"registration with tenant": func(i *ExternalTokenInput) {
			i.TokenUse = internaljwt.TokenUseRegistration
		},
		"service token use": func(i *ExternalTokenInput) {
			i.TokenUse = internaljwt.TokenUseService
		},
		"unknown token use": func(i *ExternalTokenInput) {
			i.TokenUse = "administrator"
		},
		"empty token use": func(i *ExternalTokenInput) {
			i.TokenUse = ""
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			issuer := newTestIssuer(t)

			input := validExternalTokenInput()
			mutate(&input)

			if _, err := issuer.IssueFromExternal(t.Context(), input); err == nil {
				t.Fatal("IssueFromExternal accepted an input it must reject")
			}
		})
	}
}

func TestIssueUserOriginService(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		context       internaljwt.Claims
		wantOriginSub string
		wantTenant    string
		wantEvent     string
		absent        []string
	}{
		"first re-issue from an event_access external-token conversion": {
			context: internaljwt.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "service-gateway",
					Subject:   "user-2",
					Audience:  jwt.ClaimStrings{"tolo-observation"},
					ExpiresAt: jwt.NewNumericDate(fixedNow.Add(time.Minute)),
					NotBefore: jwt.NewNumericDate(fixedNow),
					IssuedAt:  jwt.NewNumericDate(fixedNow),
					ID:        "context-jti-1",
				},
				TokenUse:       internaljwt.TokenUseEventAccess,
				ClientID:       "staff-app",
				Txn:            "01920000-0000-7000-8000-000000000001",
				Scope:          "events.write",
				SourceJTI:      "external-jti-2",
				OriginSub:      "",
				TenantPublicID: "0123456789abcdef",
				EventPublicID:  "fedcba9876543210",
			},
			wantOriginSub: "user-2",
			wantTenant:    "0123456789abcdef",
			wantEvent:     "fedcba9876543210",
			absent:        nil,
		},
		"later hop from a user-origin service token": {
			context: internaljwt.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "service-gateway",
					Subject:   "tolo-observation",
					Audience:  jwt.ClaimStrings{"tolo-observation"},
					ExpiresAt: jwt.NewNumericDate(fixedNow.Add(time.Minute)),
					NotBefore: jwt.NewNumericDate(fixedNow),
					IssuedAt:  jwt.NewNumericDate(fixedNow),
					ID:        "context-jti-2",
				},
				TokenUse:       internaljwt.TokenUseService,
				ClientID:       "tolo-observation",
				Txn:            "01920000-0000-7000-8000-000000000002",
				Scope:          "events.read",
				SourceJTI:      "context-jti-1",
				OriginSub:      "user-2",
				TenantPublicID: "0123456789abcdef",
				EventPublicID:  "",
			},
			wantOriginSub: "user-2",
			wantTenant:    "0123456789abcdef",
			wantEvent:     "",
			absent:        []string{"event_id"},
		},
		"registration context carries no tenant": {
			context: internaljwt.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "service-gateway",
					Subject:   "user-3",
					Audience:  jwt.ClaimStrings{"tolo-observation"},
					ExpiresAt: jwt.NewNumericDate(fixedNow.Add(time.Minute)),
					NotBefore: jwt.NewNumericDate(fixedNow),
					IssuedAt:  jwt.NewNumericDate(fixedNow),
					ID:        "context-jti-3",
				},
				TokenUse:       internaljwt.TokenUseRegistration,
				ClientID:       "admin-ui",
				Txn:            "01920000-0000-7000-8000-000000000003",
				Scope:          "tenant.claim",
				SourceJTI:      "external-jti-3",
				OriginSub:      "",
				TenantPublicID: "",
				EventPublicID:  "",
			},
			wantOriginSub: "user-3",
			wantTenant:    "",
			wantEvent:     "",
			absent:        []string{"tenant_id", "event_id"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			issuer := newTestIssuer(t)

			issued, err := issuer.IssueUserOriginService(t.Context(), UserOriginServiceInput{
				Audience:      "tolo-graph-authoring",
				CallerService: "tolo-observation",
				Context:       test.context,
			})
			if err != nil {
				t.Fatalf("IssueUserOriginService: %v", err)
			}

			claims, raw := verify(t, issuer, "tolo-graph-authoring", issued.Token)

			if claims.TokenUse != internaljwt.TokenUseService {
				t.Errorf("token_use = %q, want service", claims.TokenUse)
			}

			if claims.Subject != "tolo-observation" || claims.ClientID != "tolo-observation" {
				t.Errorf("sub/client_id = %q/%q, want the calling service", claims.Subject, claims.ClientID)
			}

			if claims.Txn != test.context.Txn {
				t.Errorf("txn = %q, want the context token's %q", claims.Txn, test.context.Txn)
			}

			if claims.Scope != test.context.Scope {
				t.Errorf("scope = %q, want %q", claims.Scope, test.context.Scope)
			}

			if claims.SourceJTI != test.context.ID {
				t.Errorf("src_jti = %q, want the context token's jti %q", claims.SourceJTI, test.context.ID)
			}

			if claims.OriginSub != test.wantOriginSub {
				t.Errorf("origin_sub = %q, want %q", claims.OriginSub, test.wantOriginSub)
			}

			if claims.TenantPublicID != test.wantTenant || claims.EventPublicID != test.wantEvent {
				t.Errorf("tenant_id/event_id = %q/%q, want %q/%q",
					claims.TenantPublicID, claims.EventPublicID, test.wantTenant, test.wantEvent)
			}

			// The re-issue gets a full TTL of its own: the context token's
			// shorter life does not cap it.
			if want := fixedNow.Add(DefaultTTL); !claims.ExpiresAt.Time.Equal(want) {
				t.Errorf("exp = %v, want %v", claims.ExpiresAt, want)
			}

			assertUUIDv7(t, claims.ID, "jti")

			if claims.ID == test.context.ID {
				t.Error("the re-issued token reuses the context token's jti")
			}

			assertPresent(t, raw, "scope", "src_jti", "origin_sub", "txn")
			assertAbsent(t, raw, test.absent...)
		})
	}
}

func userOriginContext() internaljwt.Claims {
	return internaljwt.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "service-gateway",
			Subject:   "user-1",
			Audience:  jwt.ClaimStrings{"tolo-observation"},
			ExpiresAt: jwt.NewNumericDate(fixedNow.Add(time.Minute)),
			NotBefore: jwt.NewNumericDate(fixedNow),
			IssuedAt:  jwt.NewNumericDate(fixedNow),
			ID:        "context-jti-1",
		},
		TokenUse:       internaljwt.TokenUseTenantAccess,
		ClientID:       "admin-ui",
		Txn:            "01920000-0000-7000-8000-000000000001",
		Scope:          "tenant.write",
		SourceJTI:      "external-jti-1",
		OriginSub:      "",
		TenantPublicID: "0123456789abcdef",
		EventPublicID:  "",
	}
}

func TestIssueUserOriginServiceRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		audience string
		caller   string
		mutate   func(*internaljwt.Claims)
	}{
		"empty audience": {audience: "", caller: "tolo-observation", mutate: nil},
		"empty caller":   {audience: "tolo-graph-authoring", caller: "", mutate: nil},
		"empty scope": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.Scope = ""
		}},
		"empty txn": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.Txn = ""
		}},
		"empty jti": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.ID = ""
		}},
		"empty subject": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.Subject = ""
		}},
		"machine-origin service context": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.TokenUse = internaljwt.TokenUseService
			c.OriginSub = ""
		}},
		"unknown context token use": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.TokenUse = "workload"
		}},
		"context token has expired": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.ExpiresAt = jwt.NewNumericDate(fixedNow.Add(-time.Second))
		}},
		"context token expires now": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.ExpiresAt = jwt.NewNumericDate(fixedNow)
		}},
		"context token without exp": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.ExpiresAt = nil
		}},
		"context token addressed to another service": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.Audience = jwt.ClaimStrings{"tolo-realtime"}
		}},
		"context token without audience": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.Audience = nil
		}},
		"user-origin service context without src_jti": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.TokenUse = internaljwt.TokenUseService
			c.OriginSub = "user-1"
			c.SourceJTI = ""
		}},
		"tenant_access context without src_jti": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.SourceJTI = ""
		}},
		"event_access context without src_jti": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.TokenUse = internaljwt.TokenUseEventAccess
			c.EventPublicID = "fedcba9876543210"
			c.SourceJTI = ""
		}},
		"registration context without src_jti": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.TokenUse = internaljwt.TokenUseRegistration
			c.TenantPublicID = ""
			c.SourceJTI = ""
		}},
		"tenant_access context without tenant_id": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.TenantPublicID = ""
		}},
		"tenant_access context with event_id": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.EventPublicID = "fedcba9876543210"
		}},
		"event_access context without event_id": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.TokenUse = internaljwt.TokenUseEventAccess
		}},
		"registration context with tenant_id": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.TokenUse = internaljwt.TokenUseRegistration
		}},
		"service context with an event but no tenant": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.TokenUse = internaljwt.TokenUseService
			c.OriginSub = "user-1"
			c.TenantPublicID = ""
			c.EventPublicID = "fedcba9876543210"
		}},
		"empty context token use": {audience: "tolo-graph-authoring", caller: "tolo-observation", mutate: func(c *internaljwt.Claims) {
			c.TokenUse = ""
		}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			issuer := newTestIssuer(t)

			claims := userOriginContext()
			if test.mutate != nil {
				test.mutate(&claims)
			}

			_, err := issuer.IssueUserOriginService(t.Context(), UserOriginServiceInput{
				Audience:      test.audience,
				CallerService: test.caller,
				Context:       claims,
			})
			if err == nil {
				t.Fatal("IssueUserOriginService accepted an input it must reject")
			}
		})
	}
}

func machineOriginContext() internaljwt.Claims {
	return internaljwt.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "service-gateway",
			Subject:   "tolo-observation",
			Audience:  jwt.ClaimStrings{"tolo-operation"},
			ExpiresAt: jwt.NewNumericDate(fixedNow.Add(time.Minute)),
			NotBefore: jwt.NewNumericDate(fixedNow),
			IssuedAt:  jwt.NewNumericDate(fixedNow),
			ID:        "context-jti-9",
		},
		TokenUse:       internaljwt.TokenUseService,
		ClientID:       "tolo-observation",
		Txn:            "01920000-0000-7000-8000-000000000009",
		Scope:          "",
		SourceJTI:      "",
		OriginSub:      "",
		TenantPublicID: "",
		EventPublicID:  "",
	}
}

func TestIssueMachineOriginService(t *testing.T) {
	t.Parallel()

	chained := machineOriginContext()

	tests := map[string]struct {
		context *internaljwt.Claims
		wantTxn string
	}{
		"new machine origin": {context: nil, wantTxn: ""},
		"continuing a chain": {context: &chained, wantTxn: chained.Txn},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			issuer := newTestIssuer(t)

			issued, err := issuer.IssueMachineOriginService(t.Context(), MachineOriginServiceInput{
				Audience:      "tolo-notification",
				CallerService: "tolo-operation",
				Context:       test.context,
			})
			if err != nil {
				t.Fatalf("IssueMachineOriginService: %v", err)
			}

			claims, raw := verify(t, issuer, "tolo-notification", issued.Token)

			if claims.TokenUse != internaljwt.TokenUseService {
				t.Errorf("token_use = %q, want service", claims.TokenUse)
			}

			if claims.Subject != "tolo-operation" || claims.ClientID != "tolo-operation" {
				t.Errorf("sub/client_id = %q/%q, want the calling service", claims.Subject, claims.ClientID)
			}

			if test.wantTxn == "" {
				assertUUIDv7(t, claims.Txn, "txn")
			} else if claims.Txn != test.wantTxn {
				t.Errorf("txn = %q, want the context token's %q", claims.Txn, test.wantTxn)
			}

			if want := fixedNow.Add(DefaultTTL); !claims.ExpiresAt.Time.Equal(want) {
				t.Errorf("exp = %v, want %v", claims.ExpiresAt, want)
			}

			assertUUIDv7(t, claims.ID, "jti")
			assertPresent(t, raw, "iss", "sub", "aud", "iat", "nbf", "exp", "jti", "txn", "token_use", "client_id")
			assertAbsent(t, raw, "scope", "src_jti", "origin_sub", "tenant_id", "event_id")
		})
	}
}

func TestIssueMachineOriginServiceRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		audience string
		caller   string
		mutate   func(*internaljwt.Claims)
	}{
		"empty audience": {audience: "", caller: "tolo-operation", mutate: nil},
		"empty caller":   {audience: "tolo-notification", caller: "", mutate: nil},
		"context is not a service token": {audience: "tolo-notification", caller: "tolo-operation", mutate: func(c *internaljwt.Claims) {
			c.TokenUse = internaljwt.TokenUseTenantAccess
		}},
		"context carries scope": {audience: "tolo-notification", caller: "tolo-operation", mutate: func(c *internaljwt.Claims) {
			c.Scope = "events.read"
		}},
		"context carries src_jti": {audience: "tolo-notification", caller: "tolo-operation", mutate: func(c *internaljwt.Claims) {
			c.SourceJTI = "context-jti-1"
		}},
		"context carries origin_sub": {audience: "tolo-notification", caller: "tolo-operation", mutate: func(c *internaljwt.Claims) {
			c.OriginSub = "user-1"
		}},
		"context carries tenant_id": {audience: "tolo-notification", caller: "tolo-operation", mutate: func(c *internaljwt.Claims) {
			c.TenantPublicID = "0123456789abcdef"
		}},
		"context carries event_id": {audience: "tolo-notification", caller: "tolo-operation", mutate: func(c *internaljwt.Claims) {
			c.EventPublicID = "fedcba9876543210"
		}},
		"context without txn": {audience: "tolo-notification", caller: "tolo-operation", mutate: func(c *internaljwt.Claims) {
			c.Txn = ""
		}},
		"context token has expired": {audience: "tolo-notification", caller: "tolo-operation", mutate: func(c *internaljwt.Claims) {
			c.ExpiresAt = jwt.NewNumericDate(fixedNow.Add(-time.Second))
		}},
		"context token without exp": {audience: "tolo-notification", caller: "tolo-operation", mutate: func(c *internaljwt.Claims) {
			c.ExpiresAt = nil
		}},
		"context token addressed to another service": {audience: "tolo-notification", caller: "tolo-operation", mutate: func(c *internaljwt.Claims) {
			c.Audience = jwt.ClaimStrings{"tolo-realtime"}
		}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			issuer := newTestIssuer(t)

			var context *internaljwt.Claims

			if test.mutate != nil {
				claims := machineOriginContext()
				test.mutate(&claims)
				context = &claims
			}

			_, err := issuer.IssueMachineOriginService(t.Context(), MachineOriginServiceInput{
				Audience:      test.audience,
				CallerService: test.caller,
				Context:       context,
			})
			if err == nil {
				t.Fatal("IssueMachineOriginService accepted an input it must reject")
			}
		})
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	provider := staticKeyProvider{
		keys: KeySet{Signing: SigningKey{KeyID: "signing-1", Key: newTestKey(t)}, Published: nil},
		err:  nil,
	}

	if _, err := New("", provider); err == nil {
		t.Error("New accepted an empty issuer ID")
	}

	if _, err := New("service-gateway", nil); err == nil {
		t.Error("New accepted a nil key provider")
	}

	if _, err := New("service-gateway", provider, WithTTL(0)); err == nil {
		t.Error("New accepted a zero TTL")
	}

	if _, err := New("service-gateway", provider, WithTTL(-time.Second)); err == nil {
		t.Error("New accepted a negative TTL")
	}

	if _, err := New("service-gateway", provider, WithClock(nil)); err == nil {
		t.Error("New accepted a nil clock")
	}
}

func TestWithTTLShortensTheToken(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t, WithTTL(30*time.Second))

	issued, err := issuer.IssueMachineOriginService(t.Context(), MachineOriginServiceInput{
		Audience:      "tolo-notification",
		CallerService: "tolo-operation",
		Context:       nil,
	})
	if err != nil {
		t.Fatalf("IssueMachineOriginService: %v", err)
	}

	claims, _ := verify(t, issuer, "tolo-notification", issued.Token)
	if want := fixedNow.Add(30 * time.Second); !claims.ExpiresAt.Time.Equal(want) {
		t.Fatalf("exp = %v, want %v", claims.ExpiresAt, want)
	}
}

func TestIssueReportsKeyProviderFailure(t *testing.T) {
	t.Parallel()

	provider := staticKeyProvider{keys: KeySet{}, err: errors.New("no keys")}

	issuer, err := New("service-gateway", provider, WithClock(func() time.Time { return fixedNow }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := issuer.IssueFromExternal(t.Context(), validExternalTokenInput()); err == nil {
		t.Error("IssueFromExternal ignored a key provider failure")
	}

	_, err = issuer.IssueUserOriginService(t.Context(), UserOriginServiceInput{
		Audience:      "tolo-graph-authoring",
		CallerService: "tolo-observation",
		Context:       userOriginContext(),
	})
	if err == nil {
		t.Error("IssueUserOriginService ignored a key provider failure")
	}

	if _, err := issuer.IssueMachineOriginService(t.Context(), MachineOriginServiceInput{
		Audience:      "tolo-notification",
		CallerService: "tolo-operation",
		Context:       nil,
	}); err == nil {
		t.Error("IssueMachineOriginService ignored a key provider failure")
	}

	if _, err := issuer.JWKS(t.Context()); err == nil {
		t.Error("JWKS ignored a key provider failure")
	}
}

func TestJWKSPublishesTheSigningKeyAndThePublishedKeys(t *testing.T) {
	t.Parallel()

	signing := newTestKey(t)
	incoming := newTestKey(t)
	outgoing := newTestKey(t)

	provider := staticKeyProvider{
		keys: KeySet{
			Signing: SigningKey{KeyID: "signing-1", Key: signing},
			Published: []PublishedKey{
				{KeyID: "incoming", Key: &incoming.PublicKey},
				{KeyID: "outgoing", Key: &outgoing.PublicKey},
			},
		},
		err: nil,
	}

	issuer, err := New("service-gateway", provider, WithClock(func() time.Time { return fixedNow }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	jwks, err := issuer.JWKS(t.Context())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	if len(jwks.Keys) != 3 {
		t.Fatalf("JWKS has %d keys, want 3", len(jwks.Keys))
	}

	byKeyID := make(map[string]*ecdsa.PublicKey, len(jwks.Keys))
	for _, key := range jwks.Keys {
		byKeyID[key.KeyID] = publicKeyFromJWK(t, key)
	}

	for keyID, want := range map[string]*ecdsa.PublicKey{
		"signing-1": &signing.PublicKey,
		"incoming":  &incoming.PublicKey,
		"outgoing":  &outgoing.PublicKey,
	} {
		got, ok := byKeyID[keyID]
		if !ok {
			t.Errorf("the JWKS is missing key %q", keyID)

			continue
		}

		if !got.Equal(want) {
			t.Errorf("the JWKS key %q is not the configured key", keyID)
		}
	}
}

func TestJWKSRejectsDuplicateKeyIDs(t *testing.T) {
	t.Parallel()

	signing := newTestKey(t)
	other := newTestKey(t)

	tests := map[string][]PublishedKey{
		"duplicate of the signing key": {{KeyID: "signing-1", Key: &other.PublicKey}},
		"duplicate among published": {
			{KeyID: "incoming", Key: &other.PublicKey},
			{KeyID: "incoming", Key: &signing.PublicKey},
		},
	}

	for name, published := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider := staticKeyProvider{
				keys: KeySet{
					Signing:   SigningKey{KeyID: "signing-1", Key: signing},
					Published: published,
				},
				err: nil,
			}

			issuer, err := New("service-gateway", provider, WithClock(func() time.Time { return fixedNow }))
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			if _, err := issuer.JWKS(t.Context()); err == nil {
				t.Fatal("JWKS accepted a duplicate key ID")
			}
		})
	}
}

// TestIssueMintsFreshIdentifiers covers that nothing is reused between two
// issues: every conversion and re-issue gets its own jti, and every external token conversion
// and new machine origin its own txn (service_gateway.md「TTL と再利用」).
func TestIssueMintsFreshIdentifiers(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t)

	const issues = 8

	jtis := make(map[string]struct{}, issues*3)
	txns := make(map[string]struct{}, issues*2)

	for range issues {
		external, err := issuer.IssueFromExternal(t.Context(), validExternalTokenInput())
		if err != nil {
			t.Fatalf("IssueFromExternal: %v", err)
		}

		machine, err := issuer.IssueMachineOriginService(t.Context(), MachineOriginServiceInput{
			Audience:      "tolo-notification",
			CallerService: "tolo-operation",
			Context:       nil,
		})
		if err != nil {
			t.Fatalf("IssueMachineOriginService: %v", err)
		}

		user, err := issuer.IssueUserOriginService(t.Context(), UserOriginServiceInput{
			Audience:      "tolo-graph-authoring",
			CallerService: "tolo-observation",
			Context:       userOriginContext(),
		})
		if err != nil {
			t.Fatalf("IssueUserOriginService: %v", err)
		}

		for _, issued := range []Issued{external, machine, user} {
			if _, seen := jtis[issued.Claims.ID]; seen {
				t.Fatalf("jti %q was issued twice", issued.Claims.ID)
			}

			jtis[issued.Claims.ID] = struct{}{}
		}

		for _, issued := range []Issued{external, machine} {
			if _, seen := txns[issued.Claims.Txn]; seen {
				t.Fatalf("txn %q was generated twice", issued.Claims.Txn)
			}

			txns[issued.Claims.Txn] = struct{}{}
		}
	}

	if len(jtis) != issues*3 || len(txns) != issues*2 {
		t.Fatalf("collected %d jti and %d txn, want %d and %d", len(jtis), len(txns), issues*3, issues*2)
	}
}

func TestNewReturnsConfigurationErrors(t *testing.T) {
	t.Parallel()

	provider := staticKeyProvider{keys: KeySet{}, err: nil}

	tests := map[string]struct {
		id   string
		keys KeyProvider
		opts []Option
		want error
	}{
		"empty issuer ID": {id: "", keys: provider, opts: nil, want: ErrMissingIssuerID},
		"nil provider":    {id: "gw", keys: nil, opts: nil, want: ErrMissingKeyProvider},
		"zero TTL":        {id: "gw", keys: provider, opts: []Option{WithTTL(0)}, want: ErrNonPositiveTTL},
		"nil clock":       {id: "gw", keys: provider, opts: []Option{WithClock(nil)}, want: ErrMissingClock},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := New(test.id, test.keys, test.opts...); !errors.Is(err, test.want) {
				t.Fatalf("New returned %v, want %v", err, test.want)
			}
		})
	}
}

func TestIssueErrorsMatchTheirSentinels(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t)

	tests := map[string]struct {
		issue func() error
		want  error
	}{
		"external token conversion without audience": {
			issue: func() error {
				input := validExternalTokenInput()
				input.Audience = ""
				_, err := issuer.IssueFromExternal(t.Context(), input)

				return err
			},
			want: ErrMissingAudience,
		},
		"external token conversion with an unknown token use": {
			issue: func() error {
				input := validExternalTokenInput()
				input.TokenUse = "unknown"
				_, err := issuer.IssueFromExternal(t.Context(), input)

				return err
			},
			want: ErrUnsupportedTokenUse,
		},
		"external token conversion with an expired source token": {
			issue: func() error {
				input := validExternalTokenInput()
				input.SourceExpiresAt = fixedNow.Add(-time.Second)
				_, err := issuer.IssueFromExternal(t.Context(), input)

				return err
			},
			want: ErrSourceExpired,
		},
		"user-origin re-issue from a context without exp": {
			issue: func() error {
				context := userOriginContext()
				context.ExpiresAt = nil
				_, err := issuer.IssueUserOriginService(t.Context(), UserOriginServiceInput{
					Audience: "tolo-graph-authoring", CallerService: "tolo-observation", Context: context,
				})

				return err
			},
			want: ErrContextMissingExpiry,
		},
		"user-origin re-issue from a context missing its tenant": {
			issue: func() error {
				context := userOriginContext()
				context.TokenUse = internaljwt.TokenUseTenantAccess
				context.TenantPublicID = ""
				_, err := issuer.IssueUserOriginService(t.Context(), UserOriginServiceInput{
					Audience: "tolo-graph-authoring", CallerService: "tolo-observation", Context: context,
				})

				return err
			},
			want: ErrMissingTenantPublicID,
		},
		"machine-origin re-issue from a user context": {
			issue: func() error {
				context := userOriginContext()
				_, err := issuer.IssueMachineOriginService(t.Context(), MachineOriginServiceInput{
					Audience: "tolo-notification", CallerService: "tolo-observation", Context: &context,
				})

				return err
			},
			want: ErrMachineContextNotService,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if err := test.issue(); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestKeyProviderFailureIsWrapped(t *testing.T) {
	t.Parallel()

	cause := errors.New("no keys")
	provider := staticKeyProvider{keys: KeySet{}, err: cause}

	issuer, err := New("service-gateway", provider, WithClock(func() time.Time { return fixedNow }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = issuer.IssueFromExternal(t.Context(), validExternalTokenInput())
	if !errors.Is(err, ErrKeyProvider) {
		t.Fatalf("got %v, want %v", err, ErrKeyProvider)
	}

	if !errors.Is(err, cause) {
		t.Fatal("the provider's failure is not reachable through the error chain")
	}
}
