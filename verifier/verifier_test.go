package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/jwtgen"
)

const (
	testIssuerID       = "service-gateway"
	testAudience       = "tolo-tenant-management"
	testKeyID          = "test-key"
	testTenantPublicID = "0123456789abcdef"
	testEventPublicID  = "fedcba9876543210"
	testScope          = "tenant.read"
)

// testNow is the clock every hand-signed token is verified against, so that
// exp, nbf, and iat are exact rather than approximate.
var testNow = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

// errNoSuchKey is what the test resolver returns for a kid it does not hold.
// A caller must be able to reach it through ErrUnknownKey.
var errNoSuchKey = errors.New("no such test key")

// staticKeys resolves the kids of a fixed set of keys.
type staticKeys struct {
	keys map[string]*ecdsa.PublicKey
}

func (s staticKeys) Key(_ context.Context, keyID string) (*ecdsa.PublicKey, error) {
	key, ok := s.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", errNoSuchKey, keyID)
	}

	return key, nil
}

// resolverFor is the key resolver of a JWKS, the way a service holds the
// Service Gateway's keys.
func resolverFor(t *testing.T, document internaljwt.JWKS) staticKeys {
	t.Helper()

	keys := make(map[string]*ecdsa.PublicKey, len(document.Keys))

	for _, jwk := range document.Keys {
		key, err := internaljwt.PublicKey(jwk)
		if err != nil {
			t.Fatalf("public key %q: %v", jwk.KeyID, err)
		}

		keys[jwk.KeyID] = key
	}

	return staticKeys{keys: keys}
}

func newVerifier(t *testing.T, keys KeyResolver, opts ...Option) *Verifier {
	t.Helper()

	verifier, err := New(testIssuerID, testAudience, keys, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return verifier
}

// generate mints a token the way the Service Gateway would.
func generate(t *testing.T, config jwtgen.Config) jwtgen.Output {
	t.Helper()

	config.Issuer = testIssuerID
	config.Audience = testAudience

	output, err := jwtgen.Generate(config)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	return output
}

// claimsJSON is the wire form of a claim set, which compares two of them
// without tripping over the monotonic clock a time.Time carries.
func claimsJSON(t *testing.T, claims internaljwt.Claims) string {
	t.Helper()

	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	return string(encoded)
}

// signer signs tokens no issuer would produce, so that a test can leave a
// claim out, change one, or sign under the wrong algorithm.
type signer struct {
	key   *ecdsa.PrivateKey
	keyID string
	keys  staticKeys
}

func newSigner(t *testing.T) signer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return signer{
		key:   key,
		keyID: testKeyID,
		keys:  staticKeys{keys: map[string]*ecdsa.PublicKey{testKeyID: &key.PublicKey}},
	}
}

// sign signs claims under the signer's own key and kid.
func (s signer) sign(t *testing.T, claims internaljwt.Claims) string {
	t.Helper()

	return signWith(t, jwt.SigningMethodES256, s.key, s.keyID, claims)
}

// signWith signs claims with an arbitrary method and key. A blank keyID
// leaves the kid header out.
func signWith(t *testing.T, method jwt.SigningMethod, key any, keyID string, claims internaljwt.Claims) string {
	t.Helper()

	token := jwt.NewWithClaims(method, claims)
	if keyID != "" {
		token.Header["kid"] = keyID
	}

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return signed
}

// signTyped signs claims under the signer's own key with the typ header set
// to tokenType. A blank tokenType leaves the header out entirely.
func (s signer) signTyped(t *testing.T, tokenType string, claims internaljwt.Claims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = s.keyID

	if tokenType == "" {
		delete(token.Header, "typ")
	} else {
		token.Header["typ"] = tokenType
	}

	signed, err := token.SignedString(s.key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return signed
}

// validClaims is a claim set every check accepts, which a test then breaks in
// exactly one way.
func validClaims() internaljwt.Claims {
	return internaljwt.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuerID,
			Subject:   "user-1",
			Audience:  jwt.ClaimStrings{testAudience},
			ExpiresAt: jwt.NewNumericDate(testNow.Add(time.Minute)),
			NotBefore: jwt.NewNumericDate(testNow),
			IssuedAt:  jwt.NewNumericDate(testNow),
			ID:        "jti-1",
		},
		TokenUse:       internaljwt.TokenUseTenantAccess,
		ClientID:       "client-1",
		Txn:            "txn-1",
		Scope:          testScope,
		SourceJTI:      "src-jti-1",
		OriginSub:      "",
		TenantPublicID: testTenantPublicID,
		EventPublicID:  "",
	}
}

// fixedClock holds the verifier's clock at testNow.
func fixedClock() Option {
	return WithClock(func() time.Time { return testNow })
}

func TestNewRejectsAnIncompleteConfiguration(t *testing.T) {
	t.Parallel()

	keys := staticKeys{keys: map[string]*ecdsa.PublicKey{}}

	tests := map[string]struct {
		issuerID string
		audience string
		keys     KeyResolver
		opts     []Option
		want     error
	}{
		"without an issuer ID": {
			issuerID: "", audience: testAudience, keys: keys, opts: nil, want: ErrMissingIssuerID,
		},
		"without an audience": {
			issuerID: testIssuerID, audience: "", keys: keys, opts: nil, want: ErrMissingAudience,
		},
		"without a key resolver": {
			issuerID: testIssuerID, audience: testAudience, keys: nil, opts: nil, want: ErrMissingKeyResolver,
		},
		"with a negative leeway": {
			issuerID: testIssuerID, audience: testAudience, keys: keys,
			opts: []Option{WithLeeway(-time.Second)}, want: ErrNegativeLeeway,
		},
		"without a clock": {
			issuerID: testIssuerID, audience: testAudience, keys: keys,
			opts: []Option{WithClock(nil)}, want: ErrMissingClock,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			verifier, err := New(test.issuerID, test.audience, test.keys, test.opts...)
			if !errors.Is(err, test.want) {
				t.Fatalf("New = %v, want %v", err, test.want)
			}

			if verifier != nil {
				t.Fatal("New returned a verifier alongside an error")
			}
		})
	}
}

func TestNewDefaultsTheLeewayToTheClockSkew(t *testing.T) {
	t.Parallel()

	verifier := newVerifier(t, staticKeys{keys: map[string]*ecdsa.PublicKey{}})
	if verifier.leeway != DefaultLeeway {
		t.Fatalf("leeway = %s, want %s", verifier.leeway, DefaultLeeway)
	}
}

func TestVerifyAcceptsEveryTokenUse(t *testing.T) {
	t.Parallel()

	tests := map[string]jwtgen.Config{
		"tenant_access": {
			TokenUse: internaljwt.TokenUseTenantAccess, Scope: testScope,
			TenantPublicID: testTenantPublicID,
		},
		"event_access": {
			TokenUse: internaljwt.TokenUseEventAccess, Scope: testScope,
			TenantPublicID: testTenantPublicID, EventPublicID: testEventPublicID,
		},
		"registration": {
			TokenUse: internaljwt.TokenUseRegistration, Scope: testScope,
		},
		"machine-origin service": {
			TokenUse: internaljwt.TokenUseService,
		},
		"user-origin service": {
			TokenUse: internaljwt.TokenUseService, Scope: testScope, OriginSub: "user-1",
			TenantPublicID: testTenantPublicID,
		},
		"user-origin service without a binding": {
			TokenUse: internaljwt.TokenUseService, Scope: testScope, OriginSub: "user-1",
		},
		"user-origin service bound to an event": {
			TokenUse: internaljwt.TokenUseService, Scope: testScope, OriginSub: "user-1",
			TenantPublicID: testTenantPublicID, EventPublicID: testEventPublicID,
		},
	}

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			output := generate(t, config)
			verifier := newVerifier(t, resolverFor(t, output.JWKS))

			claims, err := verifier.Verify(t.Context(), output.Token)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}

			if got, want := claimsJSON(t, claims), claimsJSON(t, output.Claims); got != want {
				t.Fatalf("claims = %s, want %s", got, want)
			}
		})
	}
}

func TestVerifyRejectsAnEmptyToken(t *testing.T) {
	t.Parallel()

	verifier := newVerifier(t, staticKeys{keys: map[string]*ecdsa.PublicKey{}})

	if _, err := verifier.Verify(t.Context(), ""); !errors.Is(err, ErrMissingToken) {
		t.Fatalf("Verify = %v, want %v", err, ErrMissingToken)
	}
}

func TestVerifyRejectsAnUnverifiableToken(t *testing.T) {
	t.Parallel()

	signer := newSigner(t)
	other := newSigner(t)

	tests := map[string]struct {
		token func(t *testing.T) string
		want  []error
	}{
		"signed by another key": {
			token: func(t *testing.T) string {
				t.Helper()

				return signWith(t, jwt.SigningMethodES256, other.key, testKeyID, validClaims())
			},
			want: []error{ErrInvalidToken, jwt.ErrTokenSignatureInvalid},
		},
		"signed under an unknown kid": {
			token: func(t *testing.T) string {
				t.Helper()

				return signWith(t, jwt.SigningMethodES256, signer.key, "rotated-away", validClaims())
			},
			want: []error{ErrInvalidToken, ErrUnknownKey, errNoSuchKey, jwt.ErrTokenUnverifiable},
		},
		"without a kid header": {
			token: func(t *testing.T) string {
				t.Helper()

				return signWith(t, jwt.SigningMethodES256, signer.key, "", validClaims())
			},
			want: []error{ErrInvalidToken, ErrMissingKeyID, jwt.ErrTokenUnverifiable},
		},
		"signed with alg none": {
			token: func(t *testing.T) string {
				t.Helper()

				return signWith(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, testKeyID, validClaims())
			},
			want: []error{ErrInvalidToken, jwt.ErrTokenSignatureInvalid},
		},
		"signed with HS256": {
			token: func(t *testing.T) string {
				t.Helper()

				return signWith(t, jwt.SigningMethodHS256, []byte("shared secret"), testKeyID, validClaims())
			},
			want: []error{ErrInvalidToken, jwt.ErrTokenSignatureInvalid},
		},
		"not a JWT at all": {
			token: func(t *testing.T) string {
				t.Helper()

				return "not-a-token"
			},
			want: []error{ErrInvalidToken, jwt.ErrTokenMalformed},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			verifier := newVerifier(t, signer.keys, fixedClock())

			_, err := verifier.Verify(t.Context(), test.token(t))
			for _, want := range test.want {
				if !errors.Is(err, want) {
					t.Fatalf("Verify = %v, want it to wrap %v", err, want)
				}
			}
		})
	}
}

func TestVerifyRejectsAnInvalidRegisteredClaim(t *testing.T) {
	t.Parallel()

	signer := newSigner(t)

	tests := map[string]struct {
		mutate func(claims *internaljwt.Claims)
		want   error
		detail string
	}{
		"expired beyond the leeway": {
			mutate: func(claims *internaljwt.Claims) {
				claims.ExpiresAt = jwt.NewNumericDate(testNow.Add(-DefaultLeeway - time.Second))
			},
			want: jwt.ErrTokenExpired, detail: "",
		},
		"without exp": {
			mutate: func(claims *internaljwt.Claims) { claims.ExpiresAt = nil },
			want:   jwt.ErrTokenRequiredClaimMissing, detail: "",
		},
		"not valid yet": {
			mutate: func(claims *internaljwt.Claims) {
				claims.NotBefore = jwt.NewNumericDate(testNow.Add(time.Minute))
			},
			want: jwt.ErrTokenNotValidYet, detail: "",
		},
		"issued in the future": {
			mutate: func(claims *internaljwt.Claims) {
				claims.IssuedAt = jwt.NewNumericDate(testNow.Add(time.Minute))
			},
			want: jwt.ErrTokenUsedBeforeIssued, detail: "",
		},
		"from another issuer": {
			mutate: func(claims *internaljwt.Claims) { claims.Issuer = "someone-else" },
			want:   jwt.ErrTokenInvalidIssuer, detail: "",
		},
		"for another audience": {
			mutate: func(claims *internaljwt.Claims) {
				claims.Audience = jwt.ClaimStrings{"tolo-observation"}
			},
			want: jwt.ErrTokenInvalidAudience, detail: "",
		},
		"naming two audiences": {
			mutate: func(claims *internaljwt.Claims) {
				claims.Audience = jwt.ClaimStrings{testAudience, "tolo-observation"}
			},
			want: ErrAudienceCount, detail: "",
		},
		"without sub": {
			mutate: func(claims *internaljwt.Claims) { claims.Subject = "" },
			want:   ErrMissingClaim, detail: "sub",
		},
		"without jti": {
			mutate: func(claims *internaljwt.Claims) { claims.ID = "" },
			want:   ErrMissingClaim, detail: "jti",
		},
		"without nbf": {
			mutate: func(claims *internaljwt.Claims) { claims.NotBefore = nil },
			want:   ErrMissingClaim, detail: "nbf",
		},
		"without iat": {
			mutate: func(claims *internaljwt.Claims) { claims.IssuedAt = nil },
			want:   ErrMissingClaim, detail: "iat",
		},
		"without token_use": {
			mutate: func(claims *internaljwt.Claims) { claims.TokenUse = "" },
			want:   ErrMissingClaim, detail: "token_use",
		},
		"without client_id": {
			mutate: func(claims *internaljwt.Claims) { claims.ClientID = "" },
			want:   ErrMissingClaim, detail: "client_id",
		},
		"without txn": {
			mutate: func(claims *internaljwt.Claims) { claims.Txn = "" },
			want:   ErrMissingClaim, detail: "txn",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			claims := validClaims()
			test.mutate(&claims)

			verifier := newVerifier(t, signer.keys, fixedClock())

			_, err := verifier.Verify(t.Context(), signer.sign(t, claims))
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify = %v, want %v", err, test.want)
			}

			if test.detail != "" && !strings.Contains(err.Error(), test.detail) {
				t.Fatalf("Verify = %v, want it to name %q", err, test.detail)
			}
		})
	}
}

func TestVerifyToleratesTheClockSkew(t *testing.T) {
	t.Parallel()

	signer := newSigner(t)

	// One second inside the tolerated skew, on each claim the leeway covers.
	within := DefaultLeeway - time.Second

	tests := map[string]func(claims *internaljwt.Claims){
		"exp just behind": func(claims *internaljwt.Claims) {
			claims.ExpiresAt = jwt.NewNumericDate(testNow.Add(-within))
		},
		"nbf just ahead": func(claims *internaljwt.Claims) {
			claims.NotBefore = jwt.NewNumericDate(testNow.Add(within))
		},
		"iat just ahead": func(claims *internaljwt.Claims) {
			claims.IssuedAt = jwt.NewNumericDate(testNow.Add(within))
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			claims := validClaims()
			mutate(&claims)

			verifier := newVerifier(t, signer.keys, fixedClock())

			if _, err := verifier.Verify(t.Context(), signer.sign(t, claims)); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestVerifyRejectsBeyondTheClockSkew(t *testing.T) {
	t.Parallel()

	signer := newSigner(t)

	// One second outside the tolerated skew, on each claim the leeway covers.
	beyond := DefaultLeeway + time.Second

	tests := map[string]struct {
		mutate func(claims *internaljwt.Claims)
		want   error
	}{
		"exp too far behind": {
			mutate: func(claims *internaljwt.Claims) {
				claims.ExpiresAt = jwt.NewNumericDate(testNow.Add(-beyond))
			},
			want: jwt.ErrTokenExpired,
		},
		"nbf too far ahead": {
			mutate: func(claims *internaljwt.Claims) {
				claims.NotBefore = jwt.NewNumericDate(testNow.Add(beyond))
			},
			want: jwt.ErrTokenNotValidYet,
		},
		"iat too far ahead": {
			mutate: func(claims *internaljwt.Claims) {
				claims.IssuedAt = jwt.NewNumericDate(testNow.Add(beyond))
			},
			want: jwt.ErrTokenUsedBeforeIssued,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			claims := validClaims()
			test.mutate(&claims)

			verifier := newVerifier(t, signer.keys, fixedClock())

			_, err := verifier.Verify(t.Context(), signer.sign(t, claims))
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify = %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifyChecksTheTokenType(t *testing.T) {
	t.Parallel()

	signer := newSigner(t)

	tests := map[string]struct {
		tokenType string
		want      error
	}{
		"JWT":            {tokenType: "JWT", want: nil},
		"jwt":            {tokenType: "jwt", want: nil},
		"missing":        {tokenType: "", want: ErrUnexpectedTokenType},
		"at+jwt":         {tokenType: "at+jwt", want: ErrUnexpectedTokenType},
		"another format": {tokenType: "JWS", want: ErrUnexpectedTokenType},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			verifier := newVerifier(t, signer.keys, fixedClock())

			_, err := verifier.Verify(t.Context(), signer.signTyped(t, test.tokenType, validClaims()))
			if test.want == nil {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}

				return
			}

			if !errors.Is(err, test.want) || !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Verify = %v, want it to wrap %v and %v", err, ErrInvalidToken, test.want)
			}
		})
	}
}

func TestVerifyHonoursTheConfiguredLeeway(t *testing.T) {
	t.Parallel()

	signer := newSigner(t)
	verifier := newVerifier(t, signer.keys, fixedClock(), WithLeeway(0))

	claims := validClaims()
	claims.ExpiresAt = jwt.NewNumericDate(testNow.Add(-time.Second))

	_, err := verifier.Verify(t.Context(), signer.sign(t, claims))
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("Verify = %v, want %v", err, jwt.ErrTokenExpired)
	}
}
