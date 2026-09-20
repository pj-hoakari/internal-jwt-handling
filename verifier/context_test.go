package verifier

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/jwtgen"
)

const testOtherService = "tolo-observation"

func newContextVerifier(t *testing.T, keys KeyResolver, opts ...Option) *ContextVerifier {
	t.Helper()

	contextVerifier, err := NewContextVerifier(testIssuerID, keys, opts...)
	if err != nil {
		t.Fatalf("NewContextVerifier: %v", err)
	}

	return contextVerifier
}

func generateFor(t *testing.T, audience string, config jwtgen.Config) jwtgen.Output {
	t.Helper()

	config.Issuer = testIssuerID
	config.Audience = audience

	output, err := jwtgen.Generate(config)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	return output
}

func contextTokensFor(t *testing.T, audiences ...string) (*ContextVerifier, map[string]string) {
	t.Helper()

	generator, err := jwtgen.NewGenerator(testKeyID)
	if err != nil {
		t.Fatalf("jwtgen.NewGenerator: %v", err)
	}

	tokens := make(map[string]string, len(audiences))

	for _, audience := range audiences {
		output, err := generator.Generate(jwtgen.Config{
			Issuer:   testIssuerID,
			Audience: audience,
			TokenUse: internaljwt.TokenUseService,
		})
		if err != nil {
			t.Fatalf("generate token for %q: %v", audience, err)
		}

		tokens[audience] = output.Token
	}

	document, err := generator.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	return newContextVerifier(t, resolverFor(t, document)), tokens
}

func TestContextVerifyAcceptsATokenAddressedToThePresenter(t *testing.T) {
	t.Parallel()

	tests := map[string]jwtgen.Config{
		"tenant_access": {
			TokenUse: internaljwt.TokenUseTenantAccess, Scope: testScope,
			TenantPublicID: testTenantPublicID,
		},
		"user-origin service": {
			TokenUse: internaljwt.TokenUseService, Scope: testScope, OriginSub: "user-1",
			TenantPublicID: testTenantPublicID,
		},
		"machine-origin service": {
			TokenUse: internaljwt.TokenUseService,
		},
	}

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			output := generateFor(t, testAudience, config)
			contextVerifier := newContextVerifier(t, resolverFor(t, output.JWKS))

			claims, err := contextVerifier.Verify(t.Context(), output.Token, testAudience)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}

			if got, want := claimsJSON(t, claims), claimsJSON(t, output.Claims); got != want {
				t.Fatalf("claims = %s, want %s", got, want)
			}
		})
	}
}

func TestContextVerifyRejectsATokenAddressedToAnotherService(t *testing.T) {
	t.Parallel()

	output := generateFor(t, testAudience, jwtgen.Config{TokenUse: internaljwt.TokenUseService})
	contextVerifier := newContextVerifier(t, resolverFor(t, output.JWKS))

	_, err := contextVerifier.Verify(t.Context(), output.Token, testOtherService)
	for _, want := range []error{ErrInvalidToken, jwt.ErrTokenInvalidAudience} {
		if !errors.Is(err, want) {
			t.Fatalf("Verify = %v, want it to wrap %v", err, want)
		}
	}
}

func TestContextVerifyTakesThePresenterOfEachCall(t *testing.T) {
	t.Parallel()

	contextVerifier, tokens := contextTokensFor(t, testAudience, testOtherService)
	ctx := t.Context()

	for _, audience := range []string{testAudience, testOtherService} {
		claims, err := contextVerifier.Verify(ctx, tokens[audience], audience)
		if err != nil {
			t.Fatalf("Verify as %q: %v", audience, err)
		}

		if got := strings.Join(claims.Audience, " "); got != audience {
			t.Fatalf("aud = %q, want %q", got, audience)
		}
	}

	_, err := contextVerifier.Verify(ctx, tokens[testAudience], testOtherService)
	if !errors.Is(err, jwt.ErrTokenInvalidAudience) {
		t.Fatalf("Verify = %v, want %v", err, jwt.ErrTokenInvalidAudience)
	}
}

func TestContextVerifyIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	contextVerifier, tokens := contextTokensFor(t, testAudience, testOtherService)
	ctx := t.Context()

	var callers sync.WaitGroup

	for range 16 {
		for audience, token := range tokens {
			callers.Add(1)

			go func() {
				defer callers.Done()

				claims, err := contextVerifier.Verify(ctx, token, audience)
				if err != nil {
					t.Errorf("Verify as %q: %v", audience, err)

					return
				}

				if got := strings.Join(claims.Audience, " "); got != audience {
					t.Errorf("aud = %q, want %q", got, audience)
				}
			}()

			callers.Add(1)

			go func() {
				defer callers.Done()

				if _, err := contextVerifier.Verify(ctx, token, "someone-else"); !errors.Is(err, ErrInvalidToken) {
					t.Errorf("Verify = %v, want it to wrap %v", err, ErrInvalidToken)
				}
			}()
		}
	}

	callers.Wait()
}

func TestContextVerifyRejectsAnEmptyPresenterOrToken(t *testing.T) {
	t.Parallel()

	output := generateFor(t, testAudience, jwtgen.Config{TokenUse: internaljwt.TokenUseService})

	tests := map[string]struct {
		token     string
		presenter string
		want      error
	}{
		"without a presenter": {token: output.Token, presenter: "", want: ErrMissingAudience},
		"without a token":     {token: "", presenter: testAudience, want: ErrMissingToken},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			contextVerifier := newContextVerifier(t, resolverFor(t, output.JWKS))

			_, err := contextVerifier.Verify(t.Context(), test.token, test.presenter)
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify = %v, want %v", err, test.want)
			}
		})
	}
}

func TestContextVerifyRejectsWhatVerifyRejects(t *testing.T) {
	t.Parallel()

	signer := newSigner(t)

	tests := map[string]struct {
		keys    KeyResolver
		token   func(t *testing.T) string
		want    []error
		notWant []error
	}{
		"expired beyond the leeway": {
			keys: signer.keys,
			token: func(t *testing.T) string {
				t.Helper()

				claims := validClaims()
				claims.ExpiresAt = jwt.NewNumericDate(testNow.Add(-DefaultLeeway - time.Second))

				return signer.sign(t, claims)
			},
			want:    []error{ErrInvalidToken, jwt.ErrTokenExpired},
			notWant: nil,
		},
		"from another issuer": {
			keys: signer.keys,
			token: func(t *testing.T) string {
				t.Helper()

				claims := validClaims()
				claims.Issuer = "someone-else"

				return signer.sign(t, claims)
			},
			want:    []error{ErrInvalidToken, jwt.ErrTokenInvalidIssuer},
			notWant: nil,
		},
		"signed under an unknown kid": {
			keys: signer.keys,
			token: func(t *testing.T) string {
				t.Helper()

				return signWith(t, jwt.SigningMethodES256, signer.key, "rotated-away", validClaims())
			},
			want:    []error{ErrInvalidToken, ErrUnknownKey, errNoSuchKey},
			notWant: []error{ErrKeyResolution},
		},
		"a resolver that cannot reach its key store": {
			keys: resolverFunc(func(context.Context, string) (*ecdsa.PublicKey, error) {
				return nil, errKeyStoreDown
			}),
			token: func(t *testing.T) string {
				t.Helper()

				return signer.sign(t, validClaims())
			},
			want:    []error{ErrKeyResolution, errKeyStoreDown},
			notWant: []error{ErrInvalidToken, ErrUnknownKey},
		},
		"of another token type": {
			keys: signer.keys,
			token: func(t *testing.T) string {
				t.Helper()

				return signer.signTyped(t, "at+jwt", validClaims())
			},
			want:    []error{ErrInvalidToken, ErrUnexpectedTokenType},
			notWant: nil,
		},
		"a machine-origin service token carrying a scope": {
			keys: signer.keys,
			token: func(t *testing.T) string {
				t.Helper()

				claims := validClaims()
				claims.TokenUse = internaljwt.TokenUseService
				claims.ClientID = claims.Subject
				claims.SourceJTI = ""
				claims.TenantPublicID = ""

				return signer.sign(t, claims)
			},
			want:    []error{ErrForbiddenClaim},
			notWant: nil,
		},
		"naming the presenter alongside another audience": {
			keys: signer.keys,
			token: func(t *testing.T) string {
				t.Helper()

				claims := validClaims()
				claims.Audience = jwt.ClaimStrings{testAudience, testOtherService}

				return signer.sign(t, claims)
			},
			want:    []error{ErrAudienceCount},
			notWant: nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			contextVerifier := newContextVerifier(t, test.keys, fixedClock())

			_, err := contextVerifier.Verify(t.Context(), test.token(t), testAudience)
			for _, want := range test.want {
				if !errors.Is(err, want) {
					t.Fatalf("Verify = %v, want it to wrap %v", err, want)
				}
			}

			for _, notWant := range test.notWant {
				if errors.Is(err, notWant) {
					t.Fatalf("Verify = %v, want it not to wrap %v", err, notWant)
				}
			}
		})
	}
}

func TestNewContextVerifierRejectsAnIncompleteConfiguration(t *testing.T) {
	t.Parallel()

	keys := staticKeys{keys: map[string]*ecdsa.PublicKey{}}

	tests := map[string]struct {
		issuerID string
		keys     KeyResolver
		opts     []Option
		want     error
	}{
		"without an issuer ID": {
			issuerID: "", keys: keys, opts: nil, want: ErrMissingIssuerID,
		},
		"without a key resolver": {
			issuerID: testIssuerID, keys: nil, opts: nil, want: ErrMissingKeyResolver,
		},
		"with a negative leeway": {
			issuerID: testIssuerID, keys: keys,
			opts: []Option{WithLeeway(-time.Second)}, want: ErrNegativeLeeway,
		},
		"without a clock": {
			issuerID: testIssuerID, keys: keys,
			opts: []Option{WithClock(nil)}, want: ErrMissingClock,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			contextVerifier, err := NewContextVerifier(test.issuerID, test.keys, test.opts...)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewContextVerifier = %v, want %v", err, test.want)
			}

			if contextVerifier != nil {
				t.Fatal("NewContextVerifier returned a verifier alongside an error")
			}
		})
	}
}

func TestNewContextVerifierHonoursTheClockAndTheLeeway(t *testing.T) {
	t.Parallel()

	signer := newSigner(t)

	claims := validClaims()
	claims.ExpiresAt = jwt.NewNumericDate(testNow.Add(-time.Second))
	token := signer.sign(t, claims)

	if _, err := newContextVerifier(t, signer.keys, fixedClock()).Verify(t.Context(), token, testAudience); err != nil {
		t.Fatalf("Verify within the default leeway: %v", err)
	}

	_, err := newContextVerifier(t, signer.keys, fixedClock(), WithLeeway(0)).Verify(t.Context(), token, testAudience)
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("Verify = %v, want %v", err, jwt.ErrTokenExpired)
	}
}
