package verifier_test

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/jwks"
	"github.com/pj-hoakari/internal-jwt-handling/jwtgen"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"
)

const (
	gatewayIssuerID = "service-gateway"
	gatewayAudience = "tolo-tenant-management"
	gatewayTenantID = "0123456789abcdef"
	gatewayScope    = "tenant.read"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

func mint(t *testing.T, keyID string) jwtgen.Output {
	t.Helper()

	output, err := jwtgen.Generate(jwtgen.Config{
		Issuer:         gatewayIssuerID,
		Audience:       gatewayAudience,
		TokenUse:       internaljwt.TokenUseTenantAccess,
		TenantPublicID: gatewayTenantID,
		Scope:          gatewayScope,
		KeyID:          keyID,
	})
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	return output
}

func serveJWKS(t *testing.T, document internaljwt.JWKS) *httptest.Server {
	t.Helper()

	body, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")

		if _, err := writer.Write(body); err != nil {
			t.Errorf("write JWKS: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func newCache(t *testing.T, url string, client *http.Client) *jwks.Cache {
	t.Helper()

	cache, err := jwks.New(jwks.Config{
		URL:             url,
		HTTPClient:      client,
		RetryBackoff:    []time.Duration{},
		FetchTimeout:    time.Second,
		FailureCooldown: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jwks.New: %v", err)
	}

	return cache
}

func newVerifierOn(t *testing.T, keys verifier.KeyResolver) *verifier.Verifier {
	t.Helper()

	tokenVerifier, err := verifier.New(gatewayIssuerID, gatewayAudience, keys)
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}

	return tokenVerifier
}

func TestUnknownKeyIDIsOneSentinelAcrossThePackages(t *testing.T) {
	t.Parallel()

	sentinels := map[string]error{
		"internaljwt.ErrUnknownKeyID": internaljwt.ErrUnknownKeyID,
		"jwks.ErrUnknownKeyID":        jwks.ErrUnknownKeyID,
		"verifier.ErrUnknownKey":      verifier.ErrUnknownKey,
	}

	for name, err := range sentinels {
		for otherName, other := range sentinels {
			if !errors.Is(err, other) {
				t.Fatalf("errors.Is(%s, %s) = false, want true", name, otherName)
			}
		}
	}
}

func TestVerifyAcceptsATokenTheJWKSPublishes(t *testing.T) {
	t.Parallel()

	output := mint(t, "current")
	server := serveJWKS(t, output.JWKS)
	tokenVerifier := newVerifierOn(t, newCache(t, server.URL, server.Client()))

	claims, err := tokenVerifier.Verify(t.Context(), output.Token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if claims.ID != output.Claims.ID {
		t.Fatalf("jti = %q, want %q", claims.ID, output.Claims.ID)
	}
}

func TestVerifyRejectsAKidTheJWKSDoesNotPublish(t *testing.T) {
	t.Parallel()

	rotatedAway := mint(t, "rotated-away")
	published := mint(t, "current")

	server := serveJWKS(t, published.JWKS)
	tokenVerifier := newVerifierOn(t, newCache(t, server.URL, server.Client()))

	_, err := tokenVerifier.Verify(t.Context(), rotatedAway.Token)
	for _, want := range []error{verifier.ErrInvalidToken, verifier.ErrUnknownKey, jwks.ErrUnknownKeyID} {
		if !errors.Is(err, want) {
			t.Fatalf("Verify = %v, want it to wrap %v", err, want)
		}
	}

	if errors.Is(err, verifier.ErrKeyResolution) {
		t.Fatalf("Verify = %v, want it not to wrap %v", err, verifier.ErrKeyResolution)
	}
}

func TestVerifyReportsAFailedJWKSFetchAsAKeyResolutionFailure(t *testing.T) {
	t.Parallel()

	output := mint(t, "current")

	tests := map[string]func(t *testing.T) (string, *http.Client){
		"a JWKS endpoint answering 500": func(t *testing.T) (string, *http.Client) {
			t.Helper()

			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusInternalServerError)
			}))
			t.Cleanup(server.Close)

			return server.URL, server.Client()
		},
		"a JWKS endpoint that is down": func(t *testing.T) (string, *http.Client) {
			t.Helper()

			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("a JWKS endpoint that is down answered a fetch")
			}))
			client := server.Client()

			server.Close()

			return server.URL, client
		},
	}

	for name, endpoint := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			url, client := endpoint(t)
			tokenVerifier := newVerifierOn(t, newCache(t, url, client))

			_, err := tokenVerifier.Verify(t.Context(), output.Token)
			if !errors.Is(err, verifier.ErrKeyResolution) {
				t.Fatalf("Verify = %v, want it to wrap %v", err, verifier.ErrKeyResolution)
			}

			for _, notWant := range []error{verifier.ErrInvalidToken, verifier.ErrUnknownKey} {
				if errors.Is(err, notWant) {
					t.Fatalf("Verify = %v, want it not to wrap %v", err, notWant)
				}
			}
		})
	}
}
