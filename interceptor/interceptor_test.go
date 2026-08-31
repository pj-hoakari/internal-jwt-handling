package interceptor_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/pj-hoakari/protoc-gen-authz-go/authz"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/interceptor"
	"github.com/pj-hoakari/internal-jwt-handling/jwtgen"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"
)

func TestNewRequiresAVerifier(t *testing.T) {
	t.Parallel()

	built, err := interceptor.New(nil, policies(testProcedure, authz.Policy{Level: authz.LevelAuthenticated}))
	if !errors.Is(err, interceptor.ErrMissingVerifier) {
		t.Fatalf("New = %v, want %v", err, interceptor.ErrMissingVerifier)
	}

	if built != nil {
		t.Fatal("New returned an interceptor alongside an error")
	}
}

func TestNewRequiresAPolicyTable(t *testing.T) {
	t.Parallel()

	tests := map[string]authz.Policies{
		"nil":      nil,
		"an empty": {},
	}

	for name, table := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			built, err := interceptor.New(stubVerifier{}, table)
			if !errors.Is(err, interceptor.ErrMissingPolicies) {
				t.Fatalf("New = %v, want %v", err, interceptor.ErrMissingPolicies)
			}

			if built != nil {
				t.Fatal("New returned an interceptor alongside an error")
			}
		})
	}
}

func TestInterceptorRefusesAProcedureTheTableDoesNotName(t *testing.T) {
	t.Parallel()

	token, tokenVerifier, _ := tenantAccessToken(t)
	reporter := &recorder{}
	handler := &testHandler{}
	server := newTestServer(t, handler,
		newInterceptor(t, tokenVerifier,
			policies(testProcedure, authz.Policy{Level: authz.LevelAuthenticated}),
			interceptor.WithErrorReporter(reporter.report),
		),
	)

	// A good token does not help: the table, not the credential, is what the
	// procedure is missing from.
	err := call(t, server, testUntabledProcedure, "Bearer "+token)
	assertBareCode(t, err, connect.CodeInternal)

	if handler.reached() {
		t.Fatal("the handler was reached despite the rejection")
	}

	rejected := reporter.only(t)
	if rejected.procedure != testUntabledProcedure {
		t.Fatalf("procedure = %q, want %q", rejected.procedure, testUntabledProcedure)
	}

	if !errors.Is(rejected.err, interceptor.ErrUnknownProcedure) {
		t.Fatalf("reported error = %v, want it to wrap %v", rejected.err, interceptor.ErrUnknownProcedure)
	}
}

func TestInterceptorLetsAPublicProcedureThrough(t *testing.T) {
	t.Parallel()

	token, tokenVerifier, _ := tenantAccessToken(t)

	tests := map[string]string{
		"without a credential": "",
		"with a broken one":    "Bearer " + tamper(token),
		"under another scheme": "Basic dXNlcjpwYXNzd29yZA==",
		"with a good one":      "Bearer " + token,
	}

	for name, authorization := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reporter := &recorder{}
			handler := &testHandler{}
			counting := &countingVerifier{inner: tokenVerifier}
			server := newTestServer(t, handler,
				newInterceptor(t, counting,
					policies(testPublicProcedure, authz.Policy{Level: authz.LevelPublic}),
					interceptor.WithErrorReporter(reporter.report),
				),
			)

			if err := call(t, server, testPublicProcedure, authorization); err != nil {
				t.Fatalf("call: %v", err)
			}

			claims, found := handler.result(t)
			if found {
				t.Fatalf("the handler context carries claims %+v, want none", claims)
			}

			if counting.count() != 0 {
				t.Fatalf("the verifier was called %d times, want none", counting.count())
			}

			if reporter.count() != 0 {
				t.Fatalf("reporter saw %d rejections, want none", reporter.count())
			}
		})
	}
}

func TestInterceptorHandsTheVerifiedClaimsToTheHandler(t *testing.T) {
	t.Parallel()

	token, tokenVerifier, want := tenantAccessToken(t)
	handler := &testHandler{}
	server := newTestServer(t, handler,
		newInterceptor(t, tokenVerifier, policies(testProcedure, authz.Policy{
			Level:          authz.LevelAuthenticated,
			RequiredScopes: []string{"tenant.read", "events.read"},
			TokenUses:      nil,
		})),
	)

	if err := call(t, server, testProcedure, "Bearer "+token); err != nil {
		t.Fatalf("call: %v", err)
	}

	claims, found := handler.result(t)
	if !found {
		t.Fatal("the handler context carries no claims")
	}

	if claims.ID != want.ID || claims.Subject != want.Subject || claims.TokenUse != want.TokenUse {
		t.Fatalf("claims = %+v, want %+v", claims, want)
	}

	if claims.TenantPublicID != testTenantPublicID {
		t.Fatalf("tenant public ID = %q, want %q", claims.TenantPublicID, testTenantPublicID)
	}
}

func TestInterceptorRejectsAnUnusableCredential(t *testing.T) {
	t.Parallel()

	token, tokenVerifier, _ := tenantAccessToken(t)

	tests := map[string]struct {
		authorization string
		want          error
	}{
		"without an Authorization header": {
			authorization: "",
			want:          verifier.ErrMissingAuthorization,
		},
		"under the Basic scheme": {
			authorization: "Basic dXNlcjpwYXNzd29yZA==",
			want:          verifier.ErrMalformedAuthorization,
		},
		"with a tampered token": {
			authorization: "Bearer " + tamper(token),
			want:          verifier.ErrInvalidToken,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reporter := &recorder{}
			handler := &testHandler{}
			server := newTestServer(t, handler,
				newInterceptor(t, tokenVerifier,
					policies(testProcedure, authz.Policy{Level: authz.LevelAuthenticated}),
					interceptor.WithErrorReporter(reporter.report),
				),
			)

			err := call(t, server, testProcedure, test.authorization)
			assertBareCode(t, err, connect.CodeUnauthenticated)

			if handler.reached() {
				t.Fatal("the handler was reached despite the rejection")
			}

			rejected := reporter.only(t)
			if rejected.procedure != testProcedure {
				t.Fatalf("procedure = %q, want %q", rejected.procedure, testProcedure)
			}

			if !errors.Is(rejected.err, interceptor.ErrUnauthenticated) {
				t.Fatalf("reported error = %v, want it to wrap %v", rejected.err, interceptor.ErrUnauthenticated)
			}

			if !errors.Is(rejected.err, test.want) {
				t.Fatalf("reported error = %v, want it to wrap %v", rejected.err, test.want)
			}
		})
	}
}

func TestInterceptorRejectsWithoutAReporter(t *testing.T) {
	t.Parallel()

	_, tokenVerifier, _ := tenantAccessToken(t)
	handler := &testHandler{}
	server := newTestServer(t, handler,
		newInterceptor(t, tokenVerifier, policies(testProcedure, authz.Policy{Level: authz.LevelAuthenticated})),
	)

	assertBareCode(t, call(t, server, testProcedure, ""), connect.CodeUnauthenticated)

	if handler.reached() {
		t.Fatal("the handler was reached despite the rejection")
	}
}

func TestInterceptorRefusesALevelItCannotEnforce(t *testing.T) {
	t.Parallel()

	token, tokenVerifier, _ := tenantAccessToken(t)

	tests := map[string]struct {
		level  authz.Level
		detail string
	}{
		"a policy that never named its level": {
			level:  authz.LevelUnspecified,
			detail: "must name its level",
		},
		"a level the package does not know": {
			level:  authz.Level(7),
			detail: "7",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reporter := &recorder{}
			handler := &testHandler{}
			counting := &countingVerifier{inner: tokenVerifier}
			server := newTestServer(t, handler,
				newInterceptor(t, counting,
					policies(testProcedure, authz.Policy{Level: test.level}),
					interceptor.WithErrorReporter(reporter.report),
				),
			)

			err := call(t, server, testProcedure, "Bearer "+token)
			assertBareCode(t, err, connect.CodeInternal)

			if handler.reached() {
				t.Fatal("the handler was reached despite the rejection")
			}

			// The level is a misconfiguration of the procedure, so it is
			// decided before the caller's credential is read at all.
			if counting.count() != 0 {
				t.Fatalf("the verifier was called %d times, want none", counting.count())
			}

			rejected := reporter.only(t)
			if !errors.Is(rejected.err, interceptor.ErrUnknownLevel) {
				t.Fatalf("reported error = %v, want it to wrap %v", rejected.err, interceptor.ErrUnknownLevel)
			}

			if !strings.Contains(rejected.err.Error(), test.detail) {
				t.Fatalf("reported error = %v, want it to name %q", rejected.err, test.detail)
			}
		})
	}
}

func TestInterceptorAcceptsTheCaller(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		opts      []interceptor.Option
		policy    authz.Policy
		config    jwtgen.Config
		procedure string
	}{
		"an authenticated procedure from a tenant_access token": {
			opts:   nil,
			policy: authz.Policy{Level: authz.LevelAuthenticated},
			config: jwtgen.Config{
				TokenUse:       internaljwt.TokenUseTenantAccess,
				Scope:          testScope,
				TenantPublicID: testTenantPublicID,
			},
		},
		"every required scope at once": {
			opts: nil,
			policy: authz.Policy{
				Level:          authz.LevelAuthenticated,
				RequiredScopes: []string{"tenant.read", "events.read"},
				TokenUses:      nil,
			},
			config: jwtgen.Config{
				TokenUse:       internaljwt.TokenUseTenantAccess,
				Scope:          testScope,
				TenantPublicID: testTenantPublicID,
			},
		},
		"an internal procedure from a machine-origin service token": {
			opts:      nil,
			policy:    authz.Policy{Level: authz.LevelInternal},
			config:    jwtgen.Config{TokenUse: internaljwt.TokenUseService},
			procedure: testInternalProcedure,
		},
		"a token use the policy names itself": {
			opts: nil,
			policy: authz.Policy{
				Level:          authz.LevelAuthenticated,
				RequiredScopes: nil,
				TokenUses:      []string{internaljwt.TokenUseRegistration},
			},
			config: jwtgen.Config{TokenUse: internaljwt.TokenUseRegistration, Scope: "tenant.claim"},
		},
		"an internal procedure the policy opens to another token use": {
			opts: nil,
			policy: authz.Policy{
				Level:          authz.LevelInternal,
				RequiredScopes: nil,
				TokenUses:      []string{internaljwt.TokenUseRegistration},
			},
			config:    jwtgen.Config{TokenUse: internaljwt.TokenUseRegistration, Scope: "tenant.claim"},
			procedure: testInternalProcedure,
		},
		"the token use the setting for the procedure names": {
			opts:   []interceptor.Option{interceptor.WithTokenUses(testProcedure, internaljwt.TokenUseRegistration)},
			policy: authz.Policy{Level: authz.LevelAuthenticated},
			config: jwtgen.Config{TokenUse: internaljwt.TokenUseRegistration, Scope: "tenant.claim"},
		},
		"the token use the service opened authenticated procedures to": {
			opts:   []interceptor.Option{interceptor.WithAuthenticatedTokenUses(internaljwt.TokenUseEventAccess)},
			policy: authz.Policy{Level: authz.LevelAuthenticated},
			config: jwtgen.Config{
				TokenUse:       internaljwt.TokenUseEventAccess,
				Scope:          testScope,
				TenantPublicID: testTenantPublicID,
				EventPublicID:  "fedcba9876543210",
			},
		},
		"the policy, which outranks the service-wide setting": {
			opts: []interceptor.Option{interceptor.WithAuthenticatedTokenUses(internaljwt.TokenUseEventAccess)},
			policy: authz.Policy{
				Level:          authz.LevelAuthenticated,
				RequiredScopes: nil,
				TokenUses:      []string{internaljwt.TokenUseRegistration},
			},
			config: jwtgen.Config{TokenUse: internaljwt.TokenUseRegistration, Scope: "tenant.claim"},
		},
		"the setting for the procedure, which outranks the service-wide one": {
			opts: []interceptor.Option{
				interceptor.WithAuthenticatedTokenUses(internaljwt.TokenUseEventAccess),
				interceptor.WithTokenUses(testProcedure, internaljwt.TokenUseRegistration),
			},
			policy: authz.Policy{Level: authz.LevelAuthenticated},
			config: jwtgen.Config{TokenUse: internaljwt.TokenUseRegistration, Scope: "tenant.claim"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			procedure := test.procedure
			if procedure == "" {
				procedure = testProcedure
			}

			token, tokenVerifier, _ := tokenFor(t, test.config)
			reporter := &recorder{}
			handler := &testHandler{}
			server := newTestServer(t, handler,
				newInterceptor(t, tokenVerifier, policies(procedure, test.policy),
					append(test.opts, interceptor.WithErrorReporter(reporter.report))...),
			)

			if err := call(t, server, procedure, "Bearer "+token); err != nil {
				t.Fatalf("call: %v", err)
			}

			if _, found := handler.result(t); !found {
				t.Fatal("the handler context carries no claims")
			}

			if reporter.count() != 0 {
				t.Fatalf("reporter saw %d rejections, want none", reporter.count())
			}
		})
	}
}

func TestInterceptorRejectsTheCaller(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		opts      []interceptor.Option
		policy    authz.Policy
		config    jwtgen.Config
		procedure string
		code      connect.Code
		want      error
		detail    string
	}{
		"an internal procedure from a tenant_access token": {
			opts:   nil,
			policy: authz.Policy{Level: authz.LevelInternal},
			config: jwtgen.Config{
				TokenUse:       internaljwt.TokenUseTenantAccess,
				Scope:          testScope,
				TenantPublicID: testTenantPublicID,
			},
			procedure: testInternalProcedure,
			code:      connect.CodeUnauthenticated,
			want:      interceptor.ErrTokenUse,
			detail:    internaljwt.TokenUseService,
		},
		"an authenticated procedure from a service token": {
			opts:   nil,
			policy: authz.Policy{Level: authz.LevelAuthenticated},
			config: jwtgen.Config{TokenUse: internaljwt.TokenUseService},
			code:   connect.CodeUnauthenticated,
			want:   interceptor.ErrTokenUse,
			detail: internaljwt.TokenUseTenantAccess,
		},
		"an authenticated procedure from an event_access token": {
			opts:   nil,
			policy: authz.Policy{Level: authz.LevelAuthenticated},
			config: jwtgen.Config{
				TokenUse:       internaljwt.TokenUseEventAccess,
				Scope:          testScope,
				TenantPublicID: testTenantPublicID,
				EventPublicID:  "fedcba9876543210",
			},
			code:   connect.CodeUnauthenticated,
			want:   interceptor.ErrTokenUse,
			detail: internaljwt.TokenUseTenantAccess,
		},
		"a token use the policy leaves out": {
			opts: nil,
			policy: authz.Policy{
				Level:          authz.LevelAuthenticated,
				RequiredScopes: nil,
				TokenUses:      []string{internaljwt.TokenUseRegistration},
			},
			config: jwtgen.Config{
				TokenUse:       internaljwt.TokenUseTenantAccess,
				Scope:          testScope,
				TenantPublicID: testTenantPublicID,
			},
			code:   connect.CodeUnauthenticated,
			want:   interceptor.ErrTokenUse,
			detail: internaljwt.TokenUseRegistration,
		},
		"the token use the service-wide setting replaced": {
			opts:   []interceptor.Option{interceptor.WithAuthenticatedTokenUses(internaljwt.TokenUseEventAccess)},
			policy: authz.Policy{Level: authz.LevelAuthenticated},
			config: jwtgen.Config{
				TokenUse:       internaljwt.TokenUseTenantAccess,
				Scope:          testScope,
				TenantPublicID: testTenantPublicID,
			},
			code:   connect.CodeUnauthenticated,
			want:   interceptor.ErrTokenUse,
			detail: internaljwt.TokenUseEventAccess,
		},
		"the token use the setting for the procedure replaced": {
			opts:   []interceptor.Option{interceptor.WithTokenUses(testProcedure, internaljwt.TokenUseRegistration)},
			policy: authz.Policy{Level: authz.LevelAuthenticated},
			config: jwtgen.Config{
				TokenUse:       internaljwt.TokenUseTenantAccess,
				Scope:          testScope,
				TenantPublicID: testTenantPublicID,
			},
			code:   connect.CodeUnauthenticated,
			want:   interceptor.ErrTokenUse,
			detail: internaljwt.TokenUseRegistration,
		},
		"an internal procedure, which the authenticated setting leaves alone": {
			opts:   []interceptor.Option{interceptor.WithAuthenticatedTokenUses(internaljwt.TokenUseTenantAccess)},
			policy: authz.Policy{Level: authz.LevelInternal},
			config: jwtgen.Config{
				TokenUse:       internaljwt.TokenUseTenantAccess,
				Scope:          testScope,
				TenantPublicID: testTenantPublicID,
			},
			procedure: testInternalProcedure,
			code:      connect.CodeUnauthenticated,
			want:      interceptor.ErrTokenUse,
			detail:    internaljwt.TokenUseService,
		},
		"a missing scope": {
			opts: nil,
			policy: authz.Policy{
				Level:          authz.LevelAuthenticated,
				RequiredScopes: []string{"tenant.write"},
				TokenUses:      nil,
			},
			config: jwtgen.Config{
				TokenUse:       internaljwt.TokenUseTenantAccess,
				Scope:          testScope,
				TenantPublicID: testTenantPublicID,
			},
			code:   connect.CodePermissionDenied,
			want:   interceptor.ErrMissingScope,
			detail: "tenant.write",
		},
		"one of the required scopes": {
			opts: nil,
			policy: authz.Policy{
				Level:          authz.LevelAuthenticated,
				RequiredScopes: []string{"tenant.read", "tenant.write"},
				TokenUses:      nil,
			},
			config: jwtgen.Config{
				TokenUse:       internaljwt.TokenUseTenantAccess,
				Scope:          testScope,
				TenantPublicID: testTenantPublicID,
			},
			code:   connect.CodePermissionDenied,
			want:   interceptor.ErrMissingScope,
			detail: "tenant.write",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			procedure := test.procedure
			if procedure == "" {
				procedure = testProcedure
			}

			token, tokenVerifier, _ := tokenFor(t, test.config)
			reporter := &recorder{}
			handler := &testHandler{}
			server := newTestServer(t, handler,
				newInterceptor(t, tokenVerifier, policies(procedure, test.policy),
					append(test.opts, interceptor.WithErrorReporter(reporter.report))...),
			)

			err := call(t, server, procedure, "Bearer "+token)
			assertBareCode(t, err, test.code)

			if handler.reached() {
				t.Fatal("the handler was reached despite the rejection")
			}

			rejected := reporter.only(t)
			if rejected.procedure != procedure {
				t.Fatalf("procedure = %q, want %q", rejected.procedure, procedure)
			}

			if !errors.Is(rejected.err, test.want) {
				t.Fatalf("reported error = %v, want it to wrap %v", rejected.err, test.want)
			}

			if !strings.Contains(rejected.err.Error(), test.detail) {
				t.Fatalf("reported error = %v, want it to name %q", rejected.err, test.detail)
			}
		})
	}
}

func TestInterceptorNeverChecksTheScopeOfAServiceToken(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"a machine-origin one, which carries none":            "",
		"a user-origin one, whose scope is the origin user's": testScope,
	}

	policy := authz.Policy{
		Level:          authz.LevelInternal,
		RequiredScopes: []string{"tenant.write"},
		TokenUses:      nil,
	}

	for name, scope := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			token, tokenVerifier, _ := serviceToken(t, scope)
			reporter := &recorder{}
			handler := &testHandler{}
			server := newTestServer(t, handler,
				newInterceptor(t, tokenVerifier, policies(testInternalProcedure, policy),
					interceptor.WithErrorReporter(reporter.report)),
			)

			if err := call(t, server, testInternalProcedure, "Bearer "+token); err != nil {
				t.Fatalf("call: %v", err)
			}

			if _, found := handler.result(t); !found {
				t.Fatal("the handler context carries no claims")
			}

			if reporter.count() != 0 {
				t.Fatalf("reporter saw %d rejections, want none", reporter.count())
			}
		})
	}
}

func TestInterceptorAppliesATokenUseSettingToOneProcedureOnly(t *testing.T) {
	t.Parallel()

	// ClaimTenantOwnership is the shape of this: one authenticated procedure
	// of a service takes the registration token instead of tenant_access.
	token, tokenVerifier, _ := tokenFor(t, jwtgen.Config{
		TokenUse: internaljwt.TokenUseRegistration,
		Scope:    "tenant.claim",
	})

	table := authz.Policies{
		testProcedure:         {Level: authz.LevelAuthenticated, RequiredScopes: nil, TokenUses: nil},
		testInternalProcedure: {Level: authz.LevelAuthenticated, RequiredScopes: nil, TokenUses: nil},
	}

	tests := map[string]struct {
		procedure string
		want      error
	}{
		"on the procedure the setting names": {procedure: testProcedure, want: nil},
		"on any other procedure":             {procedure: testInternalProcedure, want: interceptor.ErrTokenUse},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reporter := &recorder{}
			handler := &testHandler{}
			server := newTestServer(t, handler,
				newInterceptor(t, tokenVerifier, table,
					interceptor.WithTokenUses(testProcedure, internaljwt.TokenUseRegistration),
					interceptor.WithErrorReporter(reporter.report),
				),
			)

			err := call(t, server, test.procedure, "Bearer "+token)

			if test.want == nil {
				if err != nil {
					t.Fatalf("call: %v", err)
				}

				if !handler.reached() {
					t.Fatal("the handler was not reached")
				}

				return
			}

			assertBareCode(t, err, connect.CodeUnauthenticated)

			if !errors.Is(reporter.only(t).err, test.want) {
				t.Fatalf("reported error = %v, want it to wrap %v", reporter.only(t).err, test.want)
			}
		})
	}
}

func TestInterceptorDecidesAStreamingCall(t *testing.T) {
	t.Parallel()

	token, tokenVerifier, want := tenantAccessToken(t)
	reporter := &recorder{}

	table := authz.Policies{
		testProcedure:       {Level: authz.LevelAuthenticated, RequiredScopes: []string{"tenant.read"}, TokenUses: nil},
		testPublicProcedure: {Level: authz.LevelPublic, RequiredScopes: nil, TokenUses: nil},
		testInternalProcedure: {
			Level:          authz.LevelInternal,
			RequiredScopes: nil,
			TokenUses:      nil,
		},
	}

	wrapped := newInterceptor(t, tokenVerifier, table, interceptor.WithErrorReporter(reporter.report))

	var (
		reached bool
		claims  internaljwt.Claims
		found   bool
	)

	next := wrapped.WrapStreamingHandler(func(ctx context.Context, _ connect.StreamingHandlerConn) error {
		reached = true
		claims, found = internaljwt.ClaimsFromContext(ctx)

		return nil
	})

	reset := func() {
		reached, found = false, false
	}

	t.Run("with a valid token", func(t *testing.T) {
		reset()

		if err := next(t.Context(), newStreamingConn(testProcedure, "Bearer "+token)); err != nil {
			t.Fatalf("streaming handler: %v", err)
		}

		if !reached || !found {
			t.Fatalf("reached = %t, claims found = %t, want both true", reached, found)
		}

		if claims.ID != want.ID {
			t.Fatalf("jti = %q, want %q", claims.ID, want.ID)
		}
	})

	t.Run("on a public procedure", func(t *testing.T) {
		reset()

		if err := next(t.Context(), newStreamingConn(testPublicProcedure, "")); err != nil {
			t.Fatalf("streaming handler: %v", err)
		}

		if !reached || found {
			t.Fatalf("reached = %t, claims found = %t, want true and false", reached, found)
		}
	})

	t.Run("without a credential", func(t *testing.T) {
		reset()

		err := next(t.Context(), newStreamingConn(testProcedure, ""))
		assertBareCode(t, err, connect.CodeUnauthenticated)

		if reached {
			t.Fatal("the handler was reached despite the rejection")
		}

		rejected := reporter.only(t)
		if rejected.procedure != testProcedure {
			t.Fatalf("procedure = %q, want %q", rejected.procedure, testProcedure)
		}

		if !errors.Is(rejected.err, verifier.ErrMissingAuthorization) {
			t.Fatalf("reported error = %v, want it to wrap %v", rejected.err, verifier.ErrMissingAuthorization)
		}
	})

	t.Run("on an internal procedure from a tenant_access token", func(t *testing.T) {
		reset()

		err := next(t.Context(), newStreamingConn(testInternalProcedure, "Bearer "+token))
		assertBareCode(t, err, connect.CodeUnauthenticated)

		if reached {
			t.Fatal("the handler was reached despite the rejection")
		}
	})

	t.Run("on a procedure the table does not name", func(t *testing.T) {
		reset()

		err := next(t.Context(), newStreamingConn(testUntabledProcedure, "Bearer "+token))
		assertBareCode(t, err, connect.CodeInternal)

		if reached {
			t.Fatal("the handler was reached despite the rejection")
		}
	})
}

func TestInterceptorPassesStreamingClientsThrough(t *testing.T) {
	t.Parallel()

	_, tokenVerifier, _ := tenantAccessToken(t)

	called := false
	next := connect.StreamingClientFunc(func(context.Context, connect.Spec) connect.StreamingClientConn {
		called = true

		return nil
	})

	built := newInterceptor(t, tokenVerifier, policies(testProcedure, authz.Policy{Level: authz.LevelAuthenticated}))

	wrapped := built.WrapStreamingClient(next)
	if conn := wrapped(t.Context(), connect.Spec{Procedure: testProcedure}); conn != nil {
		t.Fatalf("conn = %v, want the wrapped function's own nil", conn)
	}

	if !called {
		t.Fatal("the wrapped streaming client was not called")
	}
}

func TestInterceptorMatchesTheProcedureExactly(t *testing.T) {
	t.Parallel()

	token, tokenVerifier, _ := tenantAccessToken(t)

	// A near miss of the public procedure is not the public procedure, so it
	// is a procedure the table does not name.
	table := authz.Policies{
		testPublicProcedure + "X":            {Level: authz.LevelPublic, RequiredScopes: nil, TokenUses: nil},
		strings.ToUpper(testPublicProcedure): {Level: authz.LevelPublic, RequiredScopes: nil, TokenUses: nil},
	}

	handler := &testHandler{}
	server := newTestServer(t, handler, newInterceptor(t, tokenVerifier, table))

	assertBareCode(t, call(t, server, testPublicProcedure, "Bearer "+token), connect.CodeInternal)

	if handler.reached() {
		t.Fatal("the handler was reached despite the rejection")
	}
}

func TestInterceptorEnforcesAMergedTable(t *testing.T) {
	t.Parallel()

	token, tokenVerifier, _ := tenantAccessToken(t)

	merged, err := authz.Merge(
		policies(testProcedure, authz.Policy{
			Level:          authz.LevelAuthenticated,
			RequiredScopes: []string{"tenant.read"},
			TokenUses:      nil,
		}),
		policies(testPublicProcedure, authz.Policy{Level: authz.LevelPublic}),
	)
	if err != nil {
		t.Fatalf("authz.Merge: %v", err)
	}

	handler := &testHandler{}
	server := newTestServer(t, handler, newInterceptor(t, tokenVerifier, merged))

	if err := call(t, server, testProcedure, "Bearer "+token); err != nil {
		t.Fatalf("call the authenticated procedure: %v", err)
	}

	if err := call(t, server, testPublicProcedure, ""); err != nil {
		t.Fatalf("call the public procedure: %v", err)
	}
}
