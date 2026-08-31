// Package interceptor authenticates and authorizes connect RPCs against the
// policy table protoc-gen-authz-go generates.
//
// New takes the generated <Service>Policies and the verifier of the internal
// JWT, and returns one interceptor that decides every call: it looks the
// procedure up in the table, verifies the Authorization header where the level
// asks for it, checks the token_use and the required scopes, and hands the
// verified claims to the handler through internaljwt.ClaimsFromContext.
//
//	policies := greetingv1connect.GreeterServicePolicies
//
//	authn, err := interceptor.New(tokenVerifier, policies,
//		interceptor.WithErrorReporter(reportRejection),
//	)
//	if err != nil {
//		return err
//	}
//
//	mux.Handle(greetingv1connect.NewGreeterServiceHandler(
//		service,
//		connect.WithInterceptors(authn),
//	))
//
// A procedure the table does not name is a misconfiguration and is refused
// with CodeInternal, so one interceptor must know every procedure it guards.
// A process serving several services either merges the tables with authz.Merge
// and puts the one interceptor on every handler, or builds an interceptor per
// service from that service's own table.
package interceptor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"connectrpc.com/connect"

	"github.com/pj-hoakari/protoc-gen-authz-go/authz"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"
)

// authorizationHeader carries the internal JWT of a call.
const authorizationHeader = "Authorization"

var (
	ErrMissingVerifier = errors.New("token verifier is required")
	ErrMissingPolicies = errors.New("policy table is required")
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrTokenUse        = errors.New("token use is not accepted by the procedure")
	ErrMissingScope    = errors.New("required scope is missing")
	ErrUnknownLevel    = errors.New("unknown access level")
	// ErrUnknownProcedure reports a procedure the table does not name, which
	// is a misconfiguration of the interceptor rather than a fault of the
	// caller.
	ErrUnknownProcedure = errors.New("the policy table does not name the procedure")
)

// TokenVerifier verifies an internal JWT. *verifier.Verifier satisfies it.
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (internaljwt.Claims, error)
}

// errorReporter observes one rejection, named by the procedure it happened on.
type errorReporter = func(ctx context.Context, procedure string, err error)

// options are the settings an Option adjusts.
type options struct {
	reporter               errorReporter
	authenticatedTokenUses []string
	tokenUses              map[string][]string
}

// Option adjusts the interceptor New builds.
type Option func(*options)

// WithErrorReporter receives every rejection with the procedure and the
// underlying error. The client only ever sees the connect code.
func WithErrorReporter(reporter func(ctx context.Context, procedure string, err error)) Option {
	return func(o *options) {
		o.reporter = reporter
	}
}

// WithAuthenticatedTokenUses replaces the token_use values an authenticated
// procedure accepts across the whole service, for example {event_access} in a
// service that acts inside one event.
// It applies to authz.LevelAuthenticated only: an internal procedure is left alone.
func WithAuthenticatedTokenUses(uses ...string) Option {
	return func(o *options) {
		o.authenticatedTokenUses = uses
	}
}

// WithTokenUses replaces the token_use values one procedure accepts, named by
// its generated Procedure constant and matched exactly,
// for example {registration} on ClaimTenantOwnership.
// It outranks WithAuthenticatedTokenUses and applies at every level.
func WithTokenUses(procedure string, uses ...string) Option {
	return func(o *options) {
		if o.tokenUses == nil {
			o.tokenUses = make(map[string][]string, 1)
		}

		o.tokenUses[procedure] = uses
	}
}

// newOptions applies opts over the defaults.
func newOptions(opts []Option) options {
	resolved := options{reporter: nil, authenticatedTokenUses: nil, tokenUses: nil}

	for _, opt := range opts {
		opt(&resolved)
	}

	return resolved
}

// interceptor decides every call against the policy table it holds.
type interceptor struct {
	verifier               TokenVerifier
	policies               authz.Policies
	reporter               errorReporter
	authenticatedTokenUses []string
	tokenUses              map[string][]string
}

// New builds the interceptor that authenticates and authorizes every procedure
// named in policies.
func New(tokenVerifier TokenVerifier, policies authz.Policies, opts ...Option) (connect.Interceptor, error) {
	if tokenVerifier == nil {
		return nil, ErrMissingVerifier
	}

	if len(policies) == 0 {
		return nil, ErrMissingPolicies
	}

	resolved := newOptions(opts)

	return &interceptor{
		verifier:               tokenVerifier,
		policies:               policies,
		reporter:               resolved.reporter,
		authenticatedTokenUses: resolved.authenticatedTokenUses,
		tokenUses:              resolved.tokenUses,
	}, nil
}

// WrapUnary decides a unary call.
func (i *interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		authorized, err := i.authorize(ctx, req.Spec().Procedure, req.Header())
		if err != nil {
			return nil, err
		}

		return next(authorized, req)
	}
}

// WrapStreamingHandler decides a streaming call the same way as a unary one.
func (i *interceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		authorized, err := i.authorize(ctx, conn.Spec().Procedure, conn.RequestHeader())
		if err != nil {
			return err
		}

		return next(authorized, conn)
	}
}

// WrapStreamingClient passes outgoing calls through: the interceptor guards a
// handler, not a client.
func (i *interceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// authorize returns the context the handler is to run under.
// Every error it returns is a *connect.Error carrying no message,
// so that the cause reaches the reporter rather than the client.
func (i *interceptor) authorize(ctx context.Context, procedure string, header http.Header) (context.Context, error) {
	policy, ok := i.policies.Lookup(procedure)
	if !ok {
		i.report(ctx, procedure, fmt.Errorf("%w: %q", ErrUnknownProcedure, procedure))

		return nil, connect.NewError(connect.CodeInternal, nil)
	}

	if policy.Level == authz.LevelPublic {
		return ctx, nil
	}

	claims, code, err := i.check(ctx, procedure, policy, header)
	if err != nil {
		i.report(ctx, procedure, err)

		return nil, connect.NewError(code, nil)
	}

	return internaljwt.ContextWithClaims(ctx, claims), nil
}

// check verifies the caller of the call and reports the violation of policy with the connect code it deserves.
func (i *interceptor) check(
	ctx context.Context,
	procedure string,
	policy authz.Policy,
	header http.Header,
) (internaljwt.Claims, connect.Code, error) {
	tokenUses, err := i.acceptedTokenUses(policy, procedure)
	if err != nil {
		return internaljwt.Claims{}, connect.CodeInternal, err
	}

	claims, err := i.verify(ctx, header)
	if err != nil {
		return internaljwt.Claims{}, connect.CodeUnauthenticated, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}

	if !slices.Contains(tokenUses, claims.TokenUse) {
		return internaljwt.Claims{}, connect.CodeUnauthenticated,
			fmt.Errorf("%w: %q, want one of %s", ErrTokenUse, claims.TokenUse, strings.Join(tokenUses, ", "))
	}

	// A service token carries the scope of the token it was re-issued from,
	// so the scope says what the origin was granted, not what the calling service may do.
	// A machine-origin one carries none at all. The edge policy governs a service call instead.
	if claims.TokenUse == internaljwt.TokenUseService {
		return claims, connect.CodeUnknown, nil
	}

	if missing := missingScopes(policy.RequiredScopes, claims.Scope); len(missing) > 0 {
		return internaljwt.Claims{}, connect.CodePermissionDenied,
			fmt.Errorf("%w: %s", ErrMissingScope, strings.Join(missing, ", "))
	}

	return claims, connect.CodeUnknown, nil
}

// verify reads the bearer token of the Authorization header and verifies it.
func (i *interceptor) verify(ctx context.Context, header http.Header) (internaljwt.Claims, error) {
	token, err := verifier.BearerToken(header.Get(authorizationHeader))
	if err != nil {
		return internaljwt.Claims{}, err
	}

	return i.verifier.Verify(ctx, token)
}

// acceptedTokenUses are the token_use values policy accepts on procedure.
func (i *interceptor) acceptedTokenUses(policy authz.Policy, procedure string) ([]string, error) {
	defaults, err := defaultTokenUses(policy.Level)
	if err != nil {
		return nil, err
	}

	if len(policy.TokenUses) > 0 {
		return policy.TokenUses, nil
	}

	if uses := i.tokenUses[procedure]; len(uses) > 0 {
		return uses, nil
	}

	if policy.Level == authz.LevelAuthenticated && len(i.authenticatedTokenUses) > 0 {
		return i.authenticatedTokenUses, nil
	}

	return defaults, nil
}

// report hands a rejection to the reporter, if one was configured.
func (i *interceptor) report(ctx context.Context, procedure string, err error) {
	if i.reporter == nil {
		return
	}

	i.reporter(ctx, procedure, err)
}

// defaultTokenUses are the token_use values a level accepts on its own.
func defaultTokenUses(level authz.Level) ([]string, error) {
	switch level {
	case authz.LevelInternal:
		return []string{internaljwt.TokenUseService}, nil
	case authz.LevelPublic:
		// Unreachable: authorize returns before a public procedure gets here.
		return nil, nil
	case authz.LevelAuthenticated:
		return []string{internaljwt.TokenUseTenantAccess}, nil
	case authz.LevelUnspecified:
		return nil, fmt.Errorf("%w: %d, a policy must name its level", ErrUnknownLevel, level)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownLevel, level)
	}
}

// missingScopes are the required scopes the space-separated granted scope does not name.
func missingScopes(required []string, scope string) []string {
	granted := strings.Fields(scope)
	missing := make([]string, 0, len(required))

	for _, want := range required {
		if !slices.Contains(granted, want) {
			missing = append(missing, want)
		}
	}

	return missing
}
