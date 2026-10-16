package interceptor_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/pj-hoakari/protoc-gen-authz-go/authz"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/interceptor"
	"github.com/pj-hoakari/internal-jwt-handling/jwtgen"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"
)

const (
	testIssuerID          = "service-gateway"
	testAudience          = "tolo-tenant-management"
	testTenantPublicID    = "0123456789abcdef"
	testScope             = "tenant.read events.read"
	testProcedure         = "/tolo.tenant.v1.TenantService/ListEvents"
	testPublicProcedure   = "/tolo.tenant.v1.TenantService/StartTenantRegistration"
	testInternalProcedure = "/tolo.tenant.v1.TenantService/ResolveTenant"
	// testUntabledProcedure is served by the test server but left out of every
	// policy table, which is the misconfiguration the interceptor refuses.
	testUntabledProcedure = "/tolo.tenant.v1.TenantService/Forgotten"
)

// errNoSuchKey is what the test resolver returns for a kid it does not hold.
var errNoSuchKey = errors.New("no such test key")

// errVerifierCalled is what the stub verifier returns when a test expected the
// token never to be read.
var errVerifierCalled = errors.New("the verifier was called")

var errKeyStoreDown = errors.New("the test key store is unreachable")

// stubVerifier stands in for a verifier no test expects to be reached.
type stubVerifier struct{}

func (stubVerifier) Verify(context.Context, string) (internaljwt.Claims, error) {
	return internaljwt.Claims{}, errVerifierCalled
}

// policies is a table naming procedure alone, which is what a service hands
// the interceptor as its generated <Service>Policies.
func policies(procedure string, policy authz.Policy) authz.Policies {
	return authz.Policies{procedure: policy}
}

// testMessage is the request and the response of the test service. It is a
// plain Go struct, so that the tests need no generated code.
type testMessage struct {
	Value string `json:"value"`
}

// jsonCodec serialises the test messages, taking the place of the protobuf
// codecs connect registers by default.
type jsonCodec struct{}

func (jsonCodec) Name() string { return "json" }

func (jsonCodec) MarshalWrite(_ context.Context, dst io.Writer, message any) error {
	if err := json.NewEncoder(dst).Encode(message); err != nil {
		return fmt.Errorf("marshal test message: %w", err)
	}

	return nil
}

func (jsonCodec) UnmarshalRead(_ context.Context, src io.Reader, message any) error {
	if err := json.NewDecoder(src).Decode(message); err != nil {
		return fmt.Errorf("unmarshal test message: %w", err)
	}

	return nil
}

// staticKeys resolves the kids of a fixed set of keys.
type staticKeys struct {
	keys map[string]*ecdsa.PublicKey
}

func (s staticKeys) Key(_ context.Context, keyID string) (*ecdsa.PublicKey, error) {
	key, ok := s.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %q: %w", internaljwt.ErrUnknownKeyID, keyID, errNoSuchKey)
	}

	return key, nil
}

type unreachableKeys struct{}

func (unreachableKeys) Key(context.Context, string) (*ecdsa.PublicKey, error) {
	return nil, errKeyStoreDown
}

// newTokenVerifier is the verifier of a service holding the JWKS a token was
// signed under.
func newTokenVerifier(t *testing.T, document internaljwt.JWKS) *verifier.Verifier {
	t.Helper()

	keys := make(map[string]*ecdsa.PublicKey, len(document.Keys))

	for _, jwk := range document.Keys {
		key, err := internaljwt.PublicKey(jwk)
		if err != nil {
			t.Fatalf("public key %q: %v", jwk.KeyID, err)
		}

		keys[jwk.KeyID] = key
	}

	return newVerifierOn(t, staticKeys{keys: keys})
}

func newVerifierOn(t *testing.T, keys verifier.KeyResolver) *verifier.Verifier {
	t.Helper()

	tokenVerifier, err := verifier.New(testIssuerID, testAudience, keys)
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}

	return tokenVerifier
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

// tokenFor mints a token and the verifier that accepts it.
func tokenFor(t *testing.T, config jwtgen.Config) (string, *verifier.Verifier, internaljwt.Claims) {
	t.Helper()

	output := generate(t, config)

	return output.Token, newTokenVerifier(t, output.JWKS), output.Claims
}

// tenantAccessToken is a token an ordinary user-facing call carries, and the
// verifier that accepts it.
func tenantAccessToken(t *testing.T) (string, *verifier.Verifier, internaljwt.Claims) {
	t.Helper()

	return tokenFor(t, jwtgen.Config{
		TokenUse:       internaljwt.TokenUseTenantAccess,
		Scope:          testScope,
		TenantPublicID: testTenantPublicID,
	})
}

// serviceToken is a token another service calling an internal procedure
// carries, and the verifier that accepts it.
func serviceToken(t *testing.T, scope string) (string, *verifier.Verifier, internaljwt.Claims) {
	t.Helper()

	config := jwtgen.Config{TokenUse: internaljwt.TokenUseService, Scope: scope}
	if scope != "" {
		// A scope only travels on a user-origin re-issue, which is the token
		// that carries the origin user's scope through the chain.
		config.OriginSub = "origin-user"
		config.TenantPublicID = testTenantPublicID
	}

	return tokenFor(t, config)
}

// countingVerifier counts how often a token is put through verification, so
// that a test can pin down when the interceptor reads a credential at all.
type countingVerifier struct {
	inner interceptor.TokenVerifier
	mu    sync.Mutex
	calls int
}

func (v *countingVerifier) Verify(ctx context.Context, token string) (internaljwt.Claims, error) {
	v.mu.Lock()
	v.calls++
	v.mu.Unlock()

	return v.inner.Verify(ctx, token)
}

func (v *countingVerifier) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()

	return v.calls
}

// tamper breaks the signature of a token without changing its shape.
func tamper(token string) string {
	dot := strings.LastIndex(token, ".")
	signature := token[dot+1:]

	// Replacing the first character with one it is not guarantees a change
	// whatever the signature holds.
	replacement := "A"
	if signature[0] == 'A' {
		replacement = "B"
	}

	return token[:dot+1] + replacement + signature[1:]
}

// rejection is one call the reporter was told about.
type rejection struct {
	procedure string
	err       error
}

// recorder collects what the reporter is handed.
type recorder struct {
	mu         sync.Mutex
	rejections []rejection
}

func (r *recorder) report(_ context.Context, procedure string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.rejections = append(r.rejections, rejection{procedure: procedure, err: err})
}

func (r *recorder) only(t *testing.T) rejection {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.rejections) != 1 {
		t.Fatalf("reporter saw %d rejections, want 1", len(r.rejections))
	}

	return r.rejections[0]
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.rejections)
}

// testHandler answers a call and records the claims the interceptor left in
// the handler's context.
type testHandler struct {
	mu     sync.Mutex
	called bool
	claims internaljwt.Claims
	found  bool
}

func (h *testHandler) handle(ctx context.Context, _ connect.Spec, stream connect.ServerStream) error {
	var req testMessage
	if err := stream.Receive(&req); err != nil {
		return err
	}

	claims, found := internaljwt.ClaimsFromContext(ctx)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.called = true
	h.claims = claims
	h.found = found

	return stream.Send(&testMessage{Value: req.Value})
}

func (h *testHandler) result(t *testing.T) (internaljwt.Claims, bool) {
	t.Helper()

	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.called {
		t.Fatal("the handler was not reached")
	}

	return h.claims, h.found
}

func (h *testHandler) reached() bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.called
}

// newTestServer serves the test procedures behind interceptors.
func newTestServer(t *testing.T, handler *testHandler, interceptors ...connect.ServerInterceptor) *httptest.Server {
	t.Helper()

	server := connect.NewServer(interceptors...)

	procedures := []string{
		testProcedure,
		testPublicProcedure,
		testInternalProcedure,
		testUntabledProcedure,
	}

	for _, procedure := range procedures {
		server.Register(connect.Method{
			Spec:    connect.Spec{Procedure: procedure, StreamType: connect.StreamTypeUnary},
			Handler: handler.handle,
		})
	}

	mux := http.NewServeMux()
	connecthttp.Mount(mux, server, connecthttp.WithCodecs(jsonCodec{}))

	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)

	return httpServer
}

// call invokes a procedure of the test server, presenting authorization when
// it is not empty.
func call(t *testing.T, server *httptest.Server, procedure, authorization string) error {
	t.Helper()

	client := connect.NewClient(connecthttp.NewTransport(
		server.Client(),
		server.URL,
		connecthttp.WithCodecs(jsonCodec{}),
	))

	ctx, info := connect.NewClientContext(t.Context())
	if authorization != "" {
		info.RequestHeader().Set("Authorization", authorization)
	}

	var response testMessage

	return client.CallUnary(
		ctx,
		connect.Spec{Procedure: procedure, StreamType: connect.StreamTypeUnary},
		&testMessage{Value: "ping"},
		&response,
	)
}

// assertBareCode checks that err reached the client as code and told it nothing else.
func assertBareCode(t *testing.T, err error, code connect.Code) {
	t.Helper()

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error = %v, want a *connect.Error", err)
	}

	if connectErr.Code() != code {
		t.Fatalf("code = %s, want %s", connectErr.Code(), code)
	}

	if connectErr.Message() != "" {
		t.Fatalf("message = %q, want it empty", connectErr.Message())
	}
}

// newInterceptor builds the interceptor under test.
func newInterceptor(
	t *testing.T,
	tokenVerifier interceptor.TokenVerifier,
	table authz.Policies,
	opts ...interceptor.Option,
) connect.ServerInterceptor {
	t.Helper()

	built, err := interceptor.New(tokenVerifier, table, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return built
}

type fakeServerStream struct{}

func (fakeServerStream) Receive(any) error  { return nil }
func (fakeServerStream) SendHeaders() error { return nil }
func (fakeServerStream) Send(any) error     { return nil }

func newStreamingServer(handler connect.ServerFunc, interceptors ...connect.ServerInterceptor) *connect.Server {
	server := connect.NewServer(interceptors...)

	for _, procedure := range []string{
		testProcedure,
		testPublicProcedure,
		testInternalProcedure,
		testUntabledProcedure,
	} {
		server.Register(connect.Method{
			Spec:    connect.Spec{Procedure: procedure, StreamType: connect.StreamTypeBidi},
			Handler: handler,
		})
	}

	return server
}

func callStreaming(t *testing.T, server *connect.Server, procedure, authorization string) error {
	t.Helper()

	info := &connect.CallInfo{}
	if authorization != "" {
		info.RequestHeader().Set("Authorization", authorization)
	}

	return server.Call(t.Context(), procedure, info, fakeServerStream{})
}
