package interceptor_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

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

func (jsonCodec) Marshal(message any) ([]byte, error) {
	encoded, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("marshal test message: %w", err)
	}

	return encoded, nil
}

func (jsonCodec) Unmarshal(data []byte, message any) error {
	if err := json.Unmarshal(data, message); err != nil {
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
		return nil, fmt.Errorf("%w: %q", errNoSuchKey, keyID)
	}

	return key, nil
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

	tokenVerifier, err := verifier.New(testIssuerID, testAudience, staticKeys{keys: keys})
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

func (h *testHandler) handle(ctx context.Context, req *connect.Request[testMessage]) (*connect.Response[testMessage], error) {
	claims, found := internaljwt.ClaimsFromContext(ctx)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.called = true
	h.claims = claims
	h.found = found

	return connect.NewResponse(&testMessage{Value: req.Msg.Value}), nil
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
func newTestServer(t *testing.T, handler *testHandler, interceptors ...connect.Interceptor) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	procedures := []string{
		testProcedure,
		testPublicProcedure,
		testInternalProcedure,
		testUntabledProcedure,
	}

	for _, procedure := range procedures {
		mux.Handle(procedure, connect.NewUnaryHandler(
			procedure,
			handler.handle,
			connect.WithCodec(jsonCodec{}),
			connect.WithInterceptors(interceptors...),
		))
	}

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server
}

// call invokes a procedure of the test server, presenting authorization when
// it is not empty.
func call(t *testing.T, server *httptest.Server, procedure, authorization string) error {
	t.Helper()

	client := connect.NewClient[testMessage, testMessage](
		server.Client(),
		server.URL+procedure,
		connect.WithCodec(jsonCodec{}),
	)

	request := connect.NewRequest(&testMessage{Value: "ping"})
	if authorization != "" {
		request.Header().Set("Authorization", authorization)
	}

	_, err := client.CallUnary(t.Context(), request)

	return err
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
) connect.Interceptor {
	t.Helper()

	built, err := interceptor.New(tokenVerifier, table, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return built
}

// fakeStreamingConn is the handler's side of a streaming call, which connect
// lets a test implement itself.
type fakeStreamingConn struct {
	spec   connect.Spec
	header http.Header
}

func (c *fakeStreamingConn) Spec() connect.Spec           { return c.spec }
func (c *fakeStreamingConn) Peer() connect.Peer           { return connect.Peer{} }
func (c *fakeStreamingConn) Receive(any) error            { return nil }
func (c *fakeStreamingConn) RequestHeader() http.Header   { return c.header }
func (c *fakeStreamingConn) Send(any) error               { return nil }
func (c *fakeStreamingConn) ResponseHeader() http.Header  { return http.Header{} }
func (c *fakeStreamingConn) ResponseTrailer() http.Header { return http.Header{} }

// newStreamingConn is a streaming call of procedure presenting authorization.
func newStreamingConn(procedure, authorization string) *fakeStreamingConn {
	header := http.Header{}
	if authorization != "" {
		header.Set("Authorization", authorization)
	}

	return &fakeStreamingConn{
		spec:   connect.Spec{Procedure: procedure, StreamType: connect.StreamTypeBidi},
		header: header,
	}
}
