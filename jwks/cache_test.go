package jwks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/jwtgen"
)

const testURL = "https://jwks.example.test/keys"

// TestMain silences the warning a failed fetch records. Every test here that
// makes one expects it, and the records would drown the output.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

func TestNewRejectsAMissingURL(t *testing.T) {
	t.Parallel()

	for name, url := range map[string]string{"empty": "", "blank": "  "} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := New(Config{URL: url}); !errors.Is(err, ErrMissingURL) {
				t.Fatalf("New error = %v, want %v", err, ErrMissingURL)
			}
		})
	}
}

// TestNewRejectsANonHTTPURL pins that a misconfigured endpoint fails at
// startup rather than on the first token that needs a key.
func TestNewRejectsANonHTTPURL(t *testing.T) {
	t.Parallel()

	urls := map[string]string{
		"no scheme":    "jwks.example.test/keys",
		"ftp":          "ftp://jwks.example.test/keys",
		"no host":      "https:///keys",
		"opaque":       "https:jwks.example.test",
		"control byte": "https://jwks.example.test/\x7f",
	}

	for name, url := range urls {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := New(Config{URL: url}); !errors.Is(err, ErrInvalidURL) {
				t.Fatalf("New(%q) error = %v, want %v", url, err, ErrInvalidURL)
			}
		})
	}
}

func TestKeyRejectsAMissingKeyID(t *testing.T) {
	t.Parallel()

	cache, _ := newTestCache(t, Config{URL: testURL, HTTPClient: failingClient(t)})

	if _, err := cache.Key(context.Background(), ""); !errors.Is(err, internaljwt.ErrMissingKeyID) {
		t.Fatalf("Key error = %v, want %v", err, internaljwt.ErrMissingKeyID)
	}
}

// TestKeyServesACachedKeyWithoutFetchingAgain pins the cache itself: the
// second lookup of a kid already held is answered without a fetch.
func TestKeyServesACachedKeyWithoutFetchingAgain(t *testing.T) {
	t.Parallel()

	document := generateJWKS(t, "key-1")

	var mu sync.Mutex

	requests := 0
	client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		requests++
		mu.Unlock()

		if got, want := request.Header.Get("Accept"), "application/json"; got != want {
			t.Errorf("Accept header = %q, want %q", got, want)
		}

		return jsonResponse(t, document), nil
	})}

	cache, _ := newTestCache(t, Config{URL: testURL, HTTPClient: client})

	for range 2 {
		key, err := cache.Key(context.Background(), "key-1")
		if err != nil {
			t.Fatalf("Key error = %v", err)
		}

		if key == nil {
			t.Fatal("Key returned no key")
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if got, want := requests, 1; got != want {
		t.Errorf("JWKS fetches = %d, want %d", got, want)
	}
}

// TestKeyFetchesOnceForConcurrentCallers pins the single-flight the mutex
// gives: every caller of a cold cache shares one fetch.
func TestKeyFetchesOnceForConcurrentCallers(t *testing.T) {
	t.Parallel()

	jwks := &countingJWKS{document: generateJWKS(t, "key-1")}
	server := httptest.NewServer(jwks)

	t.Cleanup(server.Close)

	cache, _ := newTestCache(t, Config{URL: server.URL, HTTPClient: server.Client()})

	const callers = 20

	var wait sync.WaitGroup

	failures := make(chan error, callers)

	for range callers {
		wait.Add(1)

		go func() {
			defer wait.Done()

			if _, err := cache.Key(context.Background(), "key-1"); err != nil {
				failures <- err
			}
		}()
	}

	wait.Wait()
	close(failures)

	for err := range failures {
		t.Errorf("Key error = %v", err)
	}

	if got, want := jwks.fetches(), 1; got != want {
		t.Errorf("JWKS fetches = %d, want %d", got, want)
	}
}

// TestKeyRateLimitsUnknownKeyIDRefresh covers the refresh rate limit an
// unknown kid is subject to: within the cooldown the JWKS is not fetched
// again, and once it has passed the newly published key is picked up.
func TestKeyRateLimitsUnknownKeyIDRefresh(t *testing.T) {
	t.Parallel()

	current := generateJWKS(t, "key-1")

	jwks := &countingJWKS{document: current}
	server := httptest.NewServer(jwks)

	t.Cleanup(server.Close)

	cache, clock := newTestCache(t, Config{URL: server.URL, HTTPClient: server.Client()})

	if _, err := cache.Key(context.Background(), "key-1"); err != nil {
		t.Fatalf("Key error = %v", err)
	}

	if got, want := jwks.fetches(), 1; got != want {
		t.Fatalf("JWKS fetches after the first lookup = %d, want %d", got, want)
	}

	for range 3 {
		if _, err := cache.Key(context.Background(), "key-2"); !errors.Is(err, ErrUnknownKeyID) {
			t.Fatalf("Key error = %v, want %v while the unknown kid is rate limited", err, ErrUnknownKeyID)
		}
	}

	if got, want := jwks.fetches(), 1; got != want {
		t.Errorf("JWKS fetches within the refresh cooldown = %d, want %d", got, want)
	}

	jwks.serve(mergeJWKS(current, generateJWKS(t, "key-2")))
	clock.add(DefaultRefreshCooldown)

	if _, err := cache.Key(context.Background(), "key-2"); err != nil {
		t.Fatalf("Key after the refresh cooldown error = %v", err)
	}

	if got, want := jwks.fetches(), 2; got != want {
		t.Errorf("JWKS fetches after the refresh cooldown = %d, want %d", got, want)
	}
}

// TestKeyRefreshesAnExpiredCacheDuringTheCooldown pins the precedence of the
// cache TTL over the refresh cooldown: an expired cache is refreshed even when
// the last refresh is more recent than the cooldown. A TTL shorter than the
// cooldown is the configuration where the two overlap.
func TestKeyRefreshesAnExpiredCacheDuringTheCooldown(t *testing.T) {
	t.Parallel()

	jwks := &countingJWKS{document: generateJWKS(t, "key-1")}
	server := httptest.NewServer(jwks)

	t.Cleanup(server.Close)

	cache, clock := newTestCache(t, Config{
		URL: server.URL, HTTPClient: server.Client(),
		CacheTTL: 10 * time.Second, RefreshCooldown: time.Minute,
	})

	if _, err := cache.Key(context.Background(), "key-1"); err != nil {
		t.Fatalf("Key error = %v", err)
	}

	// The cache has expired while the refresh cooldown is still running.
	clock.add(10 * time.Second)

	if _, err := cache.Key(context.Background(), "key-1"); err != nil {
		t.Fatalf("Key after the cache expired error = %v", err)
	}

	if got, want := jwks.fetches(), 2; got != want {
		t.Errorf("JWKS fetches after the cache expired = %d, want %d", got, want)
	}
}

// TestKeyDoesNotServeAStaleKey pins that the cache TTL is a limit and not a
// hint: once it has passed, a kid is answered from a fresh document or not at
// all, never from the keys the expired one held.
func TestKeyDoesNotServeAStaleKey(t *testing.T) {
	t.Parallel()

	jwks := &scriptedJWKS{document: generateJWKS(t, "key-1")}
	server := httptest.NewServer(jwks)

	t.Cleanup(server.Close)

	cache, clock := newTestCache(t, Config{URL: server.URL, HTTPClient: server.Client()})

	if _, err := cache.Key(context.Background(), "key-1"); err != nil {
		t.Fatalf("Key error = %v", err)
	}

	jwks.serveRest(jwksReply{status: http.StatusServiceUnavailable})
	clock.add(DefaultCacheTTL)

	if _, err := cache.Key(context.Background(), "key-1"); !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("Key error = %v, want %v rather than the expired key", err, ErrUnexpectedStatus)
	}
}

// TestKeyForgetsAWithdrawnKeyID pins that a refresh replaces the keys whole: a
// kid the gateway no longer publishes stops verifying anything.
func TestKeyForgetsAWithdrawnKeyID(t *testing.T) {
	t.Parallel()

	current := generateJWKS(t, "key-1")
	withdrawn := generateJWKS(t, "key-2")

	jwks := &countingJWKS{document: mergeJWKS(current, withdrawn)}
	server := httptest.NewServer(jwks)

	t.Cleanup(server.Close)

	cache, clock := newTestCache(t, Config{URL: server.URL, HTTPClient: server.Client()})

	if _, err := cache.Key(context.Background(), "key-2"); err != nil {
		t.Fatalf("Key error = %v", err)
	}

	jwks.serve(current)
	clock.add(DefaultCacheTTL)

	if _, err := cache.Key(context.Background(), "key-2"); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("Key for the withdrawn kid error = %v, want %v", err, ErrUnknownKeyID)
	}

	if _, err := cache.Key(context.Background(), "key-1"); err != nil {
		t.Fatalf("Key for the kid still published error = %v", err)
	}
}

// TestKeyRetriesTransientFetchFailures covers the retries one refresh makes: a
// Service Gateway that cannot answer for a moment still yields a key rather
// than failing the lookup.
func TestKeyRetriesTransientFetchFailures(t *testing.T) {
	t.Parallel()

	tests := map[string][]jwksReply{
		"service unavailable": {{status: http.StatusServiceUnavailable}, {status: http.StatusServiceUnavailable}},
		"too many requests":   {{status: http.StatusTooManyRequests}},
	}

	for name, replies := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			jwks := &scriptedJWKS{document: generateJWKS(t, "key-1"), replies: replies}
			server := httptest.NewServer(jwks)

			t.Cleanup(server.Close)

			cache, _ := newTestCache(t, Config{URL: server.URL, HTTPClient: server.Client()})

			sleeps := 0
			cache.sleep = countingSleep(&sleeps)

			if _, err := cache.Key(context.Background(), "key-1"); err != nil {
				t.Fatalf("Key error = %v", err)
			}

			if got, want := jwks.fetches(), len(replies)+1; got != want {
				t.Errorf("JWKS fetches = %d, want %d", got, want)
			}

			if got, want := sleeps, len(replies); got != want {
				t.Errorf("retry waits = %d, want %d", got, want)
			}
		})
	}
}

// TestKeyCoolsDownAfterAFailedRefresh covers the cooldown a refresh that
// failed every attempt starts: within it the JWKS is not fetched again, the
// failure that started it is still readable, and once it has passed the fetch
// is retried.
func TestKeyCoolsDownAfterAFailedRefresh(t *testing.T) {
	t.Parallel()

	jwks := &scriptedJWKS{document: generateJWKS(t, "key-1"), rest: jwksReply{status: http.StatusServiceUnavailable}}
	server := httptest.NewServer(jwks)

	t.Cleanup(server.Close)

	cache, clock := newTestCache(t, Config{URL: server.URL, HTTPClient: server.Client()})

	sleeps := 0
	cache.sleep = countingSleep(&sleeps)

	if _, err := cache.Key(context.Background(), "key-1"); !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("Key error = %v, want %v once every attempt has failed", err, ErrUnexpectedStatus)
	}

	attempts := len(DefaultRetryBackoff) + 1
	if got, want := jwks.fetches(), attempts; got != want {
		t.Fatalf("JWKS fetches after the failed refresh = %d, want %d", got, want)
	}

	clock.add(DefaultFailureCooldown - time.Second)

	_, err := cache.Key(context.Background(), "key-1")
	if !errors.Is(err, ErrFailureCooldown) {
		t.Fatalf("Key error = %v, want %v while the failure cooldown is running", err, ErrFailureCooldown)
	}

	// The cooldown carries the failure that started it, so a caller can tell
	// a gateway that is down from one that answers with something else.
	if !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("Key error = %v, want it to carry %v", err, ErrUnexpectedStatus)
	}

	if got, want := jwks.fetches(), attempts; got != want {
		t.Errorf("JWKS fetches within the failure cooldown = %d, want %d", got, want)
	}

	jwks.serveRest(jwksReply{status: http.StatusOK})
	clock.add(time.Second)

	if _, err := cache.Key(context.Background(), "key-1"); err != nil {
		t.Fatalf("Key after the failure cooldown error = %v", err)
	}

	if got, want := jwks.fetches(), attempts+1; got != want {
		t.Errorf("JWKS fetches after the failure cooldown = %d, want %d", got, want)
	}
}

// TestKeyCoolsDownFromWhenTheFetchGaveUp pins where the failure cooldown is
// measured from. Every attempt against a gateway that accepts the connection
// and then hangs runs out its whole timeout, so a cooldown timed from the
// start of the refresh would already have passed by the time the caller is
// handed the failure, and the next lookup would fetch again at once.
func TestKeyCoolsDownFromWhenTheFetchGaveUp(t *testing.T) {
	t.Parallel()

	hands := newClock()

	var mu sync.Mutex

	requests := 0
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		mu.Lock()
		requests++
		mu.Unlock()

		// Every attempt hangs for the whole fetch timeout before it fails.
		hands.add(DefaultFetchTimeout)

		return statusResponse(http.StatusGatewayTimeout), nil
	})}

	cache := newTestCacheOn(t, Config{URL: testURL, HTTPClient: client}, hands)

	if _, err := cache.Key(context.Background(), "key-1"); !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("Key error = %v, want %v", err, ErrUnexpectedStatus)
	}

	attempts := len(DefaultRetryBackoff) + 1

	mu.Lock()
	after := requests
	mu.Unlock()

	if after != attempts {
		t.Fatalf("JWKS fetches after the failed refresh = %d, want %d", after, attempts)
	}

	// More than the failure cooldown has passed since the refresh began, and
	// none of it since the refresh gave up.
	if elapsed := hands.at().Sub(newClock().at()); elapsed <= DefaultFailureCooldown {
		t.Fatalf("the hung fetch took %s, want more than the failure cooldown %s", elapsed, DefaultFailureCooldown)
	}

	if _, err := cache.Key(context.Background(), "key-1"); !errors.Is(err, ErrFailureCooldown) {
		t.Fatalf("Key error = %v, want %v", err, ErrFailureCooldown)
	}

	mu.Lock()
	defer mu.Unlock()

	if requests != attempts {
		t.Errorf("JWKS fetches within the failure cooldown = %d, want %d", requests, attempts)
	}
}

// TestKeyServesAKnownKeyIDDuringTheFailureCooldown pins the reach of the
// failure cooldown: a fetch that failed says nothing about the keys already
// cached, so a kid this process holds is still answered.
func TestKeyServesAKnownKeyIDDuringTheFailureCooldown(t *testing.T) {
	t.Parallel()

	jwks := &scriptedJWKS{document: generateJWKS(t, "key-1")}
	server := httptest.NewServer(jwks)

	t.Cleanup(server.Close)

	cache, clock := newTestCache(t, Config{URL: server.URL, HTTPClient: server.Client()})

	sleeps := 0
	cache.sleep = countingSleep(&sleeps)

	if _, err := cache.Key(context.Background(), "key-1"); err != nil {
		t.Fatalf("Key error = %v", err)
	}

	// The unknown kid is past its refresh cooldown and the cache is still
	// within its TTL, so the refresh it triggers is the one that fails.
	jwks.serveRest(jwksReply{status: http.StatusServiceUnavailable})
	clock.add(DefaultRefreshCooldown)

	if _, err := cache.Key(context.Background(), "key-2"); err == nil {
		t.Fatal("Key error = nil, want an error once every attempt has failed")
	}

	failed := len(DefaultRetryBackoff) + 2
	if got, want := jwks.fetches(), failed; got != want {
		t.Fatalf("JWKS fetches after the failed refresh = %d, want %d", got, want)
	}

	if _, err := cache.Key(context.Background(), "key-1"); err != nil {
		t.Fatalf("Key for the cached kid error = %v", err)
	}

	if got, want := jwks.fetches(), failed; got != want {
		t.Errorf("JWKS fetches for the cached kid = %d, want %d", got, want)
	}
}

// TestKeyDoesNotRetryPermanentFailures pins which failures the retries are
// for: a response a later attempt would only repeat ends the refresh on the
// first attempt.
func TestKeyDoesNotRetryPermanentFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		reply jwksReply
		want  error
	}{
		"unexpected status":  {reply: jwksReply{status: http.StatusNotFound}, want: ErrUnexpectedStatus},
		"malformed document": {reply: jwksReply{status: http.StatusOK, body: `{"keys":`}, want: ErrDecodeDocument},
		"trailing bytes":     {reply: jwksReply{status: http.StatusOK, body: `{"keys":[]} and then some`}, want: ErrDecodeDocument},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			jwks := &scriptedJWKS{document: generateJWKS(t, "key-1"), rest: test.reply}
			server := httptest.NewServer(jwks)

			t.Cleanup(server.Close)

			cache, _ := newTestCache(t, Config{URL: server.URL, HTTPClient: server.Client()})

			sleeps := 0
			cache.sleep = countingSleep(&sleeps)

			if _, err := cache.Key(context.Background(), "key-1"); !errors.Is(err, test.want) {
				t.Fatalf("Key error = %v, want %v", err, test.want)
			}

			if got, want := jwks.fetches(), 1; got != want {
				t.Errorf("JWKS fetches = %d, want %d", got, want)
			}

			if got, want := sleeps, 0; got != want {
				t.Errorf("retry waits = %d, want %d", got, want)
			}
		})
	}
}

// TestKeyDoesNotRetryACancelledContext covers the parent context: once it is
// done the retries are pointless, so the first failure ends the refresh.
func TestKeyDoesNotRetryACancelledContext(t *testing.T) {
	t.Parallel()

	jwks := &scriptedJWKS{document: generateJWKS(t, "key-1")}
	server := httptest.NewServer(jwks)

	t.Cleanup(server.Close)

	cache, _ := newTestCache(t, Config{URL: server.URL, HTTPClient: server.Client()})

	sleeps := 0
	cache.sleep = countingSleep(&sleeps)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := cache.Key(ctx, "key-1"); err == nil {
		t.Fatal("Key error = nil, want an error for a cancelled context")
	}

	if got, want := sleeps, 0; got != want {
		t.Errorf("retry waits = %d, want %d", got, want)
	}

	if got, want := jwks.fetches(), 0; got != want {
		t.Errorf("JWKS fetches = %d, want %d", got, want)
	}
}

// TestKeyDoesNotCoolDownAfterACancelledContext pins whose failure the cooldown
// is for. A caller that gave up on its own context has learned nothing about
// the gateway, so it must not hold every other caller off for a cooldown.
func TestKeyDoesNotCoolDownAfterACancelledContext(t *testing.T) {
	t.Parallel()

	jwks := &countingJWKS{document: generateJWKS(t, "key-1")}
	server := httptest.NewServer(jwks)

	t.Cleanup(server.Close)

	cache, _ := newTestCache(t, Config{URL: server.URL, HTTPClient: server.Client()})

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := cache.Key(cancelled, "key-1"); err == nil {
		t.Fatal("Key error = nil, want an error for a cancelled context")
	}

	// The clock has not moved, so a recorded failure would still be in its
	// cooldown and this lookup would never reach the gateway.
	key, err := cache.Key(context.Background(), "key-1")
	if err != nil {
		t.Fatalf("Key error = %v, want the fetch the cancelled caller did not make", err)
	}

	if key == nil {
		t.Fatal("Key returned no key")
	}

	if got, want := jwks.fetches(), 1; got != want {
		t.Errorf("JWKS fetches = %d, want %d", got, want)
	}
}

// TestKeyBoundsTheDocumentSize covers the bound on the response body: a
// document of exactly the maximum is read, one byte more is refused, so an
// endpoint answering with something other than a JWKS cannot fill this process.
func TestKeyBoundsTheDocumentSize(t *testing.T) {
	t.Parallel()

	body := marshalJWKS(t, generateJWKS(t, "key-1"))
	size := int64(len(body))

	tests := map[string]struct {
		body []byte
		want error
	}{
		"at the maximum":   {body: body, want: nil},
		"one byte over it": {body: append(append([]byte{}, body...), ' '), want: ErrDocumentTooLarge},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return rawResponse(http.StatusOK, test.body), nil
			})}

			cache, _ := newTestCache(t, Config{URL: testURL, HTTPClient: client, MaxDocumentSize: size})

			if _, err := cache.Key(context.Background(), "key-1"); !errors.Is(err, test.want) {
				t.Fatalf("Key error = %v, want %v", err, test.want)
			}
		})
	}
}

// TestKeyRejectsAnInvalidKey pins that a key of the wrong shape is refused
// where the document is read, and that the reason survives the wrapping.
func TestKeyRejectsAnInvalidKey(t *testing.T) {
	t.Parallel()

	document := generateJWKS(t, "key-1")
	document.Keys[0].Curve = "P-384"

	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(t, document), nil
	})}

	cache, _ := newTestCache(t, Config{URL: testURL, HTTPClient: client})

	_, err := cache.Key(context.Background(), "key-1")
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Key error = %v, want %v", err, ErrInvalidKey)
	}

	if !errors.Is(err, internaljwt.ErrUnsupportedCurve) {
		t.Fatalf("Key error = %v, want it to carry %v", err, internaljwt.ErrUnsupportedCurve)
	}
}

// TestKeyRejectsADuplicateKeyID pins that a kid names one key: a document that
// publishes the same kid twice leaves the choice to its order.
func TestKeyRejectsADuplicateKeyID(t *testing.T) {
	t.Parallel()

	document := generateJWKS(t, "key-1")
	document.Keys = append(document.Keys, document.Keys[0])

	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(t, document), nil
	})}

	cache, _ := newTestCache(t, Config{URL: testURL, HTTPClient: client})

	if _, err := cache.Key(context.Background(), "key-1"); !errors.Is(err, ErrDuplicateKeyID) {
		t.Fatalf("Key error = %v, want %v", err, ErrDuplicateKeyID)
	}
}

// TestKeyAcceptsADocumentWithoutKeys pins that a gateway publishing no key is
// a valid answer that every lookup then reports as an unknown kid.
func TestKeyAcceptsADocumentWithoutKeys(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(t, internaljwt.JWKS{Keys: nil}), nil
	})}

	cache, _ := newTestCache(t, Config{URL: testURL, HTTPClient: client})

	if _, err := cache.Key(context.Background(), "key-1"); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("Key error = %v, want %v", err, ErrUnknownKeyID)
	}
}

// TestRefreshIgnoresTheRefreshCooldown covers the warm-up a process makes at
// startup: Refresh fetches whatever the refresh cooldown says.
func TestRefreshIgnoresTheRefreshCooldown(t *testing.T) {
	t.Parallel()

	current := generateJWKS(t, "key-1")
	rotated := generateJWKS(t, "key-2")

	jwks := &countingJWKS{document: current}
	server := httptest.NewServer(jwks)

	t.Cleanup(server.Close)

	cache, _ := newTestCache(t, Config{URL: server.URL, HTTPClient: server.Client()})

	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh error = %v", err)
	}

	// The clock does not move, so the cooldown the first call started is
	// still running when the second is made.
	jwks.serve(rotated)

	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh within the refresh cooldown error = %v", err)
	}

	if got, want := jwks.fetches(), 2; got != want {
		t.Fatalf("JWKS fetches = %d, want %d", got, want)
	}

	if _, err := cache.Key(context.Background(), "key-2"); err != nil {
		t.Fatalf("Key for the newly published kid error = %v", err)
	}
}

// TestRefreshIgnoresTheFailureCooldown pins the other cooldown Refresh is
// exempt from: a process retrying its warm-up is not the per-request traffic
// the cooldown holds off.
func TestRefreshIgnoresTheFailureCooldown(t *testing.T) {
	t.Parallel()

	jwks := &scriptedJWKS{document: generateJWKS(t, "key-1"), rest: jwksReply{status: http.StatusServiceUnavailable}}
	server := httptest.NewServer(jwks)

	t.Cleanup(server.Close)

	cache, _ := newTestCache(t, Config{URL: server.URL, HTTPClient: server.Client()})

	sleeps := 0
	cache.sleep = countingSleep(&sleeps)

	if err := cache.Refresh(context.Background()); !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("Refresh error = %v, want %v once every attempt has failed", err, ErrUnexpectedStatus)
	}

	attempts := len(DefaultRetryBackoff) + 1
	if got, want := jwks.fetches(), attempts; got != want {
		t.Fatalf("JWKS fetches after the failed refresh = %d, want %d", got, want)
	}

	// The failed Refresh started the cooldown a lookup is subject to.
	if _, err := cache.Key(context.Background(), "key-1"); !errors.Is(err, ErrFailureCooldown) {
		t.Fatalf("Key error = %v, want %v", err, ErrFailureCooldown)
	}

	if got, want := jwks.fetches(), attempts; got != want {
		t.Fatalf("JWKS fetches within the failure cooldown = %d, want %d", got, want)
	}

	jwks.serveRest(jwksReply{status: http.StatusOK})

	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh within the failure cooldown error = %v", err)
	}

	if got, want := jwks.fetches(), attempts+1; got != want {
		t.Errorf("JWKS fetches after the failure cooldown was ignored = %d, want %d", got, want)
	}

	// The successful Refresh cleared the cooldown for the lookups too.
	if _, err := cache.Key(context.Background(), "key-1"); err != nil {
		t.Fatalf("Key after the successful refresh error = %v", err)
	}
}

// clock is a hand-wound time source the cache reads through its now hook.
type clock struct {
	mu   sync.Mutex
	time time.Time
}

func newClock() *clock {
	return &clock{mu: sync.Mutex{}, time: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *clock) at() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.time
}

func (c *clock) add(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.time = c.time.Add(duration)
}

// newTestCache builds a cache on a hand-wound clock and an instant backoff.
func newTestCache(t *testing.T, config Config) (*Cache, *clock) {
	t.Helper()

	hands := newClock()

	return newTestCacheOn(t, config, hands), hands
}

// newTestCacheOn builds a cache on a clock the caller already holds, for a
// test whose HTTP stub winds it on.
func newTestCacheOn(t *testing.T, config Config, hands *clock) *Cache {
	t.Helper()

	cache, err := New(config)
	if err != nil {
		t.Fatalf("New error = %v", err)
	}

	cache.now = hands.at
	cache.sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }

	return cache
}

// generateJWKS is the JWKS of one freshly generated signing key.
func generateJWKS(t *testing.T, keyID string) internaljwt.JWKS {
	t.Helper()

	generator, err := jwtgen.NewGenerator(keyID)
	if err != nil {
		t.Fatalf("NewGenerator error = %v", err)
	}

	document, err := generator.JWKS()
	if err != nil {
		t.Fatalf("JWKS error = %v", err)
	}

	return document
}

// mergeJWKS is the document that publishes every key of the given ones.
func mergeJWKS(documents ...internaljwt.JWKS) internaljwt.JWKS {
	merged := internaljwt.JWKS{Keys: nil}
	for _, document := range documents {
		merged.Keys = append(merged.Keys, document.Keys...)
	}

	return merged
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// failingClient fails every request it is asked to make.
func failingClient(t *testing.T) *http.Client {
	t.Helper()

	return &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		t.Error("the JWKS was fetched where no fetch was expected")

		return nil, errors.New("unexpected fetch")
	})}
}

func marshalJWKS(t *testing.T, document internaljwt.JWKS) []byte {
	t.Helper()

	body, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}

	return body
}

func jsonResponse(t *testing.T, document internaljwt.JWKS) *http.Response {
	t.Helper()

	return rawResponse(http.StatusOK, marshalJWKS(t, document))
}

func rawResponse(status int, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}
}

func statusResponse(status int) *http.Response {
	return rawResponse(status, nil)
}

// countingJWKS serves a swappable JWKS document and counts the fetches.
type countingJWKS struct {
	mu       sync.Mutex
	document internaljwt.JWKS
	requests int
}

func (s *countingJWKS) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	document := s.document
	s.requests++
	s.mu.Unlock()

	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(document)
}

func (s *countingJWKS) serve(document internaljwt.JWKS) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.document = document
}

func (s *countingJWKS) fetches() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.requests
}

// scriptedJWKS serves one scripted reply per fetch and falls back to rest once
// the script runs out. It counts the fetches.
type scriptedJWKS struct {
	mu       sync.Mutex
	document internaljwt.JWKS
	replies  []jwksReply
	rest     jwksReply
	requests int
}

// jwksReply is one response of the script. The zero value and any 200 without
// a body serve the JWKS document.
type jwksReply struct {
	status int
	body   string
}

func (s *scriptedJWKS) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.requests++
	document := s.document
	reply := s.rest

	if len(s.replies) > 0 {
		reply, s.replies = s.replies[0], s.replies[1:]
	}
	s.mu.Unlock()

	writer.Header().Set("Content-Type", "application/json")

	if reply.status != 0 && reply.status != http.StatusOK {
		writer.WriteHeader(reply.status)

		return
	}

	if reply.body != "" {
		io.WriteString(writer, reply.body)

		return
	}

	json.NewEncoder(writer).Encode(document)
}

func (s *scriptedJWKS) serveRest(reply jwksReply) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rest = reply
}

func (s *scriptedJWKS) fetches() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.requests
}

// countingSleep replaces the retry backoff with an instant wait, so the tests
// spend no wall-clock time on it, and counts how often it was waited out.
func countingSleep(count *int) func(context.Context, time.Duration) error {
	return func(ctx context.Context, _ time.Duration) error {
		*count++

		return ctx.Err()
	}
}
