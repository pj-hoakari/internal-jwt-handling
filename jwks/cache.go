// Package jwks fetches the Service Gateway's JWKS and keeps its verification
// keys in memory. Verifying a token with them is the caller's business; this
// package only answers which public key a kid names.
package jwks

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

const (
	DefaultCacheTTL = 5 * time.Minute
	// DefaultRefreshCooldown rate limits the immediate refresh an unknown kid triggers.
	DefaultRefreshCooldown = 30 * time.Second
	DefaultFailureCooldown = 5 * time.Second
	DefaultFetchTimeout    = 5 * time.Second
	DefaultMaxDocumentSize = 1 << 20
)

var DefaultRetryBackoff = []time.Duration{100 * time.Millisecond, 200 * time.Millisecond}

var (
	ErrMissingURL       = errors.New("JWKS URL is required")
	ErrInvalidURL       = errors.New("JWKS URL is not an HTTP URL")
	ErrUnknownKeyID     = errors.New("unknown JWT key ID")
	ErrFailureCooldown  = errors.New("JWKS fetch is in its failure cooldown")
	ErrFetch            = errors.New("fetch JWKS")
	ErrUnexpectedStatus = errors.New("unexpected JWKS response status")
	ErrDocumentTooLarge = errors.New("JWKS document is too large")
	ErrDecodeDocument   = errors.New("decode JWKS document")
	ErrInvalidKey       = errors.New("invalid JWKS key")
	ErrDuplicateKeyID   = errors.New("duplicate JWKS key ID")
)

// Config configures a Cache.
type Config struct {
	// URL is the JWKS endpoint to fetch from.
	// required, and must be an HTTP or HTTPS
	URL string
	// HTTPClient sends the fetch. Nil uses http.DefaultClient.
	HTTPClient *http.Client
	// CacheTTL is how long a fetched document is served for.
	CacheTTL time.Duration
	// RefreshCooldown rate limits the refresh an unknown kid triggers.
	RefreshCooldown time.Duration
	// FailureCooldown holds the fetch off after a refresh failed every attempt.
	FailureCooldown time.Duration
	// FetchTimeout bounds one attempt.
	FetchTimeout time.Duration
	// RetryBackoff is the wait before each retry within one refresh. Nil uses
	// DefaultRetryBackoff; an empty slice makes the one attempt and no retry.
	RetryBackoff []time.Duration
	// MaxDocumentSize bounds the response body that is read, in bytes.
	MaxDocumentSize int64
}

type Cache struct {
	url             string
	client          *http.Client
	cacheTTL        time.Duration
	refreshCooldown time.Duration
	failureCooldown time.Duration
	fetchTimeout    time.Duration
	retryBackoff    []time.Duration
	maxDocumentSize int64

	mu     sync.Mutex
	keys   map[string]*ecdsa.PublicKey
	expiry time.Time

	// lastRefresh is the time of the last successful refresh.
	// A failed refresh leaves it alone so the next lookup may retry at once.
	lastRefresh time.Time
	// lastFailure is the time of the last refresh that failed every attempt,
	// and lastError the error it failed with.
	// A successful refresh resets both.
	lastFailure time.Time
	lastError   error

	// now is time.
	// Now in production and is replaced in tests to control the cache TTL and the two cooldowns.
	now func() time.Time

	// sleep waits out the retry backoff and is replaced in tests so the
	// retries cost no wall-clock time.
	sleep func(context.Context, time.Duration) error
}

// New creates a Cache holding no keys yet.
// It reaches no network; the first fetch happens on the first Key or Refresh call.
func New(config Config) (*Cache, error) {
	if err := validateURL(config.URL); err != nil {
		return nil, err
	}

	client := config.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	backoff := config.RetryBackoff
	if backoff == nil {
		backoff = DefaultRetryBackoff
	}

	return &Cache{
		url:             config.URL,
		client:          client,
		cacheTTL:        orDefaultDuration(config.CacheTTL, DefaultCacheTTL),
		refreshCooldown: orDefaultDuration(config.RefreshCooldown, DefaultRefreshCooldown),
		failureCooldown: orDefaultDuration(config.FailureCooldown, DefaultFailureCooldown),
		fetchTimeout:    orDefaultDuration(config.FetchTimeout, DefaultFetchTimeout),
		retryBackoff:    slices.Clone(backoff),
		maxDocumentSize: orDefaultSize(config.MaxDocumentSize, DefaultMaxDocumentSize),
		mu:              sync.Mutex{},
		keys:            make(map[string]*ecdsa.PublicKey),
		expiry:          time.Time{},
		lastRefresh:     time.Time{},
		lastFailure:     time.Time{},
		lastError:       nil,
		now:             time.Now,
		sleep:           sleepContext,
	}, nil
}

// Key is the verification key the kid names, fetching the JWKS when the cache
// has expired or the kid is one this process has not seen.
func (c *Cache) Key(ctx context.Context, keyID string) (*ecdsa.PublicKey, error) {
	if keyID == "" {
		return nil, internaljwt.ErrMissingKeyID
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()

	if now.Before(c.expiry) {
		if key, ok := c.keys[keyID]; ok {
			return key, nil
		}

		if now.Sub(c.lastRefresh) < c.refreshCooldown {
			return nil, fmt.Errorf("%w: %q", ErrUnknownKeyID, keyID)
		}
	}

	if !c.lastFailure.IsZero() && now.Sub(c.lastFailure) < c.failureCooldown {
		return nil, fmt.Errorf("%w: %w", ErrFailureCooldown, c.lastError)
	}

	if err := c.fetchLocked(ctx); err != nil {
		return nil, err
	}

	key, ok := c.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKeyID, keyID)
	}

	return key, nil
}

// Refresh fetches the JWKS and replaces the cached keys.
func (c *Cache) Refresh(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.fetchLocked(ctx)
}

// fetchLocked refreshes the cached keys and records the outcome.
func (c *Cache) fetchLocked(ctx context.Context) error {
	err := c.refresh(ctx)

	now := c.now()

	if err == nil {
		c.lastFailure = time.Time{}
		c.lastError = nil

		return nil
	}

	if ctx.Err() != nil {
		return err
	}

	c.lastFailure = now
	c.lastError = err

	slog.WarnContext(ctx, "fetching the internal JWT verification keys failed",
		slog.String("url", c.url),
		slog.String("error", err.Error()),
	)

	return err
}

// refresh replaces the cached keys, retrying the attempts a transient failure may recover from.
func (c *Cache) refresh(ctx context.Context) error {
	var err error

	for attempt := range len(c.retryBackoff) + 1 {
		if attempt > 0 {
			if waited := c.sleep(ctx, c.retryBackoff[attempt-1]); waited != nil {
				return err
			}
		}

		var retryable bool

		retryable, err = c.refreshOnce(ctx)
		if err == nil {
			return nil
		}

		if !retryable || ctx.Err() != nil {
			return err
		}
	}

	return err
}

// refreshOnce runs one JWKS fetch and reports whether its failure is one a
// later attempt may recover from.
func (c *Cache) refreshOnce(ctx context.Context) (bool, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, c.fetchTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, c.url, nil)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrFetch, err)
	}

	request.Header.Set("Accept", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return true, fmt.Errorf("%w: %w", ErrFetch, err)
	}

	defer func() {
		if err := response.Body.Close(); err != nil {
			slog.WarnContext(ctx, "closing the JWKS response body failed",
				slog.String("url", c.url),
				slog.String("error", err.Error()),
			)
		}
	}()

	if response.StatusCode != http.StatusOK {
		drain(response.Body)

		return retryableStatus(response.StatusCode), fmt.Errorf("%w: %s", ErrUnexpectedStatus, response.Status)
	}

	encoded, err := io.ReadAll(io.LimitReader(response.Body, c.maxDocumentSize+1))
	if err != nil {
		return true, fmt.Errorf("%w: %w", ErrFetch, err)
	}

	if int64(len(encoded)) > c.maxDocumentSize {
		drain(response.Body)

		return false, fmt.Errorf("%w: over %d bytes", ErrDocumentTooLarge, c.maxDocumentSize)
	}

	keys, err := parseKeys(encoded)
	if err != nil {
		return false, err
	}

	refreshed := c.now()
	c.keys = keys
	c.expiry = refreshed.Add(c.cacheTTL)
	c.lastRefresh = refreshed

	return false, nil
}

// parseKeys reads a JWKS document into the keys it publishes.
func parseKeys(encoded []byte) (map[string]*ecdsa.PublicKey, error) {
	var document internaljwt.JWKS

	if err := json.Unmarshal(encoded, &document); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeDocument, err)
	}

	keys := make(map[string]*ecdsa.PublicKey, len(document.Keys))

	for _, value := range document.Keys {
		key, err := internaljwt.PublicKey(value)
		if err != nil {
			return nil, fmt.Errorf("%w: kid %q: %w", ErrInvalidKey, value.KeyID, err)
		}

		if _, duplicate := keys[value.KeyID]; duplicate {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateKeyID, value.KeyID)
		}

		keys[value.KeyID] = key
	}

	return keys, nil
}

const drainLimit = 4 << 10

func drain(body io.Reader) {
	if _, err := io.Copy(io.Discard, io.LimitReader(body, drainLimit)); err != nil {
		return
	}
}

// validateURL checks that the endpoint is one this package can fetch from.
func validateURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return ErrMissingURL
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrInvalidURL, raw, err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: %q", ErrInvalidURL, raw)
	}

	if parsed.Host == "" {
		return fmt.Errorf("%w: %q", ErrInvalidURL, raw)
	}

	return nil
}

func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func orDefaultDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}

	return value
}

func orDefaultSize(value, fallback int64) int64 {
	if value <= 0 {
		return fallback
	}

	return value
}
