package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

const (
	pemTypeECPrivateKey = "EC PRIVATE KEY"
	pemTypePrivateKey   = "PRIVATE KEY"
	pemTypePublicKey    = "PUBLIC KEY"
)

type SigningKey struct {
	KeyID string
	Key   *ecdsa.PrivateKey
}

type PublishedKey struct {
	KeyID string
	Key   *ecdsa.PublicKey
}

// KeySet is the one key the issuer signs with together with the public keys the JWKS carries beside it.
type KeySet struct {
	Signing   SigningKey
	Published []PublishedKey
}

// KeyProvider supplies the key set in force at the moment of a call.
type KeyProvider interface {
	Current(ctx context.Context) (KeySet, error)
}

// KeyFile is one key on disk and the kid that names it.
type KeyFile struct {
	Path  string
	KeyID string
}

// FileKeyProviderConfig configures a FileKeyProvider.
// Signing is the private key to sign with, and must be present.
// Published lists the further public keys the JWKS carries.
type FileKeyProviderConfig struct {
	Signing         KeyFile
	Published       []KeyFile
	RefreshInterval time.Duration
}

const DefaultRefreshInterval = time.Minute

// FileKeyProvider reads the signing key and the published public keys from
// PEM files and re-reads them as they change on disk.
type FileKeyProvider struct {
	signing         KeyFile
	published       []KeyFile
	refreshInterval time.Duration

	mu       sync.Mutex
	keys     KeySet
	loadedAt time.Time
	// now is time.Now in production and is replaced in tests to control the refresh interval.
	now func() time.Time
}

// NewFileKeyProvider reads the configured key files once.
func NewFileKeyProvider(config FileKeyProviderConfig) (*FileKeyProvider, error) {
	refreshInterval := config.RefreshInterval
	if refreshInterval <= 0 {
		refreshInterval = DefaultRefreshInterval
	}

	provider := &FileKeyProvider{
		signing:         config.Signing,
		published:       slices.Clone(config.Published),
		refreshInterval: refreshInterval,
		mu:              sync.Mutex{},
		keys:            KeySet{Signing: SigningKey{KeyID: "", Key: nil}, Published: nil},
		loadedAt:        time.Time{},
		now:             time.Now,
	}

	keys, err := provider.load(context.Background())
	if err != nil {
		return nil, err
	}

	provider.keys = keys
	provider.loadedAt = provider.now()

	return provider, nil
}

// Current returns the key set, re-reading the key files once the refresh interval has passed.
func (p *FileKeyProvider) Current(ctx context.Context) (KeySet, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	if now.Sub(p.loadedAt) < p.refreshInterval {
		return p.currentLocked(), nil
	}

	keys, err := p.load(ctx)
	if err != nil {
		// The next attempt waits out another interval rather than re-reading
		// on every token, so that a key file that stays broken does not write
		// one warning per issued JWT.
		p.loadedAt = now

		slog.WarnContext(ctx, "re-reading the internal JWT key files failed; keeping the keys loaded before",
			slog.String("error", err.Error()),
			slog.String("signing_kid", p.keys.Signing.KeyID),
		)

		return p.currentLocked(), nil
	}

	p.keys = keys
	p.loadedAt = now

	return p.currentLocked(), nil
}

func (p *FileKeyProvider) currentLocked() KeySet {
	return KeySet{
		Signing:   p.keys.Signing,
		Published: slices.Clone(p.keys.Published),
	}
}

func (p *FileKeyProvider) load(ctx context.Context) (KeySet, error) {
	if p.signing.KeyID == "" {
		return KeySet{}, errors.New("signing key ID is required")
	}

	signingKey, err := readPrivateKeyFile(p.signing.Path)
	if err != nil {
		return KeySet{}, fmt.Errorf("read signing key %q: %w", p.signing.KeyID, err)
	}

	published := make([]PublishedKey, 0, len(p.published))
	seen := map[string]struct{}{p.signing.KeyID: {}}

	for _, file := range p.published {
		if file.KeyID == "" {
			return KeySet{}, errors.New("published key ID is required")
		}

		// A kid must name one key.
		if _, duplicate := seen[file.KeyID]; duplicate {
			return KeySet{}, fmt.Errorf("duplicate key ID %q", file.KeyID)
		}

		publicKey, err := readPublicKeyFile(ctx, file)
		if err != nil {
			return KeySet{}, fmt.Errorf("read published key %q: %w", file.KeyID, err)
		}

		seen[file.KeyID] = struct{}{}
		published = append(published, PublishedKey{KeyID: file.KeyID, Key: publicKey})
	}

	return KeySet{
		Signing:   SigningKey{KeyID: p.signing.KeyID, Key: signingKey},
		Published: published,
	}, nil
}

func readPrivateKeyFile(path string) (*ecdsa.PrivateKey, error) {
	block, err := readPEMFile(path)
	if err != nil {
		return nil, err
	}

	key, err := parsePrivateKey(block)
	if err != nil {
		return nil, err
	}

	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("unsupported curve %q: internal JWTs are signed with P-256 keys", internaljwt.CurveName(key.Curve))
	}

	return key, nil
}

func readPublicKeyFile(ctx context.Context, file KeyFile) (*ecdsa.PublicKey, error) {
	block, err := readPEMFile(file.Path)
	if err != nil {
		return nil, err
	}

	if block.Type != pemTypePublicKey {
		// The public half is all that is needed here, so a private key on this
		// path is more key material in the process than the deployment has to
		// expose. The record names the file, never its contents.
		slog.WarnContext(ctx, "a published internal JWT key is configured as a private key file; only the public key is needed",
			slog.String("kid", file.KeyID),
			slog.String("path", file.Path),
		)
	}

	key, err := parsePublicKey(block)
	if err != nil {
		return nil, err
	}

	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("unsupported curve %q: internal JWT keys are P-256", internaljwt.CurveName(key.Curve))
	}

	return key, nil
}

func readPEMFile(path string) (*pem.Block, error) {
	if path == "" {
		return nil, errors.New("key file path is required")
	}

	encoded, err := os.ReadFile(path) //nolint:gosec // operator-configured key file path
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, errors.New("key file holds no PEM block")
	}

	return block, nil
}

func parsePrivateKey(block *pem.Block) (*ecdsa.PrivateKey, error) {
	switch block.Type {
	case pemTypeECPrivateKey:
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse SEC1 private key: %w", err)
		}

		return key, nil
	case pemTypePrivateKey:
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}

		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unsupported private key type %T: internal JWTs are signed with ECDSA keys", parsed)
		}

		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block %q: expected %q or %q", block.Type, pemTypeECPrivateKey, pemTypePrivateKey)
	}
}

func parsePublicKey(block *pem.Block) (*ecdsa.PublicKey, error) {
	if block.Type == pemTypePublicKey {
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}

		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("unsupported public key type %T: internal JWT keys are ECDSA keys", parsed)
		}

		return key, nil
	}

	privateKey, err := parsePrivateKey(block)
	if err != nil {
		return nil, fmt.Errorf("unsupported PEM block %q: expected %q, a private key, or: %w", block.Type, pemTypePublicKey, err)
	}

	return &privateKey.PublicKey, nil
}
