package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, path string, blockType string, der []byte) {
	t.Helper()

	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Headers: nil, Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeSEC1 writes a private key in the SEC1 ("EC PRIVATE KEY") encoding.
func writeSEC1(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal SEC1 key: %v", err)
	}

	writeFile(t, path, "EC PRIVATE KEY", der)
}

// writePKCS8 writes a private key in the PKCS#8 ("PRIVATE KEY") encoding.
func writePKCS8(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}

	writeFile(t, path, "PRIVATE KEY", der)
}

// writePKIX writes a public key in the PKIX ("PUBLIC KEY") encoding.
func writePKIX(t *testing.T, path string, key *ecdsa.PublicKey) {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshal PKIX key: %v", err)
	}

	writeFile(t, path, "PUBLIC KEY", der)
}

func generateKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return key
}

func TestFileKeyProviderReadsEveryEncoding(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	signing := generateKey(t, elliptic.P256())
	incoming := generateKey(t, elliptic.P256())
	outgoing := generateKey(t, elliptic.P256())

	signingPath := filepath.Join(dir, "signing.pem")
	incomingPath := filepath.Join(dir, "incoming.pem")
	outgoingPath := filepath.Join(dir, "outgoing.pem")

	writeSEC1(t, signingPath, signing)
	writePKIX(t, incomingPath, &incoming.PublicKey)
	// A published key may also be given as the private key file it came from.
	writePKCS8(t, outgoingPath, outgoing)

	provider, err := NewFileKeyProvider(FileKeyProviderConfig{
		Signing: KeyFile{Path: signingPath, KeyID: "signing-1"},
		Published: []KeyFile{
			{Path: incomingPath, KeyID: "incoming"},
			{Path: outgoingPath, KeyID: "outgoing"},
		},
		RefreshInterval: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}

	keys, err := provider.Current(t.Context())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	if keys.Signing.KeyID != "signing-1" || !keys.Signing.Key.Equal(signing) {
		t.Error("the signing key is not the configured SEC1 key")
	}

	if len(keys.Published) != 2 {
		t.Fatalf("published %d keys, want 2", len(keys.Published))
	}

	if keys.Published[0].KeyID != "incoming" || !keys.Published[0].Key.Equal(&incoming.PublicKey) {
		t.Error("the first published key is not the configured PKIX key")
	}

	if keys.Published[1].KeyID != "outgoing" || !keys.Published[1].Key.Equal(&outgoing.PublicKey) {
		t.Error("the second published key is not the public half of the PKCS#8 key")
	}
}

func TestFileKeyProviderReadsAPKCS8SigningKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	signing := generateKey(t, elliptic.P256())
	path := filepath.Join(dir, "signing.pem")

	writePKCS8(t, path, signing)

	provider, err := NewFileKeyProvider(FileKeyProviderConfig{
		Signing:         KeyFile{Path: path, KeyID: "signing-1"},
		Published:       nil,
		RefreshInterval: 0,
	})
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}

	if provider.refreshInterval != DefaultRefreshInterval {
		t.Errorf("refresh interval = %v, want the %v default", provider.refreshInterval, DefaultRefreshInterval)
	}

	keys, err := provider.Current(t.Context())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	if !keys.Signing.Key.Equal(signing) {
		t.Error("the signing key is not the configured PKCS#8 key")
	}
}

func TestNewFileKeyProviderRejects(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	p256 := generateKey(t, elliptic.P256())
	p384 := generateKey(t, elliptic.P384())

	sec1P256 := filepath.Join(dir, "p256.pem")
	sec1P384 := filepath.Join(dir, "p384.pem")
	pkcs8P384 := filepath.Join(dir, "p384-pkcs8.pem")
	pkixP256 := filepath.Join(dir, "p256-pub.pem")
	pkixP384 := filepath.Join(dir, "p384-pub.pem")
	garbage := filepath.Join(dir, "garbage.pem")
	certificate := filepath.Join(dir, "certificate.pem")

	writeSEC1(t, sec1P256, p256)
	writeSEC1(t, sec1P384, p384)
	writePKCS8(t, pkcs8P384, p384)
	writePKIX(t, pkixP256, &p256.PublicKey)
	writePKIX(t, pkixP384, &p384.PublicKey)

	if err := os.WriteFile(garbage, []byte("not a PEM file"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	writeFile(t, certificate, "CERTIFICATE", []byte{1, 2, 3})

	tests := map[string]FileKeyProviderConfig{
		"empty signing key ID": {
			Signing: KeyFile{Path: sec1P256, KeyID: ""}, Published: nil, RefreshInterval: 0,
		},
		"empty signing path": {
			Signing: KeyFile{Path: "", KeyID: "signing-1"}, Published: nil, RefreshInterval: 0,
		},
		"missing signing file": {
			Signing: KeyFile{Path: filepath.Join(dir, "absent.pem"), KeyID: "signing-1"}, Published: nil, RefreshInterval: 0,
		},
		"signing file is not PEM": {
			Signing: KeyFile{Path: garbage, KeyID: "signing-1"}, Published: nil, RefreshInterval: 0,
		},
		"signing PEM is a certificate": {
			Signing: KeyFile{Path: certificate, KeyID: "signing-1"}, Published: nil, RefreshInterval: 0,
		},
		"signing key is a public key": {
			Signing: KeyFile{Path: pkixP256, KeyID: "signing-1"}, Published: nil, RefreshInterval: 0,
		},
		"signing key is P-384 SEC1": {
			Signing: KeyFile{Path: sec1P384, KeyID: "signing-1"}, Published: nil, RefreshInterval: 0,
		},
		"signing key is P-384 PKCS#8": {
			Signing: KeyFile{Path: pkcs8P384, KeyID: "signing-1"}, Published: nil, RefreshInterval: 0,
		},
		"empty published key ID": {
			Signing:   KeyFile{Path: sec1P256, KeyID: "signing-1"},
			Published: []KeyFile{{Path: pkixP256, KeyID: ""}}, RefreshInterval: 0,
		},
		"missing published file": {
			Signing:   KeyFile{Path: sec1P256, KeyID: "signing-1"},
			Published: []KeyFile{{Path: filepath.Join(dir, "absent.pem"), KeyID: "incoming"}}, RefreshInterval: 0,
		},
		"published key is P-384": {
			Signing:   KeyFile{Path: sec1P256, KeyID: "signing-1"},
			Published: []KeyFile{{Path: pkixP384, KeyID: "incoming"}}, RefreshInterval: 0,
		},
		"published key repeats the signing key ID": {
			Signing:   KeyFile{Path: sec1P256, KeyID: "signing-1"},
			Published: []KeyFile{{Path: pkixP256, KeyID: "signing-1"}}, RefreshInterval: 0,
		},
		"two published keys share a key ID": {
			Signing: KeyFile{Path: sec1P256, KeyID: "signing-1"},
			Published: []KeyFile{
				{Path: pkixP256, KeyID: "incoming"},
				{Path: pkixP384, KeyID: "incoming"},
			}, RefreshInterval: 0,
		},
	}

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewFileKeyProvider(config); err == nil {
				t.Fatal("NewFileKeyProvider accepted a configuration it must reject")
			}
		})
	}
}

func TestFileKeyProviderFollowsARotation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	before := generateKey(t, elliptic.P256())
	after := generateKey(t, elliptic.P256())
	path := filepath.Join(dir, "signing.pem")

	writeSEC1(t, path, before)

	provider, err := NewFileKeyProvider(FileKeyProviderConfig{
		Signing:         KeyFile{Path: path, KeyID: "signing-1"},
		Published:       nil,
		RefreshInterval: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}

	now := fixedNow
	provider.now = func() time.Time { return now }
	provider.loadedAt = now

	// The new key is on disk, but the refresh interval has not passed yet.
	writeSEC1(t, path, after)

	keys, err := provider.Current(t.Context())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	if !keys.Signing.Key.Equal(before) {
		t.Fatal("the provider re-read the key file before the refresh interval had passed")
	}

	now = now.Add(time.Minute)

	keys, err = provider.Current(t.Context())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	if !keys.Signing.Key.Equal(after) {
		t.Fatal("the provider did not pick up the rotated key file")
	}
}

func TestFileKeyProviderKeepsTheLastGoodKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	signing := generateKey(t, elliptic.P256())
	path := filepath.Join(dir, "signing.pem")

	writeSEC1(t, path, signing)

	provider, err := NewFileKeyProvider(FileKeyProviderConfig{
		Signing:         KeyFile{Path: path, KeyID: "signing-1"},
		Published:       nil,
		RefreshInterval: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}

	now := fixedNow
	provider.now = func() time.Time { return now }
	provider.loadedAt = now

	// A half-written or removed key file must not stop the issuer.
	if err := os.WriteFile(path, []byte("-----BEGIN EC PRIVATE KEY-----"), 0o600); err != nil {
		t.Fatalf("truncate key file: %v", err)
	}

	now = now.Add(time.Minute)

	keys, err := provider.Current(t.Context())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	if keys.Signing.KeyID != "signing-1" || !keys.Signing.Key.Equal(signing) {
		t.Fatal("a failed re-read did not keep the keys that loaded before")
	}

	// The file is whole again: the next refresh interval picks it up.
	rotated := generateKey(t, elliptic.P256())
	writeSEC1(t, path, rotated)

	now = now.Add(time.Minute)

	keys, err = provider.Current(t.Context())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	if !keys.Signing.Key.Equal(rotated) {
		t.Fatal("the provider did not recover after a failed re-read")
	}
}

func TestFileKeyProviderCopiesThePublishedKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	signing := generateKey(t, elliptic.P256())
	published := generateKey(t, elliptic.P256())

	signingPath := filepath.Join(dir, "signing.pem")
	publishedPath := filepath.Join(dir, "published.pem")

	writeSEC1(t, signingPath, signing)
	writePKIX(t, publishedPath, &published.PublicKey)

	provider, err := NewFileKeyProvider(FileKeyProviderConfig{
		Signing:         KeyFile{Path: signingPath, KeyID: "signing-1"},
		Published:       []KeyFile{{Path: publishedPath, KeyID: "incoming"}},
		RefreshInterval: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}

	keys, err := provider.Current(t.Context())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	keys.Published[0] = PublishedKey{KeyID: "tampered", Key: nil}

	again, err := provider.Current(t.Context())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	if again.Published[0].KeyID != "incoming" {
		t.Fatal("a caller changed the key set the provider hands to the next caller")
	}
}

// TestFileKeyProviderFollowsASymlinkSwap covers the shape a mounted secret
// takes: the configured path is a symlink, and a rotation swaps where it
// points rather than rewriting the file in place.
func TestFileKeyProviderFollowsASymlinkSwap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	before := generateKey(t, elliptic.P256())
	after := generateKey(t, elliptic.P256())

	firstPath := filepath.Join(dir, "v1.pem")
	secondPath := filepath.Join(dir, "v2.pem")
	currentPath := filepath.Join(dir, "current")

	writeSEC1(t, firstPath, before)
	writeSEC1(t, secondPath, after)

	if err := os.Symlink(firstPath, currentPath); err != nil {
		t.Fatalf("link the current key: %v", err)
	}

	provider, err := NewFileKeyProvider(FileKeyProviderConfig{
		Signing:         KeyFile{Path: currentPath, KeyID: "signing-1"},
		Published:       nil,
		RefreshInterval: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}

	now := fixedNow
	provider.now = func() time.Time { return now }
	provider.loadedAt = now

	if err := os.Remove(currentPath); err != nil {
		t.Fatalf("unlink the current key: %v", err)
	}

	if err := os.Symlink(secondPath, currentPath); err != nil {
		t.Fatalf("relink the current key: %v", err)
	}

	now = now.Add(time.Minute)

	keys, err := provider.Current(t.Context())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	if !keys.Signing.Key.Equal(after) {
		t.Fatal("the provider did not follow the swapped symlink")
	}
}

// TestFileKeyProviderWaitsOutTheIntervalAfterAFailure covers that a failed
// re-read is not retried on every call: the next attempt waits out another
// refresh interval, so a key file that stays broken does not write one warning
// per issued token.
func TestFileKeyProviderWaitsOutTheIntervalAfterAFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	before := generateKey(t, elliptic.P256())
	after := generateKey(t, elliptic.P256())
	path := filepath.Join(dir, "signing.pem")

	writeSEC1(t, path, before)

	provider, err := NewFileKeyProvider(FileKeyProviderConfig{
		Signing:         KeyFile{Path: path, KeyID: "signing-1"},
		Published:       nil,
		RefreshInterval: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}

	now := fixedNow
	provider.now = func() time.Time { return now }
	provider.loadedAt = now

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove the key file: %v", err)
	}

	now = now.Add(time.Minute)

	if _, err := provider.Current(t.Context()); err != nil {
		t.Fatalf("Current: %v", err)
	}

	// The file is whole again half an interval after the failed re-read.
	writeSEC1(t, path, after)

	now = now.Add(30 * time.Second)

	keys, err := provider.Current(t.Context())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	if !keys.Signing.Key.Equal(before) {
		t.Fatal("the provider retried the re-read before the interval had passed")
	}

	now = now.Add(30 * time.Second)

	keys, err = provider.Current(t.Context())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	if !keys.Signing.Key.Equal(after) {
		t.Fatal("the provider did not re-read once the interval had passed")
	}
}
