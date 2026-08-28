package internaljwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestNewJWKDescribesAP256Key(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	jwk, err := NewJWK("signing-2026-08", &key.PublicKey)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}

	if jwk.KeyType != "EC" || jwk.Curve != "P-256" || jwk.Algorithm != "ES256" || jwk.Use != "sig" {
		t.Fatalf("unexpected JWK header fields: %+v", jwk)
	}

	if jwk.KeyID != "signing-2026-08" {
		t.Fatalf("kid = %q, want %q", jwk.KeyID, "signing-2026-08")
	}

	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}

	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		t.Fatalf("decode y: %v", err)
	}

	if len(x) != 32 || len(y) != 32 {
		t.Fatalf("coordinate lengths = %d/%d, want 32/32", len(x), len(y))
	}

	encoded := append([]byte{4}, x...)
	encoded = append(encoded, y...)

	decoded, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
	if err != nil {
		t.Fatalf("parse encoded public key: %v", err)
	}

	if !decoded.Equal(&key.PublicKey) {
		t.Fatal("the JWK coordinates do not describe the original public key")
	}
}

func TestNewJWKRejectsInvalidKeys(t *testing.T) {
	t.Parallel()

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}

	tests := map[string]struct {
		keyID string
		key   *ecdsa.PublicKey
	}{
		"empty key ID": {keyID: "", key: &p256.PublicKey},
		"nil key":      {keyID: "signing", key: nil},
		"curve P-384":  {keyID: "signing", key: &p384.PublicKey},
		"zero value":   {keyID: "signing", key: &ecdsa.PublicKey{}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewJWK(test.keyID, test.key); err == nil {
				t.Fatal("NewJWK accepted a key it must reject")
			}
		})
	}
}
