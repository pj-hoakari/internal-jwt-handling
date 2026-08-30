package internaljwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
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

func TestPublicKeyRoundTripsNewJWK(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	jwk, err := NewJWK("signing-2026-08", &key.PublicKey)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}

	decoded, err := PublicKey(jwk)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	if !decoded.Equal(&key.PublicKey) {
		t.Fatal("PublicKey did not return the key NewJWK described")
	}
}

func TestPublicKeyRejectsInvalidJWKs(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	valid, err := NewJWK("signing-2026-08", &key.PublicKey)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}

	tests := map[string]struct {
		mutate func(*JWK)
		want   error
	}{
		"empty key ID":        {mutate: func(j *JWK) { j.KeyID = "" }, want: ErrMissingKeyID},
		"key type RSA":        {mutate: func(j *JWK) { j.KeyType = "RSA" }, want: ErrUnsupportedKeyType},
		"curve P-384":         {mutate: func(j *JWK) { j.Curve = "P-384" }, want: ErrUnsupportedCurve},
		"algorithm ES384":     {mutate: func(j *JWK) { j.Algorithm = "ES384" }, want: ErrUnsupportedAlgorithm},
		"key use enc":         {mutate: func(j *JWK) { j.Use = "enc" }, want: ErrUnsupportedKeyUse},
		"undecodable x":       {mutate: func(j *JWK) { j.X = "!!!" }, want: ErrDecodeCoordinate},
		"undecodable y":       {mutate: func(j *JWK) { j.Y = "!!!" }, want: ErrDecodeCoordinate},
		"short x":             {mutate: func(j *JWK) { j.X = base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}) }, want: ErrUnexpectedKeyLength},
		"short y":             {mutate: func(j *JWK) { j.Y = base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}) }, want: ErrUnexpectedKeyLength},
		"point off the curve": {mutate: func(j *JWK) { j.Y = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }, want: ErrInvalidPublicKey},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			jwk := valid
			test.mutate(&jwk)

			if _, err := PublicKey(jwk); !errors.Is(err, test.want) {
				t.Fatalf("PublicKey error = %v, want %v", err, test.want)
			}
		})
	}
}
