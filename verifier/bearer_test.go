package verifier

import (
	"errors"
	"testing"
)

func TestBearerTokenExtractsTheToken(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"Bearer a.b.c": "a.b.c",
		"bearer a.b.c": "a.b.c",
		"BEARER a.b.c": "a.b.c",
		"BeArEr a.b.c": "a.b.c",
	}

	for authorization, want := range tests {
		t.Run(authorization, func(t *testing.T) {
			t.Parallel()

			got, err := BearerToken(authorization)
			if err != nil {
				t.Fatalf("BearerToken: %v", err)
			}

			if got != want {
				t.Fatalf("BearerToken = %q, want %q", got, want)
			}
		})
	}
}

func TestBearerTokenRejectsAnUnusableHeader(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		authorization string
		want          error
	}{
		"empty": {
			authorization: "", want: ErrMissingAuthorization,
		},
		"another scheme": {
			authorization: "Basic a.b.c", want: ErrMalformedAuthorization,
		},
		"the scheme alone": {
			authorization: "Bearer", want: ErrMalformedAuthorization,
		},
		"the scheme and a space": {
			authorization: "Bearer ", want: ErrMalformedAuthorization,
		},
		"two spaces": {
			authorization: "Bearer  a.b.c", want: ErrMalformedAuthorization,
		},
		"a token holding a space": {
			authorization: "Bearer a.b.c d", want: ErrMalformedAuthorization,
		},
		"the token alone": {
			authorization: "a.b.c", want: ErrMalformedAuthorization,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			token, err := BearerToken(test.authorization)
			if !errors.Is(err, test.want) {
				t.Fatalf("BearerToken = %v, want %v", err, test.want)
			}

			if token != "" {
				t.Fatalf("BearerToken returned %q alongside an error", token)
			}
		})
	}
}
