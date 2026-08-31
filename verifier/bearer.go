package verifier

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// bearerScheme is the Authorization scheme an internal JWT is presented under.
const bearerScheme = "Bearer"

var (
	ErrMissingAuthorization   = errors.New("authorization header is required")
	ErrMalformedAuthorization = errors.New("malformed authorization header")
)

// BearerToken extracts the token of an Authorization header value.
// The scheme is matched case-insensitively and is followed by one space and the token.
func BearerToken(authorization string) (string, error) {
	if authorization == "" {
		return "", ErrMissingAuthorization
	}

	scheme, token, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, bearerScheme) {
		return "", fmt.Errorf("%w: want the %s scheme", ErrMalformedAuthorization, bearerScheme)
	}

	if token == "" || strings.ContainsFunc(token, unicode.IsSpace) {
		return "", fmt.Errorf("%w: want %s followed by one space and the token", ErrMalformedAuthorization, bearerScheme)
	}

	return token, nil
}
