package verifier

import (
	"context"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

type ContextVerifier struct {
	verifier *Verifier
}

func NewContextVerifier(issuerID string, keys KeyResolver, opts ...Option) (*ContextVerifier, error) {
	verifier, err := newVerifierFor(issuerID, "", keys, opts...)
	if err != nil {
		return nil, err
	}

	return &ContextVerifier{verifier: verifier}, nil
}

func (v *ContextVerifier) Verify(ctx context.Context, token, presenter string) (internaljwt.Claims, error) {
	if presenter == "" {
		return internaljwt.Claims{}, ErrMissingAudience
	}

	return v.verifier.verify(ctx, token, presenter)
}
