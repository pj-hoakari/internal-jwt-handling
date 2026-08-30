package jwtgen

import "github.com/google/uuid"

// newTxn starts a processing chain for the context token of a user-origin re-issue.
func newTxn() string {
	txn, err := uuid.NewV7()
	if err != nil {
		return "00000000-0000-7000-8000-000000000000"
	}

	return txn.String()
}
