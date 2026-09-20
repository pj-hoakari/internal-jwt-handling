package internaljwt

import "errors"

var ErrUnknownKeyID = errors.New("no verification key for the JWT kid")
