package auth

import (
	"net/http"
)

// IsValid type of middleware for authKey and passKey
// protected endpoint routing
type IsValid interface {
	IsValid(http.Handler) http.Handler
}
