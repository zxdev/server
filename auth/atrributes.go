package auth

import (
	"net/http"
)

// Authentication interface for middleware using
// authKey and passKey protected endpoint routes
type Authentication interface {
	IsValid(http.Handler) http.Handler
}
