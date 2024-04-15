package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Client interface that exposes the minimal PassKey
// methods that a client needs to access for authentication
type Client interface {
	Configure(interface{}) *PassKey
	Interval(interface{}) *PassKey
	Start(context.Context)
	Current() uint32
}

// NewClient configures a PassKey with the provided secret
// to allow authentical with a PassKey enabled server
//
//	var pkc = passkey.NewClient(secret)
//	pkc.Start(ctx)
//	for {
//	 req.Header.Set("token",pkc.Current())
//	}
func NewClient(secret interface{}) Client {
	var pk = new(PassKey).Configure(secret)
	return pk
}

// PassKey structure to generate a time based token set
// based on a shared secret for system-to-system
// machine communication with rolling authentication
type PassKey struct {
	interval time.Duration    // defaults to one-minute
	key      [20]byte         // binary form of secret
	tokens   [3]atomic.Uint32 // interval tokens
}

// NewPassKey configurator used the provided secret or generates a
// secret on initilization that can be exported and then shared
//
//	default: generate new secret with default one-minute interval
//	accepts: nil, [20]byte slice, or a base32(A..Z,2...7) 32-character string
//	eg. AW6TJVTYMAYJXLWFW2WWJ6D3Q5B2AY25
func NewPassKey(secret interface{}) *PassKey {
	return new(PassKey).Configure(secret)
}

// Configure applies the provided secret or generates a new one
// and generates a new token set based off the current pk.interval
//
//	default: generate new
//	accepts: nil, [20]byte slice, or a base32(A..Z,2...7) 32-character string
//	eg. AW6TJVTYMAYJXLWFW2WWJ6D3Q5B2AY25
func (pk *PassKey) Configure(secret interface{}) *PassKey {

	// apply provided secret or generate a new one
	switch a := secret.(type) {
	case string:
		if len(a) != 32 {
			return nil
		}
		b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(a))
		if err != nil {
			return nil
		}
		copy(pk.key[:], b)

	case [20]byte:
		copy(pk.key[:], a[:])

	default: // nil
		rand.Read(pk.key[:])

	}

	// generate a new token set
	pk.Interval(pk.interval)

	return pk
}

// Interval sets the time duration and generates a token set
//
//	default: one-minute
//	accepts: nil, time.Duration, or int value of seconds
func (pk *PassKey) Interval(interval interface{}) *PassKey {

	switch a := interval.(type) {
	case nil: // does nothing
	case time.Duration:
		pk.interval = a

	case int: // as seconds
		pk.interval = time.Duration(a) * time.Second
	}

	if pk.interval == 0 { // set default
		pk.interval = time.Minute
	}

	pk.token()
	return pk
}

// Start interval token PassKey
func (pk *PassKey) Start(ctx context.Context) {

	tick := time.NewTicker(pk.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			pk.token()
		}
	}

}

// Secret provides the current shared secret as a base32 encoded string
func (pk *PassKey) Secret() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(pk.key[:])
}

// Tokens return the current token set
func (pk *PassKey) Tokens() []uint32 {
	return []uint32{pk.tokens[0].Load(), pk.tokens[1].Load(), pk.tokens[2].Load()}
}

// Current token
func (pk *PassKey) Current() uint32 { return pk.tokens[1].Load() }

// Validate the current token
func (pk *PassKey) Validate(token uint32) bool {

	switch token {
	case pk.tokens[1].Load(): // current
	case pk.tokens[0].Load(): // previous
	case pk.tokens[2].Load(): // next
	default:
		return false
	}

	return true

}

// generate a token set using the shared secret and time interval
func (pk *PassKey) token() {

	// previous, current, next tokens
	for i := range pk.tokens {

		bs := make([]byte, 8)
		binary.LittleEndian.PutUint64(bs, uint64(
			time.Now().Add(time.Duration(i-1)*pk.interval).Round(pk.interval).Unix(),
		))

		// sign the value using HMAC-SHA1 algorithm
		hash := hmac.New(sha1.New, pk.key[:])
		hash.Write(bs)
		h := hash.Sum(nil)

		// use the last nibble (a half-byte) to choose the start index since this value
		// is at most 0xF (decimal 15), and there are 20 bytes of SHA1; we need 4 bytes
		// to get a 32 bit chunk from hash starting n index
		n := (h[19] & 0xf)
		pk.tokens[i].Store(binary.LittleEndian.Uint32(h[n : n+4]))

	}

}

//
// MIDDLEWARE
//

// IsValid middleware is restructed to valid tokens
// set as token:{passkey} in the http header
func (pk *PassKey) IsValid(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		passkey := r.Header.Get("token")
		if len(passkey) > 0 {
			tok, _ := strconv.Atoi(passkey)
			if pk.Validate(uint32(tok)) {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.WriteHeader(http.StatusUnauthorized)
	})
}
