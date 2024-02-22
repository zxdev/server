package authkey

/*
MIT License

Copyright (c) 2023 zxdev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// Auth structure for authentication and credential management for
// authorized user acces to restricted content.
//
// The package supports path base (eg. /api/{apikey}/action) requests,
// however the admin management routes require a header token:{apikey}
// value be set to access the user management routes.
type Auth struct {
	path   *string           // user:key map file location; memory only when nil
	uMap   map[string]string // apikey->user map
	mwUser struct{}          // middleware transport chain key
	mu     sync.Mutex        // mutex for uMap concurrency protection
	silent bool              // silent output after bootstrap ends
	admin  string            // admin name
}

// NewAuth configurator will initialize an *auth.Auth and populate the
// uMap from the disk when path is provided or will use a memory uMap when
// nil is passed for path; configues the admin routes on a chi.Router
func NewAuth(path *string, r *chi.Mux) *Auth {

	if r == nil {
		r = chi.NewMux()
	}

	ak := new(Auth).Configure(path)
	r.Route("/a", func(rx chi.Router) {
		rx.Use(ak.IsAdmin)
		rx.Get("/", ak.UserHandler())
		rx.Get("/users", ak.UserHandler())
		rx.Get("/add/{user}", ak.AddHandler())
		rx.Get("/remove/{user}", ak.DeleteHandler())
		rx.Get("/update/{user}", ak.UpdateHandler())
		rx.Get("/refresh", ak.RefreshHandler())
	})

	return ak
}

// generateKey defines the key generation methodology
// used for ApiKey generation; eg. 5aee4f739eb44c2c
func (a *Auth) generateKey() string {

	var b [8]byte
	rand.Read(b[:])

	return fmt.Sprintf("%016x", b[:])
}

// Silent toggle; {default:on}
func (a *Auth) Silent() *Auth { a.silent = !a.silent; return a }

// Admin sets the admin name; {default:admin}
func (a *Auth) Admin(admin string) *Auth { a.admin = admin; return a }

// User will set a manual user,key combination; key must 6 or more characters
func (a *Auth) User(user, key string) *Auth {
	if len(user) > 0 && len(key) > 5 {
		a.mu.Lock()
		a.uMap[strings.ToLower(key)] = strings.ToLower(user)
		a.mu.Unlock()
	}
	return a
}

// Start automated authorization refreshing; useful on clusters which
// share a common file or sync'd file system
func (a *Auth) Start(ctx context.Context, refresh *time.Duration) {

	if refresh == nil || *refresh == 0 {
		freq := time.Hour
		*refresh = freq
	}

	tick := time.NewTicker(*refresh)

	select {
	case <-ctx.Done():
		tick.Stop()
		return
	case <-tick.C:
		a.refresh()
	}
}

// Configure will populate uMap from disk and create a default
// admin user when no current file exists (or path is file)
func (a *Auth) Configure(path *string) *Auth {

	// set default
	if path != nil {
		a.path = path
	}

	// set default
	if len(a.admin) == 0 {
		a.admin = "admin"
	}

	if a.refresh() == 0 {
		if key := a.add(a.admin); !a.silent {
			log.Printf("auth: add %s [%s]", a.admin, key)
		}
	}

	return a
}

// refresh builds uMap from disk; user apikey
func (a *Auth) refresh() (n int) {

	a.mu.Lock()
	defer a.mu.Unlock()

	a.uMap = make(map[string]string)

	if a.path != nil {
		f, err := os.Open(*a.path)
		if err == nil {

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				var user, key string
				fmt.Sscanf(scanner.Text(), "%s %s", &user, &key)
				a.uMap[key] = user
				n++
			}
			f.Close()
		}
	}

	if len(a.uMap) > 0 && !a.silent {
		log.Printf("auth: load @%s [%d]", *a.path, n)
	}

	return
}

// save uMap to disk; user apikey
func (a *Auth) save() {

	if a.path != nil {
		f, err := os.Create(*a.path)
		if err == nil {
			a.mu.Lock()
			for k := range a.uMap {
				fmt.Fprintln(f, a.uMap[k], k)
			}
			a.mu.Unlock()
			f.Close()
		}
	}

}

// add user to uMap
func (a *Auth) add(user string) string {

	user = strings.ToLower(user)
	key := a.generateKey()

	a.mu.Lock()
	a.uMap[key] = user
	a.mu.Unlock()
	a.save()

	return key
}

// delete user from uMap
func (a *Auth) delete(user string) bool {

	user = strings.ToLower(user)
	if user != a.admin {
		a.mu.Lock()
		var k string
		for k = range a.uMap {
			if a.uMap[k] == user {
				delete(a.uMap, k)
				a.mu.Unlock()
				a.save()
				return true
			}
		}
		a.mu.Unlock()
	}
	return false
}

// update a user apikey in uMap
func (a *Auth) update(user string) (string, bool) {

	if a.delete(user) {
		return a.add(user), true
	}

	return "", false
}

// check the key in the uMap and returns the user and lookup status
func (a *Auth) check(key string) (user string, ok bool) {

	if len(key) > 0 {
		a.mu.Lock()
		user, ok = a.uMap[key]
		a.mu.Unlock()
	}

	return user, ok

}

//
// HANDLERS
//

// AddHandler will add a new user to the ApiKey.uMap authority
//
// .../add/{user}
func (a *Auth) AddHandler() http.HandlerFunc {

	type response struct {
		Status int    `json:"status"`
		User   string `json:"user,omitempty"`
		Key    string `json:"key,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		var resp response
		resp.User = chi.URLParam(r, "user")
		resp.Key = a.add(resp.User)
		if !a.silent {
			log.Printf("auth: add %s [%s]", resp.User, resp.Key)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)

	}

}

// DeleteHandler removes a user from the ApiKey.uMap authority
//
// .../remove/{user}
func (a *Auth) DeleteHandler() http.HandlerFunc {

	type response struct {
		Status  int    `json:"status"`
		Message string `json:"message,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		user := chi.URLParam(r, "user")
		log.Println("auth: delete", user)
		a.delete(user)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response{Message: user + " deleted"})

	}

}

// UpdateHandler reloads the ApiKey.uMap from disk
//
// .../update/{user}
func (a *Auth) UpdateHandler() http.HandlerFunc {

	type response struct {
		Status  int    `json:"status"`
		Message string `json:"message,omitempty"`
		User    string `json:"user,omitempty"`
		Key     string `json:"key,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		var ok bool
		var resp response
		resp.User = chi.URLParam(r, "user")
		resp.Key, ok = a.update(resp.User)
		if ok {
			if !a.silent {
				log.Printf("auth: update %s [%s]", resp.User, resp.Key)
			}
		} else {
			resp.Message = "failed"
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)

	}

}

// RefreshHandler reloads the ApiKey.uMap from disk
//
// .../refresh
func (a *Auth) RefreshHandler() http.HandlerFunc {

	type response struct {
		Status  int    `json:"status,omitempty"`
		Message string `json:"message,omitempty"`
		Keys    int    `json:"n,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		log.Println("auth: refresh")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response{Message: "refreshed", Keys: a.refresh()})

	}

}

// UserHandler provides the current ApiKey.uMap
//
// .../users
func (a *Auth) UserHandler() http.HandlerFunc {

	type user struct {
		name, key string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		var users []user
		a.mu.Lock()
		for k := range a.uMap {
			users = append(users, user{a.uMap[k], k})
		}
		a.mu.Unlock()
		sort.Slice(users, func(i, j int) bool { return users[i].name < users[j].name })
		if !a.silent {
			log.Printf("auth: users [%d]", len(users))
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "\n%s\n", strings.Repeat("-", 40))
		fmt.Fprintf(w, "%-20s | %s\n", "user", "apikey")
		fmt.Fprintf(w, "%s\n", strings.Repeat("-", 40))
		for i := range users {
			if users[i].name != a.admin {
				fmt.Fprintf(w, "%-20s | %s\n", users[i].name, users[i].key)
			}
		}
		fmt.Fprintf(w, "%s\n\n", strings.Repeat("-", 40))

	}

}

//
// MIDDLEWARE
//

// setUser stores the user in the r.Context middleware transport chain
// under the type specific mwUser key
func (a *Auth) setUser(r *http.Request, val string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), a.mwUser, val))
}

// GetUser retreives the user from the r.Context middleware transport chain
// using the specific mwUser key type
func (a *Auth) GetUser(r *http.Request) string {
	return r.Context().Value(a.mwUser).(string)
}

// IsValid middleware is restructed to valid users and
// requires {apikey} be part of the r.URL.Path for access
// or have token:{apikey} in the header for access (default)
//
// eg. .../api/{apikey}/action
func (a *Auth) IsValid(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		apikey := r.Header.Get("token")
		if len(apikey) == 0 { // failover to url
			apikey = chi.URLParam(r, "apikey")
		}

		if user, ok := a.check(apikey); ok {
			next.ServeHTTP(w, a.setUser(r, user))
			return
		}

		w.WriteHeader(http.StatusUnauthorized)

	})

}

// IsAdmin middleware is restricted to admin and requries
// that a token:{apikey} be set in the request header for access
//
// eg. r.Header [token:{apikey}]
func (a *Auth) IsAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if user, ok := a.check(r.Header.Get("token")); ok && user == a.admin {
			next.ServeHTTP(w, a.setUser(r, user))
			return
		}

		w.WriteHeader(http.StatusUnauthorized)

	})
}
