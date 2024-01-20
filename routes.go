/*
MIT License

# Copyright (c) 2020 zxdev

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

package server

import (
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Heartbeat; default response
func Heartbeat() string { return "alive" }

// Public represents a common set of routes for use with the chi mux router
// [root, heartbeat, endpoints, download, documentation] and returns the
// chi Router interface
func Public(heartbeat func() string, dlPath, docPath *string) *chi.Mux {

	router := chi.NewMux()

	log.Println("router: add public routes")

	// root; go away
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // 400
	})

	// heartbeat; header
	if heartbeat != nil {
		router.Get("/hb", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("heartbeat", heartbeat())
			w.WriteHeader(http.StatusOK) // 200
		})
	}

	// endpoint; list all available registered routes
	router.Get("/x/endpoint", func(w http.ResponseWriter, req *http.Request) {
		chi.Walk(router, func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
			route = strings.Replace(route, "/*/", "/", -1)
			fmt.Fprintf(w, "%s %s\n", method, route)
			return nil
		})
	})

	// download; optional public download
	if dlPath != nil && len(*dlPath) > 0 { // 200 or 404
		router.Get("/dl/{file}", func(w http.ResponseWriter, req *http.Request) {
			http.ServeFile(w, req, filepath.Join(*dlPath, chi.URLParam(req, "file")))
		})
	}

	// documentation; optional, pdf enforced public download
	if docPath != nil && len(*docPath) > 0 { // 200 or 404
		router.Get("/doc/{file}", func(w http.ResponseWriter, req *http.Request) {
			target := filepath.Join(*docPath, chi.URLParam(req, "file"))
			if !strings.HasSuffix(target, ".pdf") {
				target += ".pdf"
			}
			http.ServeFile(w, req, target)
		})
	}

	return router
}
