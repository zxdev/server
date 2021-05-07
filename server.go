/*
MIT License

Copyright (c) 2020 zxdev

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
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

/*

	router := chi.NewRouter()
	server.Public(router,nil,nil)

	ctx := context.Background()

	var srv server.Server
	srv.Start(router, nil)(ctx)

*/

// Server structure; supports the zxdev/env package
type Server struct {
	Host   string `env:"H,require" default:"localhost" help:"localhost or FQDN"`
	Mirror bool   `default:"true" help:"http request policy [mirror, 400]"`
}

// Start an http and/or https server using Let's Encrypt with a http redirect policy as
// defined by *Server.Redirect. When nil is passed for opt, reasonable defaults are applied
// for timeout settings and error log reporting, however specific configurations can be
// defined by passing a custom opt and those will take priority.
func (srv *Server) Start(router http.Handler, opt *http.Server) func(ctx context.Context) {

	if len(srv.Host) == 0 {
		srv.Host = "localhost"
	}

	if opt == nil {
		opt = new(http.Server)

		// set reasonable timeouts to avoid attacks and
		// allow operation within expected timeframes
		opt.ReadHeaderTimeout = time.Second * 5
		opt.ReadTimeout = time.Second * 20
		opt.WriteTimeout = time.Second * 20
		opt.IdleTimeout = time.Second * 15

		// configure log reporting
		opt.ErrorLog = log.New(os.Stderr, "server ", log.LstdFlags)
	}

	// configure router
	if opt.Handler == nil {
		if router == nil { // default router; 404
			router = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			})
		}
		opt.Handler = router
	}

	// localhost or an IP address; required to have a fqdn to not use http protocol
	if strings.HasPrefix(srv.Host, "localhost") || net.ParseIP(srv.Host) != nil {

		if !strings.Contains(srv.Host, ":") {
			srv.Host += ":1455" // apply default port
		}
		opt.Addr = srv.Host
		go opt.ListenAndServe()

	} else {

		// a fqdn requires 80/443 to be open and because we use Let's Encrypt for certs that
		// requires port 80 for issuance and renewals, however we can configure a http traffic
		// policy that autocert.Mangager can use for all other http traffic requests since

		mgr := autocert.Manager{
			Prompt:     autocert.AcceptTOS,               // auto accpet TOS
			HostPolicy: autocert.HostWhitelist(srv.Host), // whitelist our FQDN here
			Cache:      autocert.DirCache("/var/certs"),  // certs directory
		}
		opt.TLSConfig = &tls.Config{GetCertificate: mgr.GetCertificate}
		opt.Addr = ":https"

		// a basic redirect policy is enabled by passing mgr.HTTPHandler(nil) and that will
		// return 302 <a href="https://dev.netstar.one/{path}">Found</a>. for GET/HEAD and 400
		// for all other requests, which is not helpful in an API based use case. So we specify
		// and limit our choices to an http traffic mirror or a 400 bad-request response since
		// we do not want the default 302 redirect responses

		if srv.Mirror {

			log.Println("server: http traffic mirror")
			go http.ListenAndServe(":http", mgr.HTTPHandler(opt.Handler))

		} else {

			log.Println("server: http traffic bad-request")
			go http.ListenAndServe(":http",mgr.HTTPHandler(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
				})))

		}

		// the Key/Cert are coming from Let's Encrypt; pass empty values
		go opt.ListenAndServeTLS("", "")

	}

	log.Printf("server: %s", srv.Host)

	// wait for a server shutdown signal; shutdown gracefully
	return func(ctx context.Context) {

		<-ctx.Done()                       // wait for a shutdown signal
		opt.Shutdown(context.Background()) // gracefully shutdown
		log.Println("server: shutdown")

	}
}
