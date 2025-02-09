package server

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

/*



 */

// Server structure; supports the zxdev/env package
type Server struct {
	Host     string `env:"H,require" default:"localhost" help:"localhost or FQDN"`
	Mirror   bool   `default:"off" help:"http request policy [mirror|400]"`
	CertPath string `default:"/var/certs"`
	opt      *http.Server
}

// Configure is a *Server configurator that takes *http.Server object and
// applies defaults to opt when these reasonable defaults are not set; expects
// the Handler to have been already set
func (srv *Server) Configure(opt *http.Server) *Server {

	srv.opt = opt
	if srv.opt == nil {
		srv.opt = new(http.Server)
	}

	// set reasonable timeouts to avoid attacks and
	// allow operation within expected timeframes
	if srv.opt.ReadTimeout < 1 {
		srv.opt.ReadTimeout = time.Second * 10
	}

	// we can allow the user to set the value negative which
	// implies that the method will have an internal timeout
	if srv.opt.WriteTimeout == 0 {
		srv.opt.WriteTimeout = srv.opt.ReadTimeout * 3
	}

	// configure router; default 404 response
	if srv.opt.Handler == nil { // default router; 404
		srv.opt.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
	}

	// configure log reporting
	// srv.opt.ErrorLog = log.New(os.Stderr, "server ", log.LstdFlags)

	return srv
}

// Listen an http and/or https server using Let's Encrypt with a http redirect policy as
// defined by *Server.Redirect; ctx is required so that the server will automatically
// shutdown on context cancellation, but init is optional unless a flow controller
// is utilized or is necessary to confirm the server is in a ready state
func (srv *Server) Listen(ctx context.Context, init *sync.WaitGroup) {

	if srv.opt == nil {
		log.Println("alert: server was not configured")
		srv.Configure(nil)
	}

	if len(srv.Host) == 0 {
		srv.Host = "localhost"
	}

	// localhost or an IP address; required to have a fqdn to not use http protocol
	if strings.HasPrefix(srv.Host, "localhost") || net.ParseIP(srv.Host) != nil {

		if !strings.Contains(srv.Host, ":") {
			srv.Host += ":1455" // apply default port
		}
		srv.opt.Addr = srv.Host
		go srv.opt.ListenAndServe()

	} else {

		// a fqdn requires 80/443 to be open and because we use Let's Encrypt for certs that
		// requires port 80 for issuance and renewals, however we can configure a http traffic
		// policy that autocert.Mangager can use for all other http traffic requests since

		mgr := autocert.Manager{
			Prompt:     autocert.AcceptTOS,               // auto accpet TOS
			HostPolicy: autocert.HostWhitelist(srv.Host), // whitelist our FQDN here
			Cache:      autocert.DirCache(srv.CertPath),  // certs directory
		}
		srv.opt.TLSConfig = &tls.Config{GetCertificate: mgr.GetCertificate}
		srv.opt.Addr = ":https"

		// a basic redirect policy is enabled by passing mgr.HTTPHandler(nil) and that will
		// return 302 <a href="https://dev.netstar.one/{path}">Found</a>. for GET/HEAD and 400
		// for all other requests, which is not helpful in an API based use case. So we specify
		// and limit our choices to an http traffic mirror or a 400 bad-request response since
		// we do not want the default 302 redirect responses

		if srv.Mirror {

			log.Println("server: http traffic mirror")
			go http.ListenAndServe(":http", mgr.HTTPHandler(srv.opt.Handler))

		} else {

			log.Println("server: http traffic bad-request")
			go http.ListenAndServe(":http", mgr.HTTPHandler(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
				})))

		}

		// the Key/Cert are coming from Let's Encrypt; pass empty values
		go srv.opt.ListenAndServeTLS("", "")

	}

	log.Printf("server: %s", srv.Host)
	defer log.Println("server: shutdown")

	if init != nil {
		init.Done() // signal initialization is done
	}

	<-ctx.Done() // wait for a shutdown signal
	cx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	srv.opt.Shutdown(cx) // gracefully shutdown
	cancel()

}
