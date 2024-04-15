package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zxdev/env/v2"
	"github.com/zxdev/server"
	"github.com/zxdev/server/auth"
)

type params struct {
	Secret  string `help:"passKey shared secret"`
	AuthKey string `help:"authKey filename"`
}

func main() {

	// bootstrap
	var srv server.Server
	var param params
	paths := env.NewEnv(&param, &srv)
	grace := env.NewGraceful()

	// handlers; default public
	router := server.Public(server.Heartbeat, nil, nil)

	switch {
	case len(param.Secret) > 0:

		pk := auth.NewPassKey(param.Secret)
		if pk == nil {
			pk = auth.NewPassKey(nil)
			log.Println("tokens:", pk.Tokens())  // token set
			log.Println("passkey:", pk.Secret()) // to stderr
			fmt.Fprintln(os.Stdout, pk.Secret()) // to stdout
		}
		private(pk, router)
		grace.Manager(pk)

		// demonstration for a client passkey configuration
		// for authentication with a passkey remote server
		pkc := auth.NewClient(pk.Secret())
		log.Println("demo-client:", pkc.Current())
		log.Println("demo-tokens:", pk.Tokens())

	case len(param.AuthKey) > 0:

		param.AuthKey = env.Dir(paths.Srv, "conf", param.AuthKey)
		ak := auth.NewAuth(&param.AuthKey, router) // .Silent() .User("bob","I'mBobI'mBobI'mBob")
		private(ak, router)

	default:
		log.Println("alert: no auth system configured")
		return
	}

	grace.Manager(srv.Configure(&http.Server{
		Handler:           router,
		ReadHeaderTimeout: time.Second * 5,
		ReadTimeout:       time.Second * 10,
		WriteTimeout:      time.Second * 30,
	}))

	// wait for bootstraps to complete
	grace.Done()

	// wait for a shutdown signal
	grace.Wait()

}

// private route; sample auth.IsValid protected routes so that
// is it agnositic to authKey or passKey validation
func private(auth auth.IsValid, router *chi.Mux) {

	router.Route("/demo", func(rx chi.Router) {
		rx.Use(auth.IsValid)
		rx.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("auth", "success")
			w.WriteHeader(http.StatusOK)
		})
	})

}
