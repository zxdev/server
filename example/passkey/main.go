package main

import (
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zxdev/env/v2"
	"github.com/zxdev/server"
	"github.com/zxdev/server/passkey"
)

/*
	$curl -i -H token:3317539975 http://localhost:1455/demo
	HTTP/1.1 200 OK
	Auth: success
	Date: Fri, 29 Mar 2024 05:47:31 GMT
	Content-Length: 0

	$curl -i -H token:3317539975 http://localhost:1455/demo
	HTTP/1.1 401 Unauthorized
	Date: Fri, 29 Mar 2024 05:50:44 GMT
	Content-Length: 0
*/

type params struct {
	Secret string `help:"shared secret"`
}

func main() {

	// bootstrap
	var srv server.Server
	var param params
	env.NewEnv(&param, &srv)

	// handlers
	router := server.Public(server.Heartbeat, nil, nil)
	pk := passkey.NewPassKey(param.Secret)
	if pk == nil {
		pk = passkey.NewPassKey(nil)
		log.Println("passkey:", pk.Secret())
	}
	log.Println("tokens:", pk.Tokens())

	// download; optional public download
	router.Route("/demo", func(rx chi.Router) {
		rx.Use(passkey.IsValid(pk, nil))
		rx.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("auth", "success")
			w.WriteHeader(http.StatusOK)
		})
	})

	// start graceful managers
	grace := env.NewGraceful()
	grace.Manager(srv.Configure(&http.Server{
		Handler:           router,
		ReadHeaderTimeout: time.Second * 5,
		ReadTimeout:       time.Second * 10,
		WriteTimeout:      time.Second * 30,
	}))

	grace.Manager(pk)

	// wait for bootstraps to complete
	grace.Done()

	// demonstration of a client passkey configuration
	// for authentication with a passkey remote server
	pkc := passkey.NewClient(pk.Secret())
	log.Println("client-demo:", pkc.Current())

	// wait for a shutdown signal
	grace.Wait()

}
