package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zxdev/env/v2"
	"github.com/zxdev/server"
	"github.com/zxdev/server/authkey"
)

type params struct {
	authPath string
}

func main() {

	// bootstrap
	var param params
	var srv server.Server
	environ := env.NewEnv(&srv)

	// paths
	param.authPath = env.Dir(environ.Var, "conf", "auth.keys")

	// handlers
	router := server.Public(server.Heartbeat, nil, nil)
	ak := authkey.NewAuth(&param.authPath, router) // .Silent() .User("bob","I'mBobI'mBobI'mBob")

	// download; optional public download
	router.Route("/demo", func(rx chi.Router) {
		rx.Use(ak.IsValid)
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

	// wait for bootstraps to complete
	grace.Done()

	// wait for a shutdown signal
	grace.Wait()

}
