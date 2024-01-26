package main

import (
	"net/http"
	"time"

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
	authkey.NewAuth(&param.authPath, router) // .Silent()

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
