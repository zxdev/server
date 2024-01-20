# Server

This starts a http or an http/https server using Let's Encrypt certificates which auto renew via acme controller. 

Uses graceful shutdown when it's time to die, meaning in-flight connections finish and are not dropped in the middle of the request while new requests are rejected during the shutdown process. 

This package supports ```github.com/zxdev/env``` package and tags. 

```golang

// Server structure; supports the zxdev/env package
type Server struct {
	Host     string `env:"require" default:"localhost" help:"localhost or FQDN"`
	Mirror   bool   `default:"false" help:"http request policy [mirror, 400]"`
	CertPath string `default:"/var/certs"`
	opt      *http.Server
}

```

The default senario is ```http``` on ```localhost:1455```, however when a FQDN (eg. example.com) is configured as a HOST paramater, then requests will be served based on the server.Mirror policy. 

server.Mirror = true responsed on port 80 or 443.
server.Mirror = false returns 400 response codes for http requests requiring port 443 connections

```golang

	// bootstrap
	var param params
	var srv server.Server
	environ := env.NewEnv(&srv)

	// paths
	param.authPath = env.Dir(environ.Var, "conf", "auth.keys")

	// handlers
	router := server.Public(server.Heartbeat, nil, nil)
	authkey.NewAuth(&param.authPath, router).Silent()

	// start graceful managers
	grace := env.NewGraceful()
	grace.Manager(srv.Configure(&http.Server{
		Handler:           router,
		ReadHeaderTimeout: time.Second * 5,
		ReadTimeout:       time.Second * 10,
		WriteTimeout:      time.Second * 30,
	}))

	grace.Done()
	grace.Wait()

```

