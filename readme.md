# Server

This starts a http or an http/https server using Let's Encrypt certificates which auto renew via acme controller. 

Uses graceful shutdown when it's time to die, meaning in-flight connections finish and are not dropped in the middle of the request while new requests are rejected during the shutdown process. 

```golang

// Server structure; supports the zxdev/env package
type Server struct {
	Host     string `env:"require" default:"localhost" help:"localhost or FQDN"`
	Mirror   bool   `default:"false" help:"http request policy [mirror, 400]"`
	CertPath string `default:"/var/certs"`
	opt      *http.Server
}

```

The default configuration is ```http``` on ```localhost:1455```, however when a FQDN (eg. example.com) is configured as a HOST paramater, then requests will be served based on an https server and follow the server.Mirror policy. 

* server.Mirror = true responsed on port 80 or 443.
* server.Mirror = false returns 400 response codes for http requests requiring port 443 connections

# Authentication

*	```authkey``` is a simple user:pass based system and middleware with supporting management endpoints
*	```passkey``` is an interval based rolling token generation system with middleware for machine-to-machine communication based on shared secret concept of RFC 4226 standards
	* For passkey manual api tesing a passkey generator ```go build passkey/cmd/pkgen.go``` is provided to obtain the current passkey which can be used from the shell ```curl -H token:$(./pkgen AW6TJVTYMAYJXLWFW2WWJ6D3Q5B2AY25) http://localhost:1455/demo``` for command line testing

See the example folder for working sample use cases

```golang

	type params struct {
		Secret string `help:"shared secret"`
	}

	// bootstrap
	var param params
	var srv server.Server
	env.NewEnv(&param, &srv)

	// generic public paths
	router := server.Public(server.Heartbeat, nil, nil)

	// configure passkey for the server
	pk := passkey.NewPassKey(param.Secret)
	if pk == nil { // failed; generate new secret
		pk = passkey.NewPassKey(nil)
		log.Println("passkey:", pk.Secret())
	}

	// sample passkey.IsValid middleware; protected api path
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

	grace.Done()
	grace.Wait()

```

Sample passkey access responses

```shell
	$curl -i -H token:3317539975 http://localhost:1455/demo
	HTTP/1.1 200 OK
	Auth: success
	Date: Fri, 29 Mar 2024 05:47:31 GMT
	Content-Length: 0

	$curl -i -H token:3317539975 http://localhost:1455/demo
	HTTP/1.1 401 Unauthorized
	Date: Fri, 29 Mar 2024 05:49:44 GMT
	Content-Length: 0
```




