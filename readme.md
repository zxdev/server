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
*	```passkey``` is an interval based rolling token generation system with middleware for machine-to-machine communication based on the shared secret concept of RFC 4226 standards
	* For passkey manual api tesing a passkey generator ```go build cmd/pkgen.go``` is provided to obtain the current passkey which can be used from the shell ```curl -H token:$(./pkgen AW6TJVTYMAYJXLWFW2WWJ6D3Q5B2AY25) http://localhost:1455/demo``` for command line testing

See the ```example``` folder for the following working sample that integrates both auth types; shown here for reference.

```golang


	type params struct {
		Secret  string `help:"passKey shared secret"`
		AuthKey string `help:"authKey filename"`
	}

	// bootstrap
	var srv server.Server
	var param params
	paths := env.NewEnv(&param, &srv)
	grace := env.NewGraceful()

	// handlers; default public
	router := server.Public(server.Heartbeat, nil, nil)

	// auth; showing both configuration types
	switch {
	case len(param.Secret) > 0:

		pk := auth.NewPassKey(param.Secret)
		if pk == nil { 
			pk = auth.NewPassKey(nil)
			log.Println("tokens:", pk.Tokens())  // token set
			log.Println("passkey:", pk.Secret()) // to stderr
			fmt.Fprintln(os.Stdout, pk.Secret()) // to stdout; 
		}
		private(pk, router)
		grace.Manager(pk) // pk.Start; roll timer

	case len(param.AuthKey) > 0:

		param.AuthKey = env.Dir(paths.Srv, "conf", param.AuthKey)
		ak := auth.NewAuthKey(&param.AuthKey, router) // .Silent() .User("bob","I'mBobI'mBobI'mBob")
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
	grace.Done()
	grace.Wait()

```

PassKey client configuration

```golang

	type params struct {
		Secret  string `help:"passKey shared secret"`
	}

	// showing the client passkey configuration for
	// authentication with a passkey; remote server
	pkc := auth.NewClient(param.Secret)
	pkc.Start(ctx) // start roll timer
	// ...
	r.Header.Set("token", pkc.Current())


```


Generate/Save/Load a shared secret from a file for testing purposes


```shell
	# generate a new shared secret for passKey
	# and write the secret to a local file; start server
	go run example/main.go -secret gen > sandbox/secret 

	# use a shared secret from a local file; start server
	go run example/main.go -secret $(cat sandbox/secret)

	# client testing example using the pkgen passkey token generator
	# with a shared secret to generate the current token; also reads
	# the shared secret from a local file for pkgen to use
	curl -i -H token:$(sandbox/pkgen $(cat sandbox/secret)) http://localhost:1455/demo
	HTTP/1.1 200 OK
	Auth: success
	Date: Mon, 15 Apr 2024 20:19:45 GMT
	Content-Length: 0

```