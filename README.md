# Server

This starts a http or a http/https server using Let's Encrypt certificates which auto renew via acme controller. This server will also gracefully shutdown when it's time to die, meaning in-flight connections finish and are not dropped in the middle of the request while new requests are rejected during the shutdown process. This package supports the zxdev/env package.

```golang

// Server structure; settings supports the zxdev/env package
type Server struct {
	Host   string `env:"H,require" default:"localhost" help:"localhost or FQDN"`
	Mirror bool   `default:"true" help:"http request policy [mirror, 400]"`
}

```

The default senario is http on localhost:1455, however when a FQDN (eg. example.com) is configured for HOST paramater requests will be served on both 80/443 based on the stated Server.Redirect policy, as defined. 

```golang

func main() {

	router := chi.NewRouter()
	server.Public(router,nil,nil)

	ctx := context.Background()
	
	var srv server.Server
	srv.Start(router, nil)(ctx)

}

```

