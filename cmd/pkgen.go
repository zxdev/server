package main

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/zxdev/server/auth"
)

/*

	# client testing example using the pkgen passkey token generator
	# with a shared secret to generate the current token; also reads
	# the shared secret from a local file for pkgen to use
	curl -i -H token:$(sandbox/pkgen $(cat sandbox/secret)) http://localhost:1455/demo
	HTTP/1.1 200 OK
	Auth: success
	Date: Mon, 15 Apr 2024 20:19:45 GMT
	Content-Length: 0

	# pkgen can be used to generate a new secret or generates a new passkey
	# using the specified interval when the secret is provided

	./pkgen
	usage:
	passkey {secret} {interval}
	secret   : LGU4NNOKNUXFD7RKJX3JEPHVY44AZ5CI
	interval : is n seconds (default 60s)

	./pkgen LGU4NNOKNUXFD7RKJX3JEPHVY44AZ5CI
	323077921
*/

func main() {
	var secret string
	var interval int

	switch len(os.Args) {
	case 3:
		interval, _ = strconv.Atoi(os.Args[2])
		fallthrough
	case 2:
		secret = os.Args[1]
	default:
		var b [20]byte
		rand.Read(b[:])
		fmt.Printf("\nusage:\npasskey {secret} {interval}\n secret   : %s\n interval : is n seconds (default 60s)\n\n",
			base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
		return
	}

	_, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil || len(secret) != 32 {
		fmt.Print("passkey:\n secret : requires a 32-character base32 encoded string value(A..Z,2..7)\n\n")
		return
	}

	pkc := auth.NewClient(secret)
	if interval > 0 {
		pkc.Interval(interval)
	}

	fmt.Println(pkc.Current())

}
