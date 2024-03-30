package main

import (
	"encoding/base32"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/zxdev/server/passkey"
)

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
		fmt.Print("\nusage:\npasskey {secret} {interval}\n secret   : a 32-character base32 encoded string\n interval : is n seconds (default 60s)\n\n")
		return
	}

	_, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil || len(secret) != 32 {
		fmt.Print("passkey:\n secret : requires a 32-character base32 encoded string value(A..Z,2..7)\n\n")
		return
	}

	pkc := passkey.NewClient(secret)
	if interval > 0 {
		pkc.Interval(interval)
	}

	fmt.Println(pkc.Current())

}
