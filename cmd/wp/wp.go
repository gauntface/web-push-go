// Command line tool to generate VAPID keys and tokens
// The subscription can be provided as JSON, or as separate flags
// The message to be sent must be provided as stdin or 'msg'
// The VAPID key pair should be set as environment variables, not in commaond line.
package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/costinm/push-encryption-go/webpush"
	"os"
)

var (
	vapid = flag.NewFlagSet("vapid", flag.ExitOnError)
	curl  = flag.NewFlagSet("curl", flag.ExitOnError)

	sub = vapid.String("sub", "", "Optional email or URL identifying the sender")
	// TODO: txt   = flag.String("txt", "", "Generate a VAPID key with full content")
	aud = vapid.String("aud", "", "Generate a VAPID key with the given domain")

	msg    = flag.String("msg", "", "Message to send, or stdin")
	p256dh = flag.String("p256dh", "", "The p256dh parameter from subscription")
	auth   = flag.String("auth", "", "The auth parameter from subscription")

	curve = elliptic.P256()
)

type Keys struct {
	P256dh string ``
	Auth   string ``
}

type Sub struct {
	Endpoint string ``
}

func genKeys() {
	priv, x, y, _ := elliptic.GenerateKey(curve, rand.Reader)
	pub := elliptic.Marshal(curve, x, y)
	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	pub64 := b64.EncodeToString(pub)
	priv64 := b64.EncodeToString(priv)

	// 87 bytes encoded, 65 bytes starting with 0x4
	fmt.Println("# Environment variables for webpush")
	fmt.Println("export VAPID_PUB=" + pub64)
	// 43 encoded, 32 uncompressed point, no prefix
	fmt.Println("export VAPID_PRIV=" + priv64)

	fmt.Println()
	fmt.Println("# Public key hex: " + hex.EncodeToString(pub))
	// TODO(costin): print snippet for W3C subscribe
	return
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("gen\tGenerate VAPID key pair")
		fmt.Println("vapid\tGenerate VAPID token")
		fmt.Println("curl\tEncrypt and generate curl command parameters. Reads message from stdin")
		fmt.Println("send\tEncrypt and send. Reads message from stdin")

		os.Exit(1)
	}

	switch os.Args[1] {
	case "gen":
		genKeys()
		os.Exit(0)
	case "vapid":
		vapid.Parse(os.Args[2:])
	default:
		flag.PrintDefaults()
		os.Exit(1)
	}

	pub64 := os.Getenv("VAPID_PUB")
	priv64 := os.Getenv("VAPID_PRIV")

	if len(pub64) == 0 || len(priv64) == 0 {
		fmt.Println()
		fmt.Println("VAPID_PUB and VAPID_PRIV environment variables must be set")
		os.Exit(2)
	}

	vapid := webpush.NewVapid(pub64, priv64)

	if len(*sub) > 0 {
		vapid.Sub = *sub
	}

	if len(*aud) > 0 {
		// TODO: extract the base URL only, if full endpoint provided
		fmt.Println("-H\"Authorization:WebPush " + vapid.Token(*aud) + "\"" +
			" -H\"Crypto-Key:p256ecdsa=" + pub64 + "\"")
	} else {
		return
	}

}
