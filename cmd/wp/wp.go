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
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
)

var (
	vapid  = flag.NewFlagSet("vapid", flag.ExitOnError)
	curl   = flag.NewFlagSet("curl", flag.ExitOnError)
	send   = flag.NewFlagSet("send", flag.ExitOnError)
	server = flag.NewFlagSet("server", flag.ExitOnError)
	ua     = flag.NewFlagSet("ua", flag.ExitOnError)

	sub = vapid.String("sub", "", "Optional email or URL identifying the sender")
	// TODO: txt   = flag.String("txt", "", "Generate a VAPID key with full content")
	aud = vapid.String("aud", "", "Generate a VAPID key with the given domain")

	serverPort = server.String("port", ":5222", "Main port")
	// Has to be separate because for now framing is trickier
	serverPortH2 = server.String("portH2", ":5223", "Server to listen for long lived connections using standard protocol")

	uaPort = ua.String("port", ":5222", "Main port")
	// Has to be separate because for now framing is trickier
	uaPortH2 = ua.String("portH2", ":5223", "Port for standard HTTP/2 connections")

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

func sendMessage() {
	pub64, priv64 := getKeys()
	vapid := webpush.NewVapid(pub64, priv64)
	msg, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Println("Failed to read message")
		os.Exit(3)
	}
	to, err := webpush.SubscriptionFromJSON([]byte(os.Args[2]))

	if err != nil {
		fmt.Println("Invalid endpoint "+flag.Arg(1), err)
		os.Exit(3)
	}

	req, err := webpush.NewRequest(to, string(msg), 0, vapid)
	res, err := http.DefaultClient.Do(req)

	if err != nil || res.StatusCode != 201 {
		dmpReq, err := httputil.DumpRequest(req, true)
		fmt.Printf(string(dmpReq))
		dmp, err := httputil.DumpResponse(res, true)
		fmt.Printf(string(dmp))
		fmt.Printf("Failed to send ", err, res.StatusCode)
	}
}

func getKeys() (string, string) {
	pub64 := os.Getenv("VAPID_PUB")
	priv64 := os.Getenv("VAPID_PRIV")

	if len(pub64) == 0 || len(priv64) == 0 {
		fmt.Println()
		fmt.Println("VAPID_PUB and VAPID_PRIV environment variables must be set")
		os.Exit(2)
	}
	return pub64, priv64
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("gen\tGenerate VAPID key pair")
		fmt.Println("vapid\tGenerate VAPID token")
		fmt.Println("curl\tEncrypt and generate curl command parameters. Reads message from stdin")
		fmt.Println("send\tEncrypt and send. Reads message from stdin")
		fmt.Println("server\tStart a micro server")
		fmt.Println("ua\tStart a client connection ( user agent )")

		os.Exit(1)
	}

	switch os.Args[1] {
	case "gen":
		genKeys()
		break
	case "vapid":
		vapid.Parse(os.Args[2:])
		curlVapid()
		break
	case "send":
		send.Parse(os.Args[2:])
		sendMessage()
		break
	case "server":
		server.Parse(os.Args[2:])
		startServer()
		break
	case "ua":
		ua.Parse(os.Args[2:])
		startClient()
		break

	default:
		flag.PrintDefaults()
		os.Exit(1)
	}
}

func startServer() {
	webpush.InitServer(*serverPort)

}

func startClient() {
	ua := webpush.UA{}
	pushSet := os.Getenv("PUSH_SET")
	if len(pushSet) == 0 {
		sub, err := ua.Subscribe()
		if err != nil {
			return
		}
		fmt.Println("" + sub)
	} else {

	}
}

// Print VAPID curl header
func curlVapid() {
	pub64, priv64 := getKeys()

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
