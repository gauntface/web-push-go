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
	aud = vapid.String("aud", "", "Generate a VAPID key with the given domain. Defaults to https://fcm.googleapis.com")

	serverPort = server.String("port", ":5222", "Main port")
	// Has to be separate because for now framing is trickier
	serverPortH2 = server.String("portH2", ":5223", "Server to listen for long lived connections using standard protocol")

	uaPort = ua.String("port", ":5222", "Main port")
	// Has to be separate because for now framing is trickier
	uaPortH2 = ua.String("portH2", ":5223", "Port for standard HTTP/2 connections")
	sendVerbose = send.Bool("v", false, "Show request and response body")

	curve = elliptic.P256()
)

const (
	// Environment variable for the private key.
	// Using env is more secure than flags - "ps" can expose it.
	EnvVapidPrivate = "VAPID_PRIV"

	// Environment variable for the public key. It is passed as
	// env for consistency with the private key, and to simplify
	// the command line
	EnvVapidPublic = "VAPID_PUB"
	Subscription = "TO"

)

type Keys struct {
	P256dh string ``
	Auth   string ``
}

type Sub struct {
	Endpoint string ``
}

// Generate a snippet of js defining APPLICATION_SERVER_KEY.
// Needs to be passed as "applicationServerKey" parameter in the subscription
// options
func genJsKey() {
	pub64 := os.Getenv(EnvVapidPublic)

	if len(pub64) == 0 {
		fmt.Println()
		fmt.Println(EnvVapidPublic + " environment variable must be set")
		os.Exit(2)
	}
	publicUncomp, _ := base64.RawURLEncoding.DecodeString(pub64)

	if publicUncomp[0] != 4 {
		fmt.Println()
		fmt.Println("VAPID_PUB must be basae64 encoding of an uncompressed public key, starting with 0x04")
		os.Exit(3)

	}

	if len(publicUncomp) != 65 {
		fmt.Println()
		fmt.Println("VAPID_PUB must be basae64 encoding of an uncompressed public key, of 65 bytes length")
		os.Exit(4)

	}
	fmt.Println("const APPLICATION_SERVER_KEY = new Uint8Array([4,")
	for i := 0; i < 4; i++ {
		fmt.Print("    ")
		for j := 0; j < 16; j++ {
			fmt.Print(publicUncomp[i*16+j+1])
			if i != 3 || j != 15 {
				fmt.Print(", ")
			} else {
				fmt.Print("]);")
			}
		}
		fmt.Println()
	}
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

// Show a CURL command line for sending the message
func showCurl() {
	pub64, priv64 := getKeys()
	vapid := webpush.NewVapid(pub64, priv64)
	msg, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Println("Failed to read message")
		os.Exit(3)
	}
	to, err := webpush.SubscriptionFromJSON([]byte(os.Getenv(Subscription)))

	if err != nil {
		fmt.Println("Invalid endpoint "+flag.Arg(1), err)
		os.Exit(3)
	}

	payload, err:= webpush.Encrypt(to, string(msg))
	payload64 := base64.StdEncoding.EncodeToString(payload.Ciphertext)
	tok := vapid.Token(to.Endpoint);

	fmt.Println(
		"echo -n " + string(payload64) + " | base64 -d > /tmp/$$.bin; " +
 		"curl -HTtl:0" +
		" -XPOST" +
		" --data-binary @/tmp/$$.bin" +
			" -HContent-Encoding:aesgcm" +
		" -H Encryption:salt=" + base64.RawURLEncoding.EncodeToString(payload.Salt) +
		" -H \"Authorization:Bearer " + tok + "\"" +
		" -H \"Crypto-Key: dh=" + base64.RawURLEncoding.EncodeToString(payload.ServerPublicKey) +
			"; p256ecdsa=" + vapid.PublicKey + "\" " +
			to.Endpoint)

}

// Send the message.
func sendMessage() {
	pub64, priv64 := getKeys()
	vapid := webpush.NewVapid(pub64, priv64)
	msg, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Println("Failed to read message")
		os.Exit(3)
	}
	to, err := webpush.SubscriptionFromJSON([]byte(os.Getenv(Subscription)))

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
	} else if *sendVerbose {
		dmpReq, _ := httputil.DumpRequest(req, true)
		fmt.Printf(string(dmpReq))
		dmp, _ := httputil.DumpResponse(res, true)
		fmt.Printf(string(dmp))
	}
}

func genVapid() {
	pub64, priv64 := getKeys()

	vapid := webpush.NewVapid(pub64, priv64)

	if len(*sub) > 0 {
		vapid.Sub = *sub
	}

	a := *aud
	if len(a) == 0 {
		// by default generate for google
		a = "https://fcm.googleapis.com"
	}
	// TODO: extract the base URL only, if full endpoint provided
	fmt.Println("-H\"Authorization:WebPush " + vapid.Token(*aud) + "\"" +
		" -H\"Crypto-Key:p256ecdsa=" + pub64 + "\"")

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
		fmt.Println("js\tGenerate js snippet for applicationServerKey, to use in subscribe calls")
		fmt.Println("send\tEncrypt and send. Reads message from stdin")

		fmt.Println()
		fmt.Println("vapid\tGenerate VAPID token")
		fmt.Println("curl\tEncrypt and generate curl command parameters. Reads message from stdin")
		fmt.Println("send\tEncrypt and send. Reads message from stdin")
		//fmt.Println("server\tStart a micro push service")
		//fmt.Println("ua\tStart a client connection ( user agent )")

		os.Exit(1)
	}

	switch os.Args[1] {
	case "gen":
		genKeys()
	case "js":
		genJsKey()
		os.Exit(0)
	case "vapid":
		vapid.Parse(os.Args[2:])
		genVapid()
	case "send":
		send.Parse(os.Args[2:])
		sendMessage()
	case "curl":
		showCurl()
	case "server":
		server.Parse(os.Args[2:])
		startServer()
	case "ua":
		ua.Parse(os.Args[2:])
		startClient()
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
		fmt.Println(sub)
	} else {

	}
}

