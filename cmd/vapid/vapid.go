// Command line tool to generate VAPID keys and tokens
package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

var (
	sub   = flag.String("sub", "", "Generate a VAPID key with the given domain")
	aud   = flag.String("aud", "", "Generate a VAPID key with the given domain")
	txt   = flag.String("txt", "", "Generate a VAPID key with full content")
	curve = elliptic.P256()
)

func main() {
	pub64 := os.Getenv("VAPID_PUB")
	priv64 := os.Getenv("VAPID_PRIV")

	if len(pub64) == 0 || len(priv64) == 0 {
		priv, x, y, _ := elliptic.GenerateKey(curve, rand.Reader)
		pub := elliptic.Marshal(curve, x, y)
		b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

		pub64 = b64.EncodeToString(pub)
		priv64 = b64.EncodeToString(priv)

		// 87 bytes encoded, 65 bytes starting with 0x4
		fmt.Println("VAPID_PUB=" + pub64)
		// 43 encoded, 32 uncompressed point, no prefix
		fmt.Println("VAPID_PRIV=" + priv64)
	}

	toSign := ""
	if len(*sub) > 0 {
		toSign = "{sub=" + *sub + "}"
	} else if len(*txt) > 0 {
		toSign = "{" + *txt + "}";
	} else {
		return
	}
	fmt.Println("-H\"Authorization:VAPID " + toSign + "\"");


}
