package webpush

import (
	"encoding/base64"
	"testing"
)

func Test2Way(t *testing.T) {
	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	subPriv, subPub, err := randomKey()
	auth, err := b64.DecodeString("68zcbmaevQa7MS7aXXRX8Q")
	sub := &Subscription{
		Endpoint: "https://foo.com",
		Auth:     auth,
		Key:      subPub,
	}
	result, err := Encrypt(sub, message)
	if err != nil {
		t.Error(err)
	}

	plain, err := Decrypt(sub, result, subPriv)

	// assumes 2-bytes padding length == 0

	if string(plain) != message {
		t.Error(plain, message)
		return
	}
}
