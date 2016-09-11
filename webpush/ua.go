package webpush

import (
	"net/http"
	"net/textproto"
	"strings"
)

var ()

// UA represents a "user agent" - or client using the webpush protocol
// This is intended for testing and simple use.
type UA struct {
	// URL of the subscribe for the push service
	PushService string
}

// UASubscription represents one app's subscription.
// A UA may host multiple apps.
type UASubscription struct {
	Subscription

	// Used by the UA to receive messages, as PUSH promises
	location string
}

// Create a subscription.
func (ua *UA) Subscribe() (sub UASubscription, err error) {
	res, err := http.Post(ua.PushService+"/subscribe", "test/plain", nil)

	if err != nil {
		return
	}
	sub = UASubscription{}
	sub.location = res.Header.Get("location")
	links := textproto.MIMEHeader(res.Header)["Link"]
	for _, l := range links {
		for _, link := range strings.Split(l, ",") {
			parts := strings.Split(link, ";")
			if len(parts) > 1 &&
				strings.TrimSpace(parts[1]) == "rel=\"urn:ietf:params:push\"" {
				sub.Endpoint = parts[0]
			}
		}
	}

	// generate encryption key and authenticator

	return
}

// Read will receive messages, using a hanging GET, for cases where HTTP/2 is not available.
func (ua *UA) Read() (sub UASubscription, err error) {
	res, err := http.Post(ua.PushService+"/subscribe", "test/plain", nil)

	if err != nil {
		return
	}
	sub = UASubscription{}
	sub.location = res.Header.Get("location")
	links := textproto.MIMEHeader(res.Header)["Link"]
	for _, l := range links {
		for _, link := range strings.Split(l, ",") {
			parts := strings.Split(link, ";")
			if len(parts) > 1 &&
				strings.TrimSpace(parts[1]) == "rel=\"urn:ietf:params:push\"" {
				sub.Endpoint = parts[0]
			}
		}
	}

	// generate encryption key and authenticator

	return
}

// Decrypt an encrypted messages.
func Decrypt(sub *Subscription, crypt *EncryptionResult, subPrivate []byte) (plain []byte, err error) {
	secret, err := sharedSecret(curve, crypt.ServerPublicKey, subPrivate)
	if err != nil {
		return
	}
	prk := hkdf(sub.Auth, secret, authInfo, 32)

	// Derive the Content Encryption Key and nonce
	ctx := newContext(sub.Key, crypt.ServerPublicKey)
	cek := newCEK(ctx, crypt.Salt, prk)
	nonce := newNonce(ctx, crypt.Salt, prk)

	plain, err = decrypt(crypt.Ciphertext, cek, nonce)
	if err != nil {
		return nil, err
	}
	return
}
