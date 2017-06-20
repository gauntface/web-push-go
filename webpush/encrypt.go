// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package webpush provides helper functions for sending encrpyted payloads
// using the Web Push protocol.
//
// Sending a message:
//   import (
//     "github.com/googlechrome/push-encryption-go/webpush"
//   )
//
//   func main() {
//     // The values that make up the Subscription struct come from the browser
//     sub := &webpush.Subscription{endpoint, key, auth}
//     webpush.Send(nil, sub, "Yay! Web Push!", "")
//   }
//
// You can turn a JSON string representation of a PushSubscription object you
// collected from the browser into a Subscription struct with a helper function.
//
//   var exampleJSON = []byte(`{"endpoint": "...", "keys": {"p256dh": "...", "auth": "..."}}`)
//   sub, err := SubscriptionFromJSON(exampleJSON)
//
// If the push service requires an authentication header (notably Google Cloud
// Messaging, used by Chrome) then you can add that as a fourth parameter:
//
//   if strings.Contains(sub.Endpoint, "https://android.googleapis.com/gcm/send/") {
//     webpush.Send(nil, sub, "A message for Chrome", myGCMKey)
//   }
package webpush

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ContentEncoding indicates the version of encoding.
type ContentEncoding int

const (
	// The encoding that is widely deployed with WebPush (as of 2016-11).
	AESGCM ContentEncoding = iota
	// The most recent encoding, the salt, record size and key identifier
	// are included in a header that is part of the encrypted content coding.
	AES128GCM
)

func (v ContentEncoding) String() string {
	switch v {
	case AESGCM:
		return "aesgcm"
	case AES128GCM:
		return "aes128gcm"
	}
	return "unknown"
}

const (
	aesgcmMaxPayloadLength = 4078
	// Due to the additional binary message header, the max playload length for
	// aes128gcm is shorter than aesgcm.
	aes128gcmMaxPayloadLength = 4057
	// A push service is not required to support more than 4096 octets of
	// payload body so the record size can be at most 4096.
	maxPayloadRecordSize = 4096
)

var (
	authInfo = []byte("Content-Encoding: auth\x00")
	// See here for details on the prefix:
	// https://tools.ietf.org/html/draft-ietf-webpush-encryption-08#section-3.3
	keyInfoPrefix = []byte("WebPush: info\x00")
	curve         = elliptic.P256()

	// Generate a random key pair to be used for the encryption. Overridable for
	// testing.
	randomKey = func() (priv []byte, pub []byte, err error) {
		priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		return priv, elliptic.Marshal(curve, x, y), nil
	}

	// Generate a random salt for the encryption. Overridable for testing.
	randomSalt = func() ([]byte, error) {
		salt := make([]byte, 16)
		_, err := rand.Read(salt)
		if err != nil {
			return nil, err
		}
		return salt, nil
	}
)

// Subscription holds the useful values from a PushSubscription object acquired
// from the browser
type Subscription struct {
	// Endpoint is the URL to send the Web Push message to. Comes from the
	// endpoint field of the PushSubscription.
	Endpoint string
	// Key is the client's public key. From the keys.p256dh field.
	Key []byte
	// Auth is a value used by the client to validate the encryption. From the
	// keys.auth field.
	Auth []byte
}

// SubscriptionFromJSON is a convenience function that takes a JSON encoded
// PushSubscription object acquired from the browser and returns a pointer to a
// Subscription
func SubscriptionFromJSON(b []byte) (*Subscription, error) {
	var sub struct {
		Endpoint string
		Keys     struct {
			P256dh string
			Auth   string
		}
	}
	if err := json.Unmarshal(b, &sub); err != nil {
		return nil, err
	}

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	// Chrome < 52 incorrectly adds padding when Base64 encoding the values, so
	// we need to strip that out
	key, err := b64.DecodeString(strings.TrimRight(sub.Keys.P256dh, "="))
	if err != nil {
		return nil, err
	}

	auth, err := b64.DecodeString(strings.TrimRight(sub.Keys.Auth, "="))
	if err != nil {
		return nil, err
	}

	return &Subscription{sub.Endpoint, key, auth}, nil
}

// EncryptionResult stores the result of encrypting a message. The ciphertext is
// the actual encrypted message, while the salt and server public key are
// required to be sent to the client so that the message can be decrypted.
type EncryptionResult struct {
	Ciphertext      []byte
	Salt            []byte
	ServerPublicKey []byte
}

// Encrypt a message such that it can be sent using the Web Push protocol.
// You can find out more about the various pieces:
//    - https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding
//    - https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman
//    - https://tools.ietf.org/html/draft-ietf-webpush-encryption
func Encrypt(sub *Subscription, message string, encoding ContentEncoding) (*EncryptionResult, error) {
	// sub.Key is the p256dh key.
	if len(sub.Key) == 0 {
		return nil, errors.New("Subscription must include the client's public key")
	}

	// sub.Auth is the authentication secret.
	if len(sub.Auth) == 0 {
		return nil, errors.New("Subscription must include the client's auth value")
	}

	plaintext := []byte(message)

	maxPayloadLength := aes128gcmMaxPayloadLength
	if encoding == AESGCM {
		maxPayloadLength = aesgcmMaxPayloadLength
	}

	if n := len(plaintext); n > maxPayloadLength {
		return nil, fmt.Errorf("Payload is too large. The max number of bytes is %d, input is %d bytes.", maxPayloadLength, n)
	}

	salt, err := randomSalt()
	if err != nil {
		return nil, err
	}

	// Use ECDH to derive a shared secret between us and the client. We generate
	// a fresh private/public key pair at random every time we encrypt.
	serverPrivateKey, serverPublicKey, err := randomKey()
	if err != nil {
		return nil, err
	}

	secret, err := sharedSecret(curve, sub.Key, serverPrivateKey)
	if err != nil {
		return nil, err
	}

	// Derive a Pseudo-Random Key (prk) that can be used to further derive our
	// other encryption parameters.
	var prk []byte
	if encoding == AESGCM {
		// aesgcm derivations are described in
		// https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00
		prk = hkdf(sub.Auth, secret, authInfo, 32)
	} else {
		// aes128gcm derivations are described in
		// https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-06
		keyInfo := newKeyInfo(sub.Key, serverPublicKey)
		prk = hkdf(sub.Auth, secret, keyInfo, 32)
	}

	// Derive the Content Encryption Key and nonce
	// Context is only needed for aesgcm
	var ctx []byte
	if encoding == AESGCM {
		ctx = newContext(sub.Key, serverPublicKey)
	}
	cek, err := newCEK(ctx, salt, prk, encoding)
	if err != nil {
		return nil, err
	}
	nonce := newNonce(ctx, salt, prk)

	// Do the actual encryption
	ciphertext, err := encrypt(plaintext, cek, nonce, encoding)
	if err != nil {
		return nil, err
	}

	if encoding == AES128GCM {
		ciphertext = appendHeader(salt, serverPublicKey, ciphertext)
	}

	// Return all of the values needed to construct a Web Push HTTP request.
	return &EncryptionResult{ciphertext, salt, serverPublicKey}, nil
}

func newCEK(ctx, salt, prk []byte, encoding ContentEncoding) ([]byte, error) {
	if encoding != AESGCM && encoding != AES128GCM {
		return []byte{}, fmt.Errorf("Content Encoding is not recognized, you must use either AESGCM or AES128GCM.")
	}
	info := newInfo(encoding.String(), ctx)
	return hkdf(salt, prk, info, 16), nil
}

func newNonce(ctx, salt, prk []byte) []byte {
	info := newInfo("nonce", ctx)
	return hkdf(salt, prk, info, 12)
}

// Creates a context for deriving encyption parameters, as described in
// https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00.
// The 'context' in this case is just the public keys of both client and server.
// The keys should always be 65 bytes each. The format of the keys is
// described in section 4.3.6 of the (sadly not freely linkable) ANSI X9.62
// specification.
func newContext(clientPublicKey, serverPublicKey []byte) []byte {
	// The context format is:
	// 0x00 || length(clientPublicKey) || clientPublicKey ||
	//         length(serverPublicKey) || serverPublicKey
	// The lengths are 16-bit, Big Endian, unsigned integers so take 2 bytes each.
	cplen := uint16(len(clientPublicKey))
	cplenbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(cplenbuf, cplen)

	splen := uint16(len(serverPublicKey))
	splenbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(splenbuf, splen)

	var ctx []byte
	ctx = append(ctx, 0)
	ctx = append(ctx, cplenbuf...)
	ctx = append(ctx, []byte(clientPublicKey)...)
	ctx = append(ctx, splenbuf...)
	ctx = append(ctx, []byte(serverPublicKey)...)

	return ctx
}

// Returns an info record. See sections 3.2 and 3.3 of
// https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00.
// The context argument should match what newContext creates
func newInfo(infoType string, context []byte) []byte {
	info := append([]byte("Content-Encoding: "), []byte(infoType)...)
	info = append(info, 0)
	// For aes128gcm ctx is not needed.
	if len(context) > 0 {
		info = append(info, []byte("P-256")...)
		info = append(info, context...)
	}
	return info
}

// Returns a keying material. See sections of
// https://tools.ietf.org/html/draft-ietf-webpush-encryption-07#section-3.3
func newKeyInfo(subscriptionPublicKey, serverPublicKey []byte) []byte {
	info := make([]byte, len(keyInfoPrefix)+len(subscriptionPublicKey)+len(serverPublicKey))
	n := copy(info, keyInfoPrefix)
	n += copy(info[n:], subscriptionPublicKey)
	copy(info[n:], serverPublicKey)
	return info
}

// Returns an 86 octet header. See section 2.1 of:
// https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-06#section-2.1
func appendHeader(salt, serverPublicKey, ciphertext []byte) []byte {
	var result []byte
	// A push service is not required to support more than 4096 octets of
	// payload body so the record size can be at most 4096.
	rsbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(rsbuf, uint32(maxPayloadRecordSize))
	idlen := uint8(len(serverPublicKey))

	result = append(result, salt...)
	result = append(result, rsbuf...)
	result = append(result, byte(idlen))
	result = append(result, serverPublicKey...)
	result = append(result, ciphertext...)

	return result
}

// HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
//
// This is used to derive a secure encryption key from a mostly-secure shared
// secret.
//
// This is a partial implementation of HKDF tailored to our specific purposes.
// In particular, for us the value of N will always be 1, and thus T always
// equals HMAC-Hash(PRK, info | 0x01). This is true because the maximum output
// length we need/allow is 32.
//
// See https://www.rfc-editor.org/rfc/rfc5869.txt
func hkdf(salt, ikm, info []byte, length int) []byte {
	// HMAC length for SHA256 is 32 bytes, so that is the maximum result length.
	if length > 32 {
		panic("Can only produce HKDF outputs up to 32 bytes long")
	}

	// Extract
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)

	// Expand
	mac = hmac.New(sha256.New, prk)
	mac.Write(info)
	mac.Write([]byte{1})
	return mac.Sum(nil)[0:length]
}

// Encrypt the plaintext message using AES128/GCM
func encrypt(plaintext, key, nonce []byte, encoding ContentEncoding) ([]byte, error) {
	var data []byte
	if encoding == AES128GCM {
		// The padding delimiter octet MUST be checked, values other than 0x02 MUST
		// cause the message to be discarded.
		// See here for more details for restrictions on use of "aes128gcm":
		// https://tools.ietf.org/html/draft-ietf-webpush-encryption-08#section-4
		data = append(plaintext, []byte{0x02}...)
	} else {
		// Add padding. There is a uint16 size followed by that number of bytes of
		// padding.
		// TODO: Right now we leave the size at zero. We should add a padding option
		// that allows the payload size to be obscured.
		data = append([]byte{0, 0}, plaintext...)
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	return gcm.Seal([]byte{}, nonce, data, nil), nil
}

// Given the coordinates of a party A's public key and the bytes of party B's
// private key, compute a shared secret.
func sharedSecret(curve elliptic.Curve, pub, priv []byte) ([]byte, error) {
	publicX, publicY := elliptic.Unmarshal(curve, pub)
	if publicX == nil {
		return nil, errors.New("Couldn't unmarshal public key. Not a valid point on the curve")
	}
	x, _ := curve.ScalarMult(publicX, publicY, priv)
	return x.Bytes(), nil
}
