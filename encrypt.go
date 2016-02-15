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
	"fmt"
)

const (
	maxPayloadLength = 4078
)

var (
	authInfo = []byte("Content-Encoding: auth\x00")
	curve    = elliptic.P256()

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

// SubscriptionKey represents the keys property of a subscription
type SubscriptionKey struct {
	P256dh string `json:"p256dh"`
	Auth   string `json:"auth"`
}

// Subscription is a representation of a PushSubscription object acquired from
// the browser
type Subscription struct {
	Endpoint string          `json:"endpoint"`
	Keys     SubscriptionKey `json:"keys"`
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
// - https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding
// - https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman
// - https://tools.ietf.org/html/draft-ietf-webpush-encryption
func Encrypt(sub Subscription, message string) (*EncryptionResult, error) {
	plaintext := []byte(message)
	if len(plaintext) > maxPayloadLength {
		return nil, fmt.Errorf("Payload is too large. The max number of bytes is %d, input is %d bytes.", maxPayloadLength, len(plaintext))
	}

	clientPublicKey, err := base64.URLEncoding.DecodeString(sub.Keys.P256dh)
	if err != nil {
		return nil, err
	}

	auth, err := base64.URLEncoding.DecodeString(sub.Keys.Auth)
	if err != nil {
		return nil, err
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
	secret := sharedSecret(curve, clientPublicKey, serverPrivateKey)

	// Derive a Pseudo-Random Key (prk) that can be used to further derive our
	// other encryption parameters. These derivations are described in
	// https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00
	prk := hkdf(auth, secret, authInfo, 32)

	// Derive the Content Encryption Key and nonce
	ctx := newContext(clientPublicKey, serverPublicKey)
	cek := newCEK(ctx, salt, prk)
	nonce := newNonce(ctx, salt, prk)

	// Do the actual encryption
	ciphertext, err := encrypt(plaintext, cek, nonce)
	if err != nil {
		return nil, err
	}

	// Return all of the values needed to construct a Web Push HTTP request.
	return &EncryptionResult{ciphertext, salt, serverPublicKey}, nil
}

func newCEK(ctx, salt, prk []byte) []byte {
	info := newInfo("aesgcm", ctx)
	return hkdf(salt, prk, info, 16)
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
	var info []byte
	info = append(info, []byte("Content-Encoding: ")...)
	info = append(info, []byte(infoType)...)
	info = append(info, 0)
	info = append(info, []byte("P-256")...)
	info = append(info, context...)
	return info
}

// HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
//
// This is used to derive a secure encryption key from a mostly-secure shared
// secret.
//
// This is a partial implementation of HKDF tailored to our specific purposes.
// In particular, for us the value of N will always be 1, and thus T always
// equals HMAC-Hash(PRK, info | 0x01).
//
// See https://www.rfc-editor.org/rfc/rfc5869.txt
func hkdf(salt, ikm, info []byte, length int) []byte {
	// HMAC length for SHA256 is 32 bytes, so that is the maximum result length.
	// HKDF defines a way to have longer lengths, but our partial implementation
	// will just truncate the result.
	if length > 32 {
		length = 32
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
func encrypt(plaintext, key, nonce []byte) ([]byte, error) {
	// Add padding. There is a uint16 size followed by that number of bytes of
	// padding.
	// TODO: Right now we leave the size at zero. We should add a padding option
	// that allows the payload size to be obscured.
	padding := make([]byte, 2)
	data := append(padding, plaintext...)

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
func sharedSecret(curve elliptic.Curve, pub, priv []byte) []byte {
	publicX, publicY := elliptic.Unmarshal(curve, pub)
	x, _ := curve.ScalarMult(publicX, publicY, priv)
	return x.Bytes()
}
