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

package webpush

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

var (
	// The hex representation of the expected end result of encrypting the test
	// message using the mock salt and keys and the fake subscription.
	expectedCiphertextHex = "c29da35b8ad084b3cda4b3c20bd9d1bb9098dfb5c8e7c2e3a67fe7c91ff887b72f"
	// A fake subscription created with random key and auth values
	subscriptionJSON = []byte(`{
		"endpoint": "https://example.com/",
		"keys": {
			"p256dh": "BCXJI0VW7evda9ldlo18MuHhgQVxWbd0dGmUfpQedaD7KDjB8sGWX5iiP7lkjxi-A02b8Fi3BMWWLoo3b4Tdl-c=",
			"auth": "WPF9D0bTVZCV2pXSgj6Zug=="
		}
	}`)
	message          = `I am the walrus`
	aes128gcmMessage = `When I grow up, I want to be a watermelon`

	rfcAESgcmPublic    = "BCEkBjzL8Z3C-oi2Q7oE5t2Np-p7osjGLg93qUP0wvqRT21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQU"
	rfcAES128gcmPublic = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"

	rfcAESgcmCipher    = "6nqAQUME8hNqw5J3kl8cpVVJylXKYqZOeseZG8UueKpA"
	rfcAES128gcmCipher = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
	rfcAESgcmAuth      = "R29vIGdvbyBnJyBqb29iIQ"
	rfcAES128gcmAuth   = "BTBZMqHH6r4Tts7J_aSIgg"
)

func mockSalt() ([]byte, error) {
	return hex.DecodeString("00112233445566778899aabbccddeeff")
}

func mockKeys() ([]byte, []byte, error) {
	priv, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	// Generate the right public key for the static private key
	x, y := curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, priv)

	return priv, elliptic.Marshal(curve, x, y), nil
}

func stubFuncs(salt func() ([]byte, error), key func() ([]byte, []byte, error)) func() {
	origSalt, origKey := randomSalt, randomKey
	randomSalt, randomKey = salt, key
	return func() {
		randomSalt, randomKey = origSalt, origKey
	}
}

func TestSubscriptionFromJSON(t *testing.T) {
	_, err := SubscriptionFromJSON(subscriptionJSON)
	if err != nil {
		t.Errorf("Failed to parse main sample subscription: %v", err)
	}

	// key and auth values are valid Base64 with or without padding
	_, err = SubscriptionFromJSON([]byte(`{
		"endpoint": "https://example.com",
		"keys": {
			"p256dh": "AAAA",
			"auth": "AAAA"
		}
	}`))
	if err != nil {
		t.Errorf("Failed to parse subscription with 4-character values: %v", err)
	}

	// key and auth values are padded Base64
	_, err = SubscriptionFromJSON([]byte(`{
		"endpoint": "https://example.com",
		"keys": {
			"p256dh": "AA==",
			"auth": "AAA="
		}
	}`))
	if err != nil {
		t.Errorf("Failed to parse subscription with padded values: %v", err)
	}

	// key and auth values are unpadded Base64
	_, err = SubscriptionFromJSON([]byte(`{
		"endpoint": "https://example.com",
		"keys": {
			"p256dh": "AA",
			"auth": "AAA"
		}
	}`))
	if err != nil {
		t.Errorf("Failed to parse subscription with unpadded values: %v", err)
	}
}

func TestEncrypt(t *testing.T) {
	sub, err := SubscriptionFromJSON(subscriptionJSON)
	if err != nil {
		t.Error("Couldn't decode JSON subscription")
	}

	// 4079 bytes should be too big for aesgcm
	_, err = Encrypt(sub, strings.Repeat(" ", 4079), AESGCM)
	if err == nil {
		t.Error("Expected to get an error due to long payload")
	}
	// 4079 bytes should be too big for aes128gcm
	_, err = Encrypt(sub, strings.Repeat(" ", 4079), AES128GCM)
	if err == nil {
		t.Error("Expected to get an error due to long payload")
	}

	// 4078 bytes should be fine aesgcm
	_, err = Encrypt(sub, strings.Repeat(" ", 4078), AESGCM)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	// 4057 bytes should be fine aes128gcm
	_, err = Encrypt(sub, strings.Repeat(" ", 4057), AES128GCM)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	defer stubFuncs(mockSalt, mockKeys)()

	// Use the library to encrypt the message
	result, err := Encrypt(sub, message, AESGCM)
	if err != nil {
		t.Error(err)
	}

	expCiphertext, err := hex.DecodeString(expectedCiphertextHex)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(result.Ciphertext, expCiphertext) {
		t.Errorf("Ciphertext was %v, expected %v", result.Ciphertext, expCiphertext)
	}

	_, expKey, err := mockKeys()
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(result.ServerPublicKey, expKey) {
		t.Errorf("Server key was %v, expected %v", result.ServerPublicKey, expKey)
	}

	expSalt, err := mockSalt()
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(result.Salt, expSalt) {
		t.Errorf("Salt was %v, expected %v", result.Salt, expSalt)
	}
}

func rfcAESgcmSalt() ([]byte, error) {
	return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString("lngarbyKfMoi9Z75xYXmkg")
}

func rfcAESgcmKeys() ([]byte, []byte, error) {
	priv, _ := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString("nCScek-QpEjmOOlT-rQ38nZzvdPlqa00Zy0i6m2OJvY")

	// Generate the right public key for the static private key
	x, y := curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, priv)

	return priv, elliptic.Marshal(curve, x, y), nil
}

func rfcAES128gcmSalt() ([]byte, error) {
	return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString("DGv6ra1nlYgDCS1FRnbzlw")
}

func rfcAES128gcmKeys() ([]byte, []byte, error) {
	priv, _ := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")

	// Generate the right public key for the static private key
	x, y := curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, priv)

	return priv, elliptic.Marshal(curve, x, y), nil
}

// TestAESgcmRfcVectors uses the values given in the RFC for HTTP encryption to verify
// that the code conforms to the RFC
// See: https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-02#appendix-B
func TestAESgcmRfcVectors(t *testing.T) {
	defer stubFuncs(rfcAESgcmSalt, rfcAESgcmKeys)()

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	auth, err := b64.DecodeString(rfcAESgcmAuth)
	if err != nil {
		t.Fatal(err)
	}
	key, err := b64.DecodeString(rfcAESgcmPublic)
	if err != nil {
		t.Fatal(err)
	}

	sub := &Subscription{Auth: auth, Key: key}

	result, err := Encrypt(sub, message, AESGCM)
	if err != nil {
		t.Fatal(err)
	}

	expCiphertext, err := b64.DecodeString(rfcAESgcmCipher)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Ciphertext, expCiphertext) {
		t.Fatalf("Ciphertext was %v, expected %v", result.Ciphertext, expCiphertext)
	}
}

// TestAES128gcmRfcVectors uses the values given in the RFC for HTTP encryption to verify
// that the code conforms to the RFC
// See: https://tools.ietf.org/html/draft-ietf-webpush-encryption-07#appendix-A
func TestAES128gcmRfcVectors(t *testing.T) {
	defer stubFuncs(rfcAES128gcmSalt, rfcAES128gcmKeys)()
	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	auth, err := b64.DecodeString(rfcAES128gcmAuth)
	if err != nil {
		t.Fatal(err)
	}
	key, err := b64.DecodeString(rfcAES128gcmPublic)
	if err != nil {
		t.Fatal(err)
	}

	sub := &Subscription{Auth: auth, Key: key}
	result, err := Encrypt(sub, aes128gcmMessage, AES128GCM)
	if err != nil {
		t.Fatal(err)
	}

	expCiphertext, err := b64.DecodeString(rfcAES128gcmCipher)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Ciphertext, expCiphertext) {
		t.Fatalf("Ciphertext was %v, expected %v", b64.EncodeToString(result.Ciphertext), rfcAES128gcmCipher)
	}
}

func TestSharedSecret(t *testing.T) {
	serverPrivateKey, _, _ := randomKey()
	invalidPub, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	_, err := sharedSecret(curve, invalidPub, serverPrivateKey)
	if err == nil {
		t.Error("Expected an error due to invalid public key")
	}
	_, err = sharedSecret(curve, nil, serverPrivateKey)
	if err == nil {
		t.Error("Expected an error due to nil key")
	}
}
