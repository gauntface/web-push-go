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
	message = `I am the walrus`
)

func generateMockSalt() ([]byte, error) {
	return hex.DecodeString("00112233445566778899aabbccddeeff")
}

func generateMockKeys() ([]byte, []byte, error) {
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

	// 4079 byted should be too big
	_, err = Encrypt(sub, strings.Repeat(" ", 4079))
	if err == nil {
		t.Error("Expected to get an error due to long payload")
	}

	// 4078 bytes should be fine
	_, err = Encrypt(sub, strings.Repeat(" ", 4078))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	defer stubFuncs(generateMockSalt, generateMockKeys)()

	// Use the library to encrypt the message
	result, err := Encrypt(sub, message)
	if err != nil {
		t.Error(err)
	}

	expCiphertext, err := hex.DecodeString(expectedCiphertextHex)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(result.Ciphertext, expCiphertext) {
		t.Errorf("Expected ciphertext to be %v, got %v", result.Ciphertext, expCiphertext)
	}

	_, expKey, err := generateMockKeys()
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(result.ServerPublicKey, expKey) {
		t.Errorf("Expected server key to be %v, got %v", result.ServerPublicKey, expKey)
	}

	expSalt, err := generateMockSalt()
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(result.Salt, expSalt) {
		t.Errorf("Expected salt to be %v, got %v", result.Salt, expSalt)
	}
}
