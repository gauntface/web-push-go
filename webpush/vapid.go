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
	"crypto/elliptic"
	"math/big"
	"crypto/ecdsa"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
)


var (
	//curve = elliptic.P256()
	vapid_prefix = []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.")
	dot = []byte(".")
)

type jwtPrefix struct {

}

type jwtBody struct {
	Aud string `json:"aud"`
	Sub string `json:"sub"`
	Exp int64 `json:"exp"`
}

// Vapid represents a sender identity.
type Vapid struct {
	// The EC256 public key. This value should be used in 'subscribe' requests
	// and is included a p256ecdsa in the Crypto-Key header.
	PublicKey []byte

	// The private key used to sign tokens
	pkey *ecdsa.PrivateKey
}

// Create a token with the specified audience, subject and expiry
func (vapid *Vapid) Token(aud, sub string, exp int64) (res string, err error) {
	t, _ := json.Marshal(
		jwtBody{Aud: aud,
			Sub: sub,
			Exp: exp})
	enc := base64.RawURLEncoding

	t64 := make([]byte, enc.EncodedLen(len(t)))
	enc.Encode(t64, t)

	token := make([]byte, len(t) + len(vapid_prefix) + 100)
	token = append(token[:0], vapid_prefix...)
	token = append(token, t64...)

	hasher := crypto.SHA256.New()
	hasher.Write(token)

	if r, s, err := ecdsa.Sign(rand.Reader, vapid.pkey, hasher.Sum(nil)); err == nil {
		// Vapid key is 32 bytes
		keyBytes := 32
		sig := make([]byte, 2 *keyBytes)

		rBytes := r.Bytes()
		rBytesPadded := make([]byte, keyBytes)
		copy(rBytesPadded[keyBytes - len(rBytes):], rBytes)

		sBytes := s.Bytes()
		sBytesPadded := make([]byte, keyBytes)
		copy(sBytesPadded[keyBytes - len(sBytes):], sBytes)

		sig = append(sig[:0], rBytesPadded...)
		sig = append(sig, sBytesPadded...)

		sigB64 := make([]byte, enc.EncodedLen(len(sig)))
		enc.Encode(sigB64, sig)


		token = append(token, dot...)
		token = append(token, sigB64...)
	}
	res = string(token)
	return
}


// NewVapid constructs a new Vapid generator from EC256 public and private keys,
// in uncompressed format
func NewVapid(publicUncomp, privateUncom []byte) (v *Vapid){
	// Public key is a point, starting with 0x4
	x, y := elliptic.Unmarshal(curve, publicUncomp)
	d := new(big.Int).SetBytes(privateUncom)
	pubkey := ecdsa.PublicKey{curve, x, y}
	pkey := ecdsa.PrivateKey{pubkey, d}
	enc := base64.RawURLEncoding
	pub64 := make([]byte, enc.EncodedLen(len(publicUncomp)))
	enc.Encode(pub64, publicUncomp)

	v = &Vapid{
		PublicKey: pub64,
		pkey: &pkey}

	return
}