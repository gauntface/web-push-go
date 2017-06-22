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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"time"
)

var (
	// JWT header is always the same, so use a pre-encoded string
	vapidPrefix = []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.")
	dot         = []byte(".")
)

type jwtBody struct {
	Aud string `json:"aud"`
	Sub string `json:"sub,omitempty"`
	Exp int64  `json:"exp"`
}

// Vapid provides helpers for authenticating the sender of a push message
type Vapid struct {
	// The application's private key
	priv *ecdsa.PrivateKey

	// Sub should be an email or URL, for identification
	Sub string
}

// PublicKey returns an uncompressed EC point representing the
// application's public key
func (v *Vapid) PublicKey() []byte {
	pub := v.priv.PublicKey
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

// Token creates a token with the specified endpoint, using configured Sub id
// and a default expiration (1h).
func (v *Vapid) Token(aud string) (string, error) {
	url, err := url.Parse(aud)
	if err != nil {
		return "", err
	}
	jwt := jwtBody{Aud: url.Scheme + "://" + url.Host}
	if v.Sub != "" {
		jwt.Sub = v.Sub
	}
	jwt.Exp = int64(time.Now().Unix() + 3600)
	t, err := json.Marshal(jwt)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding

	t64 := make([]byte, enc.EncodedLen(len(t)))
	enc.Encode(t64, t)

	token := make([]byte, len(t)+len(vapidPrefix)+100)
	token = append(token[:0], vapidPrefix...)
	token = append(token, t64...)

	hasher := crypto.SHA256.New()
	hasher.Write(token)

	r, s, err := ecdsa.Sign(rand.Reader, v.priv, hasher.Sum(nil))
	if err != nil {
		return "", err
	}
	// Vapid key is 32 bytes
	keyBytes := 32
	sig := make([]byte, 2*keyBytes)

	rBytes := r.Bytes()
	copy(sig[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	copy(sig[2*keyBytes-len(sBytes):], sBytes)

	sigB64 := make([]byte, enc.EncodedLen(len(sig)))
	enc.Encode(sigB64, sig)

	token = append(token, dot...)
	token = append(token, sigB64...)
	return string(token), nil
}

// NewVapid constructs a new Vapid generator from a p256 EC private key
func NewVapid(privateKey []byte) *Vapid {
	d := new(big.Int).SetBytes(privateKey)
	x, y := curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, privateKey)
	pub := ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	pkey := ecdsa.PrivateKey{PublicKey: pub, D: d}

	return &Vapid{priv: &pkey}
}
