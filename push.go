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
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

const (
	gcmURL     = "https://android.googleapis.com/gcm/send"
	tempGcmURL = "https://gcm-http.googleapis.com/gcm"
)

type authToken struct {
	Pattern string
	Token   string
}

var authTokens []authToken

// NewPushRequest creates a valid Web Push HTTP request for sending a message
// to a subscriber.
func NewPushRequest(sub Subscription, message string, token string) (*http.Request, error) {
	payload, err := Encrypt(sub, message)
	if err != nil {
		return nil, err
	}

	// If the endpoint is GCM then we temporarily need to rewrite it, as not all
	// GCM servers support the Web Push protocol. This should go away in the
	// future.
	endpoint := strings.Replace(sub.Endpoint, gcmURL, tempGcmURL, 1)

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(payload.Ciphertext))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Encryption", headerField("salt", payload.Salt))
	req.Header.Add("Crypto-Key", headerField("dh", payload.ServerPublicKey))
	req.Header.Add("Content-Encoding", "aesgcm")

	if token != "" {
		req.Header.Add("Authorization", fmt.Sprintf(`key=%s`, token))
	}

	return req, nil
}

// SendWebPush sends a message using the Web Push protocol to the recipient
// identified by the given subscription object.
func SendWebPush(client *http.Client, sub Subscription, message, token string) (*http.Response, error) {
	if client == nil {
		client = http.DefaultClient
	}

	req, err := NewPushRequest(sub, message, token)
	if err != nil {
		return nil, err
	}

	return client.Do(req)
}

// A helper for creating the value part of the HTTP encryption headers
func headerField(headerType string, value []byte) string {
	return fmt.Sprintf(`%s=%s`, headerType, base64.URLEncoding.EncodeToString(value))
}
