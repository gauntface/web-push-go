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
	"io/ioutil"
	"net/http"
	"strings"
	"strconv"
)

const (
	gcmURL     = "https://android.googleapis.com/gcm/send"
	tempGcmURL = "https://gcm-http.googleapis.com/gcm"
	minimumTTL = 0
	maximumTTL = 2419200
)

// NewPushRequest creates a valid Web Push HTTP request for sending a message
// to a subscriber. If the push service requires an authentication header
// (notably Google Cloud Messaging, used by Chrome) then you can add that as the
// token parameter.
func NewPushRequest(sub *Subscription, message string, token string, TTL int) (*http.Request, error) {
	// If the endpoint is GCM then we temporarily need to rewrite it, as not all
	// GCM servers support the Web Push protocol. This should go away in the
	// future.
	endpoint := strings.Replace(sub.Endpoint, gcmURL, tempGcmURL, 1)

	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		return nil, err
	}

	// TODO: Make the TTL variable
	req.Header.Add("TTL", strconv.Itoa(TTL))

	if token != "" {
		req.Header.Add("Authorization", fmt.Sprintf(`key=%s`, token))
	}

	// If there is no payload then we don't actually need encryption
	if message == "" {
		return req, nil
	}

	payload, err := Encrypt(sub, message)
	if err != nil {
		return nil, err
	}

	req.Body = ioutil.NopCloser(bytes.NewReader(payload.Ciphertext))
	req.ContentLength = int64(len(payload.Ciphertext))
	req.Header.Add("Encryption", headerField("salt", payload.Salt))
	req.Header.Add("Crypto-Key", headerField("dh", payload.ServerPublicKey))
	req.Header.Add("Content-Encoding", "aesgcm")

	return req, nil
}

// Send a message using the Web Push protocol to the recipient identified by the
// given subscription object. If the client is nil then the default HTTP client
// will be used. If the push service requires an authentication header (notably
// Google Cloud Messaging, used by Chrome) then you can add that as the token
// parameter. 'extra' can be used to pass multiple parameters like TTL,
// collapse_key or dry_run(as documented by gcm http-server-ref) without much
// changes in Send signature.
func Send(client *http.Client, sub *Subscription, message, token string, extra map[string]interface{}) (*http.Response, error) {
	if client == nil {
		client = http.DefaultClient
	}

	// Define default TTL as maximumTTL because GCM stores notifications for 4
	// weeks if no time_to_live parameter is passed with request.
	TTL := maximumTTL

	if ttl, ok := extra["TTL"]; ok {
		if ttlInt, found := ttl.(int); found {
			if ttlInt > maximumTTL || ttlInt < minimumTTL {
				return nil, fmt.Errorf("TTL should be between %d and %d, was %d", minimumTTL, maximumTTL, ttlInt)
			} else {
				TTL = ttlInt
			}
		} else {
			return nil, fmt.Errorf("TTL should be integer between %d and %d", minimumTTL, maximumTTL)
		}
	}

	req, err := NewPushRequest(sub, message, token, TTL)
	if err != nil {
		return nil, err
	}

	return client.Do(req)
}

// A helper for creating the value part of the HTTP encryption headers
func headerField(headerType string, value []byte) string {
	return fmt.Sprintf(`%s=%s`, headerType, base64.URLEncoding.EncodeToString(value))
}
