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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type FakeTransport struct {
	URL *url.URL
}

func (transport *FakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = transport.URL.Scheme
	req.URL.Host = transport.URL.Host
	return http.DefaultTransport.RoundTrip(req)
}

func TestSendWebPush(t *testing.T) {

	// Test server checks that the request is well-formed
	ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)

		defer request.Body.Close()

		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}

		// 2 bytes padding and 16 bytes auth tag
		expectedLength := len(message) + 2 + 16

		if len(body) != expectedLength {
			t.Errorf("Expected body to be length %d, was %d", expectedLength, len(body))
		}

		if request.Header.Get("Content-Encoding") != "aesgcm" {
			t.Errorf("Expected Content-Encoding header to be aesgcm, got %v", request.Header.Get("Content-Encoding"))
		}

		if !strings.HasPrefix(request.Header.Get("Crypto-Key"), "dh=") {
			t.Errorf("Expected Crypto-Key header to have a dh field, got %v", request.Header.Get("Crypto-Key"))
		}

		if !strings.HasPrefix(request.Header.Get("Encryption"), "salt=") {
			t.Errorf("Expected Encryption header to have a salt field, got %v", request.Header.Get("Encryption"))
		}
	}))
	defer ts.Close()

	serverURL, _ := url.Parse(ts.URL)

	// Make a fake transport that redirects all requests to the fake server
	transport := &FakeTransport{serverURL}
	client := &http.Client{Transport: transport}

	subscriptionJSON := []byte(`{
		"endpoint": "https://example.com/",
		"keys": {
			"p256dh": "BCXJI0VW7evda9ldlo18MuHhgQVxWbd0dGmUfpQedaD7KDjB8sGWX5iiP7lkjxi-A02b8Fi3BMWWLoo3b4Tdl-c=",
			"auth": "WPF9D0bTVZCV2pXSgj6Zug=="
		}
	}`)
	message := "I am the walrus"

	sub, err := SubscriptionFromJSON(subscriptionJSON)
	if err != nil {
		t.Error("Couldn't decode JSON subscription")
	}

	_, err = Send(client, sub, message, "")
	if err != nil {
		t.Error(err)
	}
}
