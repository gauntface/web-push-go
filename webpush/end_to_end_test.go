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
	"testing"
	"net/http"
	"encoding/json"
	"io/ioutil"
	"fmt"
)

var (
	PortNumber = 9012
	GcmSenderID = "759071690750"
	GcmAPIKey = "AIzaSyBAU0VfXoskxUSg81K5VgLgwblHbZWe6tA"

	GcmOptions = map[string]string{
		"gcm": GcmAPIKey,
	}

	VapidOptions = map[string]string{
		"subject": "http://test.com",
    "publicKey": "BA6jvk34k6YjElHQ6S0oZwmrsqHdCNajxcod6KJnI77Dagikfb--O_kYXcR2eflRz6l3PcI2r8fPCH3BElLQHDk",
    "privateKey": "-3CdhFOqjzixgAbUSa0Zv9zi-dwDVmWO7672aBxSFPQ",
	}
)

func performTest(t *testing.T, browserName string, browserRelease string, options map[string]string) {
	fmt.Println("Testing: ", browserName, "Release: ", browserRelease)

	testUrl := "http://localhost:9012"

	resp, err := http.Post(testUrl + "/api/start-test-suite/", "application/json", nil)
	if err != nil {
		t.Errorf("Error when calling /api/start-test-suite/: %v", err)
		return
	}

	if resp.Body == nil {
		t.Errorf("No body from /api/start-test-suite/: %v", err)
		return
	}

	decodeErr := json.NewDecoder(resp.Body)
	if err != nil {
		t.Errorf("Unable to parse response from /api/start-test-suite/: %v", decodeErr)
		return
	}

	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
  bodyString := string(bodyBytes)
	fmt.Println("resp: ", bodyString)
}

// Web Push
func TestWebPushFFStable(t *testing.T) {
	performTest(t, "firefox", "stable", nil);
}

func TestWebPushFFBeta(t *testing.T) {
	performTest(t, "firefox", "beta", nil);
}

// Web Push + GCM
func TestWebPushAndGCMChromeStable(t *testing.T) {
	performTest(t, "chrome", "stable", GcmOptions);
}

func TestWebPushAndGCMChromeBeta(t *testing.T) {
	performTest(t, "chrome", "beta", GcmOptions);
}

func TestWebPushAndGCMFFStable(t *testing.T) {
	performTest(t, "firefox", "stable", GcmOptions);
}

func TestWebPushAndGCMFFBeta(t *testing.T) {
	performTest(t, "firefox", "beta", GcmOptions);
}

// Web Push + VAPID
func TestWebPushAndVAPIDChromeStable(t *testing.T) {
	performTest(t, "chrome", "stable", VapidOptions);
}

func TestWebPushAndVAPIDChromeBeta(t *testing.T) {
	performTest(t, "chrome", "beta", VapidOptions);
}

func TestWebPushAndVAPIDFFStable(t *testing.T) {
	performTest(t, "firefox", "stable", VapidOptions);
}

func TestWebPushAndVAPIDFFBeta(t *testing.T) {
	performTest(t, "firefox", "beta", VapidOptions);
}
