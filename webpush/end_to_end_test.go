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
	"fmt"
)

var (
	GCM_SENDER_ID = "759071690750"
	GCM_API_KEY = "AIzaSyBAU0VfXoskxUSg81K5VgLgwblHbZWe6tA"

	GCM_OPTS = map[string]string{
		"gcm": GCM_API_KEY,
	}

	VAPID_OPTS = map[string]string{
		"subject": "http://test.com",
    "publicKey": "BA6jvk34k6YjElHQ6S0oZwmrsqHdCNajxcod6KJnI77Dagikfb--O_kYXcR2eflRz6l3PcI2r8fPCH3BElLQHDk",
    "privateKey": "-3CdhFOqjzixgAbUSa0Zv9zi-dwDVmWO7672aBxSFPQ",
	}
)

func performTest(browserName string, browserRelease string, options map[string]string) {
	fmt.Println("Testing: ", browserName, "Release: ", browserRelease)

}

// Web Push
func TestWebPushFFStable(t *testing.T) {
	performTest("firefox", "stable", nil);
}

func TestWebPushFFBeta(t *testing.T) {
	performTest("firefox", "beta", nil);
}

// Web Push + GCM
func TestWebPushAndGCMChromeStable(t *testing.T) {
	performTest("chrome", "stable", GCM_OPTS);
}

func TestWebPushAndGCMChromeBeta(t *testing.T) {
	performTest("chrome", "beta", GCM_OPTS);
}

func TestWebPushAndGCMFFStable(t *testing.T) {
	performTest("firefox", "stable", GCM_OPTS);
}

func TestWebPushAndGCMFFBeta(t *testing.T) {
	performTest("firefox", "beta", GCM_OPTS);
}

// Web Push + VAPID
func TestWebPushAndVAPIDChromeStable(t *testing.T) {
	performTest("chrome", "stable", VAPID_OPTS);
}

func TestWebPushAndVAPIDChromeBeta(t *testing.T) {
	performTest("chrome", "beta", VAPID_OPTS);
}

func TestWebPushAndVAPIDFFStable(t *testing.T) {
	performTest("firefox", "stable", VAPID_OPTS);
}

func TestWebPushAndVAPIDFFBeta(t *testing.T) {
	performTest("firefox", "beta", VAPID_OPTS);
}
