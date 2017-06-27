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
	performTest("chrome", "stable", GcmOptions);
}

func TestWebPushAndGCMChromeBeta(t *testing.T) {
	performTest("chrome", "beta", GcmOptions);
}

func TestWebPushAndGCMFFStable(t *testing.T) {
	performTest("firefox", "stable", GcmOptions);
}

func TestWebPushAndGCMFFBeta(t *testing.T) {
	performTest("firefox", "beta", GcmOptions);
}

// Web Push + VAPID
func TestWebPushAndVAPIDChromeStable(t *testing.T) {
	performTest("chrome", "stable", VapidOptions);
}

func TestWebPushAndVAPIDChromeBeta(t *testing.T) {
	performTest("chrome", "beta", VapidOptions);
}

func TestWebPushAndVAPIDFFStable(t *testing.T) {
	performTest("firefox", "stable", VapidOptions);
}

func TestWebPushAndVAPIDFFBeta(t *testing.T) {
	performTest("firefox", "beta", VapidOptions);
}
