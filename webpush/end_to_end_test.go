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
	"bytes"
	"fmt"
	"encoding/base64"
	// "io/ioutil"
)

var (
	PortNumber = 9012
	TestUrl = "http://localhost:9012"
	Payload = "Hello."

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

type SubscriptionResponse struct {
	Data struct {
		TestId int
		Subscription struct {
			Endpoint string
			Keys struct {
				Auth string
				P256dh string
			}
		}
	}
}

type TestSuite struct {
	Data struct {
		TestSuiteId int
	}
}

type NotificationResponse struct {
	Data struct {
		Messages []string
	}
}



func startTestSuite(t *testing.T) (int) {
	resp, err := http.Post(TestUrl + "/api/start-test-suite/", "application/json", nil)
	if err != nil {
		t.Errorf("Error when calling /api/start-test-suite/: %v", err)
	}

	if resp.Body == nil {
		t.Errorf("No body from /api/start-test-suite/: %v", err)
	}

	testSuite := &TestSuite{}
	decodeErr := json.NewDecoder(resp.Body).Decode(testSuite);
	if err != nil {
		t.Errorf("Unable to parse response from /api/start-test-suite/: %v", decodeErr)
	}

	return testSuite.Data.TestSuiteId;
}

func endTestSuite(testSuiteId int) {
	endSuiteOptions := map[string]interface{} {
		"testSuiteId": testSuiteId,
	}

	jsonString, endSuiteOptionsErr := json.Marshal(endSuiteOptions)
	if endSuiteOptionsErr != nil {
		return
	}

	http.Post(TestUrl + "/api/end-test-suite/", "application/json", bytes.NewBuffer(jsonString))
}

func getTestSubscription(t *testing.T, testSuiteId int, browserName string, browserRelease string, options map[string]string) (*SubscriptionResponse) {
	subscriptionOptions := map[string]interface{} {
		"testSuiteId": testSuiteId,
    "browserName": browserName,
    "browserVersion": browserRelease,
	}

	_, gcmPresent := options["gcm"]
	if (gcmPresent) {
		subscriptionOptions["gcmSenderId"] = GcmSenderID;
	}

	jsonString, subscriptOptionsErr := json.Marshal(subscriptionOptions)
	if subscriptOptionsErr != nil {
		t.Errorf("Unable to encode subscription options: %v", subscriptOptionsErr)
	}

	resp, getSubErr := http.Post(TestUrl + "/api/get-subscription/", "application/json", bytes.NewBuffer(jsonString))
	if getSubErr != nil {
		t.Errorf("Error when calling /api/get-subscription/: %v", getSubErr)
	}

	subscription := &SubscriptionResponse{}
	decodeErr := json.NewDecoder(resp.Body).Decode(subscription);
	if decodeErr != nil {
		t.Errorf("Unable to parse response from /api/get-subscription/: %v", decodeErr)
	}

	return  subscription;
}

func getNotificationStatus(t *testing.T, testSuiteId int, testId int) ([]string) {
	notificationData := map[string]interface{} {
		"testSuiteId": testSuiteId,
    "testId": testId,
	}

	jsonString, notifErr := json.Marshal(notificationData)
	if notifErr != nil {
		t.Errorf("Unable to encode subscription options: %v", notificationData)
	}

	resp, notifErr := http.Post(TestUrl + "/api/get-notification-status/", "application/json", bytes.NewBuffer(jsonString))
	if notifErr != nil {
		t.Errorf("Error when calling /api/get-notification-status/: %v", notifErr)
	}

	/** defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
  bodyString := string(bodyBytes)
	fmt.Println(bodyString);**/

	notification := &NotificationResponse{}
	decodeErr := json.NewDecoder(resp.Body).Decode(notification);
	if decodeErr != nil {
		t.Errorf("Unable to parse response from /api/get-notification-status/: %v", decodeErr)
	}

	return notification.Data.Messages
}

func performTest(t *testing.T, testSuiteId int, browserName string, browserRelease string, options map[string]string) {
	fmt.Println("");
	fmt.Println("    Testing: ", browserName)
	fmt.Println("    Release: ", browserRelease)
	fmt.Println("");

	subscriptionDetails := getTestSubscription(t, testSuiteId, browserName, browserRelease, options)

	fmt.Println("    [web-push-testing-service] TestID: ", subscriptionDetails.Data.TestId)
	fmt.Println("    [web-push-testing-service] Endpoint: ", subscriptionDetails.Data.Subscription.Endpoint)
	fmt.Println("    [web-push-testing-service] Auth: ", subscriptionDetails.Data.Subscription.Keys.Auth)
	fmt.Println("    [web-push-testing-service] P256DH: ", subscriptionDetails.Data.Subscription.Keys.P256dh)
	fmt.Println("");

	decodeP256dh, err := base64.RawURLEncoding.DecodeString(subscriptionDetails.Data.Subscription.Keys.P256dh)
	if err != nil {
		t.Error(err)
	}

	decodeAuth, err := base64.RawURLEncoding.DecodeString(subscriptionDetails.Data.Subscription.Keys.Auth)
	if err != nil {
		t.Error(err)
	}

	libSub := &Subscription{subscriptionDetails.Data.Subscription.Endpoint, decodeP256dh, decodeAuth}
	_, err = Send(nil, libSub, Payload, "")
	if err != nil {
		t.Error(err)
	}

	notificationMsgs := getNotificationStatus(t, testSuiteId, subscriptionDetails.Data.TestId);
	if len(notificationMsgs) != 1 {
		t.Error("Expected messages to have a length of 1.")
	}
  
	if notificationMsgs[0] != Payload {
		t.Error("Invalid message payload.")
	}
	fmt.Println("");
}

// Web Push
func TestWebPushFFStable(t *testing.T) {
	testSuiteId := startTestSuite(t)

	fmt.Println("    [web-push-testing-service] Test Suite ID: ", testSuiteId)
	fmt.Println("");

	performTest(t, testSuiteId, "firefox", "stable", nil);

	endTestSuite(testSuiteId)
}

func TestWebPushFFBeta(t *testing.T) {
	testSuiteId := startTestSuite(t)

	fmt.Println("    [web-push-testing-service] Test Suite ID: ", testSuiteId)
	fmt.Println("");

	performTest(t, testSuiteId, "firefox", "beta", nil);

	endTestSuite(testSuiteId)
}

// Web Push + GCM
func TestWebPushAndGCMChromeStable(t *testing.T) {
	testSuiteId := startTestSuite(t)

	fmt.Println("    [web-push-testing-service] Test Suite ID: ", testSuiteId)
	fmt.Println("");

	performTest(t, testSuiteId, "chrome", "stable", GcmOptions);

	endTestSuite(testSuiteId)
}

func TestWebPushAndGCMChromeBeta(t *testing.T) {
	// performTest(t, "chrome", "beta", GcmOptions);
}

func TestWebPushAndGCMFFStable(t *testing.T) {
	// performTest(t, "firefox", "stable", GcmOptions);
}

func TestWebPushAndGCMFFBeta(t *testing.T) {
	// performTest(t, "firefox", "beta", GcmOptions);
}

// Web Push + VAPID
func TestWebPushAndVAPIDChromeStable(t *testing.T) {
	// performTest(t, "chrome", "stable", VapidOptions);
}

func TestWebPushAndVAPIDChromeBeta(t *testing.T) {
	// performTest(t, "chrome", "beta", VapidOptions);
}

func TestWebPushAndVAPIDFFStable(t *testing.T) {
	// performTest(t, "firefox", "stable", VapidOptions);
}

func TestWebPushAndVAPIDFFBeta(t *testing.T) {
	// performTest(t, "firefox", "beta", VapidOptions);
}
