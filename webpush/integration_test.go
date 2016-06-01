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
  "github.com/tebeka/selenium"
	"net/http"
	"log"
	"time"
)

func startServer() {
	panic(http.ListenAndServe(":8080", http.FileServer(http.Dir("../test/data"))))
}

func TestSubscribeAndTicker(t *testing.T) {
	// Start Server
	go startServer()

	// Start Browser
	caps := selenium.Capabilities{"browserName": "firefox"}
  wd, err := selenium.NewRemote(caps, "")
  if err != nil {
    t.Fatal(err)
  }

	defer wd.Quit()

  // Get test page
	wd.Get("http://localhost:8080/index.html")

	// Set up notification permissions
	ffProfile := selenium.FirefoxProfile("");
	log.Println(ffProfile);

  // Subscribe and get subscription
	var pushSubscription string
	for(pushSubscription == "") {
		script := "return window.succesfulSubscription;"
		args := []interface{}{}
		reply, err := wd.ExecuteScript(script, args)
		if err != nil {
			t.Fatal(err)
		}

		if (reply == nil) {
			time.Sleep(100 * time.Millisecond)
			continue;
		}

		if reply.(bool) {
			// We have a subscription
			subscription, err := wd.ExecuteScript("return window.testSubscription", args)
			if err != nil {
				t.Fatal(err)
			}
			log.Println(subscription);
			pushSubscription = "done"
		} else {
			// We have an error with subscription
			browserError, err := wd.ExecuteScript("return window.subscriptionError", args)
			if err != nil {
				t.Fatal(err)
			}

			t.Fatal(browserError)
		}
	}
  // Send Push

  // Wait for notification to show

  // Success
}
