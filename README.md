Push Encryption (Go)
----------------------

This library provides the functions necessary to encrypt a payload for sending
with the Web Push protocol. It also includes a helper function for creating new
HTTP requests to send the message to the Web Push endpoint.

What is this for?
-----------------

The [Push API](http://w3c.github.io/push-api/) allow users to subscribe for
notifications from a web site, which can be delivered to them even if the
browser has been closed. This was first shipped as part of Chrome 42, but the
push message could not contain any payload data.

As of Chrome 50 and Firefox 44 (desktop-only) payloads are supported, but the
server must encrypt the payload or the receiving browser will reject it.

This library implements the necessary encryption as a Go package.

Overview
--------

Send a message:

```
import (
  "strings"
  "github.com/googlechrome/push-encryption-go/webpush"
)

func main() {
  // The values that make up the Subscription struct come from the browser
  sub := &webpush.Subscription{endpoint, key, auth}
  webpush.Send(nil, sub, "Yay! Web Push!", "")
}
```

You can turn a JSON string representation of a PushSubscription object you
collected from the browser into a Subscription struct with a helper function.

```
var exampleJSON = `{"endpoint": "...", "keys": {"p256dh": "...", "auth": "..."}}`

sub, err := SubscriptionFromJSON(exampleJSON)
```

If the push service requires an authentication header (notably Google Cloud
Messaging, used by Chrome) then you can add that as a fourth parameter:

```
if strings.Contains(sub.Endpoint, "https://android.googleapis.com/gcm/send/") {
  webpush.Send(nil, sub, "A message for Chrome", myGCMKey)
}
```

Docs
-----

You can [find docs here](https://godoc.org/github.com/GoogleChrome/push-encryption-go/webpush).

Support
-------

If you've found an error in this library, please file an issue:
https://github.com/GoogleChrome/push-encryption-go/issues

Patches are encouraged, and may be submitted by forking this project and
submitting a pull request through GitHub.

License
-------

Copyright 2016 Google, Inc.

Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements.  See the NOTICE file distributed with this work for
additional information regarding copyright ownership.  The ASF licenses this
file to you under the Apache License, Version 2.0 (the "License"); you may not
use this file except in compliance with the License.  You may obtain a copy of
the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
License for the specific language governing permissions and limitations under
the License.
