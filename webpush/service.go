package webpush

import (
	"crypto/rand"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"sync"
)

var channels = struct {
	sync.RWMutex
	// Key is the subscription, as a base64 string
	m map[string]*Channel
}{m: make(map[string]*Channel)}

var SendBaseUrl = "https://localhost:8443"
var ReceiveBaseUrl = "https://localhost:9443"

// Channel represents an active connection to a UA
type Channel struct {
}

func (*Channel) Send(*Message) {

}

func (*Channel) Close() {

}

func (*Channel) Run() {

}

var targets = struct {
	sync.RWMutex
	// Key is the subscription, as a base64 string
	m map[string]*Target
}{m: make(map[string]*Target)}

// Target represents a delivery target, identified by a subscription
// or subscription set.
type Target struct {
	// Queued messages
	Messages []Message
}

type Message struct {
	Body []byte
	TTL  int
	Key  string
	Salt string
	ID   string
}

// Subscribe creates a subscription. Initial version is just a
// random - some interface will be added later, to allow sets.
func SubscribeHandler(res http.ResponseWriter, req *http.Request) {
	// For simple testing we ignore sender auth, as well as subscription sets
	token := make([]byte, 16)
	rand.Read(token)

	id := base64.RawURLEncoding.EncodeToString(token)

	res.WriteHeader(201)

	// TODO: try to use a different server, to verify UA is
	// parsing both

	// Used for send - on same server as subscribe
	res.Header().Add("Link", "</p/"+
		id+
		">;rel=\"urn:ietf:params:push\"")

	// May provide support for set: should be enabled if a
	// set interface is present, want to test without set as well
	//res.Header().Add("Link", "</p/" +
	//	"JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV" +
	//	">;rel=\"urn:ietf:params:push:set\"")

	res.Header().Add("Location", ReceiveBaseUrl+"/r/"+id)

	return
}

// Poll provides a backward compatible mechanism for
func Poll(res http.ResponseWriter, req *http.Request) {
	newChannel := &Channel{}
	token := req.RequestURI[3:] // skip /r/
	channels.Lock()
	// May replace an old channel, which needs to be closed
	oldChannel, oldFound := channels.m[token]
	channels.m[token] = newChannel
	channels.Unlock()

	if oldFound {
		oldChannel.Close()
	}

	go newChannel.Run()

	return
}

func SendHandler(res http.ResponseWriter, req *http.Request) {
	token := req.RequestURI[3:] // skip /s/

	defer req.Body.Close()

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return
	}

	channels.Lock()
	ch, ok := channels.m[token]
	channels.Unlock()

	m := &Message{Body: body}

	if !ok {
		targets.Lock()
		t, ok := targets.m[token]
		targets.Unlock()

		if ok {
			t.Messages = append(t.Messages, *m)
		} else {

		}

		return
	}

	res.WriteHeader(200)

	ch.Send(m)

	return
}
