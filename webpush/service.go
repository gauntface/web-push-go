package webpush

import (
	"crypto/rand"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"sync"
	"net"
	"golang.org/x/net/http2"
	"log"
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

func InitServer(port string) {
	http.HandleFunc("/subscribe", SubscribeHandler)
	http.HandleFunc("/p", Poll)
	http.HandleFunc("/s", SendHandler)

	lis, err := net.Listen("tcp", port)
	if err != nil {
		return
	}
	for {
		conn, err := lis.Accept()
		if err != nil {
			return err
		}
		go handleCon(conn)
	}
}

// Special handler for receipts and poll, which use push promises
func handleCon(con net.Conn) {
	defer con.Close()
	// writer: bufio.NewWriterSize(conn, http2IOBufSize),
	f := http2.NewFramer(con, con)
	settings := []http2.Setting{}

	if err := f.WriteSettings(settings...); err != nil {
		return
	}

	frame, err := f.ReadFrame()
	if err != nil {
		log.Println(" failed to read frame", err)
		return
	}
	sf, ok := frame.(*http2.SettingsFrame)
	if !ok {
		log.Println("wrong frame %T from client", frame)
		return
	}
	log.Println(sf)
	//hDec := hpack.NewDecoder()

	for {
		select {

		}

	}

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
	res.Header().Add("Link", "</p/" +
		id +
		">;rel=\"urn:ietf:params:push\"")

	// May provide support for set: should be enabled if a
	// set interface is present, want to test without set as well
	//res.Header().Add("Link", "</p/" +
	//	"JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV" +
	//	">;rel=\"urn:ietf:params:push:set\"")

	res.Header().Add("Location", ReceiveBaseUrl + "/r/" + id)

	return
}

func heartbeat(m *Message) {
	channels.RLock()
	defer channels.RUnlock()

	for _, c := range channels.m {
		c.Send(m)
	}
}

// Poll provides a backward compatible mechanism for fetching messages using
// streaming json. The format is similar with BrowserChannel, for easier parsing.
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

	// TODO: write to a 'connections' DB, for distributed servers
	go newChannel.Run()

	return
}

// Webpush send will look for a connection and send the message.
func SendHandler(res http.ResponseWriter, req *http.Request) {
	// TODO: if not found, attempt to lookup in a 'connections' DB to find a better
	// server.

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
