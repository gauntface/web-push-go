package webpush

import (
	"encoding/hex"
	"net/http"
	"net/http/httputil"
	"testing"
)

var (
	// From peter.sh sample
	vapidPub  = []byte("048623C185F06C5D551AD919AAE9022F4355D25C59866990ADF72DD422D863B6CDEF33B1BB662F47E5E620FF0E107FCDA34F8C65F4647E2CF36BF87C4B0CBDBFFE")
	vapidPriv = []byte("3C8F4B1E164169C80F3F1C60E5EA3CDD72CCE6056B0240EEDF7B1D5CA8529181")
)

func TestChrome(t *testing.T) {
	// Send to a real chrome subscription.
	ep := []byte(`{"endpoint":"https://jmt17.google.com/gcm/demo-webpush-00/eRUec0FiUOA:APA91bFyWIKZz5QAusYHrIXwINgssqQ-pz9dG4pzOYUoOEvqmbjVicNj8beZUfZUT3rWrbYC3-khWp4hyOGJbj9_4hfAN5dSj5PHrQ7i5fUGiqgt04upfsQP_ACAZLJGs5qnIudrBcyo","keys":{"p256dh":"BJIzHZoGcIay4RAnAvz5mo0s-zu6na9fJKKCmt1ekBOXHxfOVF05bv2AeKaz6b8XMd4n5QpnWJAnHPjaTJKlJcU","auth":"68zcbmaevQa7MS7aXXRX8Q"}}`)

	sub, err := SubscriptionFromJSON(ep)
	if err != nil {
		t.Error(err)
	}

	message := "I am the walrus"

	vpub := make([]byte, len(vapidPub)/2)
	vpriv := make([]byte, len(vapidPriv)/2)
	hex.Decode(vpub, vapidPub)
	hex.Decode(vpriv, vapidPriv)

	vapid := NewVapid(vpub, vpriv)
	vapid.Sub = "test@example.com"
	req, err := NewVapidRequest(sub, message, vapid)
	dmpReq, err := httputil.DumpRequest(req, true)
	t.Log(string(dmpReq))
	res, err := http.DefaultClient.Do(req)

	if err != nil {
		t.Error(err)
	}
	dmp, err := httputil.DumpResponse(res, true)
	t.Log(string(dmp))

}
