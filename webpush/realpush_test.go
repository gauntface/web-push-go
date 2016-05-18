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
	//ep := []byte(`{"endpoint":"https://jmt17.google.com/gcm/demo-webpush-00/eRUec0FiUOA:APA91bFyWIKZz5QAusYHrIXwINgssqQ-pz9dG4pzOYUoOEvqmbjVicNj8beZUfZUT3rWrbYC3-khWp4hyOGJbj9_4hfAN5dSj5PHrQ7i5fUGiqgt04upfsQP_ACAZLJGs5qnIudrBcyo","keys":{"p256dh":"BJIzHZoGcIay4RAnAvz5mo0s-zu6na9fJKKCmt1ekBOXHxfOVF05bv2AeKaz6b8XMd4n5QpnWJAnHPjaTJKlJcU","auth":"68zcbmaevQa7MS7aXXRX8Q"}}`)
	//ep := []byte(`{"endpoint":"https://android.googleapis.com/gcm/send/eRUec0FiUOA:APA91bFyWIKZz5QAusYHrIXwINgssqQ-pz9dG4pzOYUoOEvqmbjVicNj8beZUfZUT3rWrbYC3-khWp4hyOGJbj9_4hfAN5dSj5PHrQ7i5fUGiqgt04upfsQP_ACAZLJGs5qnIudrBcyo","keys":{"p256dh":"BJIzHZoGcIay4RAnAvz5mo0s-zu6na9fJKKCmt1ekBOXHxfOVF05bv2AeKaz6b8XMd4n5QpnWJAnHPjaTJKlJcU","auth":"68zcbmaevQa7MS7aXXRX8Q"}}`)
	send(t, `{"endpoint":"https://android.googleapis.com/gcm/eRUec0FiUOA:APA91bFyWIKZz5QAusYHrIXwINgssqQ-pz9dG4pzOYUoOEvqmbjVicNj8beZUfZUT3rWrbYC3-khWp4hyOGJbj9_4hfAN5dSj5PHrQ7i5fUGiqgt04upfsQP_ACAZLJGs5qnIudrBcyo","keys":{"p256dh":"BJIzHZoGcIay4RAnAvz5mo0s-zu6na9fJKKCmt1ekBOXHxfOVF05bv2AeKaz6b8XMd4n5QpnWJAnHPjaTJKlJcU","auth":"68zcbmaevQa7MS7aXXRX8Q"}}`)
	
}

func TestFirefox(t *testing.T) {
	send(t, `{"endpoint":"https://updates.push.services.mozilla.com/push/v1/gAAAAABXPLrsYo31tV6tu1Uel7DX1chKCXMoAfMPL8QTEUohyiboXrqvQB28HG_2pVGLMA81xo4NL-x3Sk8pJ_x0vaeW1b7iy7GGiksF8kirhhdwEwM9a24E5kfZGIv8n8fzXLXJWUkE","keys":{"auth":"v5PkWe77dsf8WM45-RZB-g","p256dh":"BJdj267lZztFo5bRUcIybOKCkoWRLLas9Mriv4ibYi3S5cWYsHHPd6fzYXtSji0iq3c20LsfCOpPguBPXkocxMY"}}`)
	send(t, `{"endpoint":"https://updates.push.services.mozilla.com/push/v1/gAAAAABXMRmjsxpU7aqwHIKnC41PvQDkn5dqAL2S0Geq-2DtG7H6W6Geql1YMpihJ6GeHtg-SNfUCX4lLfxAyMLu7JVZRFH_4bXL_MhgXIqWWIQcGGx5YnGdvvtOaf82EmyOpoWvlf0E","keys":{"auth":"S0DdWigLjQ-5j4Ug9McYgQ","p256dh":"BIRCXK5p71SKDo7Gy8gaXLnLsvJRjSyoxim9MVEQgL2Mb5YCXUdbjJXcU_sdhmwSm6T5NWTfJ1hwmn8cph8Jw98"}}`)
}

func send(t *testing.T, epjson string) {
	ep := []byte(epjson)
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
	req.Header.Add("ttl", "0")
	dmpReq, err := httputil.DumpRequest(req, true)
	t.Log(string(dmpReq))
	res, err := http.DefaultClient.Do(req)

	if err != nil {
		t.Error(err)
	}
	dmp, err := httputil.DumpResponse(res, true)
	t.Log(string(dmp))
	if res.StatusCode != 201 {
		t.Fatal("Invalid response code ", res.StatusCode)
	}

}
