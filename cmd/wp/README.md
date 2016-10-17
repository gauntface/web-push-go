Command line to help testing webpush.

It uses environment variables instead of flags for VAPID_PUB, VAPID_PRIV
and TO (the webpush subscription) to avoid having them show up in "ps" 
and /proc - it is not a concern on docker or dedicated servers, but it
seems safer.

# Setup and config

```
$ go get github.com/costinm/push-encryption-go/cmd/wp

$ wp
...

$ wp gen > ~/.webpush_vapid_private.env
$ chmod 700 ~/.webpush_vapid_private.env
$ cat ~/.webpush_vapid_private.env
# Environment variables for webpush
export VAPID_PUB=BGvfZeUDO-_QesouDAamZJlUQYU3RXdVbkFNHi2KfjTayT22QXR37lvf1PpU42H6rKgO2GjXlVBTlljTtYA22Zw
export VAPID_PRIV=xmNTjTmEbH50xbRobzo_v8mXYXTY039WlXPl-mSaSdw

# Public key hex: 046bdf65e5033befd07aca2e0c06a66499544185374577556e414d1e2d8a7e34dac93db6417477ee5bdfd4fa54e361faaca80ed868d79550539658d3b58036d99c

$ . ~/.webpush_vapid_private.env

```

# Generate js snippet

```
$ . ~/.webpush_vapid_private.env

$ wp js
const APPLICATION_SERVER_KEY = new Uint8Array([4,
    107, 223, 101, 229, 3, 59, 239, 208, 122, 202, 46, 12, 6, 166, 100, 153, 
    84, 65, 133, 55, 69, 119, 85, 110, 65, 77, 30, 45, 138, 126, 52, 218, 
    201, 61, 182, 65, 116, 119, 238, 91, 223, 212, 250, 84, 227, 97, 250, 172, 
    168, 14, 216, 104, 215, 149, 80, 83, 150, 88, 211, 181, 128, 54, 217, 156]);


```

The generated js needs to be added to the subscribe() request:

```
const APPLICATION_SERVER_KEY = new Uint8Array([4,
    107, 223, 101, 229, 3, 59, 239, 208, 122, 202, 46, 12, 6, 166, 100, 153, 
    84, 65, 133, 55, 69, 119, 85, 110, 65, 77, 30, 45, 138, 126, 52, 218, 
    201, 61, 182, 65, 116, 119, 238, 91, 223, 212, 250, 84, 227, 97, 250, 172, 
    168, 14, 216, 104, 215, 149, 80, 83, 150, 88, 211, 181, 128, 54, 217, 156]);

serviceWorkerRegistration.pushManager.subscribe({
    applicationServerKey: APPLICATION_SERVER_KEY,
    // other options - userVisibleOnly,...
});

```

# Send a messages

```
$ . ~/.webpush_vapid_private.env
$ TO='{"endpoint":"https://updates.push.services.mozilla.com/wpush/v2/gAAAAABX-wNAnli2Q5O07x9SJXFa5M9uc0eOro9VjFmULRLqIk322-pQJYi8X9T0XBDgyOOmSc2fD99M8IsnMbJsZSItSaDKYneYhDpKOJjkZYlkn4rak30QZNjDMKMpzqNmKARBLF6BBgFWxF3Rut5XJrX0UUxvBjaRBy35TGS1EK0KTWtJteg","keys":{"auth":"3ieapOtquui-OygM-RNydA","p256dh":"BO8dnsK8PlSHoYIVb5E2CATEbncYkIsuH16R_olSV0HBLk97evVb1qFVJHi7EF-kCt2KmPCE259i3JccrdLohLY"}}'

$ echo -n "hello world" | TO=$TO wp send -v
```

# Generate a curl command to send

```
$ . ~/.webpush_vapid_private.env
$ TO='{"endpoint":"https://updates.push.services.mozilla.com/wpush/v2/gAAAAABX-wNAnli2Q5O07x9SJXFa5M9uc0eOro9VjFmULRLqIk322-pQJYi8X9T0XBDgyOOmSc2fD99M8IsnMbJsZSItSaDKYneYhDpKOJjkZYlkn4rak30QZNjDMKMpzqNmKARBLF6BBgFWxF3Rut5XJrX0UUxvBjaRBy35TGS1EK0KTWtJteg","keys":{"auth":"3ieapOtquui-OygM-RNydA","p256dh":"BO8dnsK8PlSHoYIVb5E2CATEbncYkIsuH16R_olSV0HBLk97evVb1qFVJHi7EF-kCt2KmPCE259i3JccrdLohLY"}}'

$ echo -n "hello world" | TO=$TO wp curl

echo -n EoW0izPs8J6pR2qh+tU+Bw/E1VPVwquS559Bw+NMxiW/QBk7jc+164ezrUoHVxc= | base64 -d > /tmp/$$.bin; curl -HTtl:0 -XPOST --data-binary @/tmp/$$.bin -HContent-Encoding:aesgcm -H Encryption:salt=dVA7GsGdkQpwi6BtUL-otQ -H "Authorization:Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3VwZGF0ZXMucHVzaC5zZXJ2aWNlcy5tb3ppbGxhLmNvbSIsImV4cCI6MTQ3NjA3MjAwNX0.lD3MvELqfo5C3ZADKLqPF14svuJF5OFggybdB4OGILGk6xK0W3HduKSVG7WT4RksJ_z1n190k6VcTNn_rLkHbw" -H "Crypto-Key: dh=BK19OoYflQrGp83nDOKqJvRSUU24QQJ4Ap2CHVVatA9K9wd9pME-C0ClSHTIpoQ8MleKOK9lNinE_KYW8Z6erq8; p256ecdsa=BGvfZeUDO-_QesouDAamZJlUQYU3RXdVbkFNHi2KfjTayT22QXR37lvf1PpU42H6rKgO2GjXlVBTlljTtYA22Zw" https://updates.push.services.mozilla.com/wpush/v2/gAAAAABX-wNAnli2Q5O07x9SJXFa5M9uc0eOro9VjFmULRLqIk322-pQJYi8X9T0XBDgyOOmSc2fD99M8IsnMbJsZSItSaDKYneYhDpKOJjkZYlkn4rak30QZNjDMKMpzqNmKARBLF6BBgFWxF3Rut5XJrX0UUxvBjaRBy35TGS1EK0KTWtJteg
```

# Generate only the vapid headers

```
$ . ~/.webpush_vapid_private.env

$ wp vapid 
-H"Authorization:WebPush eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovLyIsImV4cCI6MTQ3NjA3MjA5MX0.Azx-L4GDiR4vByyctP-ChfRH1kYxBa0byU7FgrxK4eSxOv_xHebWTomMqtjhIHGVv-rmhymZ2DcEmAKWo9LcXA" -H"Crypto-Key:p256ecdsa=BGvfZeUDO-_QesouDAamZJlUQYU3RXdVbkFNHi2KfjTayT22QXR37lvf1PpU42H6rKgO2GjXlVBTlljTtYA22Zw"
```
