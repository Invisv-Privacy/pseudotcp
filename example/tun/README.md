# Tun Example

This is a very simple binary to demonstrate some of the functionality of PseudoTCP without needing to run it on Android/an Android emulator.

Instead, we'll create a TUN device that our binary can read from and write to and then we'll configure PseudoTCP to point to a running MASQUE proxy and connect the pieces.

## Run a MASQUE server

We include a [docker-compose](../../docker-compose.yml) file for running a MASQUE-enabled h2o server for convenience:
```sh
pseudotcp $ docker-compose up -d
pseudotcp $ docker-compose logs
Attaching to masque-h2o-1
masque-h2o-1 | [INFO] raised RLIMIT_NOFILE to 1048576
masque-h2o-1 | h2o server (pid:1) is ready to serve requests with 2 threads
masque-h2o-1 | fetch-ocsp-response (using OpenSSL 3.1.4 24 Oct 2023 (Library: OpenSSL 3.1.4 24 Oct 2023))
masque-h2o-1 | fetch-ocsp-response (using OpenSSL 3.1.4 24 Oct 2023 (Library: OpenSSL 3.1.4 24 Oct 2023))
masque-h2o-1 | failed to extract ocsp URI from /tmp/mejKcoIw2o/cert.crt
masque-h2o-1 | failed to extract ocsp URI from /tmp/3o0KIztDWj/cert.crt
masque-h2o-1 | [OCSP Stapling] disabled for certificate file:/etc/h2o/server.crt
masque-h2o-1 | [OCSP Stapling] disabled for certificate file:/etc/h2o/server.crt
```

Alternatively you can run a h2o server wherever and however you'd like.

In the case of running the h2o server as a docker container we can now get the address it's bound to:

```sh
pseudotcp $ docker-compose exec h2o ip addr show eth0
200: eth0@if201: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:18:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.24.0.2/16 brd 172.24.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

So in my case h2o is running on 172.24.0.2.

We can test this in 2 ways. First curl the `/status` endpoint:
```sh
pseudotcp $ curl -I http://172.24.0.2:8081/status
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 6049
Server: h2o/2.3.0-DEV@123f5e2b6
cache-control: no-cache
content-type: text/html; charset=utf-8
last-modified: Tue, 20 Feb 2024 01:02:58 GMT
etag: "65d3fa42-17a1"
accept-ranges: bytes
```

Because the h2o server is also a regular HTTP CONNECT proxy, we can use curl's proxy flag to check that it's proxying correctly:
```sh
pseudotcp $ curl  --proxy-insecure --proxy https://172.24.0.2:8444 -I  https://ipinfo.io
HTTP/1.1 200 OK
Connection: close
Server: h2o/2.3.0-DEV@123f5e2b6

HTTP/2 200 
access-control-allow-origin: *
content-length: 319
content-type: application/json; charset=utf-8
date: Mon, 16 Dec 2024 22:47:35 GMT
referrer-policy: strict-origin-when-cross-origin
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block
via: 1.1 google
strict-transport-security: max-age=2592000; includeSubDomains
alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
```
(We have to use `proxy-insecure` here because our MASQUE proxy's cert is not configured for this `172.24.0.2` address)


## Run the example TUN binding code

First compile the binary and give it appropriate permissions:
```sh
pseudotcp $ go build ./example/tun && sudo setcap cap_net_admin=eip ./tun
```

Then run the binary, pointing it to the MASQUE proxy server:

```sh
./tun -proxyAddr 172.24.0.2 -proxyPort 8444
time=2024-12-16T14:56:16.694-08:00 level=INFO msg="TUN setup" iface="&{isTAP:false ReadWriteCloser:0xc00006e088 name:tun0}"
time=2024-12-16T14:56:16.694-08:00 level=DEBUG msg=Initializing proxyFQDN=172.24.0.2
time=2024-12-16T14:56:16.694-08:00 level=INFO msg="Starting Relay"
time=2024-12-16T14:56:16.695-08:00 level=DEBUG msg="resolved proxy" proxyAddr=172.24.0.2:8444
time=2024-12-16T14:56:16.695-08:00 level=DEBUG msg=Protecting fd=8
```

In another terminal you can now curl through that interface to see that we are successfully relaying packets through the TUN interface -> PseudoTCP -> MASQUE proxy:
```sh
$ curl --interface tun0 -v -4 -I http://neverssl.com
*   Trying 34.223.124.45:80...
* Connected to neverssl.com (34.223.124.45) port 80 (#0)
> HEAD / HTTP/1.1
> Host: neverssl.com
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Date: Mon, 16 Dec 2024 22:57:48 GMT
Date: Mon, 16 Dec 2024 22:57:48 GMT
< Server: Apache/2.4.62 ()
Server: Apache/2.4.62 ()
< Upgrade: h2,h2c
Upgrade: h2,h2c
< Connection: Upgrade
Connection: Upgrade
< Last-Modified: Wed, 29 Jun 2022 00:23:33 GMT
Last-Modified: Wed, 29 Jun 2022 00:23:33 GMT
< ETag: "f79-5e28b29d38e93"
ETag: "f79-5e28b29d38e93"
< Accept-Ranges: bytes
Accept-Ranges: bytes
< Content-Length: 3961
Content-Length: 3961
< Vary: Accept-Encoding
Vary: Accept-Encoding
< Content-Type: text/html; charset=UTF-8
Content-Type: text/html; charset=UTF-8

< 
* Connection #0 to host neverssl.com left intact 
```

🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉
