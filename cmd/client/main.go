package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"github.com/swerveaux/acmev2"
)

const (
	acmeURL        = "https://acme-v02.api.letsencrypt.org/directory"
	acmeStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeLocalURL   = "https://localhost:14000/dir"
)

func main() {
	// key, err := rsa.GenerateKey(rand.Reader, 2048)
	var contactsArg string
	var domainsArg string
	pflag.StringVar(&contactsArg, "contacts", "somebody@example.org", "Command separated list of email contacts")
	pflag.StringVar(&domainsArg, "domains", "example.org", "Comma separated list of domains to request certs for.")
	pflag.Parse()

	contacts := strings.Split(contactsArg, ",")
	domains := strings.Split(domainsArg, ",")
	for i := range contacts {
		contacts[i] = fmt.Sprintf("mailto:%s", strings.TrimSpace(contacts[i]))
	}
	for i := range domains {
		domains[i] = strings.TrimSpace(domains[i])
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	acmeClientOpts := acmev2.ClientOpts{
		AccountKey:    key,
		CertKey:       certKey,
		ContactEmails: contacts,
		Logger:        acmev2.StdoutLogger{},
	}

	acmeURL := acmeStagingURL
	if acmeURL == acmeLocalURL {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	certStore, err := acmev2.NewASMCertStore("us-east-1")
	if err != nil {
		log.Fatal(err)
	}

	dnsModifier, err := acmev2.NewRoute53("us-east-1")
	if err != nil {
		log.Fatal(err)
	}

	client, err := acmev2.NewClient(acmeURL, certStore, dnsModifier, acmeClientOpts)
	if err != nil {
		log.Fatal(err)
	}

	for _, domain := range domains {
		if err := client.FetchOrRenewCert(domain); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to fetch or renew cert for %s\n", domain)
		}
	}
}
