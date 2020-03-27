package acmev2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

// ClientOpts are options for the ACME v2 client.
type ClientOpts struct {
	// HTTPClient lets you set an optional *http.Client if you, for instance, want to set your own timeouts or other options.
	HTTPClient *http.Client
	// AccountKey is the ECDSA key associated with your Let's Encrypt account. You must supply either this
	// to identify yourself for a previously created account or pass in ContactEmails to create a new
	// account.
	AccountKey *ecdsa.PrivateKey
	// CertKey will be deprecated. It's a key for an existing cert to be used for renewal. It will be
	// the CertRetriever's job to provide that.
	CertKey *rsa.PrivateKey // TODO: Remove this eventually
	// ContactEmails is a slice of email addresses used to identify points of contact for a Let's Encrypt
	// account.
	ContactEmails []string
}

// DNSModifier is an interface that allows for adding and removing TXT recordsets from DNS.
type DNSModifier interface {
	AddTextRecord(domain, token string) error
	RemoveTextRecord(domain, token string) error
}

// CertStorer is an interface that provides a way to store a TLS key and cert for a domain.
type CertStorer interface {
	Store(keyPEM, certPEM, domain string) error
}

// CertRetriever is an interface that provides a way to retrieve a TLS key and cert based on a domain.
// It should return "", "", nil if the cert isn't found vs. an actual error trying to retrieve it.
type CertRetriever interface {
	Retrieve(domain string) (string, string, error)
}

// CertStoreRetriever combines the CertStorer and CertRetriever interfaces.
type CertStoreRetriever interface {
	CertStorer
	CertRetriever
}

// Client acts as an ACME client for LetsEncrypt.   It keeps track
// of the current Nonce, the ecdsa key for signing messages, and
// the keyID.
type Client struct {
	Nonce         string
	KID           string
	Key           *ecdsa.PrivateKey
	Directory     Directory
	DNS           DNSModifier
	CertsManager  CertStoreRetriever
	OrderURL      string
	ContactEmails []string
	Finalize      string
	CertKey       *rsa.PrivateKey
}

// NewClient takes a directory URL (e.g, https://acme-staging-v02.api.letsencrypt.org/directory) and
// a slice of contact emails for the cert being requested (Let's Encrypt will generally send you an
// email when a cert is approaching expiration, though I've found that to be flaky).   There's
// the Directory from that URL and get a Nonce for the next request.
func NewClient(dirURL string, csr CertStoreRetriever, dm DNSModifier, opts ClientOpts) (Client, error) {
	c := Client{Key: opts.AccountKey, CertKey: opts.CertKey, ContactEmails: opts.ContactEmails}

	directory, err := queryDirectory(dirURL)
	if err != nil {
		return c, err
	}
	c.Directory = directory

	nonce, err := GetNonce(c.Directory.NewNonce)
	if err != nil {
		return c, err
	}
	fmt.Printf("Fetched nonce: %s\n", nonce)
	c.Nonce = nonce

	if err := c.newAccount(c.ContactEmails); err != nil {
		return c, err
	}

	c.DNS = dm

	c.CertsManager = csr

	return c, nil
}

// FetchOrRenewCert takes a domain name and tries to renew an existing cert or, if it can't find that, get
// a new cert.   It uses the CertStoreRetriever passed in to the client to try to fetch an existing cert and, if
// it finds that, will re-use the existing RSA key for the cert when asking for a renewal.   Otherwise, it will
// generate a new key and ask for a new cert.
func (c *Client) FetchOrRenewCert(domain string) error {
	if domain == "" {
		return errors.New("no domain passed in")
	}
	certApply, err := c.CertApply([]string{domain})
	if err != nil {
		return err
	}

	challengeResponse, err := c.FetchChallenges(certApply.Authorizations[0])
	fmt.Println(challengeResponse)
	var challenge Challenge
	for _, c := range challengeResponse.Challenges {
		if c.Type == "dns-01" {
			challenge = c
			break
		}
	}
	authHash, err := c.AcmeAuthHash(challenge.Token)
	if err != nil {
		log.Fatal(err)
		return err
	}
	fmt.Println(authHash)

	err = c.DNS.AddTextRecord(domain, authHash)
	if err != nil {
		log.Fatal(err)
		return err
	}

	defer func() {
		err = c.DNS.RemoveTextRecord(domain, authHash)
		if err != nil {
			log.Fatal(err)
		}
	}()

	<-time.After(1 * time.Minute)

	err = c.ChallengeReady(challenge.URL)
	if err != nil {
		log.Printf("Failed posting challenge: %v\n", err)
		return err
	}

	err = c.PollForStatus(domain)
	if err != nil {
		log.Printf("Bad response when polling: %v\n", err)
		return err
	}

	return nil
}

func (c *Client) makeRequest(claimset interface{}, url string, postAsGet bool) ([]byte, error) {
	var b []byte
	token, err := c.JWSEncodeJSON(claimset, url, postAsGet)
	if err != nil {
		return b, err
	}

	fmt.Printf("Request token sent to %s\n", url)
	fmt.Println(string(token))

	req, err := http.NewRequest("POST", url, bytes.NewReader(token))
	if err != nil {
		fmt.Println("Failed on http.NewRequest")
		return b, err
	}

	req.Header.Set("Content-Type", "application/jose+json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Failed on executing http.DefaultClient.Do")
		return b, err
	}
	defer func() { _ = res.Body.Close() }()

	b, err = ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Failed reading response body")
		return b, err
	}

	c.Nonce = res.Header.Get("Replay-Nonce")
	if c.KID == "" {
		c.KID = res.Header.Get("Location")
	}

	return b, nil
}

func queryDirectory(url string) (Directory, error) {
	var d Directory

	res, err := http.Get(url)
	if err != nil {
		return d, err
	}
	defer func() { _ = res.Body.Close() }()

	dirJSON, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return d, err
	}

	d, err = Parse(dirJSON)
	return d, err
}

// JWKThumbprint gets a thumbprint of the JWK as defined by RFC7638
func JWKThumbprint(key *ecdsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	jwk := jose.JSONWebKey{Key: key}
	return jwk.Thumbprint(hash)

	// return acme.JWKThumbprint(key.Public())
}

func (c *Client) acmeAuthString(token string) (string, error) {
	var thumb []byte
	thumb, err := JWKThumbprint(c.Key, crypto.SHA256)
	fmt.Printf("JWK Thumbprint as bytes: %v\n", thumb)
	if err != nil {
		return string(thumb), err
	}
	fmt.Printf("Generated JSONWebKey thumbprint %q\n", thumb)
	return fmt.Sprintf("%s.%s", token, base64.RawURLEncoding.EncodeToString(thumb)), nil
}

// AcmeAuthHash generates the value that should be put into a DNS TXT record for _acme-challenge.{domain}
func (c *Client) AcmeAuthHash(token string) (string, error) {
	authString, err := c.acmeAuthString(token)
	fmt.Printf("Sending token %q\n", authString)
	if err != nil {
		return authString, err
	}
	h := sha256.New()
	h.Write([]byte(authString))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
