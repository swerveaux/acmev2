package acmev2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
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
	// Logger takes something that implements the Logger interface.   If set, it will log any output to the
	// Logger's Log(string) function.   Otherwise, it won't output much of anything.
	Logger Logger
}

// Logger is an interface that allows you to capture log output and do with it what you will.
type Logger interface {
	Log(msg interface{})
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
	Logger        Logger
}

// NewClient takes a directory URL (e.g, https://acme-staging-v02.api.letsencrypt.org/directory) and
// a slice of contact emails for the cert being requested (Let's Encrypt will generally send you an
// email when a cert is approaching expiration, though I've found that to be flaky).   There's
// the Directory from that URL and get a Nonce for the next request.
// If no key is provided in the options, a key will be generated for a new account and be subsequently
// available in the Key field of the Client struct.   That key can be re-used to keep using the same
// Let's Encrypt account in the future.
func NewClient(dirURL string, csr CertStoreRetriever, dm DNSModifier, opts ClientOpts) (Client, error) {
	contacts := prependContacts(opts.ContactEmails)
	c := Client{Key: opts.AccountKey, CertKey: opts.CertKey, ContactEmails: contacts}

	directory, err := queryDirectory(dirURL)
	if err != nil {
		return c, err
	}
	c.Directory = directory

	if opts.AccountKey == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		opts.AccountKey = key
	}

	if opts.Logger != nil {
		c.Logger = opts.Logger
	}

	c.DNS = dm

	c.CertsManager = csr

	return c, nil
}

// FetchOrRenewCert takes a domain name and tries to renew an existing cert or, if it can't find that, get
// a new cert.   It uses the CertStoreRetriever passed in to the client to try to fetch an existing cert and, if
// it finds that, will re-use the existing RSA key for the cert when asking for a renewal.   Otherwise, it will
// generate a new key and ask for a new cert.   It is not recommended to run this in parallel with other requests
// due to the way nonces with with the session.
func (c *Client) FetchOrRenewCert(ctx context.Context, domain string) error {
	if domain == "" {
		return errors.New("no domain passed in")
	}

	nonce, err := GetNonce(c.Directory.NewNonce)
	if err != nil {
		c.log(err)
		return err
	}
	c.Nonce = nonce

	err = c.newAccount(ctx, c.ContactEmails)
	if err != nil {
		c.log("failed starting new session")
		return err
	}

	certApply, err := c.CertApply(ctx, []string{domain})
	if err != nil {
		return err
	}

	challengeResponse, err := c.FetchChallenges(ctx, certApply.Authorizations[0])
	c.log(challengeResponse)
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
	c.log(authHash)

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

	err = c.ChallengeReady(ctx, challenge.URL)
	if err != nil {
		c.log(fmt.Sprintf("Failed posting challenge: %v\n", err))
		return err
	}

	err = c.PollForStatus(ctx, domain)
	if err != nil {
		c.log(fmt.Sprintf("Bad response when polling: %v\n", err))
		return err
	}

	return nil
}

func (c *Client) makeRequest(ctx context.Context, claimset interface{}, url string, postAsGet bool) ([]byte, error) {
	var b []byte
	token, err := c.JWSEncodeJSON(claimset, url, postAsGet)
	if err != nil {
		return b, err
	}

	c.log(fmt.Sprintf("Request token sent to %s\n", url))
	c.log(string(token))

	req, err := http.NewRequest("POST", url, bytes.NewReader(token))
	if err != nil {
		c.log("Failed on http.NewRequest")
		return b, err
	}

	req.Header.Set("Content-Type", "application/jose+json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.log("Failed on executing http.DefaultClient.Do")
		return b, err
	}
	defer func() { _ = res.Body.Close() }()

	b, err = ioutil.ReadAll(res.Body)
	if err != nil {
		c.log("Failed reading response body")
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
	c.log(fmt.Sprintf("JWK Thumbprint as bytes: %v\n", thumb))
	if err != nil {
		return string(thumb), err
	}
	c.log(fmt.Sprintf("Generated JSONWebKey thumbprint %q\n", thumb))
	return fmt.Sprintf("%s.%s", token, base64.RawURLEncoding.EncodeToString(thumb)), nil
}

// AcmeAuthHash generates the value that should be put into a DNS TXT record for _acme-challenge.{domain}
func (c *Client) AcmeAuthHash(token string) (string, error) {
	authString, err := c.acmeAuthString(token)
	c.log(fmt.Sprintf("Sending token %q\n", authString))
	if err != nil {
		return authString, err
	}
	h := sha256.New()
	h.Write([]byte(authString))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

func (c *Client) log(msg interface{}) {
	if c.Logger != nil {
		c.Logger.Log(fmt.Sprintf("%s\n", msg))
	}
}

func prependContacts(c []string) []string {
	contacts := make([]string, len(c))
	for i := range c {
		if !strings.HasPrefix(c[i], "mailto:") {
			c[i] = fmt.Sprintf("mailto:%s", strings.TrimSpace(c[i]))
		}
		contacts[i] = c[i]
	}
	return contacts
}
