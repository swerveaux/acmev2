package acmev2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"

	jose "gopkg.in/square/go-jose.v2"
)

type ClientOpts struct {
	HttpClient *http.Client
	AccountKey *ecdsa.PrivateKey
	CertKey    *rsa.PrivateKey // TODO: Remove this eventually
}

type DNSModifier interface {
	AddTextRecord(domain, token string) error
	RemoveTextRecord(domain, token string) error
}

type CertStorer interface {
	Store(keyPEM, certPEM, domain string) error
}

type CertRetriever interface {
	Retrieve(domain string) (string, string, error)
}

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
func NewClient(dirURL string, contactEmails []string, csr CertStoreRetriever, dm DNSModifier, opts ClientOpts) (Client, error) {
	c := Client{Key: opts.AccountKey, CertKey: opts.CertKey, ContactEmails: contactEmails}

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

	c.newAccount(contactEmails)

	c.DNS = dm

	c.CertsManager = csr

	return c, nil
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
	defer res.Body.Close()

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
	defer res.Body.Close()

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
	return fmt.Sprintf("%s.%s", token, base64.RawURLEncoding.EncodeToString([]byte(thumb))), nil
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
