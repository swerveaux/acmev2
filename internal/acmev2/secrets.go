package acmev2

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

type ASMCertStore struct {
	asm *secretsmanager.SecretsManager
}

func NewASMCertStore(region string) (*ASMCertStore, error) {
	s, err := session.NewSession(&aws.Config{Region: aws.String(region)})
	if err != nil {
		return nil, err
	}
	return &ASMCertStore{asm: secretsmanager.New(s)}, nil
}

// Secret lets us marshal our secret into JSON.
type Secret struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

const (
	key = iota
	cert
)

func (c *ASMCertStore) Store(keyPEM, certPEM, domain string) error {
	err := c.addSecret(keyPEM, domain, key)
	if err != nil {
		return err
	}
	err = c.addSecret(certPEM, domain, cert)
	return err
}

func (c *ASMCertStore) Retrieve(domain string) (string, string, error) {
	return "i_am", "fake", nil
}

func (c *ASMCertStore) addSecret(pem, domain string, secretType int) error {
	var secretName string
	domain = strings.Replace(domain, "*", "_", 1)
	switch secretType {
	case key:
		secretName = fmt.Sprintf("ssl_%s.key", domain)
	case cert:
		secretName = fmt.Sprintf("ssl_%s.crt", domain)
	}

	secret := Secret{
		Type:  "opaque",
		Value: pem,
		// Value: strings.ReplaceAll(pem, "\n", "\\n"),
	}

	secretBytes, err := json.Marshal(secret)
	if err != nil {
		fmt.Printf("Failed marshalling secret into JSON: %v\n", err)
		return err
	}

	// Try to update first.   This is likely going to be the
	// most common use case, as a secret will be updated every
	// couple of months or so but only created once.   If it
	// errors, check to see if it's secretsmanager.ErrCodeResourceNotFoundException,
	// and if so, go ahead and create the new secret.
	_, err = c.asm.UpdateSecret(&secretsmanager.UpdateSecretInput{
		SecretId:     aws.String(secretName),
		SecretString: aws.String(string(secretBytes)),
	})

	if err != nil {
		_, err2 := c.asm.CreateSecret(&secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String(string(secretBytes)),
		})
		if err2 != nil {
			fmt.Printf("Failed creating secret: %v\n", err)
			return err
		}
	}

	return nil
}

func genSecretInput(name, value string) secretsmanager.CreateSecretInput {
	return secretsmanager.CreateSecretInput{
		Name:         aws.String(name),
		SecretString: aws.String(strings.ReplaceAll(value, "\n", "\\n")),
	}
}
