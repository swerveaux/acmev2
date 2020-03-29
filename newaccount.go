package acmev2

import (
	"context"
	"fmt"
)

// NewAccount encapsulates what we need to create a new account
type NewAccount struct {
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	Contact              []string `json:"contact"`
}

// newAccount is the first thing to hit after creating a client.
// If your public key matches a previous attempt, the server should
// respond back with that account, otherwise it'll create a new one
// for you.
func (c *Client) newAccount(ctx context.Context, contactEmails []string) error {
	newAcct := NewAccount{
		Contact:              contactEmails,
		TermsOfServiceAgreed: true,
	}

	res, err := c.makeRequest(ctx, newAcct, c.Directory.NewAccount, false)

	fmt.Println(string(res))

	return err
}
