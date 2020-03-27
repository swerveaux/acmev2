package acmev2

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/route53"
)

// Route53 implements DNSModifier to set and remove TXT records from AWS Hosted Zones
type Route53 struct {
	r53 *route53.Route53
}

// NewRoute53 returns a pointer to a Route53 value with an AWS session based on the passed in AWS region.
func NewRoute53(region string) (*Route53, error) {
	s, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return nil, err
	}

	r53 := route53.New(s)

	return &Route53{r53: r53}, nil
}

// AddTextRecord adds the ACME challenge text record to the DNS entry for a domain.
// The text record is added to an entry for _acme-challenge.<domain>.
func (c *Route53) AddTextRecord(domain, token string) error {
	hostedZoneID, err := findHostedZoneID(c.r53, domain)
	if err != nil {
		return err
	}

	input, err := createChangeRecordSetInput(hostedZoneID, domain, token, "UPSERT")
	if err != nil {
		return err
	}
	fmt.Println(input.String())

	_, err = c.r53.ChangeResourceRecordSets(input)
	if err != nil {
		return err
	}

	return nil
}

// RemoveTextRecord removes the ACME challenge text record for cleanup.
func (c *Route53) RemoveTextRecord(domain, token string) error {
	hostedZoneID, err := findHostedZoneID(c.r53, domain)
	if err != nil {
		return err
	}

	input, err := createChangeRecordSetInput(hostedZoneID, domain, token, "DELETE")
	if err != nil {
		return err
	}
	fmt.Println(input.String())
	_, err = c.r53.ChangeResourceRecordSets(input)
	if err != nil {
		return err
	}

	return nil
}

func createChangeRecordSetInput(hostedZoneID, domain, token, action string) (*route53.ChangeResourceRecordSetsInput, error) {
	var input route53.ChangeResourceRecordSetsInput

	// Strip leading wildcard for text record if present.
	if domain[:2] == "*." {
		domain = domain[2:]
	}

	input = route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{
					Action: aws.String(action),
					ResourceRecordSet: &route53.ResourceRecordSet{
						Name: aws.String(fmt.Sprintf("_acme-challenge.%s", domain)),
						ResourceRecords: []*route53.ResourceRecord{
							{
								Value: aws.String(fmt.Sprintf("%q", token)),
							},
						},
						TTL:  aws.Int64(20),
						Type: aws.String("TXT"),
					},
				},
			},
			Comment: aws.String("Text record for letsencrypt"),
		},
		HostedZoneId: aws.String(hostedZoneID),
	}

	return &input, nil
}

func findHostedZoneID(r53 *route53.Route53, hostname string) (string, error) {
	var hostedZoneID string

	_, domain, err := splitHostname(hostname)
	if err != nil {
		return hostedZoneID, err
	}

	fmt.Printf("Searching for %s\n", domain)

	lhzbnInput := &route53.ListHostedZonesByNameInput{
		DNSName:  aws.String(domain),
		MaxItems: aws.String("1"),
	}

	lhzbnOutput, err := r53.ListHostedZonesByName(lhzbnInput)
	if err != nil {
		return hostedZoneID, err
	}

	if len(lhzbnOutput.HostedZones) != 1 {
		return hostedZoneID, fmt.Errorf("Failed to find HostedZoneID for %s", domain)
	}

	hostedZoneID = *lhzbnOutput.HostedZones[0].Id

	return hostedZoneID, nil
}

func splitHostname(hostname string) (string, string, error) {
	s := strings.Split(hostname, ".")
	h := make([]string, 0, 0)
	for _, t := range s {
		if t != "" && t != "*" {
			h = append(h, t)
		}
	}

	if len(h) < 2 {
		return "", "", fmt.Errorf("%s is basically a great big TLD", hostname)
	}

	return strings.Join(h[:len(h)-2], "."), strings.Join(h[len(h)-2:], "."), nil
}
