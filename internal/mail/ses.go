package mail

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// SES sends through the Amazon SES v2 API. Credentials come from the standard
// AWS chain: env vars, shared config, or the instance/task IAM role.
type SES struct{ client *sesv2.Client }

func NewSES(ctx context.Context, region string) (*SES, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &SES{client: sesv2.NewFromConfig(cfg)}, nil
}

func (s *SES) Send(ctx context.Context, m Message) error {
	raw, err := Build(m, time.Now())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err = s.client.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(m.From.Address),
		Destination:      &types.Destination{ToAddresses: []string{m.To}},
		Content:          &types.EmailContent{Raw: &types.RawMessage{Data: raw}},
	})
	return err
}
