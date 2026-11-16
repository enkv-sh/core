package awsprovider

import (
	"context"

	"enkv.sh/providers/aws/credentials"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// LoadDefaultCredentials uses the SDK's standard credential provider chain.
// Each operation captures one credential value before its first request.
func LoadDefaultCredentials(ctx context.Context, region string) (aws.CredentialsProvider, error) {
	return credentials.LoadDefaultCredentials(ctx, region)
}
