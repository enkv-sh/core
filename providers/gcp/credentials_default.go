package gcp

import (
	"context"

	providercredentials "enkv.sh/providers/gcp/credentials"
)

// LoadDefaultCredentials uses Application Default Credentials. The selected
// provider can refresh cached tokens in the background; caller cancellation
// does not join that refresh.
func LoadDefaultCredentials(ctx context.Context) (CredentialSource, error) {
	return providercredentials.LoadDefaultCredentials(ctx)
}
