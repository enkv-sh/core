package compositionaws

import (
	"context"

	core "enkv.sh/core"
	awsprovider "enkv.sh/providers/aws"
)

// LoadDefaultConfig installs one standard SDK source in the exact supplied
// routes. It adds no signing or private key route. New retains explicit injection.
func LoadDefaultConfig(ctx context.Context, c Config) (Config, error) {
	if c.StoreClass != awsprovider.StoreClass || c.TrustClass != awsprovider.TrustClass || c.VerifierClass != awsprovider.VerifierClass {
		return Config{}, ErrClass
	}
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, c.Store.Region)
	if err != nil {
		return Config{}, err
	}
	c.Store.Credentials, c.Trust.Credentials = credentials, credentials
	c.KeyAccess = append([]awsprovider.KeyAccessConfig(nil), c.KeyAccess...)
	for i := range c.KeyAccess {
		c.KeyAccess[i].Credentials = credentials
	}
	return c, nil
}

// NewDefaultReader constructs only GET routes and local public verification.
func NewDefaultReader(ctx context.Context, c ReaderConfig) (*core.ReaderEngine, error) {
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, c.Candidate.Region)
	if err != nil {
		return nil, err
	}
	c.Candidate.Credentials = credentials
	return NewReader(c)
}

func NewDefaultReconstruction(ctx context.Context, c ReconstructionConfig) (*core.ReconstructionEngine, error) {
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, c.Candidate.Region)
	if err != nil {
		return nil, err
	}
	c.Candidate.Credentials, c.KeyAccess.Credentials = credentials, credentials
	if c.Normal != nil {
		value := *c.Normal
		value.Credentials = credentials
		c.Normal = &value
	}
	if c.Recovery != nil {
		value := *c.Recovery
		value.Credentials = credentials
		c.Recovery = &value
	}
	return NewReconstruction(c)
}
