package compositiongcp

import (
	"context"
	"net/http"

	core "enkv.sh/core"
	gcp "enkv.sh/providers/gcp"
)

// LoadDefaultConfig installs one ADC client in the exact supplied routes.
// It adds no signing or private key route. New retains explicit injection.
func LoadDefaultConfig(ctx context.Context, c Config) (Config, error) {
	if c.StoreClass != gcp.StoreClass || c.TrustClass != gcp.TrustClass || c.VerifierClass != gcp.VerifierClass {
		return Config{}, ErrClass
	}
	client, err := defaultClient(ctx)
	if err != nil {
		return Config{}, err
	}
	c.Store.Client, c.Trust.Client = client, client
	c.KeyAccess = append([]gcp.KeyAccessConfig(nil), c.KeyAccess...)
	for i := range c.KeyAccess {
		c.KeyAccess[i].Client = client
	}
	return c, nil
}

func defaultClient(ctx context.Context) (*gcp.Client, error) {
	source, err := gcp.LoadDefaultCredentials(ctx)
	if err != nil {
		return nil, err
	}
	return gcp.NewClient(&http.Transport{}, source)
}

// NewDefaultReader constructs only GET routes and local public verification.
func NewDefaultReader(ctx context.Context, c ReaderConfig) (*core.ReaderEngine, error) {
	client, err := defaultClient(ctx)
	if err != nil {
		return nil, err
	}
	c.Candidate.Client = client
	return NewReader(ctx, c)
}

func NewDefaultReconstruction(ctx context.Context, c ReconstructionConfig) (*core.ReconstructionEngine, error) {
	client, err := defaultClient(ctx)
	if err != nil {
		return nil, err
	}
	c.Candidate.Client, c.KeyAccess.Client = client, client
	if c.Normal != nil {
		value := *c.Normal
		value.Client = client
		c.Normal = &value
	}
	if c.Recovery != nil {
		value := *c.Recovery
		value.Client = client
		c.Recovery = &value
	}
	return NewReconstruction(ctx, c)
}
