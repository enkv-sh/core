package compositiongcp

import (
	"context"
	"enkv.sh/core"
)

// NewGeneratedReader installs only authenticated GET reach for generated work.
func NewGeneratedReader(ctx context.Context, c ReaderConfig) (*core.InstalledGeneratedReader, error) {
	i, err := newReaderInstallation(ctx, c)
	if err != nil {
		return nil, err
	}
	return core.NewInstalledGeneratedReader(core.GeneratedReadInstallation{Candidate: i.Candidate, Construct: i.Construct, ExpectedDomain: i.ExpectedDomain, ExpectedStore: i.ExpectedStore, PublicBasis: i.PublicBasis, ResolveImplementation: c.ResolveGeneratedImplementation, CloseInstalled: i.CloseInstalled})
}

func NewDefaultGeneratedReader(ctx context.Context, c ReaderConfig) (*core.InstalledGeneratedReader, error) {
	client, err := defaultClient(ctx)
	if err != nil {
		return nil, err
	}
	c.Candidate.Client = client
	return NewGeneratedReader(ctx, c)
}
