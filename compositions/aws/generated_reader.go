package compositionaws

import (
	"context"
	"enkv.sh/core"
	awsprovider "enkv.sh/providers/aws"
)

// NewGeneratedReader installs only authenticated GET reach for generated work.
func NewGeneratedReader(c ReaderConfig) (*core.InstalledGeneratedReader, error) {
	i, err := newReaderInstallation(c)
	if err != nil {
		return nil, err
	}
	return core.NewInstalledGeneratedReader(core.GeneratedReadInstallation{Candidate: i.Candidate, Construct: i.Construct, ExpectedDomain: i.ExpectedDomain, ExpectedStore: i.ExpectedStore, PublicBasis: i.PublicBasis, ResolveImplementation: c.ResolveGeneratedImplementation, CloseInstalled: i.CloseInstalled})
}

func NewDefaultGeneratedReader(ctx context.Context, c ReaderConfig) (*core.InstalledGeneratedReader, error) {
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, c.Candidate.Region)
	if err != nil {
		return nil, err
	}
	c.Candidate.Credentials = credentials
	return NewGeneratedReader(c)
}
