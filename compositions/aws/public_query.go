package compositionaws

import (
	"context"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	awsprovider "enkv.sh/providers/aws"
)

// ReceiptReaderConfig binds public GET construction to exact captured inputs.
type ReceiptReaderConfig struct {
	ReaderConfig
	CompositionID contract.ID
	SourcePins    core.AdministrativeSourcePins
	CheckSource   func(context.Context) error
}

// InspectionReaderConfig installs passive interpretation and exact source checks.
type InspectionReaderConfig struct {
	ReaderConfig
	SourcePins  core.AdministrativeSourcePins
	CheckSource func(context.Context) error
}

func NewReceiptReader(c ReceiptReaderConfig) (*core.InstalledReceiptReader, error) {
	if c.CompositionID.IsZero() || !c.SourcePins.Valid() || c.CheckSource == nil {
		return nil, contract.ErrRecord
	}
	i, err := newReaderInstallation(c.ReaderConfig)
	if err != nil {
		return nil, err
	}
	return core.NewInstalledReceiptReader(core.ReceiptReadInstallation{Candidate: i.Candidate, Construct: i.Construct, ExpectedDomain: i.ExpectedDomain, ExpectedStore: i.ExpectedStore, PublicBasis: i.PublicBasis, CompositionID: c.CompositionID, SourcePins: c.SourcePins, CheckSource: c.CheckSource, CloseInstalled: i.CloseInstalled})
}

func NewDefaultReceiptReader(ctx context.Context, c ReceiptReaderConfig) (*core.InstalledReceiptReader, error) {
	if c.CompositionID.IsZero() || !c.SourcePins.Valid() || c.CheckSource == nil {
		return nil, contract.ErrRecord
	}
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, c.Candidate.Region)
	if err != nil {
		return nil, err
	}
	c.Candidate.Credentials = credentials
	return NewReceiptReader(c)
}

func NewInspectionReader(c InspectionReaderConfig) (*core.InstalledInspectionReader, error) {
	if !c.SourcePins.Valid() || c.CheckSource == nil {
		return nil, contract.ErrRecord
	}
	i, err := newReaderInstallation(c.ReaderConfig)
	if err != nil {
		return nil, err
	}
	return core.NewInstalledInspectionReader(core.InspectionReadInstallation{Candidate: i.Candidate, Construct: i.Construct, ExpectedDomain: i.ExpectedDomain, ExpectedStore: i.ExpectedStore, PublicBasis: i.PublicBasis, Validator: i.Validator, SourcePins: c.SourcePins, CheckSource: c.CheckSource, CloseInstalled: i.CloseInstalled, ResolveImplementation: c.ResolveGeneratedImplementation})
}

func NewDefaultInspectionReader(ctx context.Context, c InspectionReaderConfig) (*core.InstalledInspectionReader, error) {
	if !c.SourcePins.Valid() || c.CheckSource == nil {
		return nil, contract.ErrRecord
	}
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, c.Candidate.Region)
	if err != nil {
		return nil, err
	}
	c.Candidate.Credentials = credentials
	return NewInspectionReader(c)
}
