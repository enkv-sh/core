package compositiongcp

import (
	"context"
	"enkv.sh/core"
	"enkv.sh/core/contract"
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

func NewReceiptReader(ctx context.Context, c ReceiptReaderConfig) (*core.InstalledReceiptReader, error) {
	if c.CompositionID.IsZero() || !c.SourcePins.Valid() || c.CheckSource == nil {
		return nil, contract.ErrRecord
	}
	i, err := newReaderInstallation(ctx, c.ReaderConfig)
	if err != nil {
		return nil, err
	}
	return core.NewInstalledReceiptReader(core.ReceiptReadInstallation{Candidate: i.Candidate, Construct: i.Construct, ExpectedDomain: i.ExpectedDomain, ExpectedStore: i.ExpectedStore, PublicBasis: i.PublicBasis, CompositionID: c.CompositionID, SourcePins: c.SourcePins, CheckSource: c.CheckSource, CloseInstalled: i.CloseInstalled})
}

func NewDefaultReceiptReader(ctx context.Context, c ReceiptReaderConfig) (*core.InstalledReceiptReader, error) {
	if c.CompositionID.IsZero() || !c.SourcePins.Valid() || c.CheckSource == nil {
		return nil, contract.ErrRecord
	}
	client, err := defaultClient(ctx)
	if err != nil {
		return nil, err
	}
	c.Candidate.Client = client
	return NewReceiptReader(ctx, c)
}

func NewInspectionReader(ctx context.Context, c InspectionReaderConfig) (*core.InstalledInspectionReader, error) {
	if !c.SourcePins.Valid() || c.CheckSource == nil {
		return nil, contract.ErrRecord
	}
	i, err := newReaderInstallation(ctx, c.ReaderConfig)
	if err != nil {
		return nil, err
	}
	return core.NewInstalledInspectionReader(core.InspectionReadInstallation{Candidate: i.Candidate, Construct: i.Construct, ExpectedDomain: i.ExpectedDomain, ExpectedStore: i.ExpectedStore, PublicBasis: i.PublicBasis, Validator: i.Validator, SourcePins: c.SourcePins, CheckSource: c.CheckSource, CloseInstalled: i.CloseInstalled, ResolveImplementation: c.ResolveGeneratedImplementation})
}

func NewDefaultInspectionReader(ctx context.Context, c InspectionReaderConfig) (*core.InstalledInspectionReader, error) {
	if !c.SourcePins.Valid() || c.CheckSource == nil {
		return nil, contract.ErrRecord
	}
	client, err := defaultClient(ctx)
	if err != nil {
		return nil, err
	}
	c.Candidate.Client = client
	return NewInspectionReader(ctx, c)
}
