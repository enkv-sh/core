package compositiongcp

import (
	"context"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// CapacityReaderConfig adds bounded enumeration to a separate public reader.
type CapacityReaderConfig struct {
	ReaderConfig
	SourcePins  core.AdministrativeSourcePins
	CheckSource func(context.Context) error
}

type capacitySelectedStore struct{ *publicSelectedStore }

func (r *capacitySelectedStore) ListPage(ctx context.Context, cursor string) contract.ListPageResult {
	if r == nil || r.publicSelectedStore == nil || r.store == nil {
		return contract.ListPageResult{Status: contract.ListPageInvalid, Reason: contract.ReasonConstruction}
	}
	return r.store.ListPage(ctx, cursor)
}

func NewCapacityReader(ctx context.Context, c CapacityReaderConfig) (*core.InstalledCapacityReader, error) {
	if !c.SourcePins.Valid() || c.CheckSource == nil {
		return nil, contract.ErrRecord
	}
	i, err := newReaderInstallation(ctx, c.ReaderConfig)
	if err != nil {
		return nil, err
	}
	construct := i.Construct
	return core.NewInstalledCapacityReader(core.CapacityReadInstallation{Candidate: i.Candidate, ExpectedDomain: i.ExpectedDomain,
		ExpectedStore: i.ExpectedStore, PublicBasis: i.PublicBasis, SourcePins: c.SourcePins, CheckSource: c.CheckSource,
		CloseInstalled: i.CloseInstalled, Construct: func(ctx context.Context, selected contract.StoreConfiguration) (core.PublicCapacityReader, core.Result) {
			r, result := construct(ctx, selected)
			if result.Outcome != 0 {
				return nil, result
			}
			selectedStore, ok := r.(*publicSelectedStore)
			if !ok || selectedStore == nil {
				if r != nil {
					r.Close()
				}
				return nil, core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}
			}
			return &capacitySelectedStore{selectedStore}, core.Result{}
		}})
}

func NewDefaultCapacityReader(ctx context.Context, c CapacityReaderConfig) (*core.InstalledCapacityReader, error) {
	if !c.SourcePins.Valid() || c.CheckSource == nil {
		return nil, contract.ErrRecord
	}
	client, err := defaultClient(ctx)
	if err != nil {
		return nil, err
	}
	c.Candidate.Client = client
	return NewCapacityReader(ctx, c)
}
