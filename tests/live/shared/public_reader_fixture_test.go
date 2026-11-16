package core

import (
	"context"
	genericjson "enkv.sh/plugins/manifest-generators/generic-json"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	manifest "enkv.sh/sdk/manifest-generator"
)

// This fixture lends only GET reach. The production Reader independently
// authenticates the supplied public basis, HEAD and complete selected closure.
type fixturePublicReadSource struct {
	source        selectedObjectSource
	descriptor    contract.Descriptor
	configuration contract.StoreConfiguration
}

func (s fixturePublicReadSource) CandidateLocation() contract.StoreLocation {
	c := s.configuration
	return contract.StoreLocation{Provider: c.Provider, Region: c.Region, Bucket: c.Bucket, PrefixBeforeHEAD: c.PrefixBeforeHEAD, ExpectedOwner: c.ExpectedOwner}
}
func (s fixturePublicReadSource) ReadHEAD(ctx context.Context) contract.ReadResult {
	return s.source.Read(ctx, s.descriptor.HeadKey, contract.MaxHeadLength)
}
func (s fixturePublicReadSource) ReadHEADGuarded(ctx context.Context, owner string) contract.ReadResult {
	if owner != s.configuration.ExpectedOwner {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return s.ReadHEAD(ctx)
}
func (s fixturePublicReadSource) ReadConfiguration(ctx context.Context, domain, store contract.ID) contract.ReadResult {
	key, err := contract.StoreConfigurationKeyForID(s.configuration.Provider, s.configuration.PrefixBeforeHEAD, domain, store)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return s.source.Read(ctx, key, contract.MaxStoreConfigurationLength)
}
func (s fixturePublicReadSource) ReadRoot(ctx context.Context, ref contract.Ref) contract.ReadResult {
	key, err := format.Key(s.configuration.PrefixBeforeHEAD, ref)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return s.source.Read(ctx, key, ref.Length)
}
func (s fixturePublicReadSource) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	return s.source.Read(ctx, key, maximum)
}
func (s fixturePublicReadSource) Descriptor() contract.Descriptor { return s.descriptor }
func (s fixturePublicReadSource) StoreConfiguration() contract.StoreConfiguration {
	return s.configuration
}
func (s fixturePublicReadSource) Close() {}

func fixtureInstalledPublicReader(t testing.TB, env fixtureEnvironment, selected *StateSession, interpret PublicOutputInterpreter) *ReaderEngine {
	t.Helper()
	configuration, ok := env.Store.(contract.StoreConfigurationSource)
	if !ok || selected == nil {
		t.Fatal("fixture lacks independent public read connection")
	}
	source := fixturePublicReadSource{source: env.Store, descriptor: env.Store.Descriptor(), configuration: configuration.StoreConfiguration()}
	basis := PublicBasis{Descriptor: selected.admission.descriptor}
	if current := selected.admission.current; current != nil {
		basis = PublicBasis{Control: current.control, Selection: current.selection, Enrollment: make([]PublicEnrollment, len(current.enrollment))}
		for index, row := range current.enrollment {
			basis.Enrollment[index] = PublicEnrollment{RecipientID: row.id, Status: row.status, DisplayName: row.name}
		}
	}
	validator := NewPublicConfigurationValidator(interpret)
	engine, err := NewInstalledReader(ReaderInstallation{Candidate: source, ExpectedDomain: env.Domain, ExpectedStore: source.descriptor, PublicBasis: basis, Validator: validator, PrepareManifestRenderer: func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure) {
		return genericjson.Render, ""
	},
		Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
			return source, Result{}
		}, CloseInstalled: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	return engine
}
