package core

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// This probe has only the read-only methods visible to the reconstruction
// basis. The underlying fixture Store is not returned to that basis.
type constructedReadProbe struct {
	store         contract.Store
	descriptor    contract.Descriptor
	configuration contract.StoreConfiguration
	reads         int
	closes        int
	missingKey    string
	change        func(context.Context, contract.ReadResult) contract.ReadResult
}

func (p *constructedReadProbe) Descriptor() contract.Descriptor { return p.descriptor }
func (p *constructedReadProbe) Close()                          { p.closes++ }
func (p *constructedReadProbe) StoreConfiguration() contract.StoreConfiguration {
	return p.configuration
}
func (p *constructedReadProbe) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	p.reads++
	if key == p.missingKey {
		return contract.ReadResult{Status: contract.ReadMissing}
	}
	r := p.store.Read(ctx, key, limit)
	if p.change != nil && key == p.descriptor.HeadKey {
		return p.change(ctx, r)
	}
	return r
}

// full_only: false
func TestReconstructionReadBasisBindsConstructedStoreBeforeChildren(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	storage := requireAdmittedMemoryStore(t, env.Store)
	probe := candidateProbeForSelected(t, env, f.session)
	anchor, result := anchorPublicCandidate(ctx, probe, env.Domain, &candidateQualifierProbe{}, nil)
	if result.Outcome != 0 {
		t.Fatal("public selection anchor", result)
	}
	makeSource := func() *constructedReadProbe {
		return &constructedReadProbe{store: env.Store, descriptor: env.Store.Descriptor(),
			configuration: env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
	}
	initialCreates, initialCAS := storage.creates, storage.cas
	source := makeSource()
	basis, result := bindPublicReadBasis(ctx, anchor, source)
	if result.Outcome != 0 || source.reads != 1 || basis.reader.descriptor != source.descriptor {
		t.Fatal("normal Store did not reread the identical selected HEAD", result, source.reads)
	}
	image, result := readCompleteSelectedImage(ctx, basis.reader, basis.anchor.root, false)
	if result.Outcome != 0 || image.root.Snapshot != f.session.root.Snapshot ||
		len(image.supportFacts) != len(f.session.supportFacts) ||
		storage.creates != initialCreates || storage.cas != initialCAS {
		t.Fatal("read-only basis changed selection or reached a write", result)
	}
	complete, result := completePublicSelection(ctx, basis, nil)
	if result.Outcome != 0 || complete.image.root.Snapshot != f.session.root.Snapshot ||
		complete.authorityID != f.session.root.CurrentAccess.Core.AuthorityRecipientID ||
		storage.creates != initialCreates || storage.cas != initialCAS {
		t.Fatal("complete Genesis selection did not retain read-only facts", result)
	}
	refs := capacityConfigurationSelectedRefs(t, f.session)
	configKey, err := format.Key(source.descriptor.Prefix, refs[len(refs)-1])
	if err != nil {
		t.Fatal(err)
	}
	source.missingKey = configKey
	if _, result := completePublicSelection(ctx, basis, nil); result.Outcome != EvidenceUnavailable ||
		result.Reason != MissingSelectedObject || storage.creates != initialCreates || storage.cas != initialCAS {
		t.Fatal("missing selected configuration became an empty configuration", result)
	}
	source.missingKey = ""
	for _, tc := range []struct {
		name string
		edit func(*constructedReadProbe)
	}{
		{"StoreID", func(p *constructedReadProbe) { p.descriptor.Identity[0] ^= 1 }},
		{"coordinate", func(p *constructedReadProbe) { p.descriptor.Coordinate[0] ^= 1 }},
		{"nonbody", func(p *constructedReadProbe) { p.descriptor.NonBody[0] ^= 1 }},
		{"prefix", func(p *constructedReadProbe) {
			p.descriptor.Prefix += "-other"
			p.descriptor.HeadKey = p.descriptor.Prefix + "/HEAD"
		}},
		{"provider", func(p *constructedReadProbe) { p.descriptor.Family = contract.AWS }},
		{"construction", func(p *constructedReadProbe) { p.configuration.Bucket += "-other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := makeSource()
			tc.edit(p)
			if _, result := bindPublicReadBasis(ctx, anchor, p); result.Outcome != IntegrityFailure ||
				result.Reason != ConstructionMismatch || p.reads != 0 || storage.creates != initialCreates || storage.cas != initialCAS {
				t.Fatal("wrong constructed Store reached selected children", result, p.reads)
			}
		})
	}
	for _, tc := range []struct {
		name    string
		change  func(context.Context, contract.ReadResult) contract.ReadResult
		outcome Outcome
		reason  Reason
	}{
		{"changed body", func(_ context.Context, r contract.ReadResult) contract.ReadResult {
			r.Body = bytes.Clone(r.Body)
			r.Body[0] ^= 1
			return r
		}, Contention, DifferentSelection},
		{"changed token", func(_ context.Context, r contract.ReadResult) contract.ReadResult {
			r.Token.Value = "999999"
			return r
		}, Contention, DifferentSelection},
		{"read denied", func(_ context.Context, _ contract.ReadResult) contract.ReadResult {
			return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
		}, EvidenceUnavailable, ReadUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := makeSource()
			p.change = tc.change
			if _, result := bindPublicReadBasis(ctx, anchor, p); result.Outcome != tc.outcome ||
				result.Reason != tc.reason || p.reads != 1 || storage.creates != initialCreates || storage.cas != initialCAS {
				t.Fatal("changed normal HEAD admitted selected children", result, p.reads)
			}
		})
	}
	p := makeSource()
	canceled, cancel := context.WithCancel(ctx)
	cancelAnchor, result := anchorPublicCandidate(canceled, candidateProbeForSelected(t, env, f.session), env.Domain,
		&candidateQualifierProbe{}, nil)
	if result.Outcome != 0 {
		t.Fatal("cancellation fixture needs its own original invocation", result)
	}
	p.change = func(_ context.Context, r contract.ReadResult) contract.ReadResult {
		cancel()
		return r
	}
	if _, result := bindPublicReadBasis(canceled, cancelAnchor, p); result.Outcome != EvidenceUnavailable ||
		result.Reason != ReadUnavailable || p.reads != 1 {
		t.Fatal("canceled normal HEAD read continued to children", result, p.reads)
	}
	if storage.creates != initialCreates || storage.cas != initialCAS {
		t.Fatal("read basis caused a Store effect")
	}
}

// full_only: false
func TestReconstructionReadBasisAWSOwnerDenialStopsBeforeChildren(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.AWS, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	storage := requireAdmittedMemoryStore(t, env.Store)
	probe := candidateProbeForSelected(t, env, f.session)
	anchor, result := anchorPublicCandidate(ctx, probe, env.Domain, &candidateQualifierProbe{}, nil)
	if result.Outcome != 0 || probe.guardedOwner != anchor.configuration.ExpectedOwner {
		t.Fatal("initial AWS owner guard was not selected", result)
	}
	initialCreates, initialCAS := storage.creates, storage.cas
	source := &constructedReadProbe{store: env.Store, descriptor: env.Store.Descriptor(),
		configuration: env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
	source.change = func(_ context.Context, _ contract.ReadResult) contract.ReadResult {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
	}
	if _, result := bindPublicReadBasis(ctx, anchor, source); result.Outcome != EvidenceUnavailable ||
		result.Reason != ReadUnavailable || result.StoreReason != contract.ReasonAccess || source.reads != 1 ||
		storage.creates != initialCreates || storage.cas != initialCAS {
		t.Fatal("normal AWS owner denial reached selected children or effects", result, source.reads)
	}
	source.change = nil
	source.reads = 0
	source.configuration.ExpectedOwner = "999999999999"
	if _, result := bindPublicReadBasis(ctx, anchor, source); result.Outcome != IntegrityFailure ||
		result.Reason != ConstructionMismatch || source.reads != 0 {
		t.Fatal("different AWS owner became an authenticated Store construction", result, source.reads)
	}
}
