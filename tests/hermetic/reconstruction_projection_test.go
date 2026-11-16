package core

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestReconstructionProjectionCopyAndCloseHaveOneOwnedLifetime(t *testing.T) {
	original := []byte("selected encrypted observation")
	projection := &ReconstructionProjection{parts: []reconstructionProjectionPart{{
		kind: reconstructionValuePagePart, body: bytes.Clone(original),
	}}}
	prior, ok := projection.CopyPart(0)
	if !ok {
		t.Fatal("owned result did not make its first independent copy")
	}
	var workers sync.WaitGroup
	var damaged atomic.Bool
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for n := 0; n < 100; n++ {
				part, ok := projection.CopyPart(0)
				if ok && !bytes.Equal(part.Body, original) {
					damaged.Store(true)
				}
				_ = projection.PartCount()
				_, _ = projection.Provenance()
			}
		}()
	}
	close(start)
	projection.Close()
	workers.Wait()
	if damaged.Load() || !bytes.Equal(prior.Body, original) || projection.PartCount() != 0 {
		t.Fatal("concurrent Close changed a returned copy or left owned bytes visible")
	}
	if _, ok := projection.CopyPart(0); ok {
		t.Fatal("closed result returned selected bytes")
	}
}

type fixedProjectionProbe struct {
	parts    []reconstructionProjectionPart
	returnAt int
	answer   Result
	cancel   context.CancelFunc
	commits  int
	aborts   int
}

// This Store gives the next GET the same backing when it fits. The selected
// reader may lend it to Accept only until that callback returns.
type reusedProjectionReadSource struct {
	store      contract.Store
	backing    []byte
	reuseCount int
}

func (s *reusedProjectionReadSource) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	r := s.store.Read(ctx, key, limit)
	if r.Status != contract.ReadOK {
		return r
	}
	if len(s.backing) != 0 && len(r.Body) <= cap(s.backing) {
		s.reuseCount++
	}
	s.backing = append(s.backing[:0], r.Body...)
	r.Body = s.backing
	return r
}

func (p *fixedProjectionProbe) Accept(_ context.Context, part reconstructionProjectionPart) Result {
	p.parts = append(p.parts, reconstructionProjectionPart{kind: part.kind, ref: part.ref,
		physicalOrdinal: part.physicalOrdinal, supportKind: part.supportKind,
		recordID: part.recordID, body: bytes.Clone(part.body)})
	if p.cancel != nil && len(p.parts) == p.returnAt {
		p.cancel()
	}
	if len(p.parts) == p.returnAt {
		return p.answer
	}
	return Result{}
}

func (p *fixedProjectionProbe) Commit(context.Context, Result) Result {
	p.commits++
	return Result{}
}
func (p *fixedProjectionProbe) Abort() { p.aborts++ }

// full_only: false
func TestReconstructionFixedProjectionHasExactOrderAndNoCompletion(t *testing.T) {
	ctx, cancel, selected, store := selectedProjectionFixture(t)
	defer cancel()
	beforeCreates, beforeCAS := store.creates, store.cas
	reused := &reusedProjectionReadSource{store: store}
	selected.basis.reader.source = reused
	probe := &fixedProjectionProbe{}
	progress, result := emitReconstructionFixedParts(ctx, &selected, probe)
	if result.Outcome != 0 || probe.commits != 0 || probe.aborts != 0 {
		t.Fatal("fixed stream claimed completion or failed", result)
	}
	want := fixedProjectionExpected(selected.image.root)
	if len(probe.parts) != len(want) || progress.parts != uint32(len(want)) {
		t.Fatal("fixed projection omitted a selected fixed object", len(probe.parts), len(want), progress)
	}
	var total uint64
	for i, part := range probe.parts {
		if part.kind != want[i].kind || i >= 3 && part.ref != want[i].ref {
			t.Fatal("fixed projection order or reference changed", i, part.kind)
		}
		if len(part.body) == 0 || part.physicalOrdinal != 0 {
			t.Fatal("fixed projection has an empty or support-only part", i)
		}
		if i >= 2 && format.CheckReference(part.ref, part.body) != nil {
			t.Fatal("fixed projection bytes do not match exact selected reference", i)
		}
		total += uint64(len(part.body))
	}
	if !bytes.Equal(probe.parts[0].body, selected.basis.anchor.configBody) ||
		!bytes.Equal(probe.parts[1].body, selected.basis.anchor.headBody) ||
		progress.bytes != total || reused.reuseCount == 0 ||
		store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("fixed projection changed authenticated bytes or used a Store effect")
	}
}

// full_only: false
func TestReconstructionFixedProjectionRefusesPartialAndFalseSuccess(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer Result
		cancel bool
		want   Outcome
	}{
		{"consumer failure", failure(EvidenceUnavailable, ReadUnavailable), false, EvidenceUnavailable},
		{"false completion", Result{Outcome: ObservedCurrent}, false, AdmissionRefused},
		{"false unchanged", Result{Outcome: Unchanged}, false, AdmissionRefused},
		{"nonzero success", Result{Reason: InvalidIntent}, false, AdmissionRefused},
		{"cancel during callback", Result{}, true, EvidenceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel, selected, store := selectedProjectionFixture(t)
			defer cancel()
			beforeCreates, beforeCAS := store.creates, store.cas
			probe := &fixedProjectionProbe{returnAt: 4, answer: tc.answer}
			if tc.cancel {
				probe.cancel = cancel
			}
			progress, result := emitReconstructionFixedParts(ctx, &selected, probe)
			if result.Outcome != tc.want || progress.parts != 3 || probe.commits != 0 ||
				store.creates != beforeCreates || store.cas != beforeCAS {
				t.Fatal("partial projection crossed a failure boundary", result, progress)
			}
		})
	}
	t.Run("unqualified image", func(t *testing.T) {
		ctx, cancel, selected, store := selectedProjectionFixture(t)
		defer cancel()
		selected.complete = false
		beforeReads, beforeCreates, beforeCAS := store.reads, store.creates, store.cas
		probe := &fixedProjectionProbe{}
		if _, result := emitReconstructionFixedParts(ctx, &selected, probe); result.Outcome != AdmissionRefused ||
			len(probe.parts) != 0 || store.reads != beforeReads || store.creates != beforeCreates || store.cas != beforeCAS {
			t.Fatal("unqualified selected image reached the projection consumer")
		}
	})
}

// full_only: false
func TestReconstructionFixedProjectionRejectsChangedSelectedChild(t *testing.T) {
	ctx, cancel, selected, store := selectedProjectionFixture(t)
	defer cancel()
	first := fixedProjectionExpected(selected.image.root)[3].ref
	key, err := format.Key(selected.basis.reader.descriptor.Prefix, first)
	if err != nil {
		t.Fatal(err)
	}
	selected.basis.reader.source = &constructedReadProbe{store: store, descriptor: store.Descriptor(),
		configuration: store.StoreConfiguration(), missingKey: key}
	beforeCreates, beforeCAS := store.creates, store.cas
	probe := &fixedProjectionProbe{}
	progress, result := emitReconstructionFixedParts(ctx, &selected, probe)
	if result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject ||
		progress.parts != 3 || probe.commits != 0 || store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("missing selected child became a complete projection", result, progress)
	}
}

// full_only: false
func TestReconstructionProjectionAttemptOwnsAndDiscardsParts(t *testing.T) {
	ctx, cancel, selected, store := selectedProjectionFixture(t)
	defer cancel()
	beforeCreates, beforeCAS := store.creates, store.cas
	owner, result := beginReconstructionProjection(&selected)
	if result != (Result{}) || owner == nil {
		t.Fatal("complete selected image did not begin a private attempt", result)
	}
	if cap(owner.parts) != int(owner.partLimit) {
		t.Fatal("projection did not reserve exact selected part backing", cap(owner.parts), owner.partLimit)
	}
	progress, result := emitReconstructionFixedParts(ctx, &selected, owner)
	if result != (Result{}) || progress.parts == 0 || progress.parts >= owner.partLimit {
		t.Fatal("fixed parts did not leave selected support pending", result, progress, owner.partLimit)
	}
	observed := Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure,
		ObservedRevision:   selected.basis.anchor.head.Core.Revision,
		ObservedSnapshotID: selected.image.root.Snapshot}
	if result := owner.Commit(ctx, observed); result.Outcome != AdmissionRefused || owner.takeCommitted() != nil {
		t.Fatal("partial selected support became a complete projection", result)
	}
	if result := owner.Commit(ctx, Result{Outcome: ObservedCurrent}); result.Outcome != AdmissionRefused {
		t.Fatal("unproven final observation completed the attempt", result)
	}
	withReason := observed
	withReason.Reason = InvalidProof
	if result := owner.Commit(ctx, withReason); result.Outcome != AdmissionRefused {
		t.Fatal("inconsistent final result completed the attempt", result)
	}
	owner.Abort()
	if owner.state != projectionAborted || len(owner.parts) != 0 || owner.takeCommitted() != nil ||
		store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("aborted projection retained parts or made a Store effect")
	}
	if result := owner.Accept(ctx, reconstructionProjectionPart{kind: reconstructionHEADPart, body: []byte("later")}); result.Outcome != AdmissionRefused {
		t.Fatal("aborted attempt accepted another part", result)
	}

	// This small owner-only case checks one-copy transfer. It does not claim
	// that a fabricated part is an authenticated selected projection.
	owner = &reconstructionProjectionAttempt{anchor: selected.basis.anchor,
		provenance: projectionProvenance(&selected), partLimit: 1, byteLimit: 32}
	if result := owner.Accept(ctx, reconstructionProjectionPart{kind: reconstructionConfigurationPart,
		body: make([]byte, contract.MaxStoreConfigurationLength+1)}); result.Outcome != AdmissionRefused {
		t.Fatal("oversize part entered bounded projection", result)
	}
	input := []byte("encrypted observation")
	if result := owner.Accept(ctx, reconstructionProjectionPart{kind: reconstructionValuePagePart, body: input}); result != (Result{}) {
		t.Fatal("owner refused a bounded provisional part", result)
	}
	input[0] = 'X'
	if result := owner.Commit(ctx, observed); result != (Result{}) {
		t.Fatal("verified owner-only transfer failed", result)
	}
	projection := owner.takeCommitted()
	if projection == nil || projection.partCount() != 1 || owner.takeCommitted() != nil {
		t.Fatal("commit did not transfer one owned result")
	}
	owner.Abort()
	part, ok := projection.copyPart(0)
	if !ok || !bytes.Equal(part.body, []byte("encrypted observation")) {
		t.Fatal("borrowed input changed the owned projection")
	}
	part.body[0] = 'Y'
	part, ok = projection.copyPart(0)
	if !ok || !bytes.Equal(part.body, []byte("encrypted observation")) {
		t.Fatal("caller changed the owner's backing through a copied part")
	}
	cancel()
	part, ok = projection.copyPart(0)
	if !ok || !bytes.Equal(part.body, []byte("encrypted observation")) {
		t.Fatal("post-Commit cancellation revoked a complete owned result")
	}
	projection.Close()
	if projection.partCount() != 0 {
		t.Fatal("closed projection retained visible parts")
	}
	if _, ok := projection.copyPart(0); ok {
		t.Fatal("closed projection exposed a part")
	}
}

// full_only: false
func TestReconstructionSelectedSupportProjectionUsesExactRows(t *testing.T) {
	ctx, cancel, selected, store := selectedProjectionFixture(t)
	defer cancel()
	beforeCreates, beforeCAS := store.creates, store.cas
	owner, result := beginReconstructionProjection(&selected)
	if result != (Result{}) {
		t.Fatal("selected support did not begin a private projection", result)
	}
	fixed, result := emitReconstructionFixedParts(ctx, &selected, owner)
	if result != (Result{}) {
		t.Fatal("fixed projection failed", result)
	}
	beforeReads := store.reads
	all, result := emitReconstructionSupportRows(ctx, &selected, owner, fixed)
	if result != (Result{}) || all.parts != owner.partLimit || uint64(len(owner.parts)) != uint64(owner.partLimit) ||
		store.reads-beforeReads != len(selected.image.root.RequiredSupport) ||
		store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("selected row projection missed facts, reread a page, or made an effect", result, all)
	}
	position := int(fixed.parts)
	for _, page := range selected.image.supportFacts {
		for j, fact := range page.rows {
			part := owner.parts[position]
			if part.kind != reconstructionSupportRowPart || part.ref != page.ref ||
				part.physicalOrdinal != page.ordinals[j] || part.supportKind != fact.Kind() ||
				part.recordID != fact.RecordID() || uint32(len(part.body)) != fact.BodyLength() ||
				contract.Hash(part.body) != fact.BodyDigest() {
				t.Fatal("selected support identity or body changed", position)
			}
			position++
		}
	}
	if position != len(owner.parts) {
		t.Fatal("projection included an obsolete physical row")
	}
	owner.Abort()
	if len(owner.parts) != 0 {
		t.Fatal("provisional selected rows survived Abort")
	}

	t.Run("missing selected page", func(t *testing.T) {
		ctx, cancel, selected, store := selectedProjectionFixture(t)
		defer cancel()
		ref := selected.image.root.RequiredSupport[0]
		key, err := format.Key(store.desc.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		selected.basis.reader.source = &constructedReadProbe{store: store, descriptor: store.Descriptor(),
			configuration: store.StoreConfiguration(), missingKey: key}
		probe := &fixedProjectionProbe{}
		fixed, result := emitReconstructionFixedParts(ctx, &selected, probe)
		if result != (Result{}) {
			t.Fatal("fixed selected bytes changed", result)
		}
		all, result := emitReconstructionSupportRows(ctx, &selected, probe, fixed)
		if result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject ||
			all.parts != fixed.parts || probe.commits != 0 || len(probe.parts) != int(fixed.parts) {
			t.Fatal("missing selected page became empty or complete", result, all)
		}
	})
	t.Run("shifted selected ordinal", func(t *testing.T) {
		ctx, cancel, selected, store := selectedProjectionFixture(t)
		defer cancel()
		selected.image.supportFacts = slices.Clone(selected.image.supportFacts)
		selected.image.supportFacts[0].ordinals = slices.Clone(selected.image.supportFacts[0].ordinals)
		selected.image.supportFacts[0].ordinals[0]++
		beforeReads, beforeCreates, beforeCAS := store.reads, store.creates, store.cas
		probe := &fixedProjectionProbe{}
		progress, result := emitReconstructionSupportRows(ctx, &selected, probe, reconstructionProjectionProgress{})
		if result.Outcome != AdmissionRefused || progress.parts != 0 || len(probe.parts) != 0 ||
			store.reads != beforeReads || store.creates != beforeCreates || store.cas != beforeCAS {
			t.Fatal("shifted selected ordinal reached Store or consumer", result, progress)
		}
	})
}

// full_only: false
func TestReconstructionProjectionRetainsNonemptySelectedConfiguration(t *testing.T) {
	setup := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, setup, env)
	f := newEnvironmentFixture(t, setup, run.env, []int{1}, false)
	run.suppliedSelection(f, append(f.session.currentEntryInputs(),
		suppliedSecret(t, env, "selected value", "selected source", custody.StandardValue)))
	store, ordinary := signedNonemptyOutputSelection(t, env, f.session)
	ctx, cancel := context.WithTimeout(setup, time.Minute)
	defer cancel()
	public, result := anchorPublicCandidate(ctx, candidateProbeForSelected(t, env, ordinary), env.Domain,
		&candidateQualifierProbe{}, nil)
	if result != (Result{}) {
		t.Fatal("public nonempty output anchor", result)
	}
	source := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
	basis, result := bindPublicReadBasis(ctx, public, source)
	if result != (Result{}) {
		t.Fatal("nonempty output read basis", result)
	}
	selected, result := completePublicSelection(ctx, basis, nil)
	if result != (Result{}) || !selected.complete {
		t.Fatal("nonempty output selected closure", result)
	}
	owner, result := beginReconstructionProjection(&selected)
	if result != (Result{}) {
		t.Fatal("nonempty output projection bound", result)
	}
	fixed, result := emitReconstructionFixedParts(ctx, &selected, owner)
	if result != (Result{}) {
		t.Fatal("nonempty output fixed parts", result)
	}
	all, result := emitReconstructionSupportRows(ctx, &selected, owner, fixed)
	if result != (Result{}) || all.parts != owner.partLimit {
		t.Fatal("nonempty selected support missing", result, all)
	}
	var outputCount int
	for _, part := range owner.parts[fixed.parts:] {
		if part.supportKind != contract.OutputConfigurationSliceSupportKind {
			continue
		}
		row, err := contract.InspectOutputConfigurationSlice(part.body)
		if err != nil || row.ConfigurationDigest != selected.image.root.OutputConfiguration.ConfigurationDigest ||
			row.SliceIndex != uint16(outputCount) || part.recordID.IsZero() ||
			part.ref.Kind != contract.RequiredSupportKind {
			t.Fatal("selected nonempty configuration changed in projection", err)
		}
		outputCount++
	}
	if outputCount != int(selected.image.root.OutputConfiguration.SliceCount) ||
		selected.image.root.OutputConfiguration.BindingCount != 1 {
		t.Fatal("nonempty selected output became an empty projection")
	}
	owner.Abort()
}

// full_only: false
func TestReconstructionProjectionRereadsAfterSelectedSupportRelease(t *testing.T) {
	ctx, cancel, selected, store := selectedProjectionFixture(t)
	defer cancel()
	if len(selected.image.cache) == 0 || len(selected.image.supportFacts) == 0 {
		t.Fatal("complete selected fixture has no retained reference facts")
	}
	beforeCreates, beforeCAS := store.creates, store.cas
	releasePublicSupportBodies(&selected)
	if selected.image.cache != nil {
		t.Fatal("complete selected image kept encoded child cache")
	}
	for _, page := range selected.image.support {
		if page.Records != nil {
			t.Fatal("complete selected image kept support row bodies")
		}
	}
	owner, result := beginReconstructionProjection(&selected)
	if result != (Result{}) {
		t.Fatal("fact-bound projection refused released support bodies", result)
	}
	defer owner.Abort()
	fixed, result := emitReconstructionFixedParts(ctx, &selected, owner)
	if result != (Result{}) {
		t.Fatal("fixed selected objects failed after support release", result)
	}
	all, result := emitReconstructionSupportRows(ctx, &selected, owner, fixed)
	if result != (Result{}) || all.parts != owner.partLimit {
		t.Fatal("exact selected support reread lost a row", result, all)
	}
	verifier := &reconstructionVerifyProbe{}
	observed := verifyReconstructionSelection(ctx, &selected,
		func(_ context.Context, _ contract.ReconstructionVerificationPins, _ time.Time) (reconstructionVerifier, error) {
			return verifier, nil
		})
	if observed.Outcome != ObservedCurrent || verifier.calls != 1 || verifier.closes != 1 ||
		store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("selected support release changed private verification or Store effects", observed)
	}
}

// The oracle reads the selected physical bodies and signed index spans. It does
// not use projection emitters or selected support facts to derive expected rows.
func assertReconstructionProjectionExact(t *testing.T, projection *ReconstructionProjection, selected *StateSession, store *memoryStore) {
	t.Helper()
	ctx := t.Context()
	fixed := fixedProjectionExpected(selected.root)
	configuration, err := contract.EncodeStoreConfiguration(store.StoreConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	var expected []reconstructionProjectionPart
	for i, part := range fixed {
		switch i {
		case 0:
			part.body = configuration
		case 1:
			part.body = selected.body
		case 2:
			part.ref = selected.head.Core.Root
			part.body = store.Read(ctx, mustKey(t, store.desc.Prefix, part.ref), part.ref.Length).Body
		default:
			read := store.Read(ctx, mustKey(t, store.desc.Prefix, part.ref), part.ref.Length)
			if read.Status != contract.ReadOK {
				t.Fatal("oracle selected body", read.Status)
			}
			part.body = read.Body
		}
		expected = append(expected, part)
	}
	for _, page := range selected.adminIndex.Pages {
		read := store.Read(ctx, mustKey(t, store.desc.Prefix, page.Ref), page.Ref.Length)
		if read.Status != contract.ReadOK {
			t.Fatal("oracle selected support page", read.Status)
		}
		physical, err := format.InspectRequiredSupportPage(read.Body)
		if err != nil {
			t.Fatal(err)
		}
		for _, span := range page.Spans {
			for ordinal := uint32(span.First); ordinal < uint32(span.First)+uint32(span.Count); ordinal++ {
				if ordinal >= uint32(len(physical.Records)) {
					t.Fatal("oracle span exceeds physical page")
				}
				row := physical.Records[ordinal]
				expected = append(expected, reconstructionProjectionPart{kind: reconstructionSupportRowPart, ref: page.Ref,
					physicalOrdinal: uint16(ordinal), supportKind: row.Kind, recordID: row.RecordID, body: row.Body})
			}
		}
	}
	if projection.PartCount() != len(expected) {
		t.Fatal("projection whole-set count", projection.PartCount(), len(expected))
	}
	children := map[format.Ref]bool{}
	for _, part := range expected {
		if part.kind == reconstructionRootPart || part.ref.Object.IsZero() {
			continue
		}
		children[part.ref] = true
	}
	childBytes := uint64(0)
	for ref := range children {
		if ref.Length > 2<<20 {
			t.Fatal("selected child exceeds physical ceiling")
		}
		childBytes += uint64(ref.Length)
	}
	if len(children) != int(selected.root.ChildCount) || childBytes != selected.root.ChildEncodedBytes {
		t.Fatal("unique selected child inventory", len(children), selected.root.ChildCount, childBytes, selected.root.ChildEncodedBytes)
	}
	var total uint64
	for i, want := range expected {
		got, ok := projection.CopyPart(i)
		if !ok || got.Kind != ReconstructionPartKind(want.kind) || got.Ref != want.ref || got.PhysicalOrdinal != want.physicalOrdinal || got.SupportKind != want.supportKind || got.RecordID != want.recordID || !bytes.Equal(got.Body, want.body) {
			t.Fatal("projection changed selected part", i, want.kind, want.supportKind)
		}
		total += uint64(len(got.Body))
	}
	if total > selected.root.ChildEncodedBytes+uint64(len(configuration)+len(selected.body))+uint64(selected.head.Core.Root.Length) || selected.root.ChildCount > contract.MaxChildPages {
		t.Fatal("projection exceeded selected physical bounds", total, selected.root.ChildEncodedBytes, selected.root.ChildCount)
	}
	provenance, ok := projection.Provenance()
	if !ok || provenance.Domain != selected.root.Domain || provenance.Snapshot != selected.root.Snapshot || provenance.Revision != selected.head.Core.Revision || provenance.HEADDigest != contract.Hash(selected.body) || provenance.HEADToken != selected.token {
		t.Fatal("projection changed exact selected provenance")
	}
}
