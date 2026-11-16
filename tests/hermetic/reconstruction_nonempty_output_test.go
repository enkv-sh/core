package core

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestCompleteReconstructionKeepsNonemptySelectedOutput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	run.suppliedSelection(f, append(f.session.currentEntryInputs(),
		suppliedSecret(t, env, "selected value", "selected source", custody.StandardValue)))
	store, selected := signedNonemptyOutputSelection(t, env, f.session)
	public, result := anchorPublicCandidate(ctx, candidateProbeForSelected(t, env, selected), env.Domain,
		&candidateQualifierProbe{}, nil)
	if result.Outcome != 0 {
		t.Fatal("nonempty selected public anchor", result)
	}
	source := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
	basis, result := bindPublicReadBasis(ctx, public, source)
	if result.Outcome != 0 {
		t.Fatal("nonempty selected read basis", result)
	}
	creates, cas := store.creates, store.cas
	complete, result := completePublicSelection(ctx, basis, nil)
	if result.Outcome != 0 || complete.image.root.OutputConfiguration != selected.root.OutputConfiguration ||
		complete.image.root.OutputConfiguration.BindingCount != 1 ||
		!complete.image.selectedOutputComplete() ||
		store.creates != creates || store.cas != cas {
		t.Fatal("nonempty selected output became empty or caused an effect", result)
	}
}

// full_only: false
func TestCompleteReconstructionRefusesUnknownSelectedOutputRow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	run.suppliedSelection(f, append(f.session.currentEntryInputs(),
		suppliedSecret(t, env, "selected value", "selected source", custody.StandardValue)))
	goodStore, selected := signedNonemptyOutputSelection(t, env, f.session)
	store := selectedMemoryStoreCopy(goodStore)
	root := selected.root
	root.RequiredSupport = slices.Clone(root.RequiredSupport)
	index := selected.adminIndex
	index.Pages = slices.Clone(index.Pages)
	position := -1
	for i, page := range selected.supportFacts {
		for _, fact := range page.rows {
			if fact.Kind() == contract.OutputConfigurationSliceSupportKind {
				position = i
			}
		}
	}
	if position < 0 || len(index.Pages[position].Spans) != 1 || index.Pages[position].Spans[0].First != 0 {
		t.Fatal("fixture has no simple selected output page")
	}
	ref := root.RequiredSupport[position]
	key, err := format.Key(store.desc.Prefix, ref)
	if err != nil {
		t.Fatal(err)
	}
	physical, present := store.objects[key]
	if !present || len(physical.Body) <= contract.RequiredSupportPageHeaderLength {
		t.Fatal("signed selected output page missing")
	}
	altered := bytes.Clone(physical.Body)
	altered[contract.RequiredSupportPageHeaderLength] = 20 // Unknown support kind; the signed index still names kind 17.
	if _, err := format.InspectRequiredSupportPage(altered); err == nil {
		t.Fatal("unknown support row unexpectedly has a typed reader")
	}
	// The fixture signs an exact digest of malformed selected bytes. Reference
	// would reject those bytes before the complete reader can inspect them.
	changedRef := ref
	changedRef.Digest = contract.Hash(altered)
	changedRef.Length = uint32(len(altered))
	changedKey, err := format.Key(store.desc.Prefix, changedRef)
	if err != nil {
		t.Fatal(err)
	}
	store.put(changedKey, altered)
	root.RequiredSupport[position] = changedRef
	index.Pages[position].Ref = changedRef
	// Keep the signed public projection internally consistent with the index.
	// The physical row remains deliberately unknown and has no selected fact.
	facts := slices.Clone(selected.supportFacts)
	facts[position].ref = changedRef
	indexPages, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil || len(indexPages) != 1+len(root.AdministrativeIndexShards) {
		t.Fatal("unknown-row signed index", err)
	}
	root.AdministrativeIndex = indexPages[0].Ref
	for i := range root.AdministrativeIndexShards {
		root.AdministrativeIndexShards[i] = indexPages[i+1].Ref
	}
	for _, page := range indexPages {
		pageKey, err := format.Key(store.desc.Prefix, page.Ref)
		if err != nil {
			t.Fatal(err)
		}
		store.put(pageKey, page.Body)
	}
	updated := StateSession{root: root}
	updated.recountChildren()
	root = updated.root
	rootBody, err := format.EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	rootRef, err := format.Reference(format.RootKind, root.Domain, root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := format.Key(store.desc.Prefix, rootRef)
	if err != nil {
		t.Fatal(err)
	}
	store.put(rootKey, rootBody)
	head := selected.head
	head.Core.Root = rootRef
	image := selected.selectedImage()
	image.root, image.adminIndex, image.supportFacts = root, index, facts
	head.Subject.Normal.PublicState = image.publicState()
	if head.Subject.Normal.PublicState.Digest.IsZero() {
		t.Fatal("unknown-row public projection could not be signed")
	}
	coreBody, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	conditionalBody, err := format.EncodeConditionalPlan(conditional(head.Core, coreBody))
	if err != nil {
		t.Fatal(err)
	}
	head.Subject.HeadCore, head.Subject.HeadCoreLength = contract.Hash(coreBody), uint32(len(coreBody))
	head.Subject.ConditionalPlan = contract.Hash(conditionalBody)
	head.Subject.Request = requestCommitment(head.Core, head.Subject)
	request, err := contract.NewLifecycleRequest(head.Subject)
	if err != nil {
		t.Fatal(err)
	}
	proof := env.Trust.Sign(ctx, request)
	if proof.Reason != contract.ReasonNone {
		t.Fatal("unknown-row HEAD signing failed", proof.Reason)
	}
	head.AuthorizationSignature = proof.Signature
	headBody, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	store.put(store.desc.HeadKey, headBody)
	selected.head, selected.root, selected.body = head, root, headBody
	selected.token = store.objects[store.desc.HeadKey].Token
	public, result := anchorPublicCandidate(ctx, candidateProbeForSelected(t, env, selected), env.Domain,
		&candidateQualifierProbe{}, nil)
	if result.Outcome != 0 {
		t.Fatal("signed unknown-row public anchor", result)
	}
	source := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
	basis, result := bindPublicReadBasis(ctx, public, source)
	if result.Outcome != 0 {
		t.Fatal("signed unknown-row read basis", result)
	}
	creates, cas := store.creates, store.cas
	if _, result := completePublicSelection(ctx, basis, nil); result.Outcome != IntegrityFailure ||
		result.Reason != InvalidReference || store.creates != creates || store.cas != cas {
		t.Fatal("signed unknown selected output became an empty configuration", result)
	}
}

// full_only: false
func TestReconstructionRetainsPublicationObservationsAndWarnings(t *testing.T) {
	env, f, coordinate, marker := signedPublicationReadFixture(t)
	store := env.Store.(*memoryStore)
	root := f.session.root
	root.WarningBits = WarningOrphanGeneratedEffect | WarningDiscardedExactEvidence | WarningPossibleStoreGarbage | WarningLateDestructiveEffect | WarningPublicationOrderValue
	writer := &fixture{store: store, trust: env.Trust.(*fixtureTrust), admission: f.admission, session: f.session}
	storeContractRoot(t, writer, root, f.session.currentEntryInputs())
	selected, result := Open(t.Context(), f.admission, store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("signed retained warnings", result)
	}
	projection := reconstructProjectionFixture(t, env, selected, store)
	assertReconstructionProjectionExact(t, projection, selected, store)
	returned := reconstructionReturnedSession(t, projection, selected)
	if returned.root.WarningBits != root.WarningBits {
		t.Fatal("permanent warnings omitted")
	}
	var coordinates, markers int
	for i := 0; i < projection.PartCount(); i++ {
		part, _ := projection.CopyPart(i)
		switch part.SupportKind {
		case contract.PublicationCoordinateSupportKind:
			want, err := contract.EncodePublicationCoordinate(coordinate)
			if err != nil || !bytes.Equal(part.Body, want) {
				t.Fatal("retained coordinate/deletion details changed", err)
			}
			coordinates++
		case contract.PublicationMarkerSupportKind:
			want, err := contract.EncodePublicationMarker(marker)
			if err != nil || !bytes.Equal(part.Body, want) {
				t.Fatal("retained populated marker changed", err)
			}
			markers++
		}
	}
	if coordinates != 1 || markers != 1 || coordinate.BindingState != contract.PublicationBindingRetired || coordinate.DeletionDestinationID == "" {
		t.Fatal("fixture did not cover retired coordinate/deletion/marker", coordinates, markers)
	}
}

// full_only: false
func TestReconstructionMissingNonemptyOutputCannotComplete(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
	store, selected := signedNonemptyOutputSelection(t, env, f.session)
	var missing format.Ref
	for _, page := range selected.supportFacts {
		for _, row := range page.rows {
			if row.Kind() == contract.OutputConfigurationSliceSupportKind {
				missing = page.ref
			}
		}
	}
	if missing.Object.IsZero() {
		t.Fatal("missing-output fixture has no configuration")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	private := 0
	engine, err := NewInstalledReconstruction(ReconstructionInstallation{Candidate: candidateProbeForSelected(t, env, selected), Normal: &candidateQualifierProbe{},
		Construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
			return &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: configuration, missingKey: mustKey(t, store.desc.Prefix, missing)}, Result{}
		},
		Verify: func(ctx context.Context, pins contract.ReconstructionVerificationPins, deadline time.Time) (ReconstructionVerifier, error) {
			private++
			return env.Custody.ReconstructionVerifier(ctx, pins, deadline)
		}, CloseInstalled: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	projection, result := engine.Reconstruct(ctx)
	if projection != nil {
		projection.Close()
		t.Fatal("missing selected configuration exposed complete projection")
	}
	if result != (Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}) || private != 0 {
		t.Fatal("missing nonempty output reached private work or default empty", result, private)
	}
}
