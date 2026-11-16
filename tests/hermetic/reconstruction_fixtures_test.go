package core

import (
	"context"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	"testing"
	"time"
)

func selectedProjectionFixture(t *testing.T) (context.Context, context.CancelFunc, publicSelection, *memoryStore) {
	t.Helper()
	setup := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, setup, env)
	f := newEnvironmentFixture(t, setup, run.env, []int{1}, false)
	run.suppliedSelection(f, append(f.session.currentEntryInputs(),
		suppliedSecret(t, env, "projected secret", "private observation", custody.StandardValue)))
	ctx, cancel := context.WithTimeout(setup, time.Minute)
	public, result := anchorPublicCandidate(ctx, candidateProbeForSelected(t, env, f.session), env.Domain,
		&candidateQualifierProbe{}, nil)
	if result.Outcome != 0 {
		cancel()
		t.Fatal("public anchor", result)
	}
	store := env.Store.(*memoryStore)
	source := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
	basis, result := bindPublicReadBasis(ctx, public, source)
	if result.Outcome != 0 {
		cancel()
		t.Fatal("normal read basis", result)
	}
	selected, result := completePublicSelection(ctx, basis, nil)
	if result.Outcome != 0 || !selected.complete {
		cancel()
		t.Fatal("complete selected image", result)
	}
	return ctx, cancel, selected, store
}

func fixedProjectionExpected(root format.Root) []reconstructionProjectionPart {
	parts := []reconstructionProjectionPart{{kind: reconstructionConfigurationPart},
		{kind: reconstructionHEADPart}, {kind: reconstructionRootPart}}
	for _, ref := range root.ValueEntryPages {
		if ref != nil {
			parts = append(parts, reconstructionProjectionPart{kind: reconstructionValuePagePart, ref: *ref})
		}
	}
	for _, ref := range root.Recipients {
		if ref != nil {
			parts = append(parts, reconstructionProjectionPart{kind: reconstructionRecipientPagePart, ref: *ref})
		}
	}
	for _, ref := range root.CurrentAccess.Core.AccessPageRefs {
		parts = append(parts, reconstructionProjectionPart{kind: reconstructionAccessPagePart, ref: ref})
	}
	parts = append(parts, reconstructionProjectionPart{kind: reconstructionIndexPagePart, ref: root.AdministrativeIndex})
	for _, ref := range root.AdministrativeIndexShards {
		parts = append(parts, reconstructionProjectionPart{kind: reconstructionIndexPagePart, ref: ref})
	}
	return parts
}

// Use the current configuration/publication fixture writer on a small image.
func signedNonemptyOutputSelection(t *testing.T, env fixtureEnvironment, selected *StateSession) (*memoryStore, *StateSession) {
	t.Helper()
	var member contract.ID
	for slot := 0; slot < contract.CryptoMaxValueEntries; slot++ {
		if entry := selected.valueEntry(uint16(slot)); entry != nil {
			member = entry.Incarnation
			break
		}
	}
	if member.IsZero() {
		t.Fatal("nonempty output requires a selected entry")
	}
	configuration := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: selected.root.Domain,
		Bindings: []contract.OutputBinding{{IncarnationID: fixtureID(selected.root.Domain, "reconstruction output incarnation"), DestinationID: "selected-destination", Destination: contract.OutputDestination{ConfigContractID: "profile", ServiceContractID: "selected-provider", CanonicalSettings: hermeticDestinationSettings([][2]string{{"a", "a"}, {"b", "b"}, {"c", "c"}}), Policy: contract.OutputPolicy{}, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot)}, Targets: []contract.OutputTarget{{EntryIncarnationID: member, ServiceContractID: "selected-provider", CanonicalTarget: "provider/selected", ConsumerLocator: "consumer/selected", TargetContractID: "fixture/target/v1", TargetData: []byte("target:provider/selected"), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot), CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: contract.OutputPolicy{}}}}},
		Routes:   []contract.OutputRoute{{EntryIncarnationID: member, Destinations: []string{"selected-destination"}}}}
	return signedCapacityConfigurationImage(t, env, selected, selected, "reconstruction nonempty", false, configuration)
}

func reconstructProjectionFixture(t *testing.T, env fixtureEnvironment, selected *StateSession, store *memoryStore) *ReconstructionProjection {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	engine, err := NewInstalledReconstruction(ReconstructionInstallation{
		Candidate: candidateProbeForSelected(t, env, selected), Normal: &candidateQualifierProbe{},
		Construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
			return &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: configuration}, Result{}
		},
		Verify: func(ctx context.Context, pins contract.ReconstructionVerificationPins, deadline time.Time) (ReconstructionVerifier, error) {
			return env.Custody.ReconstructionVerifier(ctx, pins, deadline)
		}, CloseInstalled: func() {},
	})
	if err != nil {
		t.Fatal("projection installation", err)
	}
	defer engine.Close()
	creates, cas := store.creates, store.cas
	projection, result := engine.Reconstruct(ctx)
	if result.Outcome != ObservedCurrent || projection == nil || store.creates != creates || store.cas != cas {
		if projection != nil {
			projection.Close()
		}
		t.Fatal("complete owned reconstruction", result)
	}
	t.Cleanup(projection.Close)
	return projection
}

// Fresh page owners are decoded only from the returned projection. The ordinary
// test admission is used solely for the independent private content oracle.
func reconstructionReturnedSession(t *testing.T, projection *ReconstructionProjection, basis *StateSession) *StateSession {
	t.Helper()
	returned := *basis
	returned.pages = [contract.MaxValueEntryPages]*format.ValueEntryPage{}
	returned.recipients = [contract.MaxRecipientPages]*format.RecipientPage{}
	returned.access = [contract.MaxChildPages]*format.AccessPage{}
	returned.support = nil
	returned.cache = nil
	support := make(map[format.Ref]*format.RequiredSupportPageView)
	for i := 0; i < projection.PartCount(); i++ {
		part, ok := projection.CopyPart(i)
		if !ok {
			t.Fatal("returned part missing", i)
		}
		var err error
		switch part.Kind {
		case ReconstructionHEADPart:
			returned.body = part.Body
			returned.head, err = format.DecodeHead(part.Body)
		case ReconstructionRootPart:
			returned.root, err = format.DecodeRoot(part.Body)
		case ReconstructionValuePagePart:
			page, e := format.DecodeValueEntryPage(part.Body)
			err = e
			returned.pages[page.Index] = &page
		case ReconstructionRecipientPagePart:
			page, e := format.DecodeRecipientPage(part.Body)
			err = e
			returned.recipients[page.Index] = &page
		case ReconstructionAccessPagePart:
			page, e := format.DecodeAccessPage(part.Body)
			err = e
			returned.access[page.Index] = &page
		case ReconstructionSupportRowPart:
			page := support[part.Ref]
			if page == nil {
				page = &format.RequiredSupportPageView{Domain: returned.root.Domain, Object: part.Ref.Object, Index: part.Ref.Index}
				support[part.Ref] = page
			}
			page.Records = append(page.Records, contract.SupportRecordView{Kind: part.SupportKind, RecordID: part.RecordID, Body: part.Body})
		}
		if err != nil {
			t.Fatal("returned selected body", part.Kind, err)
		}
	}
	for _, ref := range returned.root.RequiredSupport {
		page := support[ref]
		if page == nil {
			t.Fatal("returned support page missing")
		}
		returned.support = append(returned.support, *page)
	}
	if !returned.indexSelectedMaterials() {
		t.Fatal("returned value/access relations incomplete")
	}
	return &returned
}
