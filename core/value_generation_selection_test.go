package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedSelectedEntryState(t testing.TB) *StateSession {
	t.Helper()
	return generatedSelectedEntryOrigin(t, generatedVectorID(10), generatedVectorID(11), 0)
}

func generatedSelectedEntryOrigin(t testing.TB, operation, incarnation contract.ID, branch uint8) *StateSession {
	return generatedSelectedEntryOriginNamed(t, operation, incarnation, branch, "generated", generatedVectorID(9), generatedVectorID(12), operation)
}

func generatedSelectedEntryOriginNamed(t testing.TB, operation, incarnation contract.ID, branch uint8,
	name string, profile, account, token contract.ID) *StateSession {
	t.Helper()
	return generatedSelectedEntryOriginWithIntent(t, operation, incarnation, branch, name, profile, account, token,
		generatedVectorID(21), generatedVectorID(30), []byte("{}"))
}

func generatedSelectedEntryOriginWithIntent(t testing.TB, operation, incarnation contract.ID, branch uint8,
	name string, profile, account, token, generation, blob contract.ID, intent []byte) *StateSession {
	t.Helper()
	id := generatedVectorID
	fixture := generatedFixtureProfile{LifecycleMode: contract.GeneratorLifecycleManaged, ConfigContractID: profile, ResourceContractID: id(7)}
	intent = generatedFixtureCanonicalIntent(t, intent, fixture)
	intentID, err := contract.GeneratorIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	lineage, err := contract.GeneratorLineageID(id(1), operation, name, incarnation, 1, intentID)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := contract.GeneratorAttemptID(lineage, branch)
	if err != nil {
		t.Fatal(err)
	}
	transmission, err := contract.GeneratorTransmissionID(attempt, 1)
	if err != nil {
		t.Fatal(err)
	}
	result, err := contract.GeneratorResultID(id(1), operation, attempt, transmission, 1)
	if err != nil {
		t.Fatal(err)
	}
	material, err := contract.GeneratorMaterialID(id(1), operation)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := contract.GeneratorResourceID(id(1), operation, attempt)
	if err != nil {
		t.Fatal(err)
	}
	facts := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: contract.GeneratorActionCreate,
		LifecycleMode: contract.GeneratorLifecycleManaged, ResourceContractID: id(7), Disposition: contract.GeneratorDispositionCompleteCreate,
		Target: bytes.Clone(account[:]), ResourceData: bytes.Clone(token[:]), RequestDigest: id(14), IntentDigest: intentID}
	resourceDigest, err := contract.GeneratorResourceDigest(facts)
	if err != nil {
		t.Fatal(err)
	}
	factsBody, err := contract.EncodeGeneratorSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	factsDigest, err := contract.GeneratorSafeFactsDigest(facts)
	if err != nil {
		t.Fatal(err)
	}
	resultCore, err := contract.EncodeGeneratedResultCore(contract.GeneratedResultCore{Schema: contract.GeneratedResultCoreSchema, Profile: 2, DomainID: id(1), OperationID: operation,
		MaterialID: material, UsePlanDigest: id(15), PlanGraphID: id(16), AttemptID: attempt, TransmissionID: transmission, ResultID: result,
		ExecutorID: id(17), ConfigContractID: profile, DescriptorID: id(19), ResultContractID: id(20), RequestDigest: facts.RequestDigest, SafeFactsDigest: factsDigest})
	if err != nil {
		t.Fatal(err)
	}
	location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: intentID,
		BlobID: blob, Length: uint32(len(intent)), Digest: contract.Hash(intent)}
	logical, err := contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{location.Logical()})
	if err != nil {
		t.Fatal(err)
	}
	evidence := contract.GeneratedCreateEvidence{Schema: contract.GeneratedCreateEvidenceSchema, LifecycleMode: contract.GeneratorLifecycleManaged, OriginalResultID: result, CredentialRouteID: defaultGeneratedFixtureProfile().CredentialRouteID, ResultCore: resultCore, SafeFacts: factsBody, Intent: logical, CompletionClass: 1}
	evidenceBody, err := contract.EncodeGeneratedCreateEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidenceDescriptor, err := contract.GeneratedCreateEvidenceDescriptor(evidence)
	if err != nil {
		t.Fatal(err)
	}
	data, commitment, err := contract.GeneratorValueKeyIDs(generation)
	if err != nil {
		t.Fatal(err)
	}
	value, err := contract.EncodeCanonicalPayload(contract.CanonicalPayload{Profile: 2, CryptoSupportID: id(22), DataKeyID: data, CommitmentKeyID: commitment,
		DataKeyEpoch: 1, CommitmentKeyEpoch: 1, ContentLength: 3, Ciphertext: bytes.Repeat([]byte{23}, 19), InputEncoding: contract.InputEncodingRaw, RetainedLength: 3})
	if err != nil {
		t.Fatal(err)
	}
	entry := contract.ValueEntry{Name: name, Incarnation: incarnation, ValueState: generation, OriginSnapshot: id(24), OriginTransition: id(25), ValueSource: contract.Generated,
		ConfidentialityClass: contract.Secret, ValueBytes: value, Recipients: []contract.ID{id(26)}, Generated: contract.GeneratedEntryMetadata{Schema: contract.GeneratedEntryMetadataSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 1, ConfigContractID: profile,
			ResourceContractID: id(7), IntentDigest: intentID, ResourceIncarnationID: resource, OriginOperationID: operation, OriginAttemptID: attempt, GenerationID: generation,
			ResourceDigest: resourceDigest, CreateResultID: result, CreateEvidence: evidenceDescriptor,
			RequiredSupport: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), CompletionClass: 1, RetirementMode: 1}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len(value) - contract.CanonicalPayloadOverhead), RetainedLength: uint32(len(value) - contract.CanonicalPayloadOverhead)}
	s := generatedContentState(t, []generatedContentFixtureBlob{{blob, intent}}, []contract.GeneratorSliceLocation{location})
	generatedFixtureSelectedShell(t, s)
	generatedInitializeFixtureOutput(t, s)
	s.pages[0] = &format.ValueEntryPage{Domain: id(1), Object: id(31)}
	s.pages[0].Slots[0] = &entry
	s.root.Names = []format.NameEntry{{Name: entry.Name}}
	s.root.ValueEntryCount, s.root.Generated.GeneratedCurrent = 1, 1
	s.support = append(s.support, format.RequiredSupportPageView{Domain: id(1), Object: id(32), Index: uint16(len(s.support)),
		Records: []contract.SupportRecordView{{Kind: 13, RecordID: result, Body: evidenceBody}}})
	binding := generatedPublicBinding(t, 66)
	s.recipients[0].Slots[1] = &contract.RecipientRecord{RecipientID: entry.Recipients[0], Status: contract.CurrentRecipient, CurrentBinding: &binding}
	core, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, entry)
	if err != nil {
		t.Fatal(err)
	}
	contextID, err := contract.ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	bindingDigest, err := contract.PublicBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	s.access[0] = &format.AccessPage{Records: []contract.AccessRecord{{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: entry.ValueState,
		MaterialContextDigest: contextID, Wraps: []contract.WrapRow{{SubjectKind: 1, SubjectID: entry.Recipients[0], BindingID: binding.BindingID, BindingSerial: binding.BindingSerial,
			PublicBindingDigest: bindingDigest, RSACiphertext: bytes.Repeat([]byte{68}, 384)}}}}}
	generatedSealSelectedFixture(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("selected fixture material index")
	}

	return s
}

// full_only: false
func TestGeneratedSelectedMemberRootsExactDetachedEvidence(t *testing.T) {
	s := generatedSelectedEntryState(t)
	selected, err := s.selectedGeneratedWork(context.Background())
	if err != nil || selected == nil {
		t.Fatal("detached selected member refused", err)
	}
	for name, change := range map[string]func(*StateSession){
		"changed origin": func(s *StateSession) { s.pages[0].Slots[0].Generated.OriginOperationID = generatedVectorID(99) },
		"missing member": func(s *StateSession) {
			s.root.Names = nil
			s.root.ValueEntryCount = 0
			s.root.Generated.GeneratedCurrent = 0
		},
		"wrong count": func(s *StateSession) { s.root.Generated.GeneratedCurrent = 0 },
		"unresolved retirement": func(s *StateSession) {
			s.pages[0].Slots[0].Generated.RetiringDutyPresent = 1
			s.pages[0].Slots[0].Generated.RetiringDutyID = generatedVectorID(99)
		},
		"invented seed": func(s *StateSession) { s.root.Generated.Materials = 1 },
		"unrooted graph index": func(s *StateSession) {
			s.root.Generated.Graphs = contract.GeneratorDescriptor{Digest: generatedVectorID(99), Length: 40, Count: 1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := generatedSelectedEntryState(t)
			change(s)
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("unowned or mismatched generated support accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedSelectionCacheKeepsSessionAndRootScope(t *testing.T) {
	for _, condition := range []string{"same-session-root", "foreign-session", "different-root"} {
		t.Run(condition, func(t *testing.T) {
			state := generatedSelectedEntryState(t)
			selected, err := state.selectedGeneratedWork(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			root, valid := state.generatedSelectionRoot()
			if !valid {
				t.Fatal("invalid generated test root")
			}
			state.generatedWork = &validatedGeneratedSelection{session: state, root: root, selection: selected}
			switch condition {
			case "foreign-session":
				state.generatedWork.session = &StateSession{}
			case "different-root":
				state.generatedWork.root[0] ^= 1
			}
			got, err := state.selectedGeneratedWork(t.Context())
			if err != nil || got == nil || got.session != state || (got == selected) != (condition == "same-session-root") {
				t.Fatal("generated cache escaped its session/root relation", err)
			}
		})
	}
}

// full_only: false
func TestNormalSupportProspectiveEntriesRejectInvalidBindings(t *testing.T) {
	first := contract.GeneratedEntryMetadata{
		Schema: contract.GeneratedEntryMetadataSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 7,
		ConfigContractID: generatedVectorID(1), ResourceContractID: generatedVectorID(2), IntentDigest: generatedVectorID(3),
		ResourceIncarnationID: generatedVectorID(4), OriginOperationID: generatedVectorID(5), OriginAttemptID: generatedVectorID(6),
		GenerationID: generatedVectorID(7), ResourceDigest: generatedVectorID(9), CreateResultID: generatedVectorID(10),
		CreateEvidence:  contract.GeneratorDescriptor{Digest: generatedVectorID(11), Length: 453, Count: 1},
		RequiredSupport: contract.GeneratorDescriptor{Digest: generatedVectorID(12), Length: 4, Count: 0},
		CompletionClass: 1, RetirementMode: contract.GeneratedRetirementManual,
		RetiringDutyPresent: 1, RetiringDutyID: generatedVectorID(13),
	}
	second := first
	second.Epoch = 9
	second.GenerationID = generatedVectorID(14)
	second.CreateResultID = generatedVectorID(15)
	second.RetiringDutyPresent, second.RetiringDutyID = 0, contract.ID{}

	type bindingCase struct {
		name          string
		change        func(*Comparison)
		nilComparison bool
		want          []contract.GeneratedEntryMetadata
		wantErr       bool
	}
	cases := []bindingCase{
		{name: "nil comparison", nilComparison: true, wantErr: true},
		{name: "nil session", change: func(c *Comparison) { c.session = nil }, wantErr: true},
		{name: "empty", change: func(c *Comparison) { c.intent, c.slots = nil, nil }},
		{name: "supplied only", change: func(c *Comparison) {
			c.intent = []contract.CryptoIntentRow{{Name: "alpha", ValueSource: contract.Supplied, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}, {Name: "zulu", ValueSource: contract.Supplied, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}}
			c.slots = []uint16{17, contract.CryptoMaxValueEntries - 1}
		}},
		{name: "mixed supplied and generated", want: []contract.GeneratedEntryMetadata{first, second}},
		{name: "empty generated name", change: func(c *Comparison) {
			c.intent[0].Name, c.session.pages[1].Slots[1].Name = "", ""
		}, want: []contract.GeneratedEntryMetadata{first, second}},
		{name: "maximum name bytes", change: func(c *Comparison) {
			c.intent[2].Name = strings.Repeat("é", contract.CryptoMaxName/2)
			c.session.pages[contract.MaxValueEntryPages-1].Slots[format.PageSlots-1].Name = c.intent[2].Name
		}, want: []contract.GeneratedEntryMetadata{first, second}},
		{name: "missing slot", change: func(c *Comparison) { c.slots = c.slots[:2] }, wantErr: true},
		{name: "extra slot", change: func(c *Comparison) { c.slots = append(c.slots, 1) }, wantErr: true},
		{name: "slots without intents", change: func(c *Comparison) { c.intent = nil }, wantErr: true},
		{name: "duplicate generated slot", change: func(c *Comparison) { c.slots[2] = c.slots[0] }, wantErr: true},
		{name: "duplicate supplied slot", change: func(c *Comparison) {
			c.intent[0].ValueSource, c.intent[2].ValueSource = contract.Supplied, contract.Supplied
			c.slots[2] = c.slots[0]
		}, wantErr: true},
		{name: "generated slot one beyond limit", change: func(c *Comparison) {
			c.slots[2] = contract.CryptoMaxValueEntries
		}, wantErr: true},
		{name: "supplied slot one beyond limit", change: func(c *Comparison) {
			c.intent[2].ValueSource, c.slots[2] = contract.Supplied, contract.CryptoMaxValueEntries
		}, wantErr: true},
		{name: "largest uint16 slot", change: func(c *Comparison) { c.slots[2] = ^uint16(0) }, wantErr: true},
		{name: "missing generated page", change: func(c *Comparison) { c.session.pages[1] = nil }, wantErr: true},
		{name: "missing generated entry", change: func(c *Comparison) { c.session.pages[1].Slots[1] = nil }, wantErr: true},
		{name: "generated entry has another name", change: func(c *Comparison) {
			c.session.pages[1].Slots[1].Name = "another"
		}, wantErr: true},
		{name: "generated entry is supplied", change: func(c *Comparison) {
			c.session.pages[1].Slots[1].ValueSource = contract.Supplied
		}, wantErr: true},
		{name: "generated entry has invalid source", change: func(c *Comparison) {
			c.session.pages[1].Slots[1].ValueSource = 0
		}, wantErr: true},
		{name: "zero intent source", change: func(c *Comparison) { c.intent[1].ValueSource = 0 }, wantErr: true},
		{name: "unknown intent source", change: func(c *Comparison) { c.intent[1].ValueSource = 255 }, wantErr: true},
		{name: "invalid UTF-8 name", change: func(c *Comparison) { c.intent[1].Name = "\xff" }, wantErr: true},
		{name: "name one byte beyond limit", change: func(c *Comparison) {
			c.intent[1].Name = "m" + strings.Repeat("x", contract.CryptoMaxName)
		}, wantErr: true},
		{name: "multibyte name beyond byte limit", change: func(c *Comparison) {
			c.intent[2].Name = strings.Repeat("é", contract.CryptoMaxName/2+1)
			c.session.pages[contract.MaxValueEntryPages-1].Slots[format.PageSlots-1].Name = c.intent[2].Name
		}, wantErr: true},
		{name: "duplicate name", change: func(c *Comparison) { c.intent[1].Name = c.intent[0].Name }, wantErr: true},
		{name: "descending names with exact bindings", change: func(c *Comparison) {
			c.intent[0], c.intent[2] = c.intent[2], c.intent[0]
			c.slots[0], c.slots[2] = c.slots[2], c.slots[0]
		}, wantErr: true},
	}
	for _, count := range []int{contract.CryptoMaxValueEntries, contract.CryptoMaxValueEntries + 1} {
		cases = append(cases, bindingCase{
			name: fmt.Sprintf("supplied count %d", count), wantErr: count > contract.CryptoMaxValueEntries,
			change: func(c *Comparison) {
				c.intent, c.slots = make([]contract.CryptoIntentRow, count), make([]uint16, count)
				for i := range c.intent {
					c.intent[i] = contract.CryptoIntentRow{Name: fmt.Sprintf("entry-%03d", i), ValueSource: contract.Supplied, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0, OutputEncoding: contract.OutputEncodingRaw}
					c.slots[i] = uint16(i % contract.CryptoMaxValueEntries)
				}
			},
		})
	}
	for _, count := range []int{contract.GeneratedCurrentEntryLimit, contract.GeneratedCurrentEntryLimit + 1} {
		var want []contract.GeneratedEntryMetadata
		if count <= contract.GeneratedCurrentEntryLimit {
			want = make([]contract.GeneratedEntryMetadata, count)
			for i := range want {
				want[i] = first
				want[i].Epoch = uint64(i + 1)
			}
		}
		cases = append(cases, bindingCase{
			name: fmt.Sprintf("maximum total with generated count %d", count), want: want, wantErr: count > contract.GeneratedCurrentEntryLimit,
			change: func(c *Comparison) {
				c.intent, c.slots = make([]contract.CryptoIntentRow, contract.CryptoMaxValueEntries), make([]uint16, contract.CryptoMaxValueEntries)
				for i := range c.intent {
					name := fmt.Sprintf("entry-%03d", i)
					c.intent[i], c.slots[i] = contract.CryptoIntentRow{Name: name, ValueSource: contract.Supplied, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0, OutputEncoding: contract.OutputEncodingRaw}, uint16(i)
					if i >= count {
						continue
					}
					c.intent[i].ValueSource = contract.Generated
					page, slot := i/format.PageSlots, i%format.PageSlots
					if c.session.pages[page] == nil {
						c.session.pages[page] = &format.ValueEntryPage{}
					}
					metadata := first
					metadata.Epoch = uint64(i + 1)
					c.session.pages[page].Slots[slot] = &format.ValueEntry{Name: name, ValueSource: contract.Generated, Generated: metadata, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
				}
			},
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := &StateSession{}
			state.pages[1] = &format.ValueEntryPage{}
			state.pages[1].Slots[1] = &format.ValueEntry{Name: "alpha", ValueSource: contract.Generated, Generated: first, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
			state.pages[contract.MaxValueEntryPages-1] = &format.ValueEntryPage{}
			state.pages[contract.MaxValueEntryPages-1].Slots[format.PageSlots-1] = &format.ValueEntry{Name: "zulu", ValueSource: contract.Generated, Generated: second, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
			comparison := &Comparison{session: state,
				intent: []contract.CryptoIntentRow{{Name: "alpha", ValueSource: contract.Generated, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}, {Name: "middle", ValueSource: contract.Supplied, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}, {Name: "zulu", ValueSource: contract.Generated, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}},
				slots:  []uint16{17, 0, contract.CryptoMaxValueEntries - 1},
			}
			if tc.change != nil {
				tc.change(comparison)
			}
			if tc.nilComparison {
				comparison = nil
			}
			type predecessorEntry struct {
				entry    *format.ValueEntry
				metadata contract.GeneratedEntryMetadata
			}
			before := make(map[uint16]predecessorEntry)
			for pageIndex, page := range state.pages {
				if page == nil {
					continue
				}
				for rowIndex, entry := range page.Slots {
					if entry != nil {
						before[uint16(pageIndex*format.PageSlots+rowIndex)] = predecessorEntry{entry, entry.Generated}
					}
				}
			}
			checkPredecessor := func() {
				t.Helper()
				for slot, want := range before {
					entry := state.valueEntry(slot)
					if entry != want.entry || entry.Generated != want.metadata {
						t.Fatalf("prospective metadata changed predecessor slot %d", slot)
					}
				}
			}
			got, err := prospectiveNormalGeneratedEntryMetadata(comparison)
			checkPredecessor()
			if tc.wantErr {
				if err == nil || got != nil {
					t.Fatal("invalid prospective binding returned usable metadata", err)
				}
				return
			}
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatal("prospective metadata differs from exact intended generated entries", err)
			}
			for i := range got {
				got[i].Schema = 0
				got[i].Epoch++
				got[i].ConfigContractID[0] ^= 0xff
				got[i].CreateEvidence.Length++
			}
			checkPredecessor()
		})
	}
}

// full_only: false
func TestNormalSupportPlanningKeepsAuthenticatedPredecessorConfigurationFacts(t *testing.T) {
	before := generatedEmptyPredecessor(t)
	selected := *before
	if err := before.bindPreservedOutputConfiguration(&selected); err != nil {
		t.Fatal(err)
	}
	selected.support = slices.Clone(selected.support)
	selected.support[0].Records = slices.Clone(selected.support[0].Records)
	selected.support[0].Records[0].Body = nil
	for _, condition := range []string{"complete", "missing facts", "wrong ref", "wrong row"} {
		t.Run(condition, func(t *testing.T) {
			state := selected
			state.supportFacts = slices.Clone(selected.supportFacts)
			switch condition {
			case "missing facts":
				state.supportFacts = nil
			case "wrong ref":
				state.supportFacts[0].ref.Index++
			case "wrong row":
				state.supportFacts[0].rows = slices.Clone(state.supportFacts[0].rows)
				fragment := generatedMaterializerFragment(t, generatedVectorID(8), []byte("different opaque row"))
				fact, err := contract.InspectSupportRecordDigest(state.root.Domain, fragment)
				if err != nil {
					t.Fatal(err)
				}
				state.supportFacts[0].rows[0] = fact
			}
			comparison := &Comparison{session: &state, slots: []uint16{0}, added: []uint16{0},
				intent: []contract.CryptoIntentRow{{Name: "plain", Recipients: []contract.ID{state.admission.recipient},
					ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, ContentLength: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 1, OutputEncoding: contract.OutputEncodingRaw, PayloadLength: 1, PayloadDigest: contract.Hash([]byte("v"))}}}
			transition, err := state.generatedSupportTransition(t.Context(), comparison, nil)
			if condition != "complete" {
				if err == nil || transition != nil {
					t.Fatal("missing or mismatched predecessor facts admitted", condition)
				}
				return
			}
			if err != nil || transition == nil || transition.Inspect() != nil || len(transition.Records) != 1 ||
				transition.Records[0].Kind != contract.OutputConfigurationSliceSupportKind || transition.Records[0].Body != nil ||
				transition.RecordFacts[0] != selected.supportFacts[0].rows[0] {
				t.Fatal("normal planning lost exact metadata or retained configuration body", err)
			}
			entryMetadata, err := prospectiveNormalGeneratedEntryMetadata(comparison)
			if err != nil || len(entryMetadata) != 0 {
				t.Fatal("supplied-only intent acquired generated metadata", err)
			}
		})
	}
}
