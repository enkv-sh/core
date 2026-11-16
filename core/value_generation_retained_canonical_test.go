package core

import (
	"bytes"
	stdcontext "context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedCanonicalSource(t testing.TB) (contract.GeneratorDeclarationEntry, contract.RetainedCanonicalRecord) {
	t.Helper()
	id := generatedVectorID
	payload, err := contract.EncodeCanonicalPayload(contract.CanonicalPayload{Profile: 2, CryptoSupportID: contract.CryptoSupportID(),
		DataKeyID: id(86), DataKeyEpoch: 1, CommitmentKeyID: id(87), CommitmentKeyEpoch: 1, PackageCheck: id(88),
		ContentLength: 4, Ciphertext: bytes.Repeat([]byte{89}, 20), InputEncoding: contract.InputEncodingRaw, RetainedLength: 4})
	if err != nil {
		t.Fatal(err)
	}
	m := contract.ValueEntry{Name: "alpha", Incarnation: id(81), ValueState: id(82), OriginSnapshot: id(83), OriginTransition: id(84),
		ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, ValueBytes: payload, Recipients: []contract.ID{id(11)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len(payload) - contract.CanonicalPayloadOverhead), RetainedLength: uint32(len(payload) - contract.CanonicalPayloadOverhead)}
	for n := byte(100); n < 163; n++ {
		m.Recipients = append(m.Recipients, id(n))
	}
	r := contract.RetainedCanonicalRecord{OriginalSlot: 7, Entry: m}
	body, err := contract.EncodeRetainedCanonicalRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	return contract.GeneratorDeclarationEntry{InputEncoding: m.InputEncoding, OutputEncoding: m.OutputEncoding, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained, Name: m.Name,
		Recipients: []contract.ID{id(11)}, Payload: body}, r
}

func generatedSetDutyConsumersUnrefreshed(t testing.TB, s *StateSession, consumers []contract.GeneratorConsumer) {
	t.Helper()
	var duty contract.GeneratedDutyRecord
	for _, row := range s.supportRecords() {
		if row.Kind == 10 {
			var err error
			duty, err = contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	var bodies [][]byte
	for _, consumer := range consumers {
		body, err := contract.EncodeGeneratorConsumer(consumer)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
	}
	slices.SortFunc(bodies, bytes.Compare)
	descriptor, carriers := generatedVectorRows(t, 10, duty.DutyID, contract.GeneratorVectorConsumers, bodies)
	for i := range s.support {
		kept := s.support[i].Records[:0]
		for _, row := range s.support[i].Records {
			if row.Kind == contract.GeneratorVectorSupportKind {
				v, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if v.OwnerKind == 10 && v.OwnerID == duty.DutyID && v.VectorKind == contract.GeneratorVectorConsumers {
					continue
				}
			}
			kept = append(kept, row)
		}
		s.support[i].Records = kept
	}
	last := &s.support[len(s.support)-1]
	for _, row := range carriers {
		last.Records = append(last.Records, contract.SupportRecordView(row))
	}
	duty.Consumers = descriptor
	body, err := contract.EncodeGeneratedDutyRecord(duty)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 10, duty.DutyID, body)
	generatedRefreshPhaseSetsUnrefreshed(t, s)
}

func generatedSetDutyConsumers(t testing.TB, s *StateSession, consumers []contract.GeneratorConsumer, bundles ...contract.GeneratorPlanBundle) {
	t.Helper()
	generatedSetDutyConsumersUnrefreshed(t, s, consumers)
	if len(bundles) == 0 {
		bundles = generatedFixtureBundles(t, s)
	}
	generatedRepackSupport(t, s, s.supportRecords(), bundles)
}

func generatedCanonicalState(t testing.TB, recovery bool, generationNames ...string) (*StateSession, contract.RetainedCanonicalRecord, []contract.GeneratorConsumer) {
	t.Helper()
	id := generatedVectorID
	entry, retained := generatedCanonicalSource(t)
	if len(generationNames) == 0 {
		generationNames = []string{"generated"}
	}
	s := generatedReservationStateForNames(t, generationNames, entry)
	var consumers []contract.GeneratorConsumer
	var owner contract.ID
	for _, row := range s.supportRecords() {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		v, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		if v.OwnerKind == 10 && v.VectorKind == contract.GeneratorVectorConsumers {
			consumer, err := contract.InspectGeneratorConsumer(v.Row)
			if err != nil {
				t.Fatal(err)
			}
			owner = v.OwnerID
			consumers = append(consumers, consumer)
		}
	}
	core, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, retained.Entry)
	if err != nil {
		t.Fatal(err)
	}
	context, err := contract.ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	consumers = append(consumers, contract.GeneratorConsumer{Schema: 1, OwnerID: owner, MaterialID: core.ValueStateID,
		ContextDigest: context, SubjectKind: 2, SubjectID: core.ValueStateID, Purpose: 2})
	last := &s.support[len(s.support)-1]
	last.Records = append(last.Records, contract.SupportRecordView{Kind: 6, RecordID: core.ValueStateID, Body: entry.Payload})
	current := retained.Entry
	current.Recipients = []contract.ID{id(11)}
	for n := byte(163); n < 226; n++ {
		current.Recipients = append(current.Recipients, id(n))
	}
	s.pages[0] = &format.ValueEntryPage{Domain: s.root.Domain, Object: id(90)}
	s.pages[0].Slots[retained.OriginalSlot] = &current
	s.root.Names, s.root.ValueEntryCount, s.root.SecretCount = []format.NameEntry{{Name: current.Name, Slot: retained.OriginalSlot}}, 1, 1
	access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: 1, MaterialID: core.ValueStateID, MaterialContextDigest: context, PackageCheck: id(88)}
	readers := append(slices.Clone(retained.Entry.Recipients), current.Recipients[1:]...)
	for i, reader := range readers {
		binding := generatedPublicBinding(t, byte(i+1))
		if s.root.CurrentAccess.Core.Provider == contract.AWS {
			binding.Provider, binding.ProtectionClass = contract.AWS, contract.HardwareProtection
			binding.KeySelector = fmt.Sprintf("arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-%012d", 1000+i)
		}
		if reader == id(11) {
			binding = *s.recipients[0].Slots[0].CurrentBinding
		} else {
			// Reader key identities must not collide with the fixture's value,
			// authority or other selected IDs when the full closure is checked.
			binding.BindingID = contract.Hash(append([]byte("canonical fixture reader binding/v1"), reader[:]...))
			binding.BindingIncarnationID = contract.Hash(append([]byte("canonical fixture reader incarnation/v1"), reader[:]...))
			page, slot := i/8, i%8
			if s.recipients[page] == nil {
				s.recipients[page] = &format.RecipientPage{Domain: s.root.Domain, Object: generatedFixtureChildID(s, contract.RecipientKind, uint16(page)), Index: uint16(page)}
			}
			s.recipients[page].Slots[slot] = &contract.RecipientRecord{RecipientID: reader, Status: contract.CurrentRecipient, CurrentBinding: &binding}
		}
		digest, err := contract.PublicBindingDigest(binding)
		if err != nil {
			t.Fatal(err)
		}
		access.Wraps = append(access.Wraps, contract.WrapRow{SubjectKind: 1, SubjectID: reader, BindingID: binding.BindingID,
			BindingSerial: binding.BindingSerial, PublicBindingDigest: digest, RSACiphertext: bytes.Repeat([]byte{91}, 384)})
	}
	if recovery {
		binding := generatedPublicBinding(t, 92)
		binding.Provider, binding.ProtectionClass = contract.AWS, contract.HardwareProtection
		binding.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000092"
		binding, signing := generatedFixtureIndependentRecovery(t, s, binding, "canonical fixture recovery signing binding/v1")
		digest, err := contract.PublicBindingDigest(binding)
		if err != nil {
			t.Fatal(err)
		}
		s.root.CurrentAccess.Core.Recovery = &contract.RecoveryBindings{RoleID: id(93), Signing: signing, KMS: binding}
		wrap := contract.WrapRow{SubjectKind: 2, SubjectID: id(93), BindingID: binding.BindingID, BindingSerial: 1,
			PublicBindingDigest: digest, RSACiphertext: bytes.Repeat([]byte{94}, 384)}
		access.Wraps = append(access.Wraps, wrap)
		s.access[0].Records[0].Wraps = append(s.access[0].Records[0].Wraps, wrap)
	}
	s.access[0].Records = append(s.access[0].Records, access)
	s.root.AccessRecordCount++
	generatedSetDutyConsumers(t, s, consumers)
	generatedSealSelectedFixture(t, s)
	// The registry is an explicit fixture input. Keep the public admission
	// basis complete, including recovery, rather than retaining the shell's
	// one-recipient descriptor after adding selected readers.
	basis, err := contract.DecodeGenesisDescriptorCore(s.admission.descriptor)
	if err != nil {
		t.Fatal("canonical fixture public basis", err)
	}
	basis.Recipients, basis.Recovery = s.registry(), s.root.CurrentAccess.Core.Recovery
	s.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(basis)
	if err != nil {
		t.Fatal("canonical fixture public registry", err)
	}
	if !s.indexSelectedMaterials() {
		t.Fatal("material index")
	}
	return s, retained, consumers
}

// full_only: false
func TestGeneratedCanonicalConsumerPreservesExactOriginalAndReaderUnion(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		s, retained, _ := generatedCanonicalState(t, recovery)
		selected, err := s.selectedGeneratedWork(stdcontext.Background())
		if err != nil {
			t.Fatal("valid canonical consumer with 127 ordinary readers refused", err)
		}
		key := materialIdentity{1, retained.Entry.ValueState}
		if !selected.materials[key] || len(selected.consumers[key]) != 1 || len(selected.materials) != 2 {
			t.Fatal("canonical consumer or shared access missing")
		}
		if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.access[0].Records); coverageErr != nil {
			t.Fatal("canonical consumer or shared access missing")
		}
		owner := generatedRecordKey{10, selected.consumers[key][0].OwnerID}
		reader := retained.Entry.Recipients[1]
		selection, err := selected.canonicalConsumer(owner, key.id, reader)
		if err != nil || !reflect.DeepEqual(selection.Record, retained) ||
			!reflect.DeepEqual(selection.Selection.Entry, retained.Entry) || selection.Selection.Binding.SubjectID != reader ||
			selection.Selection.Slot != retained.OriginalSlot || selection.Selection.Access.MaterialID != retained.Entry.ValueState {
			t.Fatal("retained reader did not get the exact original member", err)
		}
		if _, err := selected.canonicalConsumer(owner, key.id, generatedVectorID(163)); err == nil {
			t.Fatal("current-only reader acquired retained consumer authority")
		}
		for _, wrong := range []generatedRecordKey{{11, owner.id}, {10, generatedVectorID(99)}, {6, key.id}} {
			if _, err := selected.canonicalConsumer(wrong, key.id, reader); err == nil {
				t.Fatal("unrelated owner acquired retained consumer authority")
			}
		}
		if _, err := selected.canonicalConsumer(owner, generatedVectorID(99), reader); err == nil {
			t.Fatal("owner acquired a different retained value")
		}
		selection.Record.Entry.ValueBytes[0] ^= 1
		selection.Selection.Access.Wraps[0].RSACiphertext[0] ^= 1
		selection.Selection.Binding.Binding.SPKI[0] ^= 1
		selection.Owner.Body[0] ^= 1
		selection.Consumers[0][0] ^= 1
		if _, err := s.selectedGeneratedWork(stdcontext.Background()); err != nil {
			t.Fatal("consumer output aliased the selected state", err)
		}
	}
}

// full_only: false
func TestGeneratedCanonicalConsumerDoesNotSubstituteNewerCurrentValue(t *testing.T) {
	s, retained, _ := generatedCanonicalState(t, false)
	current := *s.pages[0].Slots[retained.OriginalSlot]
	current.ValueState, current.OriginSnapshot, current.OriginTransition = generatedVectorID(240), generatedVectorID(241), generatedVectorID(242)
	core, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, current)
	if err != nil {
		t.Fatal(err)
	}
	access := *generatedFixtureMaterialAccess(t, s, contract.ValueMaterialKind, generatedVectorID(82))
	access.MaterialID = core.ValueStateID
	access.MaterialContextDigest, err = contract.ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	access.Wraps = slices.DeleteFunc(slices.Clone(access.Wraps), func(row contract.WrapRow) bool {
		return !slices.Contains(current.Recipients, row.SubjectID)
	})
	generatedFixtureMaterialAccess(t, s, contract.ValueMaterialKind, generatedVectorID(82)).Wraps = slices.DeleteFunc(slices.Clone(generatedFixtureMaterialAccess(t, s, contract.ValueMaterialKind, generatedVectorID(82)).Wraps), func(row contract.WrapRow) bool {
		return !slices.Contains(retained.Entry.Recipients, row.SubjectID)
	})
	s.access[0].Records = append(s.access[0].Records, access)
	s.root.AccessRecordCount++
	s.pages[0].Slots[retained.OriginalSlot] = nil
	s.pages[0].Slots[9] = &current
	s.root.Names[0].Slot = 9
	generatedSealSelectedFixture(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("material index")
	}
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal("separate retained and current values", err)
	}
	key := materialIdentity{1, retained.Entry.ValueState}
	owner := generatedRecordKey{10, g.consumers[key][0].OwnerID}
	selection, err := g.canonicalConsumer(owner, key.id, retained.Entry.Recipients[1])
	if err != nil || !reflect.DeepEqual(selection.Record, retained) || selection.Selection.Core.ValueStateID != key.id ||
		selection.Selection.Slot != retained.OriginalSlot || selection.Selection.Access.MaterialID != key.id {
		t.Fatal("retained consumer substituted the new value or current slot", err)
	}
	if _, err := g.canonicalConsumer(owner, current.ValueState, current.Recipients[0]); err == nil {
		t.Fatal("current value became the owner's retained source")
	}
}

// full_only: false
func TestGeneratedConsumerRequiresAdmittedSessionBeforeEffects(t *testing.T) {
	for _, session := range []*StateSession{nil, {store: refusalBoundary{t: t}}} {
		selection, result := session.generatedConsumerSelection(stdcontext.Background(), 10, generatedVectorID(1), generatedVectorID(2), generatedVectorID(3))
		if result != refused(AdmissionInvalid) || !reflect.DeepEqual(selection, contract.GeneratedCanonicalSelection{}) {
			t.Fatalf("unadmitted generated consumer: result=%+v", result)
		}
	}
}

// full_only: false
func TestGeneratedActiveConsumerCannotAddAnUndeclaredCanonicalSource(t *testing.T) {
	occupied, retained, consumers := generatedCanonicalState(t, false)
	s := generatedReservationState(t)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.root.Names = occupied.root.Names
	s.root.ValueEntryCount, s.root.SecretCount, s.root.AccessRecordCount = occupied.root.ValueEntryCount, occupied.root.SecretCount, occupied.root.AccessRecordCount
	s.recipients, s.pages = occupied.recipients, occupied.pages
	s.access[0].Records = append(s.access[0].Records, *generatedFixtureMaterialAccess(t, occupied, contract.ValueMaterialKind, retained.Entry.ValueState))
	body, err := contract.EncodeRetainedCanonicalRecord(retained)
	if err != nil {
		t.Fatal(err)
	}
	s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records,
		contract.SupportRecordView{Kind: 6, RecordID: retained.Entry.ValueState, Body: body})
	generatedSetDutyConsumers(t, s, consumers, g.bundles...)
	generatedSealSelectedFixture(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("material index")
	}
	if _, err := format.EncodeRoot(s.root); err != nil {
		t.Fatal("undeclared-source fixture Root must be valid", err)
	}
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
		t.Fatal("active Duty added a canonical source outside its fixed declaration")
	}
}

// full_only: false
func TestGeneratedCanonicalConsumerRejectsRepinnedWrongSource(t *testing.T) {
	for name, change := range map[string]func(*StateSession, *contract.RetainedCanonicalRecord, *[]contract.GeneratorConsumer){
		"missing consumer": func(_ *StateSession, _ *contract.RetainedCanonicalRecord, rows *[]contract.GeneratorConsumer) {
			*rows = (*rows)[:2]
		},
		"wrong owner": func(_ *StateSession, _ *contract.RetainedCanonicalRecord, rows *[]contract.GeneratorConsumer) {
			(*rows)[2].OwnerID = generatedVectorID(99)
		},
		"wrong context": func(_ *StateSession, _ *contract.RetainedCanonicalRecord, rows *[]contract.GeneratorConsumer) {
			(*rows)[2].ContextDigest = generatedVectorID(99)
		},
		"wrong material": func(_ *StateSession, _ *contract.RetainedCanonicalRecord, rows *[]contract.GeneratorConsumer) {
			(*rows)[2].MaterialID = generatedVectorID(99)
		},
		"wrong slot": func(_ *StateSession, r *contract.RetainedCanonicalRecord, _ *[]contract.GeneratorConsumer) {
			r.OriginalSlot++
		},
		"wrong original readers": func(_ *StateSession, r *contract.RetainedCanonicalRecord, _ *[]contract.GeneratorConsumer) {
			r.Entry.Recipients = r.Entry.Recipients[:1]
		},
		"changed current ciphertext": func(s *StateSession, _ *contract.RetainedCanonicalRecord, _ *[]contract.GeneratorConsumer) {
			s.pages[0].Slots[7].ValueBytes = bytes.Clone(s.pages[0].Slots[7].ValueBytes)
			s.pages[0].Slots[7].ValueBytes[len(s.pages[0].Slots[7].ValueBytes)-1] ^= 1
		},
		"missing old reader wrap": func(s *StateSession, _ *contract.RetainedCanonicalRecord, _ *[]contract.GeneratorConsumer) {
			generatedFixtureMaterialAccess(t, s, contract.ValueMaterialKind, generatedVectorID(82)).Wraps = append(generatedFixtureMaterialAccess(t, s, contract.ValueMaterialKind, generatedVectorID(82)).Wraps[:1], generatedFixtureMaterialAccess(t, s, contract.ValueMaterialKind, generatedVectorID(82)).Wraps[2:]...)
		},
		"stale reader binding": func(s *StateSession, _ *contract.RetainedCanonicalRecord, _ *[]contract.GeneratorConsumer) {
			generatedFixtureMaterialAccess(t, s, contract.ValueMaterialKind, generatedVectorID(82)).Wraps[1].BindingSerial++
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, retained, consumers := generatedCanonicalState(t, true)
			g, err := s.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal(err)
			}
			if (name == "missing consumer" || name == "wrong material") && generatedIndexRejectsAlteredSupport(t, s) {
				t.Fatal("valid canonical fixture was refused before the changed consumer relation")
			}
			change(s, &retained, &consumers)
			body, err := contract.EncodeRetainedCanonicalRecord(retained)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 6, retained.Entry.ValueState, body)
			switch name {
			case "wrong owner":
				// This mutation has no authentic owner. Exercise the selected-work
				// validator directly; a valid administrative index cannot be built.
				generatedSetDutyConsumersUnrefreshed(t, s, consumers)
				s.generatedWork = nil
			case "missing consumer":
				// No selected consumer owns the retained row, so index construction
				// refuses it before complete selected-work admission.
				generatedSetDutyConsumersUnrefreshed(t, s, consumers)
				if !generatedIndexRejectsAlteredSupport(t, s) {
					t.Fatal("changed canonical consumer acquired authenticated ownership")
				}
				return
			default:
				generatedSetDutyConsumers(t, s, consumers, g.bundles...)
			}
			if !s.indexSelectedMaterials() {
				t.Fatal("material index")
			}
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
				t.Fatal("unowned or changed canonical source accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedDeleteDeclarationChecksCurrentCanonicalWithoutRetainingIt(t *testing.T) {
	for _, operation := range []uint16{contract.OperationCleanOwnedFailureResidue, contract.OperationRetireGeneratedGeneration} {
		for _, recovery := range []bool{false, true} {
			for _, condition := range []string{"current only", "historical consumer", "wrong slot", "unindexed populated slot", "wrong incarnation", "wrong value", "changed ciphertext", "changed recipients", "missing access", "stale access binding", "create requires retained support"} {
				t.Run(fmt.Sprintf("operation=%d/recovery=%t/%s", operation, recovery, condition), func(t *testing.T) {
					state, historical, consumers := generatedCanonicalState(t, recovery)
					selected, err := state.selectedGeneratedWork(t.Context())
					if err != nil {
						t.Fatal("authenticated canonical predecessor", err)
					}
					current := *state.valueEntry(historical.OriginalSlot)
					current.Recipients = slices.Clone(current.Recipients)
					current.ValueBytes = bytes.Clone(current.ValueBytes)
					record := contract.RetainedCanonicalRecord{OriginalSlot: historical.OriginalSlot, Entry: current}
					facts := *selected
					facts.bundles = slices.Clone(selected.bundles)
					facts.bundles[0].Request.OperationKind = operation
					facts.records = maps.Clone(selected.records)
					facts.canonical = make(map[contract.ID]generatedCanonical)
					facts.consumers = make(map[materialIdentity][]contract.GeneratorConsumer)
					key := generatedRecordKey{kind: contract.RetainedCanonicalSupportKind, id: historical.Entry.ValueState}
					if condition != "historical consumer" {
						delete(facts.records, key)
					}
					switch condition {
					case "wrong slot":
						record.OriginalSlot++
					case "unindexed populated slot":
						record.OriginalSlot++
						image := *facts.image
						page := *image.pages[0]
						page.Slots[record.OriginalSlot] = &current
						image.pages[0] = &page
						facts.image = &image
					case "wrong incarnation":
						record.Entry.Incarnation = generatedVectorID(240)
					case "wrong value":
						record.Entry.ValueState = generatedVectorID(240)
					case "changed ciphertext":
						record.Entry.ValueBytes[len(record.Entry.ValueBytes)-1] ^= 1
					case "changed recipients":
						record.Entry.Recipients = record.Entry.Recipients[:len(record.Entry.Recipients)-1]
					case "missing access":
						facts.selectedMaterials.accessLocations = maps.Clone(facts.selectedMaterials.accessLocations)
						delete(facts.selectedMaterials.accessLocations, materialIdentity{contract.ValueMaterialKind, current.ValueState})
					case "stale access binding":
						generatedFixtureMaterialAccess(t, state, contract.ValueMaterialKind, current.ValueState).Wraps[1].BindingSerial++
					case "create requires retained support":
						facts.bundles[0].Request.OperationKind = selected.bundles[0].Request.OperationKind
					}
					payload, err := contract.EncodeRetainedCanonicalRecord(record)
					if err != nil {
						t.Fatal("bounded canonical declaration record", err)
					}
					declaration, err := contract.EncodeGeneratorDeclaration(contract.GeneratorDeclaration{Schema: 1,
						DomainID: state.root.Domain, OperationID: selected.parent.OperationID,
						Entries: []contract.GeneratorDeclarationEntry{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
							Name: record.Entry.Name, Recipients: slices.Clone(record.Entry.Recipients), Payload: payload}}})
					if err != nil {
						t.Fatal("bounded current declaration", err)
					}
					blob := contract.Hash(declaration)
					location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentDeclaration,
						ContentID: selected.parent.OperationID, BlobID: blob, Length: uint32(len(declaration)), Digest: blob}
					contentState := generatedContentState(t, []generatedContentFixtureBlob{{id: blob, body: declaration}}, []contract.GeneratorSliceLocation{location})
					content, err := newGeneratedContentValidation(t.Context(), contentState)
					if err != nil {
						t.Fatal("bounded declaration content", err)
					}
					builder := &generatedSelectionBuilder{facts: &facts, content: content, claimed: make(map[generatedRecordKey]bool)}
					err = builder.resolveActiveCanonicals()
					wantErr := condition != "current only" && condition != "historical consumer"
					if (err != nil) != wantErr {
						t.Fatal("current-only canonical declaration boundary", condition, err)
					}
					if len(facts.canonical) != 0 || builder.recordClaimed(key) || len(facts.consumers) != 0 {
						t.Fatal("current declaration invented retained work or a support claim")
					}
					if condition == "historical consumer" {
						consumer := consumers[len(consumers)-1]
						if err := builder.claimCanonicalConsumer(contract.GeneratedDutySupportKind, consumer.OwnerID, false, consumer); err != nil {
							t.Fatal("independent historical canonical consumer", err)
						}
						retained := facts.canonical[historical.Entry.ValueState].record
						if len(facts.canonical) != 1 || !builder.recordClaimed(key) || !slices.Equal(retained.Entry.Recipients, historical.Entry.Recipients) ||
							!sameRetainedEntryValue(retained.Entry, historical.Entry) || len(facts.consumers[materialIdentity{contract.ValueMaterialKind, historical.Entry.ValueState}]) != 1 {
							t.Fatal("current declaration replaced the historical value or its reader union")
						}
					}
				})
			}
		}
	}
}
