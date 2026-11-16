package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// The complete scan receives a source with no mutation or admission methods.
type selectedImageReadOnlySource struct{ store contract.Store }

func (s selectedImageReadOnlySource) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	return s.store.Read(ctx, key, limit)
}

// full_only: false
func TestCompleteSelectedImageUsesReadOnlySource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{0}, false)
	run.suppliedSelection(f, append(f.session.currentEntryInputs(),
		suppliedSecret(t, env, "selected secret", "selected material source", custody.StandardValue)))
	store := env.Store.(*memoryStore)
	beforeReads, beforeCreates, beforeCAS := store.reads, store.creates, store.cas
	selected := f.session
	reader := selectedObjectReader{domain: selected.root.Domain, descriptor: selected.admission.store,
		source: selectedImageReadOnlySource{store: store}}
	image, result := readCompleteSelectedImage(context.Background(), reader, selected.root, false)
	if result.Outcome != 0 || !reflect.DeepEqual(image.pages, selected.pages) ||
		!reflect.DeepEqual(image.recipients, selected.recipients) || !reflect.DeepEqual(image.access, selected.access) ||
		!reflect.DeepEqual(image.support, selected.support) || !reflect.DeepEqual(image.supportFacts, selected.supportFacts) ||
		!reflect.DeepEqual(image.adminIndex, selected.adminIndex) {
		t.Fatal("read-only scan changed selected facts", result)
	}
	authorityID := image.root.CurrentAccess.Core.AuthorityRecipientID
	control, ok := selectedControlFrom(image.root, &image.recipients, authorityID)
	ordinaryControl, ordinaryOK := selected.selectedControl()
	if !ok || !ordinaryOK || !controlEqual(control, ordinaryControl) {
		t.Fatal("read-only selected control differs from ordinary admitted control")
	}
	selectedMaterials, ok := indexSelectedMaterialFacts(image.root, &image.pages, &image.access, image.support)
	if !ok || !reflect.DeepEqual(selectedMaterials.accessLocations, selected.accessLocations) ||
		!reflect.DeepEqual(selectedMaterials.valueReaders, selected.valueReaders) {
		t.Fatal("read-only selected material facts differ from ordinary facts")
	}
	validatedSecrets := 0
	for _, name := range image.root.Names {
		gotCore, gotPayload, gotAccess, gotOK := selectedValueFrom(image.root.Domain, image.root,
			&image.pages, &image.recipients, &image.access, selectedMaterials.accessLocations,
			selectedMaterials.valueReaders, name.Slot)
		wantCore, wantPayload, wantAccess, wantOK := selected.selectedValue(name.Slot)
		if gotOK != wantOK || !reflect.DeepEqual(gotCore, wantCore) ||
			!reflect.DeepEqual(gotPayload, wantPayload) || !reflect.DeepEqual(gotAccess, wantAccess) {
			t.Fatal("read-only selected value differs from ordinary validation", name.Name)
		}
		if wantOK {
			validatedSecrets++
			if _, _, _, ok := selectedValueFrom(contract.Hash([]byte("wrong domain")), image.root,
				&image.pages, &image.recipients, &image.access, selectedMaterials.accessLocations,
				selectedMaterials.valueReaders, name.Slot); ok {
				t.Fatal("foreign domain validated selected secret", name.Name)
			}
			if _, _, _, ok := selectedValueFrom(image.root.Domain, image.root,
				&image.pages, &image.recipients, &image.access, nil,
				selectedMaterials.valueReaders, name.Slot); ok {
				t.Fatal("missing selected access validated selected secret", name.Name)
			}
		}
	}
	if validatedSecrets == 0 {
		t.Fatal("fixture has no selected secret for value/access proof")
	}
	selectedRows, ok := selectedValueRelations(selected.head, &image, authorityID, selectedMaterials)
	if _, err := selected.validateRelationsMode(ctx, false); !ok || len(selectedRows) != int(image.root.AccessRecordCount) || err != nil {
		t.Fatal("complete read-only value and access relations differ from ordinary admission")
	}
	completeRows, ok := selectedCompleteRelations(selected.head, &image, authorityID, selectedMaterials)
	if !ok || !reflect.DeepEqual(completeRows, selectedRows) {
		t.Fatal("complete read-only relations differ from ordinary admission")
	}
	if _, ok := selectedValueRelations(selected.head, &image, contract.Hash([]byte("unselected authority")), selectedMaterials); ok {
		t.Fatal("unselected authority validated current value membership")
	}
	alteredImage := image
	alteredImage.root.RawBytes++
	if _, ok := selectedValueRelations(selected.head, &alteredImage, authorityID, selectedMaterials); ok {
		t.Fatal("changed selected raw length passed value relations")
	}
	if selected.head.AuthKind != format.LifecycleAuth || !selectedLifecycleSelection(selected.head, &image, authorityID) ||
		!selected.validLifecycleSelection() {
		t.Fatal("read-only lifecycle result differs from ordinary selected proof")
	}
	alteredHead := selected.head
	alteredHead.Subject.AfterAccessRoot = contract.Hash([]byte("changed access root"))
	if selectedLifecycleSelection(alteredHead, &image, authorityID) {
		t.Fatal("changed lifecycle access root passed selected proof")
	}
	gotSupport, err := image.supportDescriptor()
	wantSupport, ordinaryErr := selected.supportDescriptor()
	if err != nil || ordinaryErr != nil || gotSupport != wantSupport {
		t.Fatal("read-only selected support differs from ordinary descriptor", err, ordinaryErr)
	}
	foreignImage := image
	foreignImage.root.Domain = contract.Hash([]byte("wrong domain"))
	if _, err := foreignImage.supportDescriptor(); err == nil {
		t.Fatal("foreign domain described selected support")
	}
	if len(image.supportFacts) == 0 || len(image.supportFacts[0].rows) == 0 {
		t.Fatal("fixture lacks selected output configuration")
	}
	damaged := append([]selectedSupportPageFacts(nil), image.supportFacts...)
	damaged[0].rows = append([]contract.SupportRecordDigest(nil), damaged[0].rows...)
	damaged[0].rows[0] = contract.SupportRecordDigest{}
	damagedImage := image
	damagedImage.supportFacts = damaged
	if _, err := damagedImage.supportDescriptor(); err == nil {
		t.Fatal("damaged selected support fact described a complete image")
	}
	if !image.selectedOutputComplete() {
		t.Fatal("mandatory selected output fact was lost or accepted after damage")
	}
	alteredImage = image
	alteredImage.supportFacts = damaged
	if _, ok := selectedCompleteRelations(selected.head, &alteredImage, authorityID, selectedMaterials); ok {
		t.Fatal("damaged mandatory output facts passed complete read-only relations")
	}
	if _, ok := selectedControlFrom(image.root, &image.recipients, contract.Hash([]byte("not-selected-authority"))); ok {
		t.Fatal("unselected authority acquired a control binding")
	}
	wantReads := beforeReads + int(selected.root.ChildCount) + int(selected.root.OutputConfiguration.SliceCount) + len(selected.root.Generated.Fragments)
	if store.reads != wantReads || store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("complete scan used an unexpected Store operation", store.reads, wantReads)
	}
	public, result := anchorPublicCandidate(ctx, candidateProbeForSelected(t, env, selected), env.Domain,
		&candidateQualifierProbe{}, nil)
	if result.Outcome != 0 {
		t.Fatal("selected lifecycle public anchor", result)
	}
	source := &constructedReadProbe{store: env.Store, descriptor: env.Store.Descriptor(),
		configuration: env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
	basis, result := bindPublicReadBasis(ctx, public, source)
	if result.Outcome != 0 {
		t.Fatal("selected lifecycle normal read basis", result)
	}
	complete, result := completePublicSelection(ctx, basis, nil)
	if result.Outcome != 0 || complete.image.root.Snapshot != selected.root.Snapshot ||
		complete.authorityID != selected.admission.recipient || store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("complete selected lifecycle could not be reconstructed without an ordinary admission", result)
	}
}

// full_only: false
func TestReconstructionMixedFieldsAndReturnedPrivateValues(t *testing.T) {
	ctx := t.Context()
	env, run, f, keys, _ := successionMemoryRegistryFixture(t, false)
	authority := f.session.admission.recipient
	shared := capacityRecipients(t, f.session, 2)
	input := []ApplyEntryInput{
		{Name: "", Recipients: []contract.ID{authority}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte{}},
		{Name: "e\u0301/雪", Recipients: shared, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte{0, 255, 128, 10}},
		suppliedSecret(t, env, "secret empty", "projection empty", custody.EmptyValue),
		suppliedSecret(t, env, "secret binary", "projection binary", custody.MaximumValue, shared...),
	}
	run.suppliedSelection(f, input)
	sources, _ := generatedCurrentDeclaration(t, f.session)
	selected := signedFullIntentSource(t, ctx, env, f.session, fixtureID(env.Domain, "projection generated"), []string{"generated 雪"}, sources, shared, custody.StandardValue, contract.OutputEncodingRaw, "projection generated", nil)
	store := env.Store.(*memoryStore)
	// Only the current Authority KEK is available during reconstruction and the
	// returned-content oracle. Registry preservation does not require cooperation.
	for _, row := range env.Bindings {
		if row.SubjectID != authority {
			keys.SetDenied(row.SubjectID, true)
		}
	}
	keys.SetDenied(keys.RecoveryID(), true)
	projection := reconstructProjectionFixture(t, env, selected, store)
	assertReconstructionProjectionExact(t, projection, selected, store)
	returned := reconstructionReturnedSession(t, projection, selected)
	assertReconstructionReturnedIntents(t, returned, 1, 384<<10)
	if !reflect.DeepEqual(returned.root.Names, selected.root.Names) || !reflect.DeepEqual(returned.recipients, selected.recipients) {
		t.Fatal("returned full name/registry set changed")
	}
	rows, unused := 0, 0
	for _, page := range returned.recipients {
		if page == nil {
			continue
		}
		for _, row := range page.Slots {
			if row == nil {
				continue
			}
			rows++
			if len(row.DisplayName) != contract.CryptoMaxName {
				t.Fatal("returned populated registry dimensions")
			}
			if row.CurrentBinding == nil || contract.Hash(row.CurrentBinding.SPKI) != row.CurrentBinding.Fingerprint {
				t.Fatal("returned public binding fingerprint")
			}
			used := false
			for _, named := range returned.root.Names {
				if slices.Contains(returned.valueEntry(named.Slot).Recipients, row.RecipientID) {
					used = true
				}
			}
			if !used {
				unused++
			}
		}
	}
	if rows != 4 || unused != 2 {
		t.Fatal("complete/unused registry rows lost", rows, unused)
	}
	for _, plain := range input[:2] {
		entry := returned.valueEntry(namedSlot(t, returned, plain.Name))
		if entry == nil || !bytes.Equal(entry.ValueBytes, plain.InputBytes) || !slices.Equal(entry.Recipients, plain.Recipients) {
			t.Fatal("returned exact plain bytes/membership", plain.Name)
		}
	}
	for _, tc := range []struct {
		name   string
		choice uint8
	}{{"secret empty", custody.EmptyValue}, {"secret binary", custody.MaximumValue}, {"generated 雪", custody.StandardValue}} {
		actual := sessionConsumerSelection(t, returned, authority, tc.name)
		if check := keys.Consume(ctx, actual, tc.choice); check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 {
			t.Fatal("returned private bytes differ from independent fixture oracle", tc.name, check)
		}
		original := selected.valueEntry(namedSlot(t, selected, tc.name))
		if !reflect.DeepEqual(actual.Entry, *original) {
			t.Fatal("returned exact entry metadata/membership", tc.name)
		}
	}
}

func namedSlot(t testing.TB, s *StateSession, name string) uint16 {
	t.Helper()
	for _, named := range s.root.Names {
		if named.Name == name {
			return named.Slot
		}
	}
	t.Fatal("missing exact name", name)
	return 0
}

// full_only: false
func TestReconstructionGeneratedPendingFamilies(t *testing.T) {
	t.Run("active parent", func(t *testing.T) {
		env, _ := genesisEnvironment(t, contract.GCP, true)
		f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
		input := generatedPlanInputForGenerations(t, f.session, fixtureID(env.Domain, "projection active plan"), []string{"generated pending"}, defaultGeneratedFixtureProfile())
		prepared, _ := preparePrivateGeneratedReservation(t, env, f.session, input, nil)
		selected, result := f.session.selectCandidate(t.Context(), prepared.reservation.candidate)
		if selected == nil || result.Outcome != ObservedCurrent {
			t.Fatal("active selected reservation", result)
		}
		env.Custody.RetireGenerated()
		projection := reconstructProjectionFixture(t, env, selected, env.Store.(*memoryStore))
		assertReconstructionProjectionExact(t, projection, selected, env.Store.(*memoryStore))
		kinds := reconstructionSupportKinds(t, projection)
		if selected.root.Generated.ActiveOwner.IsZero() || kinds[contract.GeneratedParentSupportKind] == 0 || kinds[contract.OperationMaterialSupportKind] == 0 || kinds[contract.GeneratedFragmentSupportKind] == 0 {
			t.Fatal("returned active work omitted graph/declaration/material", kinds)
		}
	})
	t.Run("retiring duty", func(t *testing.T) {
		env, _ := genesisEnvironment(t, contract.GCP, true)
		f := newEnvironmentFixture(t, t.Context(), env, nil, false)
		profile := defaultGeneratedFixtureProfile()
		current := selectPrivateGeneratedOperation(t, env, f.session, generatedPlanInputForGenerations(t, f.session, fixtureID(env.Domain, "projection original"), []string{"generated"}, profile), "projection original")
		old := *current.valueEntry(0)
		selected := selectPrivateGeneratedOperation(t, env, current, generatedStatePlanInput(t, current, fixtureID(env.Domain, "projection rotate"), []string{old.Name}, profile, old.Generated.Epoch+1, map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}), "projection rotate")
		projection := reconstructProjectionFixture(t, env, selected, env.Store.(*memoryStore))
		assertReconstructionProjectionExact(t, projection, selected, env.Store.(*memoryStore))
		kinds := reconstructionSupportKinds(t, projection)
		if selected.valueEntry(0).Generated.RetiringDutyID.IsZero() || kinds[contract.GeneratedDutySupportKind] != 1 || kinds[contract.GeneratedCreateEvidenceSupportKind] != 2 {
			t.Fatal("returned retirement omitted exact duty/old material", kinds)
		}
	})
	t.Run("uncertain attempts and hazard", func(t *testing.T) {
		env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, true, 1)
		projection := reconstructProjectionFixture(t, env, selected, env.Store.(*memoryStore))
		assertReconstructionProjectionExact(t, projection, selected, env.Store.(*memoryStore))
		kinds := reconstructionSupportKinds(t, projection)
		if kinds[contract.GeneratedAttemptSupportKind] < 2 || kinds[contract.GeneratedHazardSupportKind] == 0 || kinds[contract.GeneratedCreateEvidenceSupportKind] == 0 {
			t.Fatal("returned uncertain/retiring work omitted selected support", kinds)
		}
	})
}

func reconstructionSupportKinds(t testing.TB, p *ReconstructionProjection) map[contract.SupportRecordKind]int {
	t.Helper()
	counts := map[contract.SupportRecordKind]int{}
	for i := 0; i < p.PartCount(); i++ {
		part, ok := p.CopyPart(i)
		if !ok {
			t.Fatal("missing complete support part")
		}
		if part.Kind == ReconstructionSupportRowPart {
			counts[part.SupportKind]++
		}
	}
	return counts
}
