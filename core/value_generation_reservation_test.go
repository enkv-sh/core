package core

import (
	"bytes"
	stdcontext "context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// The direct reservation tests use a test-owned context. Production callers
// pass their original context to deriveGeneratedReservation.

func generatedEmptyPredecessor(t testing.TB) *StateSession {
	return generatedEmptyPredecessorForFamily(t, contract.AWS)
}

func generatedEmptyPredecessorForFamily(t testing.TB, family contract.Family) *StateSession {
	t.Helper()
	id := generatedVectorID
	binding := generatedPublicBinding(t, 65)
	if family == contract.AWS {
		binding.Provider, binding.ProtectionClass = contract.AWS, contract.HardwareProtection
		binding.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000001"
	} else if family != contract.GCP {
		t.Fatal("unsupported predecessor provider")
	}
	spki, err := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d030107034200043b3b69c250bef28de6d54c056c3ead1a4b4b1fb7d3acf1e936376f0f50cd9e5d1f82d8916a8ae0dbd28615676d405aa6a528727def8fad991fdd53dd67153b4e")
	if err != nil {
		t.Fatal(err)
	}
	selector := "arn:aws:kms:us-east-1:123456789012:key/eed2e660-5683-d37f-2705-5d15c8a82275"
	if family == contract.GCP {
		current := testtrust.New(t, family, id(75))
		spki, selector = current.PublicKey(), current.KeySelector()
	}
	parsed, err := x509.ParsePKIXPublicKey(spki)
	public, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || public.Curve != elliptic.P256() {
		t.Fatal("invalid public signing fixture")
	}
	token := `"original-token"`
	if family == contract.GCP {
		token = "27"
	}
	signing := contract.PublicSigningBinding{Schema: contract.CanonicalSchema, Role: 1, Provider: family, SigningProfile: 1, BindingID: id(70),
		KeySelector: selector, SPKI: spki, Fingerprint: contract.Hash(spki),
		Binding: contract.BindingSubject{Domain: id(1), Coordinate: id(72), Store: id(71), Trust: id(75), PublicKey: contract.Hash(spki), Interpretation: contract.InterpretationID(), ControlIncarnationID: id(74), Epoch: 1}}
	s := &StateSession{admission: openAdmission{domain: id(1), recipient: id(11)},
		body: []byte("authenticated predecessor HEAD"), token: contract.Token{Family: family, Value: token}, cache: make(map[format.Ref][]byte)}
	s.root = format.Root{Domain: id(1), Snapshot: id(2), Transition: id(3), RecipientCount: 1, Generated: format.EmptyGeneratedClosure(), GCPlans: contract.EmptyGCOwnersDescriptor()}
	s.root.CurrentAccess.Core.CurrentControl = contract.CurrentControl{CurrentControlFields: contract.CurrentControlFields{Schema: contract.CanonicalSchema, Profile: 2, DomainID: id(1), Provider: family,
		StoreID: id(71), CoordinateID: id(72), NonBodyID: id(73), TrustInterpretationID: contract.TrustInterpretationID(), CompatibilityID: contract.CompatibilityID(),
		CryptoSupportID: contract.CryptoSupportID(), AuthorityRecipientID: id(11), AccessIncarnationID: contract.DeriveAccessIncarnationID(id(1), id(74)), AccessGeneration: 1}, NormalSigning: signing}
	page := format.RecipientPage{Domain: id(1), Object: id(66), Slots: [format.RecipientSlots]*contract.RecipientRecord{{RecipientID: id(11), Status: contract.CurrentRecipient, CurrentBinding: &binding}}}
	body, err := format.EncodeRecipientPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(format.RecipientKind, page.Domain, page.Object, 0, body)
	if err != nil {
		t.Fatal(err)
	}
	s.recipients[0], s.recipient, s.root.Recipients[0] = &page, page, &ref
	configurationImage, err := contract.EncodeOutputConfiguration(contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: id(1)})
	if err != nil {
		t.Fatal(err)
	}
	configuration, configurationRows, err := contract.SplitOutputConfiguration(id(1), configurationImage)
	if err != nil {
		t.Fatal(err)
	}
	configurationBody, err := contract.EncodeOutputConfigurationSlice(configurationRows[0])
	if err != nil {
		t.Fatal(err)
	}
	configurationID, err := contract.OutputConfigurationSliceID(id(1), configuration.ConfigurationDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	configurationPage := format.RequiredSupportPage{Domain: id(1), Object: id(67), Index: 0, Records: []contract.SupportRecord{{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: configurationID, Body: configurationBody}}}
	supportBody, err := format.EncodeRequiredSupportPage(configurationPage)
	if err != nil {
		t.Fatal(err)
	}
	supportRef, err := format.Reference(contract.RequiredSupportKind, id(1), id(67), 0, supportBody)
	if err != nil {
		t.Fatal(err)
	}
	supportView, err := format.InspectRequiredSupportPage(supportBody)
	if err != nil {
		t.Fatal(err)
	}
	s.root.OutputConfiguration = configuration
	s.root.RequiredSupport, s.root.RequiredSupportRecordCount = []format.Ref{supportRef}, 1
	s.support = []format.RequiredSupportPageView{supportView}
	s.cache[supportRef] = bytes.Clone(supportBody)
	s.adminIndex = format.AdministrativeIndex{Domain: id(1), Object: contract.Hash([]byte("generated empty predecessor administrative index")), SliceSnapshot: s.root.Snapshot, Pages: []format.AdministrativePage{{Ref: supportRef, Spans: []format.AdministrativeSpan{{First: 0, Count: 1, Mandatory: true}}, Rows: []format.AdministrativeRowSummary{{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: configurationID, BodyLength: uint32(len(configurationBody))}}}}}
	indexPages, err := format.EncodeAdministrativeIndexPages(s.adminIndex)
	if err != nil || len(indexPages) != 1 {
		t.Fatal("empty administrative index", err)
	}
	s.root.AdministrativeIndex = indexPages[0].Ref
	s.cache[indexPages[0].Ref] = bytes.Clone(indexPages[0].Body)
	s.root.ChildCount, s.root.ChildEncodedBytes = 3, uint64(len(body))+uint64(indexPages[0].Ref.Length)+uint64(supportRef.Length)
	s.root.CurrentAccess.Core.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: id(1), Refs: []contract.Ref{ref}})
	if err != nil {
		t.Fatal(err)
	}
	s.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(id(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	body, err = format.EncodeRoot(s.root)
	if err != nil {
		t.Fatal(err)
	}
	rootRef, err := format.Reference(format.RootKind, id(1), s.root.Snapshot, 0, body)
	if err != nil {
		t.Fatal(err)
	}
	s.head.Core = format.HeadCore{Form: format.GenesisHead, Domain: id(1), Revision: id(14), Root: rootRef, Store: id(71), Trust: id(75),
		Coordinate: id(72), NonBody: id(73), Interpretation: contract.InterpretationID(), Epoch: 1}
	c := s.root.CurrentAccess.Core
	d := contract.GenesisDescriptorCore{InitID: id(90), DomainID: id(1), DescriptorArtifactID: id(91), ManifestArtifactID: id(92), Provider: c.Provider,
		StoreID: c.StoreID, CoordinateID: c.CoordinateID, NonBodyID: c.NonBodyID, TrustID: signing.Binding.Trust, InterpretationID: signing.Binding.Interpretation,
		TrustInterpretationID: c.TrustInterpretationID, CompatibilityID: c.CompatibilityID, CryptoSupportID: c.CryptoSupportID, AuthorityRecipientID: c.AuthorityRecipientID,
		NormalSigning: signing, Recipients: []contract.RecipientRecord{*page.Slots[0]}}
	s.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(d)
	if err != nil {
		t.Fatal(err)
	}
	s.admission.store = contract.Descriptor{Family: c.Provider, Identity: c.StoreID, Coordinate: c.CoordinateID, NonBody: c.NonBodyID, Prefix: "fixture", HeadKey: "fixture/HEAD"}
	s.admission.trust, s.admission.controlIncarnation, s.admission.interpretation, s.admission.epoch, s.admission.publicKey = signing.Binding.Trust, signing.Binding.ControlIncarnationID, signing.Binding.Interpretation, 1, spki
	if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
		t.Fatal("invalid empty predecessor fixture")
	}
	generatedInstallFixtureSupportReader(t, s)
	return s
}

// full_only: false
func TestGeneratedFixtureOutputConfigurationRead(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	configuration, result := s.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 {
		t.Fatalf("fixture output read refused: outcome=%d reason=%d support_refs=%d support_facts=%d store_present=%t", result.Outcome, result.Reason, len(s.root.RequiredSupport), len(s.supportFacts), s.store != nil)
	}
	if configuration.Schema != contract.OutputConfigurationSchema || configuration.DomainID != generatedVectorID(1) || len(configuration.Bindings) != 0 || len(configuration.Routes) != 0 {
		t.Fatal("fixture output read changed the canonical empty configuration")
	}
	store := s.store.(*generatedFixtureSupportStore)
	ref := s.root.RequiredSupport[0]
	key, err := format.Key(s.admission.store.Prefix, ref)
	if err != nil || !slices.Equal(store.keys, []string{key}) || !slices.Equal(store.limits, []uint32{ref.Length}) {
		t.Fatal("fixture did not serve the exact uncached selected support read", err)
	}
	for _, damage := range []string{"missing", "changed"} {
		t.Run(damage, func(t *testing.T) {
			s := generatedEmptyPredecessor(t)
			store := s.store.(*generatedFixtureSupportStore)
			ref := s.root.RequiredSupport[0]
			key, err := format.Key(s.admission.store.Prefix, ref)
			if err != nil {
				t.Fatal(err)
			}
			if damage == "missing" {
				delete(store.objects, key)
			} else {
				store.objects[key][0] ^= 1
			}
			// An already authenticated fixture must keep its stored read source.
			_ = generatedContinuationContext(t, s, 100, 101)
			_, result := s.currentOutputConfigurationForApply(t.Context())
			wantOutcome, wantReason := EvidenceUnavailable, MissingSelectedObject
			if damage == "changed" {
				wantOutcome, wantReason = IntegrityFailure, InvalidReference
			}
			if result.Outcome != wantOutcome || result.Reason != wantReason || !slices.Equal(store.keys, []string{key}) {
				t.Fatal("fixture cached slice bypassed the exact selected read", result)
			}
		})
	}
}

// full_only: false
func TestGeneratedSelectedFixtureConstructorsPreserveEmptyConfiguration(t *testing.T) {
	// Schema 5, zero bindings and groups, routing length 5, schema 3, empty selectors.
	want, err := hex.DecodeString("000500000000000000050003000000")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"empty predecessor", "active reservation", "selected entry origin"} {
		t.Run(name, func(t *testing.T) {
			var s *StateSession
			switch name {
			case "empty predecessor":
				s = generatedEmptyPredecessor(t)
			case "active reservation":
				s = generatedReservationState(t)
			case "selected entry origin":
				s = generatedSelectedEntryOrigin(t, generatedVectorID(10), generatedVectorID(11), 0)
			}
			d := s.root.OutputConfiguration
			if d.Schema != contract.OutputConfigurationSchema || d.SliceCount != 1 || d.TotalLength != 15 || d.BindingCount != 0 || d.RoutingLength != 5 || s.admission.store.Prefix != "fixture" {
				t.Fatal("selected fixture omitted the canonical empty configuration")
			}
			rows := 0
			for _, row := range s.supportRecords() {
				if row.Kind != contract.OutputConfigurationSliceSupportKind {
					continue
				}
				rows++
				part, err := contract.InspectOutputConfigurationSlice(row.Body)
				if err != nil || part.DomainID != s.root.Domain || part.SliceCount != 1 || part.SliceIndex != 0 || !bytes.Equal(part.SliceBytes, want) {
					t.Fatal("selected fixture changed the independently fixed empty slice", err)
				}
			}
			if rows != 1 || len(s.supportFacts) != len(s.root.RequiredSupport) {
				t.Fatal("selected fixture lacks complete physical support facts")
			}
		})
	}
}

func generatedReservationInputFixture(t testing.TB, s *StateSession, sources ...contract.GeneratorDeclarationEntry) generatedReservationInput {
	return generatedReservationInputForOperation(t, s, generatedVectorID(10), sources...)
}

func generatedFixtureRequestBindings(g contract.GeneratorPlanBundle, digest contract.ID) []generatedRequestBinding {
	var bindings []generatedRequestBinding
	for _, lineage := range g.Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate || g.Request.OperationKind == 31 || g.Request.OperationKind == 38 {
			bindings = append(bindings, generatedRequestBinding{LineageID: lineage.LineageID,
				AttemptID: lineage.Templates[0].AttemptID, Digest: digest})
		}
	}
	return bindings
}

func generatedReservationInputForOperation(t testing.TB, s *StateSession, operation contract.ID, sources ...contract.GeneratorDeclarationEntry) generatedReservationInput {
	return generatedReservationInputForGenerations(t, s, operation, []string{"generated"}, sources...)
}

func generatedReservationInputForGenerations(t testing.TB, s *StateSession, operation contract.ID, names []string, sources ...contract.GeneratorDeclarationEntry) generatedReservationInput {
	return generatedReservationInputForProfile(t, s, operation, names, defaultGeneratedFixtureProfile(), sources...)
}

func generatedReservationInputForProfile(t testing.TB, s *StateSession, operation contract.ID, names []string, profile generatedFixtureProfile, sources ...contract.GeneratorDeclarationEntry) generatedReservationInput {
	return generatedReservationInputForProfileIntent(t, s, operation, names, []byte(`{"name":"generated"}`), profile, sources...)
}

func generatedReservationInputForProfileIntent(t testing.TB, s *StateSession, operation contract.ID, names []string, intent []byte,
	profile generatedFixtureProfile, sources ...contract.GeneratorDeclarationEntry) generatedReservationInput {
	return generatedReservationInputForStateIntent(t, s, operation, names, intent, profile, 0, nil, nil, sources...)
}

func generatedReservationInputForState(t testing.TB, s *StateSession, operation contract.ID, names []string, profile generatedFixtureProfile,
	epoch uint64, incarnations map[string]contract.ID, retiring map[string]contract.ValueEntry,
	sources ...contract.GeneratorDeclarationEntry) generatedReservationInput {
	return generatedReservationInputForStateIntent(t, s, operation, names, []byte(`{"name":"generated"}`), profile, epoch, incarnations, retiring, sources...)
}

func generatedReservationInputForStateIntent(t testing.TB, s *StateSession, operation contract.ID, names []string, intent []byte, profile generatedFixtureProfile,
	epoch uint64, incarnations map[string]contract.ID, retiring map[string]contract.ValueEntry,
	sources ...contract.GeneratorDeclarationEntry) generatedReservationInput {
	return generatedReservationInputForMembershipStateIntent(t, s, operation, []contract.ID{s.admission.recipient}, names, intent, profile,
		epoch, incarnations, retiring, sources...)
}

func generatedReservationInputForMembershipStateIntent(t testing.TB, s *StateSession, operation contract.ID,
	generatedRecipients []contract.ID, names []string, intent []byte, profile generatedFixtureProfile,
	epoch uint64, incarnations map[string]contract.ID, retiring map[string]contract.ValueEntry,
	sources ...contract.GeneratorDeclarationEntry) generatedReservationInput {
	return generatedReservationInputForMembershipStateIntents(t, s, operation, generatedRecipients, names,
		func(string) []byte { return intent }, profile, epoch, incarnations, retiring, sources...)
}

func generatedReservationInputForMembershipStateIntents(t testing.TB, s *StateSession, operation contract.ID,
	generatedRecipients []contract.ID, names []string, intentForName func(string) []byte, profile generatedFixtureProfile,
	epoch uint64, incarnations map[string]contract.ID, retiring map[string]contract.ValueEntry,
	sources ...contract.GeneratorDeclarationEntry) generatedReservationInput {
	t.Helper()
	g, _, _ := generatedEffectPlanFixture(t)
	request := g.Request
	request.OperationID = operation
	request.DomainID = s.admission.domain
	request.PredecessorRevisionID, request.PredecessorHEADDigest = s.head.Core.Revision, contract.Hash(s.body)
	var err error
	request.ConditionDigest, err = contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		t.Fatal(err)
	}
	boundIncarnations := make(map[string]contract.ID, len(incarnations)+len(names))
	for name, incarnation := range incarnations {
		boundIncarnations[name] = incarnation
	}
	for _, entry := range s.root.Names {
		if s.valueEntry(entry.Slot).ValueSource == contract.Generated && boundIncarnations[entry.Name].IsZero() {
			boundIncarnations[entry.Name] = s.valueEntry(entry.Slot).Incarnation
		}
	}
	g, declaration, parent := generatedEffectPlanForGenerationMembershipStateWithIntents(t, &request, s.admission.recipient, generatedRecipients, names, intentForName,
		profile, epoch, boundIncarnations, retiring, sources...)
	// A whole-set fixture must keep the selected slot and stable incarnation
	// for every existing name, including supplied plain values. Retained
	// canonical entries alone cannot establish that relation for a mixed set.
	var occupied [contract.CryptoMaxValueEntries]bool
	current := make(map[string]uint16, len(s.root.Names))
	for _, entry := range s.root.Names {
		current[entry.Name] = entry.Slot
	}
	for i := range g.ValueEntryPlans {
		if slot, ok := current[g.ValueEntryPlans[i].Name]; ok {
			g.ValueEntryPlans[i].Slot = slot
			if g.ValueEntryPlans[i].ValueSource == contract.Supplied {
				g.ValueEntryPlans[i].EntryIncarnationID = s.valueEntry(slot).Incarnation
			}
			occupied[slot] = true
		}
	}
	for i := range g.ValueEntryPlans {
		if _, ok := current[g.ValueEntryPlans[i].Name]; ok {
			continue
		}
		free := slices.Index(occupied[:], false)
		if free < 0 {
			t.Fatal("whole-set fixture member capacity")
		}
		g.ValueEntryPlans[i].Slot, occupied[free] = uint16(free), true
	}
	g.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(g.Header, g.ValueEntryPlans, g.Lineages, g.Edges)
	if err != nil {
		t.Fatal(err)
	}
	parent.PlanGraphID = g.UsePlan.PlanGraphID
	parent.UsePlanDigest, err = contract.GeneratorUsePlanDigest(g.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	parent.Graph, err = contract.GeneratorPlanBundleDescriptor(g)
	if err != nil {
		t.Fatal(err)
	}
	parent.IntendedEntryPlans, err = contract.GeneratorValueEntryPlansDescriptor(g.ValueEntryPlans)
	if err != nil {
		t.Fatal(err)
	}
	parent.RequestIdentityDigest = contract.ID{}
	input := generatedReservationInput{graph: g, parent: contract.GeneratedParentPlan(parent),
		requestBindings: generatedFixtureRequestBindings(g, generatedVectorID(61))}
	input.declaration, err = contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal(err)
	}
	input.finished.Material = contract.OperationMaterialRecord{Core: contract.OperationMaterialCore{Schema: contract.CanonicalSchema, Profile: 2, DomainID: request.DomainID, OperationID: request.OperationID,
		OperationMaterialID: parent.MaterialID, UsePlanDigest: parent.UsePlanDigest, CompatibilityID: request.CompatibilityID, CryptoSupportID: contract.CryptoSupportID(), SeedEpoch: 1}, SeedCheck: generatedVectorID(63)}
	context, err := contract.OperationMaterialContextDigest(input.finished.Material.Core)
	if err != nil {
		t.Fatal(err)
	}
	binding := s.authority().CurrentBinding
	digest, err := contract.PublicBindingDigest(*binding)
	if err != nil {
		t.Fatal(err)
	}
	wraps := []contract.WrapRow{{SubjectKind: 1, SubjectID: s.admission.recipient, BindingID: binding.BindingID,
		BindingSerial: binding.BindingSerial, PublicBindingDigest: digest, RSACiphertext: bytes.Repeat([]byte{68}, 384)}}
	if recovery := s.root.CurrentAccess.Core.Recovery; recovery != nil {
		digest, err := contract.PublicBindingDigest(recovery.KMS)
		if err != nil {
			t.Fatal(err)
		}
		wraps = append(wraps, contract.WrapRow{SubjectKind: 2, SubjectID: recovery.RoleID, BindingID: recovery.KMS.BindingID,
			BindingSerial: recovery.KMS.BindingSerial, PublicBindingDigest: digest, RSACiphertext: bytes.Repeat([]byte{69}, 384)})
	}
	input.finished.SeedAccess, err = contract.EncodeAccessRecord(contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: 3, MaterialID: parent.MaterialID, MaterialContextDigest: context,
		PackageCheck: input.finished.Material.SeedCheck, Wraps: wraps})
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range g.SourceUses {
		input.finished.SourceProtections = append(input.finished.SourceProtections, contract.CryptoGeneratedSourceProtection{SourceID: source.SourceID,
			OriginalSourceCoreDigest: source.SealedInputCoreDigest, OriginalEnvelopeDigest: source.EnvelopeDigest,
			Transfer: contract.TransferEnvelope{Core: contract.TransferCore{Schema: 2, Profile: 2, CompatibilityID: request.CompatibilityID, CryptoSupportID: contract.CryptoSupportID(),
				DomainID: request.DomainID, OperationID: request.OperationID, OperationMaterialID: parent.MaterialID, UsePlanDigest: parent.UsePlanDigest,
				EnvelopeID: contract.Hash(source.SourceID[:]), UseKind: 1, PacketKind: 5, PacketLength: 68, SourceID: source.SourceID, SealedInputCoreDigest: source.SealedInputCoreDigest}, Ciphertext: bytes.Repeat([]byte{71}, 84)}})
	}
	return input
}

// full_only: false
func TestGeneratedReservationPreservesOlderRetirement(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	old, duty, _ := generatedDetachedRetirementState(t, "absent", 0)
	s.support, s.root.Generated = old.support, old.root.Generated
	generatedRefreshSupport(t, s)
	s.recountChildren()
	if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
		t.Fatal("invalid predecessor retirement")
	}
	input := generatedReservationInputForOperation(t, s, generatedVectorID(98))
	reservation, err := s.deriveGeneratedReservation(stdcontext.Background(), input)
	if err != nil {
		t.Fatal("reservation lost an older retirement", err)
	}
	g, err := reservation.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil || g.parent == nil || g.parent.OperationID != input.graph.Header.OperationID ||
		reservation.state.root.Generated.Retiring != 1 || reservation.state.root.Generated.Duties != 2 ||
		!g.hasRecord(generatedRecordKey{10, duty.DutyID}) || g.phase.Duties.Count != 1 || reservation.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("reservation changed existing retirement or claimed it as active work", err)
	}
}

// full_only: false
func TestGeneratedActiveDutyRetainsParentCapacityReservation(t *testing.T) {
	s := generatedReservationState(t)
	for _, row := range s.supportRecords() {
		if row.Kind != 10 {
			continue
		}
		duty, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		duty.CapacityReservation.Digest[0] ^= 1
		body, err := contract.EncodeGeneratedDutyRecord(duty)
		if err != nil {
			t.Fatal(err)
		}
		generatedReplaceRecord(t, s, 10, duty.DutyID, body)
	}
	generatedRefreshPhaseSets(t, s)
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
		t.Fatal("active Duty accepted a capacity reservation different from its Parent")
	}
}

// full_only: false
func TestGeneratedReservationStartsCreateAfterEarlierRetirementTemplate(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	old, duty, _ := generatedDetachedRetirementState(t, "absent", 0)
	s.support, s.root.Generated = old.support, old.root.Generated
	generatedRefreshSupport(t, s)
	s.recountChildren()
	if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
		t.Fatal("invalid predecessor retirement")
	}
	operation := generatedVectorID(98)
	input := generatedReservationInputForGenerations(t, s, operation, []string{"zeta", "zz-next"})
	retirement, _, _, _ := generatedEnteredRetirementForOperation(t, operation, false)
	prior, err := retirement.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	lineage := prior.bundles[0].Lineages[0]
	x := lineage.Templates[0]
	if lineage.Purpose != 2 || lineage.Name >= input.graph.Lineages[0].Name || x.DutyID != duty.DutyID {
		t.Fatal("fixture retirement does not precede its independent create")
	}
	input.graph.Lineages = append([]contract.GeneratorLineageTemplate{lineage}, input.graph.Lineages...)
	input.graph.Header.TemplateCount++
	join, err := contract.GeneratorCompleteJoinID(input.graph.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	template, err := contract.GeneratorTemplateID(x)
	if err != nil {
		t.Fatal(err)
	}
	for _, guard := range []uint8{3, 4} {
		input.graph.Edges = append(input.graph.Edges, contract.GeneratorEdge{Schema: 1, SourceTemplateID: template,
			DestinationTemplateID: join, Guard: guard, ResultSlotID: x.ResultID, RequiredAuthoritySet: 1})
	}
	slices.SortFunc(input.graph.Edges, func(a, b contract.GeneratorEdge) int {
		if order := bytes.Compare(a.SourceTemplateID[:], b.SourceTemplateID[:]); order != 0 {
			return order
		}
		return int(a.Guard) - int(b.Guard)
	})
	input.graph.ResultUses = append(input.graph.ResultUses, prior.bundles[0].ResultUses[0])
	slices.SortFunc(input.graph.ResultUses, func(a, b contract.GeneratorResultUse) int {
		return bytes.Compare(a.AttemptID[:], b.AttemptID[:])
	})
	input.graph.UsePlan.ResultUses, err = contract.GeneratorResultUsesDescriptor(input.graph.ResultUses)
	if err != nil {
		t.Fatal(err)
	}
	input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
	if err != nil {
		t.Fatal(err)
	}
	input.parent.TemplateCount = input.graph.Header.TemplateCount
	input.parent.PlanGraphID = input.graph.UsePlan.PlanGraphID
	input.parent.UsePlanDigest, err = contract.GeneratorUsePlanDigest(input.graph.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	input.parent.Graph, err = contract.GeneratorPlanBundleDescriptor(input.graph)
	if err != nil {
		t.Fatal(err)
	}
	input.finished.Material.Core.UsePlanDigest = input.parent.UsePlanDigest
	access, err := contract.DecodeAccessRecord(input.finished.SeedAccess)
	if err != nil {
		t.Fatal(err)
	}
	access.MaterialContextDigest, err = contract.OperationMaterialContextDigest(input.finished.Material.Core)
	if err != nil {
		t.Fatal(err)
	}
	input.finished.SeedAccess, err = contract.EncodeAccessRecord(access)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil || contract.ValidateGeneratorEffectGraph(input.graph) != nil || contract.ValidateGeneratorDeclarationGraph(declaration, input.graph) != nil {
		t.Fatal("invalid mixed reservation graph", err)
	}
	reservation, err := s.deriveGeneratedReservation(stdcontext.Background(), input)
	if err != nil {
		t.Fatal("earlier retirement template prevented independent create reservation", err)
	}
	g, err := reservation.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil || g.phase.LineageIndex != 1 || g.phase.FrontierAttemptID != input.graph.Lineages[1].Templates[0].AttemptID ||
		len(g.attempts) != 2 || g.phase.Attempts.Count != 2 || g.phase.Duties.Count != 2 ||
		reservation.state.root.Generated.Retiring != 1 || !g.hasRecord(generatedRecordKey{10, duty.DutyID}) || reservation.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("initial reservation changed or entered the older retirement", err)
	}
	kept, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, duty.DutyID}].Body)
	if err != nil || kept != duty {
		t.Fatal("initial create changed the older retirement obligation", err)
	}
	later := slices.IndexFunc(input.graph.Lineages, func(v contract.GeneratorLineageTemplate) bool {
		return v.Purpose == 1 && v.Name == "zz-next"
	})
	if later <= 1 {
		t.Fatal("fixture has no later create")
	}
	x = input.graph.Lineages[later].Templates[0]
	_, use, ok := generatedTemplate(input.graph, x.AttemptID)
	if !ok {
		t.Fatal("later create has no result use")
	}
	rows, err := generatedInitialRows(input, declaration, g.phase.PhaseID, uint16(later), x, use)
	if err != nil {
		t.Fatal(err)
	}
	var phase contract.GeneratedPhaseRecord
	var attempt contract.GeneratedAttemptRecord
	for _, row := range rows {
		switch row.Kind {
		case 5:
			phase, err = contract.InspectGeneratedPhaseRecord(row.Body)
		case 9:
			attempt, err = contract.InspectGeneratedAttemptRecord(row.Body)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	fixture := *g
	fixture.phase = &phase
	fixture.attempts = map[contract.ID]generatedAttempt{x.AttemptID: {record: attempt, expected: contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Template: x, Use: use}}}
	if err := (&generatedSelectionBuilder{facts: &fixture}).validateActivePhase(rows); err == nil {
		t.Fatal("initial phase skipped the first create despite matching later Attempt and owner sets")
	}
}

// full_only: false
func TestGeneratedReservationBuildsExactSelectedClosure(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	before := *s
	input := generatedReservationInputFixture(t, s)
	reservation, err := s.deriveGeneratedReservation(stdcontext.Background(), input)
	if err != nil {
		t.Fatal("reservation construction", err)
	}
	next, candidate := reservation.state, reservation.candidate
	selected, err := next.selectedGeneratedWork(stdcontext.Background())
	if err != nil || selected.parent == nil || len(selected.attempts) != 1 || len(selected.sources) != 0 {
		t.Fatal("new reservation did not form a complete selected closure", err)
	}
	if selected.parent.RequestIdentityDigest != reservation.identity.RequestIdentityDigest || selected.parent.RequestIdentityDigest.IsZero() ||
		candidate.head.AuthKind != format.GeneratorAuth || candidate.head.Generator == nil || candidate.session != s || len(candidate.body) != 0 {
		t.Fatal("reservation lost identity or acquired an unclaimed authority proof")
	}
	if _, err := contract.NewGeneratorRequest(*candidate.head.Generator); err != nil {
		t.Fatal("invalid authority subject", err)
	}
	if !reflect.DeepEqual(*s, before) {
		t.Fatal("construction changed the predecessor")
	}
	for _, attempt := range selected.attempts {
		if len(attempt.result) != 0 || attempt.record.InboxID.IsZero() || attempt.record.State != contract.GeneratedEffectTransmitted {
			t.Fatal("initial reservation lost its possibly-entered absent inbox")
		}
	}
	for _, object := range candidate.objects {
		if err := format.CheckReference(object.ref, object.body); err != nil {
			t.Fatal("constructed object reference", err)
		}
	}
}

// full_only: false
func TestGeneratedReservationRollsAccessIncarnationAtCounterLimit(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	s.root.CurrentAccess.Core.AccessGeneration = math.MaxUint64
	var err error
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	body, err := format.EncodeRoot(s.root)
	if err != nil {
		t.Fatal(err)
	}
	s.head.Core.Root, err = format.Reference(format.RootKind, s.root.Domain, s.root.Snapshot, 0, body)
	if err != nil {
		t.Fatal("maximum-generation predecessor is invalid", err)
	}
	if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
		t.Fatal("maximum-generation predecessor is invalid", err)
	}
	before := s.root.CurrentAccess
	reservation, err := s.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputFixture(t, s))
	if err != nil {
		t.Fatal("reservation refused maximum-generation access", err)
	}
	got := reservation.state.root.CurrentAccess
	if got.Core.AccessGeneration != 1 || !contract.IncarnationCounterStep(before.Core.AccessIncarnationID,
		before.Core.AccessGeneration, got.Core.AccessIncarnationID, got.Core.AccessGeneration) ||
		got.AccessRoot == before.AccessRoot || s.root.CurrentAccess.AccessRoot != before.AccessRoot ||
		reservation.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("reservation did not select a fresh access incarnation at the counter limit")
	}
}

// full_only: false
func TestGeneratedReservationChecksSelectedAuthorityAndInitialIdentity(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	reservation, err := s.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputFixture(t, s))
	if err != nil {
		t.Fatal(err)
	}
	next := reservation.state
	if next.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("generated reservation authority relation refused")
	}
	for name, damage := range map[string]func(*contract.GeneratorAuthoritySubject){
		"initial identity":  func(v *contract.GeneratorAuthoritySubject) { v.RequestIdentityDigest[0] ^= 1 },
		"identity plan":     func(v *contract.GeneratorAuthoritySubject) { v.IdentityPlan.Digest[0] ^= 1 },
		"phase":             func(v *contract.GeneratorAuthoritySubject) { v.PhaseID[0] ^= 1 },
		"work":              func(v *contract.GeneratorAuthoritySubject) { v.AfterWork.Digest[0] ^= 1 },
		"members":           func(v *contract.GeneratorAuthoritySubject) { v.ValueEntryUnion.Digest[0] ^= 1 },
		"membership":        func(v *contract.GeneratorAuthoritySubject) { v.MembershipChanges.Digest[0] ^= 1 },
		"access":            func(v *contract.GeneratorAuthoritySubject) { v.AfterAccessDigest[0] ^= 1 },
		"graph":             func(v *contract.GeneratorAuthoritySubject) { v.PlanGraphID[0] ^= 1 },
		"capacity":          func(v *contract.GeneratorAuthoritySubject) { v.CapacityReservation.Digest[0] ^= 1 },
		"grant suppression": func(v *contract.GeneratorAuthoritySubject) { v.RequiredAuthoritySet = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *next
			subject := *next.head.Generator
			damage(&subject)
			bad.head.Generator = &subject
			if bad.validateGeneratedSelection(t.Context(), nil) == nil {
				t.Fatal("changed selected authority relation accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedReservationBuildsExactSourceConsumers(t *testing.T) {
	var sources []contract.GeneratorDeclarationEntry
	for _, name := range []string{"alpha", "omega"} {
		entry := generatedSealedSource(t, name)
		envelope, err := contract.DecodeSealedInputEnvelope(entry.Payload)
		if err != nil {
			t.Fatal(err)
		}
		envelope.Core.CryptoSupportID = contract.CryptoSupportID()
		entry.Payload, err = contract.EncodeSealedInputEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, entry)
	}
	for count := 1; count <= len(sources); count++ {
		s := generatedEmptyPredecessor(t)
		input := generatedReservationInputFixture(t, s, sources[:count]...)
		reservation, err := s.deriveGeneratedReservation(stdcontext.Background(), input)
		if err != nil {
			t.Fatalf("%d original sources: %v", count, err)
		}
		selected, err := reservation.state.selectedGeneratedWork(stdcontext.Background())
		if err != nil || len(selected.sources[input.parent.MaterialID]) != count ||
			len(selected.consumers[materialIdentity{3, input.parent.MaterialID}]) != count+2 {
			t.Fatal("source or result consumer lost", err)
		}
		if reservation.state.validateGeneratedSelection(t.Context(), nil) != nil {
			t.Fatal("source reservation failed cold relation check")
		}
		for _, source := range input.graph.SourceUses {
			original, err := selected.readSelectedSlice(t.Context(), contract.GeneratorContentSource, source.SourceID, contract.GeneratorDeclarationEntryMaxLength)
			if err != nil || contract.Hash(original) != source.EnvelopeDigest {
				t.Fatal("source bytes changed", err)
			}
		}
		input.finished.SourceProtections = input.finished.SourceProtections[:count-1]
		if _, err := s.deriveGeneratedReservation(stdcontext.Background(), input); err == nil {
			t.Fatal("missing current source protection accepted")
		}
	}
}

// full_only: false
func TestGeneratedReservationBindsRetainedCurrentWithoutSealedSource(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	_, retained := generatedCanonicalSource(t)
	current := retained.Entry
	current.Recipients = []contract.ID{s.admission.recipient}
	payload, err := contract.DecodeCanonicalPayload(current.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload.CryptoSupportID = s.root.CurrentAccess.Core.CryptoSupportID
	current.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	valuePage := format.ValueEntryPage{Domain: s.root.Domain, Object: generatedVectorID(240)}
	valuePage.Slots[0] = &current
	valueBody, err := format.EncodeValueEntryPage(valuePage)
	if err != nil {
		t.Fatal(err)
	}
	valueRef, err := format.Reference(format.ValueEntryPageKind, s.root.Domain, valuePage.Object, 0, valueBody)
	if err != nil {
		t.Fatal(err)
	}
	s.pages[0], s.root.ValueEntryPages[0] = &valuePage, &valueRef
	s.root.Names = []format.NameEntry{{Name: current.Name, Slot: 0}}
	s.root.ValueEntryCount, s.root.SecretCount, s.root.RawBytes = 1, 1, uint64(payload.ContentLength)
	s.root.MembershipCount, s.root.SecretOrdinaryWrapCount = 1, 1
	core, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, current)
	if err != nil {
		t.Fatal(err)
	}
	context, err := contract.ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	binding := s.authority().CurrentBinding
	bindingDigest, err := contract.PublicBindingDigest(*binding)
	if err != nil {
		t.Fatal(err)
	}
	access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind,
		MaterialID: current.ValueState, MaterialContextDigest: context, PackageCheck: payload.PackageCheck,
		Wraps: []contract.WrapRow{{SubjectKind: 1, SubjectID: s.admission.recipient, BindingID: binding.BindingID,
			BindingSerial: binding.BindingSerial, PublicBindingDigest: bindingDigest, RSACiphertext: bytes.Repeat([]byte{91}, 384)}}}
	accessPage := format.AccessPage{Domain: s.root.Domain, Object: generatedVectorID(241), Records: []contract.AccessRecord{access}}
	accessBody, err := format.EncodeAccessPage(accessPage)
	if err != nil {
		t.Fatal(err)
	}
	accessRef, err := format.Reference(format.AccessKind, s.root.Domain, accessPage.Object, 0, accessBody)
	if err != nil {
		t.Fatal(err)
	}
	s.access[0] = &accessPage
	s.root.CurrentAccess.Core.AccessPageRefs = []contract.Ref{accessRef}
	s.root.AccessRecordCount = 1
	s.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(s.root.Domain, []contract.AccessRecord{access})
	if err != nil {
		t.Fatal(err)
	}
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	s.recountChildren()
	rootBody, err := format.EncodeRoot(s.root)
	if err != nil {
		t.Fatal(err)
	}
	s.head.Core.Root, err = format.Reference(format.RootKind, s.root.Domain, s.root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
		t.Fatal("current supplied predecessor is not complete")
	}
	body, err := contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: 0, Entry: current})
	if err != nil {
		t.Fatal(err)
	}
	source := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
		Name: current.Name, Recipients: []contract.ID{s.admission.recipient}, Payload: body}
	input := generatedReservationInputForGenerations(t, s, generatedVectorID(250), []string{"next"}, source)
	if len(input.graph.SourceUses) != 0 {
		t.Fatal("retained declaration acquired sealed SourceUses")
	}
	reservation, err := s.deriveGeneratedReservation(stdcontext.Background(), input)
	if err != nil {
		t.Fatal("retained reservation construction", err)
	}
	reservation.state.generatedWork = nil // Prove the stored image without cached selection facts.
	selected, err := reservation.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil || selected.parent == nil {
		t.Fatal("retained reservation failed complete cold selection", err)
	}
	sourceID := contract.ID(sha256.Sum256(append([]byte("ENKV/CRYPTO/v2/retained-member-admission-v1\x00"), body...)))
	key := generatedRecordKey{kind: contract.RetainedCanonicalSupportKind, id: sourceID}
	if _, ok := selected.records[key]; !ok {
		t.Fatal("retained declaration row absent from selected reservation")
	}
	owned := false
	for _, page := range reservation.state.adminIndex.Pages {
		for ordinal, row := range page.Rows {
			if row.Kind != key.kind || row.RecordID != key.id {
				continue
			}
			for _, span := range page.Spans {
				if ordinal < int(span.First) || ordinal >= int(span.First)+int(span.Count) {
					continue
				}
				for _, groupIndex := range span.GroupIndexes {
					owned = owned || reservation.state.adminIndex.Groups[groupIndex].OwnerKind == format.AdministrativeGeneratedDuty
				}
			}
		}
	}
	if !owned {
		t.Fatal("retained current row has no authenticated selected Duty owner")
	}
	if reservation.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("retained declaration reservation has no complete reader proof")
	}
}

// full_only: false
func TestGeneratedPhaseIdentityIncludesNewAndRetainedSparseConfigurationPage(t *testing.T) {
	state := generatedEmptyPredecessor(t)
	page := state.support[0]
	page.Index = 7
	rows := []contract.SupportRecord{contract.SupportRecord(page.Records[0])}
	body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: 7, Records: rows})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, 7, body)
	if err != nil {
		t.Fatal(err)
	}
	state.root.RequiredSupport[0], state.support[0], state.adminIndex.Pages[0].Ref = ref, page, ref
	shards, err := format.EncodeAdministrativeIndexPages(state.adminIndex)
	if err != nil || len(shards) != 1 {
		t.Fatal("sparse predecessor index", err)
	}
	state.root.AdministrativeIndex = shards[0].Ref
	state.recountChildren()
	generatedInstallFixtureSupportReader(t, state)
	newObjectBytes, err := hex.DecodeString("050c8af24a7c93f2bfb9b156045d6108f02a28dcfe43cc3bfd89e8870493cd36")
	if err != nil {
		t.Fatal(err)
	}
	var newObject contract.ID
	copy(newObject[:], newObjectBytes)
	fresh := generatedMaterializerFragment(t, generatedVectorID(8), []byte("new generated support"))
	got, err := state.materializeGeneratedSupportPages(t.Context(), [][]contract.SupportRecord{rows, {fresh}},
		[]contract.ID{generatedVectorID(6), newObject})
	if err != nil {
		t.Fatal("materialized sparse phase", err)
	}
	expectedPages := []contract.IdentityPage{{Kind: contract.RequiredSupportKind, Index: 0, Object: newObject},
		{Kind: contract.RequiredSupportKind, Index: 7, Object: generatedVectorID(67)}}
	if !slices.Equal(got.identityPages, expectedPages) || len(got.objects) != 1 || got.objects[0].ref.Object != newObject {
		t.Fatal("phase identity omitted an exact selected page or rewrote retained bytes", got.identityPages, len(got.objects))
	}
	plan := contract.IdentityPlan{Operation: generatedVectorID(1), Transition: generatedVectorID(2), Snapshot: generatedVectorID(3), Revision: generatedVectorID(4), Pages: got.identityPages}
	encoded, err := contract.EncodeIdentityPlan(plan)
	expectedBytes, decodeErr := hex.DecodeString("454e4b562f4c4946454359434c452d49442d504c414e2f76370001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030304040404040404040404040404040404040404040404040404040404040404040000000000000002080000050c8af24a7c93f2bfb9b156045d6108f02a28dcfe43cc3bfd89e8870493cd360800074343434343434343434343434343434343434343434343434343434343434343")
	if err != nil || decodeErr != nil || len(encoded) != 232 || !bytes.Equal(encoded, expectedBytes) {
		t.Fatal("complete phase identity differs from independent 232-byte framing", len(encoded), err, decodeErr)
	}
	expectedInner, err := hex.DecodeString("cfdbd3106c97504b88b958bd9c6e4ed2316f41ba64064156d6ef9b8f83ff9ac1")
	actualInner := contract.Hash(encoded)
	if err != nil || !bytes.Equal(actualInner[:], expectedInner) {
		t.Fatal("independent inner identity digest", err)
	}
	descriptor, err := contract.GeneratorAuthorityIdentityDescriptor(plan)
	if err != nil || descriptor.Length != 52 || descriptor.Count != 1 || hex.EncodeToString(descriptor.Digest[:]) != "bce8854c1b548b84246674ceccd524dd3d2a357576208ccf4cecd1e1528c6aaa" {
		t.Fatal("independent outer authority identity descriptor", descriptor, err)
	}
}

// full_only: false
func TestGeneratedFixtureRefreshRejectsStaleSliceProof(t *testing.T) {
	for _, path := range []string{"refresh", "repack"} {
		t.Run(path, func(t *testing.T) {
			s := generatedReservationState(t)
			generatedVerifySelectedFixtureSlices(t, s)
			selected, err := s.selectedGeneratedWork(t.Context())
			if err != nil {
				t.Fatal("verified selected sibling refused", err)
			}
			oldRoot := s.generatedSlicesRoot
			locations := slices.Clone(s.generatedSliceLocations)
			intentIndex := slices.IndexFunc(locations, func(v contract.GeneratorSliceLocation) bool { return v.ContentKind == contract.GeneratorContentIntent })
			declarationIndex := slices.IndexFunc(locations, func(v contract.GeneratorSliceLocation) bool {
				return v.ContentKind == contract.GeneratorContentDeclaration
			})
			if intentIndex < 0 || declarationIndex < 0 || locations[declarationIndex].Offset != 0 || locations[intentIndex].BlobID != locations[declarationIndex].BlobID {
				t.Fatal("fixture needs its intent inside the complete declaration blob")
			}
			intent := locations[intentIndex]
			want, err := hex.DecodeString("00012929292929292929292929292929292929292929292929292929292929292929022a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a000000147b226e616d65223a2267656e657261746564227d")
			if err != nil {
				t.Fatal(err)
			}
			got, err := selected.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, intent.ContentID, contract.GeneratorIntentMaxLength)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("original selected intent differs from fixed payload", err)
			}
			declaration, err := selected.readSelectedSlice(t.Context(), contract.GeneratorContentDeclaration, locations[declarationIndex].ContentID, contract.GeneratorDeclarationMaxLength)
			if err != nil {
				t.Fatal("original selected declaration", err)
			}
			locations[intentIndex].Offset = uint64(len(declaration))
			if locations[intentIndex].Offset <= intent.Offset || locations[intentIndex].Logical() != intent.Logical() {
				t.Fatal("relocation changed the logical intent")
			}
			fragments, err := generatedFragmentRows(intent.BlobID, append(slices.Clone(declaration), want...))
			if err != nil || len(fragments) != 1 {
				t.Fatal("relocated intent blob framing", err)
			}
			var bodies [][]byte
			for _, location := range locations {
				body, err := contract.EncodeGeneratorSliceLocation(location)
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, body)
			}
			descriptor, carriers := generatedVectorRows(t, contract.GeneratorSnapshotOwner, s.root.Snapshot, contract.GeneratorVectorSlices, bodies)
			generatedMaterializeFixtureSupport(t, s)
			var directories, replaced int
			for i := range s.support {
				for j, row := range s.support[i].Records {
					if row.Kind == contract.GeneratedFragmentSupportKind {
						fragment, err := contract.InspectGeneratedFragment(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						if fragment.BlobID == intent.BlobID {
							s.support[i].Records[j] = contract.SupportRecordView(fragments[0])
							replaced++
						}
					}
					_, directory, err := snapshotSliceRecord(contract.SupportRecord(row), s.root.Domain, s.root.Snapshot)
					if err != nil {
						t.Fatal(err)
					}
					if directory {
						carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
						if err != nil || int(carrier.Ordinal) >= len(carriers) {
							t.Fatal("fixture directory ordinal", err)
						}
						s.support[i].Records[j] = contract.SupportRecordView(carriers[carrier.Ordinal])
						directories++
					}
				}
			}
			if replaced != 1 || directories != len(locations) {
				t.Fatal("fixture replacement counts", replaced, directories)
			}
			s.root.Generated.Slices = descriptor
			mixedObject := contract.Hash([]byte("valid mixed fixture support before refresh/v1"))
			if path == "repack" {
				var pages []format.RequiredSupportPageView
				var rows []contract.SupportRecord
				var index uint16
				var configuration, activeParent bool
				for _, page := range s.support {
					if page.Records[0].Kind == contract.GeneratedFragmentSupportKind {
						pages = append(pages, page)
						continue
					}
					index = page.Index
					for _, row := range page.Records {
						rows = append(rows, contract.SupportRecord(row))
						configuration = configuration || row.Kind == contract.OutputConfigurationSliceSupportKind
						activeParent = activeParent || row.Kind == contract.GeneratedParentSupportKind
					}
				}
				slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
					if a.Kind != b.Kind {
						return int(a.Kind) - int(b.Kind)
					}
					return bytes.Compare(a.RecordID[:], b.RecordID[:])
				})
				body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: s.root.Domain, Object: mixedObject, Index: index, Records: rows})
				if err != nil || !configuration || !activeParent {
					t.Fatal("valid mixed mandatory/optional fixture page", err)
				}
				page, err := format.InspectRequiredSupportPage(body)
				if err != nil {
					t.Fatal(err)
				}
				s.support = append(pages, page)
			}
			resolved, err := format.ResolveGeneratedSlices(s.root.Domain, s.root.Snapshot, s.root.Generated, s.support)
			if err != nil || !slices.Equal(resolved, locations) {
				t.Fatal("actual changed physical slices are invalid", err)
			}
			generatedRefreshSupport(t, s, selected.bundles...)
			if path == "repack" && slices.ContainsFunc(s.support, func(page format.RequiredSupportPageView) bool { return page.Object == mixedObject }) {
				t.Fatal("mixed mandatory/optional page did not take the repack return")
			}
			if _, err := format.EncodeRoot(s.root); err != nil {
				t.Fatal("changed fixture Root framing", err)
			}
			content, err := newGeneratedContent(s)
			if err != nil {
				t.Fatal("changed fixture content", err)
			}
			if content.locations[generatedContentKey{contract.GeneratorContentIntent, intent.ContentID}] != locations[intentIndex] {
				t.Fatal("refresh reused a prior verified Slice instead of the changed directory")
			}
			if !s.generatedSlicesRoot.IsZero() {
				t.Fatal("refresh retained verification authority for the previous Root")
			}
			selected, err = s.selectedGeneratedWork(t.Context())
			if err != nil {
				t.Fatal("valid relocated intent refused", err)
			}
			got, err = selected.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, intent.ContentID, contract.GeneratorIntentMaxLength)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("relocation changed the required intent", err)
			}
			generatedVerifySelectedFixtureSlices(t, s)
			if s.generatedSlicesRoot == oldRoot {
				t.Fatal("new verification retained the old Root commitment")
			}
		})
	}
}

// full_only: false
func TestGeneratedFixtureAuthenticatedFragmentRead(t *testing.T) {
	for _, damage := range []string{"none", "missing", "changed"} {
		t.Run(damage, func(t *testing.T) {
			s, _, _ := generatedDetachedRetirementState(t, "absent", 0)
			selected, err := s.selectedGeneratedWork(t.Context())
			if err != nil || selected.content.fragmentFacts == nil || len(selected.content.fragments) != 0 {
				t.Fatal("fixture did not select authenticated fragment reads", err)
			}
			want, err := hex.DecodeString("00010909090909090909090909090909090909090909090909090909090909090909020707070707070707070707070707070707070707070707070707070707070707000000027b7d")
			if err != nil {
				t.Fatal(err)
			}
			intent, err := contract.GeneratorIntentDigest(want)
			if err != nil {
				t.Fatal(err)
			}
			store := s.store.(*generatedFixtureSupportStore)
			baseline := len(store.keys)
			damaged := make(map[string]bool)
			for i := range s.support {
				var released bool
				for j := range s.support[i].Records {
					row := &s.support[i].Records[j]
					if row.Kind != contract.GeneratedFragmentSupportKind {
						continue
					}
					row.Body, released = nil, true
				}
				if !released {
					continue
				}
				key, err := format.Key(s.admission.store.Prefix, s.root.RequiredSupport[i])
				if err != nil {
					t.Fatal(err)
				}
				if damaged[key] {
					continue
				}
				damaged[key] = true
				switch damage {
				case "missing":
					delete(store.objects, key)
				case "changed":
					store.objects[key][0] ^= 1
				}
			}
			got, err := selected.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, intent, contract.GeneratorIntentMaxLength)
			if damage == "none" {
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("authenticated fixture fragment read", err)
				}
			} else {
				result, selectedFailure := selectedReadResult(err)
				wantOutcome, wantReason := EvidenceUnavailable, MissingSelectedObject
				if damage == "changed" {
					wantOutcome, wantReason = IntegrityFailure, InvalidReference
				}
				if !selectedFailure || result.Outcome != wantOutcome || result.Reason != wantReason || got != nil {
					t.Fatal("fixture used retained bytes instead of the damaged Store", result, err)
				}
			}
			if len(store.keys) != baseline+1 {
				t.Fatal("fixture fragment did not use one exact selected read", len(store.keys)-baseline)
			}
		})
	}
}

// full_only: false
func TestGeneratedSelectedFixtureRootAndOutputRead(t *testing.T) {
	constructors := map[string]func(testing.TB) *StateSession{
		"reservation":        func(t testing.TB) *StateSession { return generatedReservationState(t) },
		"canonical":          func(t testing.TB) *StateSession { s, _, _ := generatedCanonicalState(t, false); return s },
		"canonical recovery": func(t testing.TB) *StateSession { s, _, _ := generatedCanonicalState(t, true); return s },
		"selected entry":     generatedSelectedEntryState,
	}
	for name, construct := range constructors {
		t.Run(name, func(t *testing.T) {
			t.Run("root", func(t *testing.T) {
				s := construct(t)
				if _, err := format.EncodeRoot(s.root); err != nil {
					t.Fatal("selected fixture Root is incomplete", err)
				}
				want := map[string][7]uint64{"reservation": {0, 1, 1, 0, 0, 0, 0}, "canonical": {1, 127, 2, 1, 4, 64, 64}, "canonical recovery": {1, 127, 2, 1, 4, 64, 64}, "selected entry": {1, 2, 1, 1, 3, 1, 1}}[name]
				got := [7]uint64{uint64(s.root.ValueEntryCount), uint64(s.root.RecipientCount), uint64(s.root.AccessRecordCount), uint64(s.root.SecretCount), s.root.RawBytes, uint64(s.root.MembershipCount), uint64(s.root.SecretOrdinaryWrapCount)}
				if got != want {
					t.Fatalf("selected fixture aggregates: got=%v want=%v", got, want)
				}
			})
			t.Run("output read", func(t *testing.T) {
				s := construct(t)
				c, result := s.currentOutputConfigurationForApply(t.Context())
				if result.Outcome != 0 {
					t.Fatalf("selected fixture output refused: outcome=%d reason=%d", result.Outcome, result.Reason)
				}
				if c.Schema != contract.OutputConfigurationSchema || c.DomainID != generatedVectorID(1) || len(c.Bindings) != 0 || len(c.Routes) != 0 || len(c.Groups) != 0 {
					t.Fatal("selected fixture empty output changed")
				}
			})
		})
	}
}
