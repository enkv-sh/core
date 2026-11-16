package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// Add an actual declaration entry to a behavior fixture; the shared graph
// validators still check every relation. This is not an expected-byte oracle.
func generatedAddDeclarationSource(t *testing.T, f *generatedRuntimeFixture, entry contract.GeneratorDeclarationEntry, plan contract.GeneratorValueEntryPlan) {
	t.Helper()
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	view, err := contract.InspectGeneratorDeclaration(f.declaration)
	if err != nil {
		t.Fatal(err)
	}
	d, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	d.Entries = append(d.Entries, entry)
	slices.SortFunc(d.Entries, func(a, b contract.GeneratorDeclarationEntry) int {
		return bytes.Compare([]byte(a.Name), []byte(b.Name))
	})
	f.declaration, err = contract.EncodeGeneratorDeclaration(d)
	if err != nil {
		t.Fatal(err)
	}
	view, err = contract.InspectGeneratorDeclaration(f.declaration)
	if err != nil {
		t.Fatal(err)
	}
	locations, err := view.Slices()
	if err != nil {
		t.Fatal(err)
	}
	entryID, err := contract.GeneratorDeclarationEntryID(d.DomainID, d.OperationID, entry.Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, location := range locations {
		if location.Logical.ContentKind == contract.GeneratorContentSource && location.Logical.ContentID == entryID {
			plan.SourceSlice, err = contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{location.Logical})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	plan.IntendedMembership, err = contract.GeneratorIntendedMembershipDescriptor(entry.Recipients)
	if err != nil {
		t.Fatal(err)
	}
	g.ValueEntryPlans = append(g.ValueEntryPlans, plan)
	slices.SortFunc(g.ValueEntryPlans, func(a, b contract.GeneratorValueEntryPlan) int { return bytes.Compare([]byte(a.Name), []byte(b.Name)) })
	if entry.Kind == contract.GeneratorDeclarationSealed {
		envelope, err := contract.DecodeSealedInputEnvelope(entry.Payload)
		if err != nil {
			t.Fatal(err)
		}
		core, err := contract.SealedInputCoreDigest(envelope.Core)
		if err != nil {
			t.Fatal(err)
		}
		use := contract.GeneratorSourceUse{Schema: 1, SourceID: envelope.Core.SourceID, SealedInputCoreDigest: core, EnvelopeDigest: contract.Hash(entry.Payload), Purpose: 2}
		for _, location := range locations {
			if location.Logical.ContentKind == contract.GeneratorContentSource && location.Logical.ContentID == use.SourceID {
				use.SourceSlice, err = contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{location.Logical})
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		consumer, err := contract.GeneratorAcceptedSourceConsumer(d.OperationID, g.Header.MaterialID, use)
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeGeneratorConsumer(consumer)
		if err != nil {
			t.Fatal(err)
		}
		use.Consumers, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, [][]byte{body})
		if err != nil {
			t.Fatal(err)
		}
		g.SourceUses = append(g.SourceUses, use)
		slices.SortFunc(g.SourceUses, func(a, b contract.GeneratorSourceUse) int { return bytes.Compare(a.SourceID[:], b.SourceID[:]) })
	}
	oldJoin, err := contract.GeneratorCompleteJoinID(g.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	g.Request.Declaration, err = view.Descriptor()
	if err != nil {
		t.Fatal(err)
	}
	g.Header.ValueEntryPlanCount = uint16(len(g.ValueEntryPlans))
	g.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(g.Request)
	if err != nil {
		t.Fatal(err)
	}
	join, err := contract.GeneratorCompleteJoinID(g.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	for i := range g.Edges {
		if g.Edges[i].DestinationTemplateID == oldJoin {
			g.Edges[i].DestinationTemplateID = join
		}
	}
	g.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(g.Header, g.ValueEntryPlans, g.Lineages, g.Edges)
	if err != nil {
		t.Fatal(err)
	}
	g.UsePlan.SourceUses, err = contract.GeneratorSourceUsesDescriptor(g.SourceUses)
	if err != nil || contract.ValidateGeneratorEffectGraph(g) != nil || contract.ValidateGeneratorDeclarationGraph(view, g) != nil {
		t.Fatal("source graph fixture", err)
	}
	f.graph, err = contract.EncodeGeneratorPlanBundle(g)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.PlanGraph, err = contract.GeneratorPlanBundleDescriptor(g)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.IntendedEntryPlans, err = contract.GeneratorValueEntryPlansDescriptor(g.ValueEntryPlans)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.UsePlanDigest, err = contract.GeneratorUsePlanDigest(g.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.AcceptedSources = g.UsePlan.SourceUses
	p := &f.compare.ParentPlan
	p.ValueEntryPlanCount, p.LineageCount, p.TemplateCount = g.Header.ValueEntryPlanCount, g.Header.LineageCount, g.Header.TemplateCount
	p.RequestCoreDigest, p.PlanGraphID, p.UsePlanDigest = g.Header.RequestCoreDigest, g.UsePlan.PlanGraphID, f.compare.UsePlanDigest
	p.Declaration, p.Graph, p.SourceUses, p.IntendedEntryPlans = g.Request.Declaration, f.compare.PlanGraph, f.compare.AcceptedSources, f.compare.IntendedEntryPlans
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	f.reservation.Session.Graph, f.reservation.Plan.Declaration = f.graph, f.declaration
}

func generatedSealedPlanFixture(t *testing.T, recovery bool) generatedRuntimeFixture {
	t.Helper()
	f := generatedRuntimeEffectFixture(t, recovery)
	entry := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed, Name: "alpha",
		Recipients: slices.Clone(f.base.q.Intent[0].Recipients), Payload: f.base.q.SealedInputs[0].EnvelopeBytes}
	generatedAddDeclarationSource(t, &f, entry, contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: 1, Name: entry.Name,
		ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, EntryIncarnationID: consumerID("alpha incarnation"), ChangeMask: 1})
	f.reservation.Accepted = map[contract.ID]contract.SealedInputCore{contract.Hash(entry.Payload): f.base.accepted[contract.Hash(entry.Payload)]}
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	f.reservation.Plan.LiveSourceUses = slices.Clone(g.SourceUses)
	return f
}

func generatedSealedFinalFixture(t *testing.T, recovery bool) generatedRuntimeFixture {
	t.Helper()
	return generatedSealedFinalFromPlan(t, generatedSealedPlanFixture(t, recovery))
}

func generatedSealedFinalFromPlan(t *testing.T, f generatedRuntimeFixture) generatedRuntimeFixture {
	t.Helper()
	f, prepared, _ := generatedProducerPlanFixture(t, f)
	f.compare.Purpose = 3
	var err error
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	var protections []byte
	if len(prepared.SourceProtections) != 0 {
		protections, err = contract.EncodeGeneratedSourceProtections(prepared.Material, prepared.SourceProtections)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.final = generatedFinalAdmissionInput{
		Session: f.producer.Session, Plan: f.producer.Plan, Material: prepared.Material, SeedAccess: prepared.SeedAccess,
		SourceProtections: protections, Target: f.producer.Target, ControlledPredecessor: f.producer.ControlledPredecessor,
		Phase: contract.GeneratorPhaseIdentity{RequestIdentityDigest: f.compare.Parent.RequestIdentityDigest,
			ObservedHEADDigest: f.compare.Context.PredecessorHEADDigest, ConditionDigest: f.compare.Context.OriginalConditionDigest,
			TransitionKind: contract.GeneratorAuthorityFinal, BeforePhase: 1, AfterPhase: 2, Evidence: contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)},
	}
	return f
}

func generatedSourceCandidate(t *testing.T, f generatedRuntimeFixture, snapshot contract.ID, uses []contract.GeneratorSourceUse) generatedCandidate {
	t.Helper()
	c := generatedCandidate{Subject: contract.GeneratorAuthoritySubject{DomainID: f.compare.Context.DomainID}, LiveSourceUses: slices.Clone(uses)}
	if len(uses) == 0 {
		return c
	}
	view, err := contract.InspectGeneratedSourceProtections(f.final.Material, f.final.SourceProtections)
	if err != nil {
		t.Fatal(err)
	}
	var rows []contract.CryptoGeneratedSourceProtection
	for i := 0; i < view.Count(); i++ {
		row, err := view.Row(i)
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(uses, func(use contract.GeneratorSourceUse) bool { return use.SourceID == row.SourceID }) {
			rows = append(rows, contract.CryptoGeneratedSourceProtection{SourceID: row.SourceID, OriginalSourceCoreDigest: row.OriginalSourceCoreDigest,
				OriginalEnvelopeDigest: row.OriginalEnvelopeDigest, Transfer: contract.TransferEnvelope(row.Transfer)})
		}
	}
	c.SourceProtections, err = contract.EncodeGeneratedSourceProtections(f.final.Material, rows)
	if err != nil {
		t.Fatal(err)
	}
	location, err := contract.EncodeGeneratorSliceLocation(contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentConfiguration,
		ContentID: f.compare.MaterialID, BlobID: consumerID("source protection blob"), Offset: 37,
		Length: uint32(len(c.SourceProtections)), Digest: contract.Hash(c.SourceProtections)})
	if err != nil {
		t.Fatal(err)
	}
	c.SupportRecords = generatedVectorSupport(t, f.compare.Context.DomainID, contract.GeneratorSnapshotOwner, snapshot, contract.GeneratorVectorSlices, [][]byte{location})
	return c
}

// full_only: false
func TestGeneratedSourceCandidatePinsConfigurationCarrier(t *testing.T) {
	f := generatedSealedFinalFixture(t, true)
	r := f.finalRuntime(t)
	generatedSourceCompare(t, r, f)
	a := r.generated
	snapshot := consumerID("source candidate snapshot")
	for _, name := range []string{"exact", "missing carrier", "carrier id", "carrier domain", "carrier descriptor", "missing vector row", "duplicate carrier", "wrong snapshot", "changed transfer", "changed logical digest", "physical relocation"} {
		t.Run(name, func(t *testing.T) {
			c := generatedSourceCandidate(t, f, snapshot, f.final.Plan.LiveSourceUses)
			carrier, err := contract.InspectGeneratorVectorCarrier(c.SupportRecords[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing carrier":
				c.SupportRecords = nil
			case "carrier id":
				c.SupportRecords[0].RecordID = consumerID("wrong configuration carrier")
			case "carrier domain":
				carrier.DomainID = consumerID("wrong configuration domain")
			case "carrier descriptor":
				carrier.Vector.Digest = consumerID("wrong slice vector")
			case "missing vector row":
				other, err := contract.InspectGeneratorSliceLocation(carrier.Row)
				if err != nil {
					t.Fatal(err)
				}
				other.ContentKind = contract.GeneratorContentSource
				body, err := contract.EncodeGeneratorSliceLocation(other)
				if err != nil {
					t.Fatal(err)
				}
				carrier.Vector, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, [][]byte{body, carrier.Row})
				if err != nil {
					t.Fatal(err)
				}
				carrier.Ordinal = 1
			case "duplicate carrier":
				c.SupportRecords = append(c.SupportRecords, c.SupportRecords[0])
			case "wrong snapshot":
				carrier.OwnerID = consumerID("other snapshot")
			case "changed transfer":
				c.SourceProtections = bytes.Clone(c.SourceProtections)
				c.SourceProtections[len(c.SourceProtections)-1] ^= 1
			case "changed logical digest", "physical relocation":
				location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
				if err != nil {
					t.Fatal(err)
				}
				if name == "physical relocation" {
					location.Offset, location.BlobID = 73, consumerID("relocated protection blob")
				} else {
					location.Digest = consumerID("wrong logical source protection")
				}
				carrier.Row, err = contract.EncodeGeneratorSliceLocation(location)
				if err != nil {
					t.Fatal(err)
				}
				carrier.Vector, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, [][]byte{carrier.Row})
				if err != nil {
					t.Fatal(err)
				}
			}
			if name == "carrier domain" || name == "carrier descriptor" || name == "missing vector row" || name == "wrong snapshot" || name == "changed logical digest" || name == "physical relocation" {
				c.SupportRecords[0].Body, err = contract.EncodeGeneratorVectorCarrier(carrier)
				if err != nil {
					t.Fatal(err)
				}
				c.SupportRecords[0].RecordID, err = contract.GeneratorVectorCarrierID(carrier)
				if err != nil {
					t.Fatal(err)
				}
			}
			want := name == "exact" || name == "physical relocation"
			if got := a.candidateProtectionsMatch(c, snapshot); got != want {
				t.Fatal("configuration carrier binding", got, want)
			}
		})
	}
	r.retireGenerated()
}

// full_only: false
func TestGeneratedSourceInitialCandidateBindsFinishPlanProtections(t *testing.T) {
	f := generatedSealedPlanFixture(t, true)
	for _, name := range []string{"exact", "missing protection", "changed transfer"} {
		t.Run(name, func(t *testing.T) {
			r := f.reservationRuntime(t)
			op := generatedCompare(t, r, f)
			generatedPlanParts(t, r, f, op)
			prepared := generatedFinishPlan(t, r, f, op)
			c := generatedPlanCandidate(t, f, prepared)
			fixed := f
			fixed.final.Material = prepared.Material
			fixed.final.Plan.LiveSourceUses = fixed.reservation.Plan.LiveSourceUses
			var err error
			fixed.final.SourceProtections, err = contract.EncodeGeneratedSourceProtections(prepared.Material, prepared.SourceProtections)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := contract.GeneratorInitialSnapshotID(f.compare.ParentPlan.RequestCoreDigest)
			if err != nil {
				t.Fatal(err)
			}
			protection := generatedSourceCandidate(t, fixed, snapshot, f.reservation.Plan.LiveSourceUses)
			c.LiveSourceUses, c.SourceProtections = protection.LiveSourceUses, protection.SourceProtections
			c.SupportRecords = append(c.SupportRecords, protection.SupportRecords...)
			generatedCanonicalizeCandidateSupport(t, &c)
			switch name {
			case "missing protection":
				c.SourceProtections = nil
			case "changed transfer":
				c.SourceProtections = bytes.Clone(c.SourceProtections)
				c.SourceProtections[len(c.SourceProtections)-1] ^= 1
			}
			want := contract.CryptoInvalidAdmission
			if name == "exact" {
				want = contract.CryptoSuccess
			}
			if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, c); code != want {
				t.Fatal("initial source protection binding", code, want)
			}
			r.retireGenerated()
		})
	}
}

// full_only: false
func TestGeneratedSourceSubsetsPreserveExactOriginalRowsAndTransfers(t *testing.T) {
	f := generatedSealedPlanFixture(t, true)
	entry := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed, Name: "beta",
		Recipients: slices.Clone(f.base.q.Intent[1].Recipients), Payload: f.base.q.SealedInputs[1].EnvelopeBytes}
	generatedAddDeclarationSource(t, &f, entry, contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: 2, Name: entry.Name,
		ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, EntryIncarnationID: consumerID("beta incarnation"), ChangeMask: 1})
	f.reservation.Accepted[contract.Hash(entry.Payload)] = f.base.accepted[contract.Hash(entry.Payload)]
	graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	f.reservation.Plan.LiveSourceUses = slices.Clone(graph.SourceUses)
	f = generatedSealedFinalFromPlan(t, f)
	r := f.finalRuntime(t)
	generatedSourceCompare(t, r, f)
	a := r.generated
	snapshot := consumerID("source subset snapshot")
	for _, uses := range [][]contract.GeneratorSourceUse{f.final.Plan.LiveSourceUses, f.final.Plan.LiveSourceUses[:1], f.final.Plan.LiveSourceUses[1:], nil} {
		c := generatedSourceCandidate(t, f, snapshot, uses)
		if !a.candidateProtectionsMatch(c, snapshot) {
			t.Fatal("exact original source subset refused", len(uses))
		}
		if len(uses) < len(f.final.Plan.LiveSourceUses) {
			c.ActiveOwner = graph.Header.OperationID
			if a.candidateProtectionsMatch(c, snapshot) {
				t.Fatal("active parent released an original source", len(uses))
			}
			c.ActiveOwner = contract.ID{}
		}
		input := f.final
		input.Plan.LiveSourceUses, input.SourceProtections = uses, c.SourceProtections
		continued := newConsumerRuntime(t, f.base.route)
		if err := continued.admitGeneratedFinal(f.compare, input, f.base.deadline); err != nil {
			t.Fatal("selected original subset refused", len(uses), err)
		}
		generatedSourceCompare(t, continued, f)
		if len(uses) < len(f.final.Plan.LiveSourceUses) {
			full := generatedSourceCandidate(t, f, snapshot, f.final.Plan.LiveSourceUses)
			if continued.generated.candidateProtectionsMatch(full, snapshot) {
				t.Fatal("detached source set revived an unselected source")
			}
		}
		continued.retireGenerated()
	}
	for _, name := range []string{"reverse", "duplicate", "changed original row", "surplus transfer", "orphan configuration"} {
		c := generatedSourceCandidate(t, f, snapshot, f.final.Plan.LiveSourceUses)
		switch name {
		case "reverse":
			slices.Reverse(c.LiveSourceUses)
		case "duplicate":
			c.LiveSourceUses[1] = c.LiveSourceUses[0]
		case "changed original row":
			c.LiveSourceUses[0].EnvelopeDigest = consumerID("substitute original source")
		case "surplus transfer":
			c.LiveSourceUses = c.LiveSourceUses[:1]
		case "orphan configuration":
			c.LiveSourceUses, c.SourceProtections = nil, nil
		}
		if a.candidateProtectionsMatch(c, snapshot) {
			t.Fatal("inexact source subset accepted", name)
		}
		if name == "reverse" || name == "duplicate" || name == "changed original row" || name == "surplus transfer" {
			input := f.final
			input.Plan.LiveSourceUses, input.SourceProtections = c.LiveSourceUses, c.SourceProtections
			continued := newConsumerRuntime(t, f.base.route)
			if err := continued.admitGeneratedFinal(f.compare, input, f.base.deadline); err == nil || continued.slot != nil {
				t.Fatal("inexact selected source subset admitted", name, err)
			}
		}
	}
	r.retireGenerated()
}

// full_only: false
func TestGeneratedSourceAdmissionRequiresExactLiveUses(t *testing.T) {
	f := generatedSealedPlanFixture(t, false)
	for _, rows := range [][]contract.GeneratorSourceUse{nil, append(slices.Clone(f.reservation.Plan.LiveSourceUses), f.reservation.Plan.LiveSourceUses[0])} {
		input := f.reservation
		input.Plan.LiveSourceUses = rows
		r := newConsumerRuntime(t, f.base.route)
		if err := r.admitGeneratedReservation(f.compare, input, f.base.deadline); err == nil {
			t.Fatal("initial source subset accepted")
		}
	}
	f = generatedSealedFinalFixture(t, true)
	for _, keep := range []bool{false, true} {
		input := f.final
		if !keep {
			input.Plan.LiveSourceUses, input.SourceProtections = nil, nil
			input.Session.Bindings = slices.DeleteFunc(slices.Clone(input.Session.Bindings), func(row contract.BindingTableRow) bool {
				return row.SubjectKind == 1 && row.SubjectID != input.Session.Control.AuthorityRecipientID
			})
		}
		r := newConsumerRuntime(t, f.base.route)
		if err := r.admitGeneratedFinal(f.compare, input, f.base.deadline); err != nil {
			t.Fatal("exact selected source subset", keep, err)
		}
		body, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
		if err != nil {
			t.Fatal(err)
		}
		if out := applyCall(r, context.Background(), contract.CryptoCompare, body); out.ResultCode != contract.CryptoSuccess {
			t.Fatal("open live subset", out.ResultCode)
		}
		candidate := generatedCandidate{}
		if !r.generated.candidateProtectionsMatch(candidate, consumerID("candidate snapshot")) {
			t.Fatal("final could not release ended sources")
		}
		if !keep {
			candidate.LiveSourceUses = f.final.Plan.LiveSourceUses
			candidate.SourceProtections = f.final.SourceProtections
			if r.generated.candidateProtectionsMatch(candidate, consumerID("candidate snapshot")) {
				t.Fatal("historical graph revived a source")
			}
		}
		r.retireGenerated()
	}
}

func generatedSourceSuccessorFixture(t *testing.T, recovery bool) generatedRuntimeFixture {
	t.Helper()
	f := generatedSealedFinalFixture(t, recovery)
	seed := generatedTestSeed(t, f, contract.CryptoGeneratedFinishPlanResult{Material: f.final.Material, SeedAccess: f.final.SeedAccess})
	defer clear(seed[:cap(seed)])
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	f.final.Session.Bindings = slices.Clone(f.final.Session.Bindings)
	index := applyBindingIndex(f.final.Session.Bindings, f.final.Session.Control.AuthorityRecipientID)
	binding := &f.final.Session.Bindings[index].Binding
	binding.BindingID, binding.BindingSerial = consumerID("successor source authority"), binding.BindingSerial+1
	binding.KeySelector = "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/successor/cryptoKeyVersions/1"
	binding.SPKI, binding.Fingerprint = spki, contract.Hash(spki)
	f.final.Session.Control.AuthorityKMSBinding = *binding
	f.final.Session.Control.AccessGeneration++
	access, err := contract.DecodeAccessRecord(f.final.SeedAccess)
	if err != nil {
		t.Fatal(err)
	}
	core, err := custody.SeedWrapCore(f.final.Material.Core, f.final.Session.Bindings[index])
	if err != nil {
		t.Fatal(err)
	}
	access.Wraps[0], err = custody.Wrap(core, *binding, seed)
	if err != nil {
		t.Fatal(err)
	}
	f.final.SeedAccess, err = contract.EncodeAccessRecord(access)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.Context.CurrentAccessRoot = consumerID("successor source access root")
	f.final.Session.BeforePublic.AccessRoot = f.compare.Context.CurrentAccessRoot
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	f.base.route = &consumerTestRoute{testKeyAccess: &testKeyAccess{key: key, binding: *binding}}
	return f
}

func generatedSourceCompare(t *testing.T, r *Runtime, f generatedRuntimeFixture) {
	t.Helper()
	body, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, context.Background(), contract.CryptoCompare, body)
	if reply.ResultCode != contract.CryptoSuccess || len(reply.KeyUseRows) != 1 ||
		reply.KeyUseRows[0].Purpose != contract.KeyUseMaterialOpen || reply.KeyUseRows[0].Count != 1 ||
		reply.KeyUseRows[0].BindingID != f.final.Session.Control.AuthorityKMSBinding.BindingID {
		t.Fatal("open current source seed", reply.ResultCode, reply.KeyUseRows)
	}
}

// full_only: false
func TestGeneratedSourceReopensThroughCurrentSeedWithoutOriginalRoute(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		f := generatedSourceSuccessorFixture(t, recovery)
		body := f.base.q.SealedInputs[0].EnvelopeBytes
		before := bytes.Clone(body)
		r := f.finalRuntime(t)
		generatedSourceCompare(t, r, f)
		a := r.generated
		id := f.final.Plan.LiveSourceUses[0].SourceID
		if code := r.verifyGeneratedSource(context.Background(), a.id, id, body); code != contract.CryptoSuccess {
			t.Fatal("reopen original source with current seed", recovery, code)
		}
		if f.base.route.privateCalls != 1 || len(a.keyUses) != 1 || a.keyUses[0].BindingID != f.final.Session.Control.AuthorityKMSBinding.BindingID {
			t.Fatal("source required an old private route", recovery, f.base.route.privateCalls, a.keyUses)
		}
		if !a.purpose.final.plan.sources[0].verified || !bytes.Equal(body, before) || len(a.purpose.final.plan.sources[0].buffer) != 0 || len(a.purpose.final.plan.sources[0].keys) != 0 {
			t.Fatal("source body was changed or retained")
		}
		if code := r.verifyGeneratedSource(context.Background(), a.id, id, body); code != contract.CryptoAlreadyUsed {
			t.Fatal("source verification replay", code)
		}
		r.retireGenerated()
	}
}

// full_only: false
func TestGeneratedSourceReopenAuthenticatesFullSourceNotOnlyPublicDigests(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		f := generatedSourceSuccessorFixture(t, recovery)
		r := f.finalRuntime(t)
		generatedSourceCompare(t, r, f)
		a := r.generated
		seed := a.seed
		envelope, err := contract.DecodeSealedInputEnvelope(f.base.q.SealedInputs[0].EnvelopeBytes)
		if err != nil {
			t.Fatal(err)
		}
		envelope.Ciphertext[0] ^= 1
		body, err := contract.EncodeSealedInputEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		// Pin the changed public commitments at the private leaf boundary. The
		// full source AEAD must still fail after the selected transfer opens.
		a.purpose.final.plan.sources[0].envelope = contract.Hash(body)
		a.purpose.final.plan.liveSources[0].EnvelopeDigest = contract.Hash(body)
		view, err := contract.InspectGeneratedSourceProtections(a.material, a.purpose.final.plan.protections)
		if err != nil {
			t.Fatal(err)
		}
		row, err := view.Row(0)
		if err != nil {
			t.Fatal(err)
		}
		row.OriginalEnvelopeDigest = contract.Hash(body)
		a.purpose.final.plan.protections, err = contract.EncodeGeneratedSourceProtections(a.material, []contract.CryptoGeneratedSourceProtection{{
			SourceID: row.SourceID, OriginalSourceCoreDigest: row.OriginalSourceCoreDigest, OriginalEnvelopeDigest: row.OriginalEnvelopeDigest,
			Transfer: contract.TransferEnvelope(row.Transfer)}})
		if err != nil {
			t.Fatal(err)
		}
		if code := r.verifyGeneratedSource(context.Background(), a.id, a.purpose.final.plan.sources[0].core.SourceID, body); code != contract.CryptoSourceAuthenticationFailed {
			t.Fatal("tampered full source authenticated", recovery, code)
		}
		if f.base.route.privateCalls != 1 {
			t.Fatal("source authentication used private source route")
		}
		r.retireGenerated()
		for _, value := range seed {
			if value != 0 {
				t.Fatal("failed source owner retained its seed")
			}
		}
	}
}

// full_only: false
func TestGeneratedSourceReopenRequiresLiveSourceAndOpenPreparation(t *testing.T) {
	f := generatedSourceSuccessorFixture(t, true)
	for _, name := range []string{"before compare", "unknown source", "dropped source", "changed bytes", "short body", "after members", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			input := f.final
			if name == "dropped source" {
				input.Plan.LiveSourceUses, input.SourceProtections = nil, nil
			}
			r := newConsumerRuntime(t, f.base.route)
			if err := r.admitGeneratedFinal(f.compare, input, f.base.deadline); err != nil {
				t.Fatal(err)
			}
			if name != "before compare" {
				generatedSourceCompare(t, r, f)
			}
			a := r.generated
			body := bytes.Clone(f.base.q.SealedInputs[0].EnvelopeBytes)
			source := f.final.Plan.LiveSourceUses[0].SourceID
			ctx := context.Background()
			want := contract.CryptoInvalidAdmission
			switch name {
			case "before compare":
				want = contract.CryptoAlreadyUsed
			case "unknown source":
				source = consumerID("another sealed source")
			case "changed bytes":
				body[len(body)-1] ^= 1
				want = contract.CryptoSourceAuthenticationFailed
			case "short body":
				body = body[:len(body)-1]
				want = contract.CryptoSourceAuthenticationFailed
			case "after members":
				request, err := contract.EncodeCryptoGeneratedValueEntriesRequest(contract.CryptoGeneratedValueEntriesRequest{
					OperationRef: a.operation, Context: f.compare.Context, PhaseID: a.purpose.final.phaseID, Final: 1})
				if err != nil {
					t.Fatal(err)
				}
				if reply := applyCall(r, ctx, contract.CryptoPrepare, request); reply.ResultCode != contract.CryptoSuccess {
					t.Fatal("empty final prepare", reply.ResultCode)
				}
				want = contract.CryptoAlreadyUsed
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = contract.CryptoCancelled
			}
			if code := r.verifyGeneratedSource(ctx, a.id, source, body); code != want {
				t.Fatal("source refusal", code, want)
			}
			if code := r.verifyGeneratedSource(context.Background(), a.id, source, f.base.q.SealedInputs[0].EnvelopeBytes); code != contract.CryptoInvalidAdmission {
				t.Fatal("failed verification left a reusable owner", code)
			}
			r.retireGenerated()
		})
	}
	initial := generatedSealedPlanFixture(t, false)
	r := initial.reservationRuntime(t)
	generatedCompare(t, r, initial)
	if code := r.verifyGeneratedSource(context.Background(), initial.compare.Context.AdmissionID,
		initial.reservation.Plan.LiveSourceUses[0].SourceID, initial.base.q.SealedInputs[0].EnvelopeBytes); code != contract.CryptoInvalidAdmission {
		t.Fatal("initial preparation bypassed streamed source open", code)
	}
	r.retireGenerated()
}
