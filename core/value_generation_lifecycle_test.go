package core

import (
	"bytes"
	stdcontext "context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedLifecycleFixture(t testing.TB, s *StateSession) contract.ApplyContext {
	return generatedLifecycleFixtureForFamily(t, s, contract.AWS)
}

func generatedLifecycleFixtureForFamily(t testing.TB, s *StateSession, family contract.Family) contract.ApplyContext {
	t.Helper()
	basis := generatedEmptyPredecessorForFamily(t, family)
	s.admission, s.body, s.token = basis.admission, basis.body, basis.token
	s.recipients, s.recipient = basis.recipients, basis.recipient
	if s.root.OutputConfiguration.SliceCount == 0 {
		s.root.OutputConfiguration = basis.root.OutputConfiguration
		configurationPage := basis.support[0]
		configurationPage.Object = contract.Hash(append([]byte("fixture lifecycle empty configuration"), s.root.Domain[:]...))
		configurationPage.Index = generatedFixtureFreeSupportIndex(t, s)
		s.support = append(s.support, configurationPage)
	}
	s.root.Transition = basis.root.Transition
	s.root.CurrentAccess.Core.CurrentControl = basis.root.CurrentAccess.Core.CurrentControl
	binding := basis.authority().CurrentBinding
	bindingDigest, err := contract.PublicBindingDigest(*binding)
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.support {
		for j, row := range s.support[i].Records {
			if row.Kind != 1 {
				continue
			}
			material, err := contract.DecodeOperationMaterialRecord(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			material.Core.CompatibilityID = basis.root.CurrentAccess.Core.CompatibilityID
			material.Core.CryptoSupportID = basis.root.CurrentAccess.Core.CryptoSupportID
			body, err := contract.EncodeOperationMaterialRecord(material)
			if err != nil {
				t.Fatal(err)
			}
			s.support[i].Records[j].Body = body
			context, err := contract.OperationMaterialContextDigest(material.Core)
			if err != nil {
				t.Fatal(err)
			}
			for _, page := range s.access {
				if page == nil {
					continue
				}
				for k := range page.Records {
					if page.Records[k].MaterialKind == 3 && page.Records[k].MaterialID == row.RecordID {
						page.Records[k].MaterialContextDigest = context
					}
				}
			}
		}
	}
	for _, page := range s.access {
		if page == nil {
			continue
		}
		for i := range page.Records {
			for j := range page.Records[i].Wraps {
				wrap := &page.Records[i].Wraps[j]
				wrap.BindingID, wrap.BindingSerial, wrap.PublicBindingDigest = binding.BindingID, binding.BindingSerial, bindingDigest
			}
		}
	}
	var recipientRefs []contract.Ref
	s.root.RecipientCount = 0
	for i, page := range s.recipients {
		if page == nil {
			continue
		}
		body, err := format.EncodeRecipientPage(*page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(format.RecipientKind, s.root.Domain, page.Object, uint16(i), body)
		if err != nil {
			t.Fatal(err)
		}
		s.root.Recipients[i] = &ref
		recipientRefs = append(recipientRefs, ref)
		for _, recipient := range page.Slots {
			if recipient != nil {
				s.root.RecipientCount++
			}
		}
	}
	s.root.CurrentAccess.Core.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{
		DomainID: s.root.Domain, Refs: recipientRefs,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, page := range s.pages {
		if page == nil {
			continue
		}
		body, err := format.EncodeValueEntryPage(*page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(format.ValueEntryPageKind, s.root.Domain, page.Object, uint16(i), body)
		if err != nil {
			t.Fatal(err)
		}
		s.root.ValueEntryPages[i] = &ref
	}
	var accessRows []contract.AccessRecord
	s.root.CurrentAccess.Core.AccessPageRefs = nil
	for i, page := range s.access {
		if page == nil {
			continue
		}
		if len(page.Records) == 0 {
			s.access[i] = nil
			continue
		}
		body, err := format.EncodeAccessPage(*page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(format.AccessKind, s.root.Domain, page.Object, uint16(i), body)
		if err != nil {
			t.Fatal(err)
		}
		s.root.CurrentAccess.Core.AccessPageRefs = append(s.root.CurrentAccess.Core.AccessPageRefs, ref)
		accessRows = append(accessRows, page.Records...)
	}
	s.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(s.root.Domain, accessRows)
	if err != nil {
		t.Fatal(err)
	}
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	generatedRefreshSupport(t, s)
	s.recountChildren()
	if !validAggregate(s.root) {
		t.Fatalf("fixture aggregate is invalid before lifecycle planning: members=%d raw=%d generated=%d access=%d secret=%d accessRefs=%+v refs=%+v", s.root.ValueEntryCount, s.root.RawBytes, s.root.Generated.GeneratedCurrent, s.root.AccessRecordCount, s.root.SecretCount, s.root.CurrentAccess.Core.AccessPageRefs, s.root.ValueEntryPages)
	}
	rootBody, err := format.EncodeRoot(s.root)
	if err != nil {
		t.Fatalf("encode lifecycle fixture: %v members=%d secrets=%d access=%d membership=%d wraps=%d recipients=%d children=%d childBytes=%d support=%d supportRows=%d accessRefs=%d", err,
			s.root.ValueEntryCount, s.root.SecretCount, s.root.AccessRecordCount, s.root.MembershipCount, s.root.SecretOrdinaryWrapCount,
			s.root.RecipientCount, s.root.ChildCount, s.root.ChildEncodedBytes, len(s.root.RequiredSupport),
			s.root.RequiredSupportRecordCount, len(s.root.CurrentAccess.Core.AccessPageRefs))
	}
	rootRef, err := format.Reference(format.RootKind, s.root.Domain, s.root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	s.head = basis.head
	s.head.Core.Root = rootRef
	ctx := generatedContinuationContext(t, s, 201, 202)
	if !s.generatedContextValid(ctx) {
		t.Fatal("fixture context is not current")
	}
	return ctx
}

func generatedLifecycleCanonicalRetirement(t testing.TB, s *StateSession, attemptID, dutyID contract.ID) {
	t.Helper()
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	locations, err := format.ResolveGeneratedSlices(s.root.Domain, s.root.Snapshot, s.root.Generated, s.support)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := g.attempts[attemptID]
	if !ok || len(a.result) == 0 {
		t.Fatal("retirement fixture has no recorded result")
	}
	a.material.Core.CryptoSupportID = contract.CryptoSupportID()
	materialBody, err := contract.EncodeOperationMaterialRecord(a.material)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 1, a.material.Core.OperationMaterialID, materialBody)

	result, err := contract.DecodeGeneratedResultRecord(a.result)
	if err != nil {
		t.Fatal(err)
	}
	result.Payload.CryptoSupportID = a.material.Core.CryptoSupportID
	result.Transfer.Core.CryptoSupportID = a.material.Core.CryptoSupportID
	resultBody, err := contract.EncodeGeneratedResultRecord(result)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 4, a.record.ResultID, resultBody)

	phase := *g.phase
	phase.ResultDigest = contract.Hash(resultBody)
	phaseBody, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 5, phase.OperationID, phaseBody)
	history := []contract.GeneratorHistory{{Schema: 1, PredecessorAttemptID: attemptID, ResultID: a.record.ResultID,
		ResultDigest: contract.Hash(resultBody), OwnerID: dutyID, Outcome: a.record.State}}
	generatedSetHistoryUnrefreshed(t, s, 9, attemptID, history)
	generatedSetHistoryUnrefreshed(t, s, 10, dutyID, history)
	generatedRefreshPhaseSetsUnrefreshed(t, s)
	generatedRepackSupportAtLocations(t, s, s.supportRecords(), g.bundles, locations)
}

// full_only: false
func TestGeneratedLifecyclePrivateAdmissionRefusesInvalidBoundaryBeforeEffects(t *testing.T) {
	s := &StateSession{}
	for _, tc := range []struct {
		name string
		kind generatedLifecycleKind
	}{
		{name: "zero dispatch kind"},
		{name: "unknown dispatch kind", kind: 255},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reservation, err := s.deriveGeneratedLifecycle(t.Context(), &generatedLifecyclePlan{kind: tc.kind}, nil)
			if reservation != nil || err != contract.ErrRecord {
				t.Fatal("invalid lifecycle kind reached a derivation", err)
			}
		})
	}
	for name, admit := range map[string]func() (*admittedGeneratedLifecycle, error){
		"residue": func() (*admittedGeneratedLifecycle, error) {
			return s.admitGeneratedRetirementResidueFixture(contract.ID{}, contract.ApplyContext{})
		},
		"active residue": func() (*admittedGeneratedLifecycle, error) {
			return s.admitGeneratedActiveRetirementResidue(stdcontext.Background(), contract.ID{}, nil, contract.ApplyContext{})
		},
		"park unknown": func() (*admittedGeneratedLifecycle, error) {
			return s.admitGeneratedRetirementUnknown(stdcontext.Background(), contract.ID{}, nil, contract.ApplyContext{})
		},
		"reflection": func() (*admittedGeneratedLifecycle, error) {
			return s.admitGeneratedReflection(stdcontext.Background(), contract.ID{}, nil, contract.ApplyContext{}, nil)
		},
		"retirement close": func() (*admittedGeneratedLifecycle, error) {
			return s.admitGeneratedRetirementClose(stdcontext.Background(), contract.ID{}, contract.ApplyContext{})
		},
		"ordinary cleanup close": func() (*admittedGeneratedLifecycle, error) {
			return s.admitGeneratedOrdinaryCleanupClose(stdcontext.Background(), contract.ID{}, contract.ApplyContext{})
		},
		"inbox release": func() (*admittedGeneratedLifecycle, error) {
			return s.admitGeneratedInboxRelease(stdcontext.Background(), contract.ID{}, contract.ApplyContext{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if permit, err := admit(); err == nil || permit != nil {
				t.Fatal("invalid private lifecycle boundary admitted work")
			}
		})
	}
}

// full_only: false
func TestGeneratedRetirementResidueLifecyclePlanBindsOwnerTargetAndEvidence(t *testing.T) {
	s, _, duty := generatedParkedRetirementState(t)
	ctx := generatedLifecycleFixture(t, s)
	plan, err := s.generatedRetirementResidueFixturePlan(t.Context(), duty.DutyID, ctx)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := s.deriveGeneratedRetirementResidue(t.Context(), plan, nil)
	if err != nil || reserved == nil || reserved.candidate == nil || reserved.candidate.head.Generator == nil ||
		reserved.candidate.head.Generator.Purpose != contract.GeneratorAuthorityResidue ||
		reserved.candidate.head.Generator.OwnerID != duty.DutyID || reserved.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("exact signed residue candidate", err)
	}

	for name, change := range map[string]func(*generatedLifecyclePlan){
		"owner":       func(p *generatedLifecyclePlan) { p.owner = generatedVectorID(230) },
		"target":      func(p *generatedLifecyclePlan) { p.target = generatedVectorID(231) },
		"evidence":    func(p *generatedLifecyclePlan) { p.evidence = generatedVectorID(232) },
		"predecessor": func(p *generatedLifecyclePlan) { p.predecessorDigest = generatedVectorID(233) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *plan
			change(&bad)
			if _, err := s.deriveGeneratedRetirementResidue(t.Context(), &bad, nil); err == nil {
				t.Fatal("changed closed residue plan was accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedReflectionLifecyclePlanBindsOwnerTargetAndEvidence(t *testing.T) {
	s, original, hazard := generatedCreateHazardState(t, 0, 0)
	ctx := generatedLifecycleFixture(t, s)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[original.record.AttemptID]
	result := generatedPublicResultFixture(t, a, 1)
	plan, err := s.generatedReflectionPlan(t.Context(), a.record.ResultID, result, ctx)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := s.deriveGeneratedReflection(t.Context(), plan)
	if err != nil || reserved == nil || reserved.candidate == nil || reserved.candidate.head.Generator == nil ||
		reserved.candidate.head.Generator.Purpose != contract.GeneratorAuthorityReflection ||
		reserved.candidate.head.Generator.OwnerID != hazard.HazardID || reserved.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("exact signed reflection candidate", err)
	}

	for name, change := range map[string]func(*generatedLifecyclePlan){
		"owner":       func(p *generatedLifecyclePlan) { p.owner = generatedVectorID(230) },
		"target":      func(p *generatedLifecyclePlan) { p.target = generatedVectorID(231) },
		"evidence":    func(p *generatedLifecyclePlan) { p.evidence = generatedVectorID(232) },
		"predecessor": func(p *generatedLifecyclePlan) { p.predecessorDigest = generatedVectorID(233) },
		"result":      func(p *generatedLifecyclePlan) { p.result[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *plan
			bad.result = append([]byte(nil), plan.result...)
			change(&bad)
			if _, err := s.deriveGeneratedReflection(t.Context(), &bad); err == nil {
				t.Fatal("changed closed reflection plan was accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedCleanupCloseLifecyclePlanBindsOwnerTargetAndEvidence(t *testing.T) {
	s, original, hazard, _ := generatedDeleteHazardState(t, 0)
	ctx := generatedLifecycleFixture(t, s)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[original.record.AttemptID]
	result := generatedRetirementResultFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged)
	plan, err := s.generatedReflectionPlan(t.Context(), a.record.ResultID, result, ctx)
	if err != nil || plan.kind != generatedLifecycleCleanupClose {
		t.Fatal("exact cleanup-close plan", err)
	}
	reserved, err := s.deriveGeneratedCleanupClose(t.Context(), plan)
	if err != nil || reserved == nil || reserved.candidate == nil || reserved.candidate.head.Generator == nil ||
		reserved.candidate.head.Generator.Purpose != contract.GeneratorAuthorityCleanupClose ||
		reserved.candidate.head.Generator.OwnerID != hazard.HazardID || reserved.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("exact signed cleanup-close candidate", err)
	}

	for name, change := range map[string]func(*generatedLifecyclePlan){
		"owner":       func(p *generatedLifecyclePlan) { p.owner = generatedVectorID(230) },
		"target":      func(p *generatedLifecyclePlan) { p.target = generatedVectorID(231) },
		"evidence":    func(p *generatedLifecyclePlan) { p.evidence = generatedVectorID(232) },
		"predecessor": func(p *generatedLifecyclePlan) { p.predecessorDigest = generatedVectorID(233) },
		"result":      func(p *generatedLifecyclePlan) { p.result[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *plan
			bad.result = append([]byte(nil), plan.result...)
			change(&bad)
			if _, err := s.deriveGeneratedCleanupClose(t.Context(), &bad); err == nil {
				t.Fatal("changed closed cleanup plan was accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedRetirementCloseLifecyclePlanBindsOwnerTargetAndEvidence(t *testing.T) {
	s, original, duty, _ := generatedEnteredRetirementState(t, true)
	generatedLifecycleCanonicalRetirement(t, s, original.record.AttemptID, duty.DutyID)
	ctx := generatedLifecycleFixture(t, s)
	plan, err := s.generatedRetirementClosePlan(t.Context(), original.record.AttemptID, ctx)
	if err != nil {
		t.Fatal("exact retirement-close plan", err)
	}
	reserved, err := s.deriveGeneratedRetirementClose(t.Context(), plan, nil)
	if err != nil || reserved == nil || reserved.candidate == nil || reserved.candidate.head.Generator == nil ||
		reserved.candidate.head.Generator.Purpose != contract.GeneratorAuthorityRetireClose ||
		reserved.candidate.head.Generator.OwnerID != duty.DutyID || reserved.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("exact signed retirement-close candidate", err)
	}
	for name, change := range map[string]func(*generatedLifecyclePlan){
		"owner":       func(p *generatedLifecyclePlan) { p.owner = generatedVectorID(230) },
		"target":      func(p *generatedLifecyclePlan) { p.target = generatedVectorID(231) },
		"evidence":    func(p *generatedLifecyclePlan) { p.evidence = generatedVectorID(232) },
		"predecessor": func(p *generatedLifecyclePlan) { p.predecessorDigest = generatedVectorID(233) },
		"result":      func(p *generatedLifecyclePlan) { p.result[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *plan
			bad.result = append([]byte(nil), plan.result...)
			change(&bad)
			if _, err := s.deriveGeneratedRetirementClose(t.Context(), &bad, nil); err == nil {
				t.Fatal("changed closed retirement plan was accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedRetirementCloseRollsAccessIncarnationAtCounterLimit(t *testing.T) {
	s, original, duty, _ := generatedEnteredRetirementState(t, true)
	generatedLifecycleCanonicalRetirement(t, s, original.record.AttemptID, duty.DutyID)
	generatedLifecycleFixture(t, s)
	s.root.CurrentAccess.Core.AccessGeneration = ^uint64(0)
	var err error
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	rootBody, err := format.EncodeRoot(s.root)
	if err != nil {
		t.Fatal(err)
	}
	s.head.Core.Root, err = format.Reference(format.RootKind, s.root.Domain, s.root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	ctx := generatedContinuationContext(t, s, 201, 202)
	if !s.generatedContextValid(ctx) {
		t.Fatal("overflow fixture context is not current")
	}
	plan, err := s.generatedRetirementClosePlan(t.Context(), original.record.AttemptID, ctx)
	if err != nil {
		t.Fatal(err)
	}
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	closure, err := g.generatedRetirementAcknowledgement(t.Context(), original.record.AttemptID, plan.identity.revision)
	if err != nil {
		t.Fatal(err)
	}
	if rows := generatedLifecycleAccessRows(s.accessRecords(), append(closure.materials, closure.material)...); len(rows) != 0 {
		t.Fatalf("expected the close to remove the only access row, got %d", len(rows))
	}
	before := generatedSuccessorPredecessorSnapshot(t, s)
	beforeIncarnation := s.root.CurrentAccess.Core.AccessIncarnationID
	reserved, err := s.deriveGeneratedRetirementClose(t.Context(), plan, nil)
	if err != nil || reserved == nil || reserved.state == nil ||
		reserved.state.root.CurrentAccess.Core.AccessGeneration != 1 ||
		reserved.state.root.CurrentAccess.Core.AccessIncarnationID == beforeIncarnation {
		t.Fatalf("access-incarnation rollover returned candidate=%v error=%v", reserved != nil, err)
	}
	if !bytes.Equal(before, generatedSuccessorPredecessorSnapshot(t, s)) {
		t.Fatal("retirement-close construction changed the predecessor")
	}
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err != nil {
		t.Fatal("retirement-close construction damaged the selected predecessor", err)
	}
}

// full_only: false
func TestGeneratedInboxReleaseLifecyclePlanRemovesOnlyExactCleanHandoff(t *testing.T) {
	s, _, release := generatedInboxReleaseState(t, 0, contract.GeneratedReleasePending)
	ctx := generatedLifecycleFixture(t, s)
	descriptor := s.admission.store
	descriptor.Prefix, descriptor.HeadKey = "fixture", "fixture/HEAD"
	s.admission.store = descriptor
	store := &generatedInboxDeleteStore{descriptor: descriptor,
		read: contract.ReadResult{Status: contract.ReadMissing}}
	s.store = store
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err != nil {
		t.Fatal("release fixture selection", err)
	}
	plan, err := s.generatedInboxReleasePlan(stdcontext.Background(), release.InboxID, ctx)
	if err != nil {
		t.Fatalf("exact clean release plan: %v readCalls=%d prefix=%q family=%d", err, store.readCalls, s.admission.store.Prefix, s.admission.store.Family)
	}
	reserved, err := s.deriveGeneratedInboxRelease(stdcontext.Background(), plan)
	if err != nil || reserved == nil || reserved.candidate == nil || reserved.candidate.head.Generator == nil ||
		reserved.candidate.head.Generator.Purpose != contract.GeneratorAuthorityInboxRelease ||
		reserved.candidate.head.Generator.OwnerID != release.InboxID || reserved.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("exact signed inbox-release candidate", err)
	}
	after, err := reserved.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(after.releases) != 0 || after.hasRecord(generatedRecordKey{kind: 12, id: release.InboxID}) {
		t.Fatal("released handoff remains live")
	}

	for name, change := range map[string]func(*generatedLifecyclePlan){
		"owner":       func(p *generatedLifecyclePlan) { p.owner = generatedVectorID(230) },
		"target":      func(p *generatedLifecyclePlan) { p.target = generatedVectorID(231) },
		"evidence":    func(p *generatedLifecyclePlan) { p.evidence = generatedVectorID(232) },
		"predecessor": func(p *generatedLifecyclePlan) { p.predecessorDigest = generatedVectorID(233) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *plan
			change(&bad)
			if _, err := s.deriveGeneratedInboxRelease(stdcontext.Background(), &bad); err == nil {
				t.Fatal("changed closed inbox-release plan was accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedInboxReleaseLifecycleRetainsUnknownDelete(t *testing.T) {
	s, a, release := generatedInboxReleaseState(t, 0, contract.GeneratedReleasePending)
	ctx := generatedLifecycleFixture(t, s)
	descriptor := s.admission.store
	descriptor.Prefix, descriptor.HeadKey = "fixture", "fixture/HEAD"
	s.admission.store = descriptor
	store := &generatedInboxDeleteStore{descriptor: descriptor,
		read: contract.ReadResult{Status: contract.ReadOK, Body: a.result,
			Token: contract.Token{Family: s.admission.store.Family, Value: "current"}},
		deleted: contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}}
	s.store = store
	plan, err := s.generatedInboxReleasePlan(stdcontext.Background(), release.InboxID, ctx)
	if err != nil || plan.kind != generatedLifecycleInboxReleaseUnknown {
		t.Fatal("unknown physical delete did not create an exact retained-obligation plan", err)
	}
	reserved, err := s.deriveGeneratedInboxReleaseUnknown(stdcontext.Background(), plan)
	if err != nil || reserved == nil || reserved.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("unknown physical delete did not produce signed retained state", err)
	}
	g, err := reserved.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	retained, ok := g.releases[a.record.AttemptID]
	if !ok || retained.release.State != contract.GeneratedReleaseUnknown ||
		retained.release.SelectedHandoffDigest != release.SelectedHandoffDigest || retained.release.InboxID != release.InboxID {
		t.Fatal("unknown physical delete was reported clean or lost its exact obligation")
	}
}
