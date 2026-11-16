package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func controlSuccessionFixture(t testing.TB) (*StateSession, *AdmittedSuccession, *observationExchangeCustody) {
	t.Helper()
	s := generatedEmptyPredecessorForFamily(t, contract.GCP)
	observationProtectFixture(t, s)
	before := currentControlOf(s)
	after := before
	after.AccessGeneration++
	after.AuthorityKMSBinding = observationNextBinding(t, before.AuthorityKMSBinding)
	plan := transitionPlan{operation: generatedVectorID(182), snapshot: generatedVectorID(183), transition: generatedVectorID(184), revision: generatedVectorID(185)}
	plan.recipientPages[0] = generatedVectorID(186)
	c := generatedContinuationContext(t, s, 130, 131)
	c.OperationClass = contract.CryptoAccessReplacementClass
	request := contract.SuccessionRequestCore{SuccessionRequestFields: contract.SuccessionRequestFields{Schema: contract.CanonicalSchema, OperationKind: contract.SuccessionReplaceAuthority, ApprovalRole: contract.NormalSigningRole, ChangeMask: contract.SuccessionChangeAuthorityKEK, MaterialSourceRole: contract.SuccessionMaterialAuthority,
		DomainID: s.admission.domain, StoreID: s.admission.store.Identity, CoordinateID: s.admission.store.Coordinate, NonBodyID: s.admission.store.NonBody, TrustInterpretationID: contract.TrustInterpretationID(), CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), AdmissionID: c.AdmissionID, OperationID: plan.operation, PredecessorHeadRevisionID: s.head.Core.Revision, PredecessorFullHEADDigest: contract.Hash(s.body), BeforeAccessRoot: s.root.CurrentAccess.AccessRoot},
		Token: s.token, BeforeControl: before, ProposedAfterControl: after, ReplacementPlan: successionRolePlan(before, after, contract.SuccessionReplaceAuthority, contract.SuccessionChangeAuthorityKEK), IdentityPlan: identityPlan(&Comparison{session: s}, plan)}
	descriptor, err := contract.SuccessionRequestDescriptor(request)
	if err != nil {
		t.Fatal(err)
	}
	source := contract.BindingTableRow{SubjectKind: 1, SubjectID: s.admission.recipient, Binding: before.AuthorityKMSBinding}
	q, _, err := s.successionAccessRequest(t.Context(), request, plan, c, source)
	if err != nil {
		t.Fatal("succession fixture request refused")
	}
	digest, err := contract.PublicBindingDigest(after.AuthorityKMSBinding)
	if err != nil {
		t.Fatal(err)
	}
	probe := contract.SuccessorKEKProbeCore{Schema: contract.CanonicalSchema, Profile: 2, ProbeID: generatedVectorID(187), Context: q.Context, SubjectKind: 1, SubjectID: s.admission.recipient, SuccessorBindingDigest: digest}
	custody := observationFailingCustody()
	permit := &AdmittedSuccession{session: s, request: request, plan: plan, descriptor: descriptor, context: q.Context, source: source, probe: probe, crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(q.Context.Expiry))}
	if !attachOperationObservation(&permit.observation, s, q.Context, true) {
		t.Fatal("succession observer admission refused")
	}
	return s, permit, custody
}

// full_only: false
func TestSuccessionObservationSurvivesLaterCryptoFailure(t *testing.T) {
	s, permit, custody := controlSuccessionFixture(t)
	candidate, result := s.prepareSuccession(t.Context(), permit, SuccessionSigners{Authorizer: testtrust.New(t, contract.GCP, s.admission.trust)}, nil)
	if candidate != nil || result != custodyFailure(contract.CryptoCustodyUnavailable) || len(custody.calls) != 1 {
		t.Fatal("succession did not retain its existing failure", result)
	}
	facts, status := permit.observation.read()
	if len(facts) != 2 || status.Accepted != 2 || facts[0].Change == nil || facts[1].Exchange == nil {
		t.Fatal("validated succession detail was lost before later failure", status)
	}
	controlCheckAuthorityKEKDetail(t, permit, facts[0].Change)
}

func controlCheckAuthorityKEKDetail(t testing.TB, permit *AdmittedSuccession, got *changeObservation) {
	t.Helper()
	request := permit.request
	before, after := request.BeforeControl.AuthorityKMSBinding.BindingID, request.ProposedAfterControl.AuthorityKMSBinding.BindingID
	var expectedRows []contract.ChangedSubjectIdentity
	for _, item := range []struct {
		change uint8
		id     contract.ID
	}{{2, before}, {1, after}} {
		preimage := []byte("ENKV/CRYPTO/v2/authority-binding-subject-v1\x00")
		preimage = append(preimage, request.DomainID[:]...)
		preimage = append(preimage, 3)
		preimage = append(preimage, item.id[:]...)
		expectedRows = append(expectedRows, contract.ChangedSubjectIdentity{Kind: 8, Change: item.change, Identity: contract.Hash(preimage)})
	}
	// Canonical order compares kind, change, then identity: Added precedes Removed.
	expectedRows[0], expectedRows[1] = expectedRows[1], expectedRows[0]
	vector := binary.BigEndian.AppendUint32(nil, 2)
	for _, row := range expectedRows {
		vector = binary.BigEndian.AppendUint32(vector, 34)
		vector = append(vector, row.Kind, row.Change)
		vector = append(vector, row.Identity[:]...)
	}
	preimage := []byte("ENKV/GENERATOR/v1/changed-subjects\x00")
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(vector)))
	preimage = append(preimage, vector...)
	wantDescriptor := contract.GeneratorDescriptor{Digest: contract.Hash(preimage), Length: uint64(len(vector)), Count: 2}
	wantSubjects := []observationSubject{{Row: expectedRows[0]}, {Row: expectedRows[1]}}
	wantChanges := []observationSuccession{{Purpose: 3, Role: contract.SuccessorAuthorityKEK, BeforeBindingID: before, AfterBindingID: after}}
	if got == nil || !got.HasChangedSubjects || got.Descriptor != wantDescriptor || !reflect.DeepEqual(got.Subjects, wantSubjects) || !reflect.DeepEqual(got.Succession, wantChanges) || got.Source != permit.observation.sourceFor(observationSource{Stage: observationComparison, OperationID: request.OperationID}) || got.Candidate != (observationCandidateIdentity{}) || got.Result != (Result{}) {
		t.Fatal("succession source, whole set or honest stage differs", got)
	}
}

// full_only: false
func TestSuccessionObservationNoOpHasOnlyEstablishedResult(t *testing.T) {
	s, permit, custody := controlSuccessionFixture(t)
	binding := permit.request.BeforeControl.AuthorityKMSBinding
	g := authorityGoal{Domain: s.admission.domain, Store: s.admission.store.Identity, Coordinate: s.admission.store.Coordinate, NonBody: s.admission.store.NonBody, Trust: s.admission.trust, Interpretation: s.admission.interpretation, ApprovalRole: contract.NormalSigningRole, Roles: 2,
		KMS: &kmsGoal{Provider: binding.Provider, WrapProfile: binding.WrapProfile, ProtectionClass: binding.ProtectionClass, KeySelector: binding.KeySelector, SPKI: bytes.Clone(binding.SPKI), Fingerprint: binding.Fingerprint}}
	permit.goal = &admittedAuthorityGoal{session: s, goal: g, deadline: permit.deadline}
	candidate, result := s.prepareSuccession(t.Context(), permit, SuccessionSigners{}, nil)
	facts, status := permit.observation.read()
	if candidate != nil || result != s.observed(Unchanged) || !permit.used || len(custody.calls) != 0 || len(facts) != 1 || status.Accepted != 1 {
		t.Fatal("current-binding no-op changed", result, status)
	}
	want := changeObservation{Source: permit.observation.sourceFor(observationSource{Stage: observationComparison}), Result: result}
	if !reflect.DeepEqual(facts[0].Change, &want) {
		t.Fatal("no-op invented changed-set, binding or key-use evidence", facts[0])
	}
}

// full_only: false
func TestSuccessionObservationLossDoesNotChangePreparation(t *testing.T) {
	var baselineReads []string
	for _, mode := range []string{"enabled", "absent", "disabled", "full", "busy"} {
		t.Run(mode, func(t *testing.T) {
			s, permit, custody := controlSuccessionFixture(t)
			owner := permit.observation
			switch mode {
			case "absent":
				permit.observation = nil
			case "disabled":
				owner.collector = nil
			case "full":
				owner.collector.storedBytes = observationRetainedLimit()
			case "busy":
				owner.collector.mu.Lock()
			}
			candidate, result := s.prepareSuccession(t.Context(), permit, SuccessionSigners{Authorizer: testtrust.New(t, contract.GCP, s.admission.trust)}, nil)
			if mode == "busy" {
				owner.collector.mu.Unlock()
			}
			if candidate != nil || result != custodyFailure(contract.CryptoCustodyUnavailable) || len(custody.calls) != 1 {
				t.Fatal("observation changed failure or work", result)
			}
			reads := s.store.(*generatedFixtureSupportStore).keys
			if mode == "enabled" {
				baselineReads = append([]string(nil), reads...)
			} else if !reflect.DeepEqual(reads, baselineReads) {
				t.Fatal("observation added Store reads", reads, baselineReads)
			}
			facts, status := permit.observation.read()
			switch mode {
			case "enabled":
				if len(facts) != 2 || status.Accepted != 2 {
					t.Fatal(status)
				}
				controlCheckAuthorityKEKDetail(t, permit, facts[0].Change)
			case "absent", "disabled":
				if len(facts) != 0 || status != (observationStatus{}) {
					t.Fatal(status)
				}
			case "full":
				if len(facts) != 0 || status.DroppedFull != 2 {
					t.Fatal(status)
				}
			case "busy":
				if len(facts) != 0 || status.DroppedContention != 2 {
					t.Fatal(status)
				}
			}
		})
	}
}

type controlEndStore struct {
	*generatedFixtureSupportStore
	creates int
}

func (s *controlEndStore) Create(context.Context, string, []byte) contract.WriteResult {
	s.creates++
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
}

// full_only: false
func TestAdministrativeObservationAtExactEndOwner(t *testing.T) {
	controlAdministrativeObservation(t, false)
}

// full_only: false
func TestAdministrativeObservationKeepsMissingOptionalDetailOpaque(t *testing.T) {
	controlAdministrativeObservation(t, true)
}

func controlAdministrativeObservation(t *testing.T, missingOptional bool) {
	t.Helper()
	var baselineReads []string
	for _, mode := range []string{"enabled", "absent", "disabled", "full", "busy"} {
		t.Run(mode, func(t *testing.T) {
			s, duty, ids, _ := controlEndWorkFixture(t, "new incarnation")
			var missingKeys []string
			if missingOptional {
				original := s.store.(*generatedFixtureSupportStore)
				for i, page := range s.adminIndex.Pages {
					if page.ReadRequired || slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
						continue
					}
					key, err := format.Key(s.admission.store.Prefix, page.Ref)
					if err != nil {
						t.Fatal(err)
					}
					missingKeys = append(missingKeys, key)
					delete(original.objects, key)
					delete(s.cache, page.Ref)
					s.support[i].Records = nil
					s.supportFacts[i].rows = nil
					s.supportFacts[i].ordinals = nil
				}
				if len(missingKeys) == 0 {
					t.Fatal("fixture has no optional discarded body")
				}
				original.keys = nil
				original.limits = nil
			}
			observationProtectFixture(t, s)

			a := &AuthoritySession{state: s, mode: LocalAuthorityEnd}
			if !attachLocalObservation(&a.observation, s, true) {
				t.Fatal("local command observation admission refused")
			}
			owner := a.observation
			candidate, next, err := s.deriveEndWorkCandidate(t.Context(), duty, ids)
			if err != nil || !next.validEndWorkSelection() {
				t.Fatal("pure End candidate", err)
			}
			if _, err := next.validateRelationsMode(t.Context(), true); err != nil {
				t.Fatal("End owner fixture relation validation", err)
			}
			preview, ok := previewFromCandidate(candidate)
			if !ok {
				t.Fatal("pure preview")
			}
			if facts, status := owner.read(); len(facts) != 0 || status != (observationStatus{}) {
				t.Fatal("pure derivation emitted observation")
			}
			store := &controlEndStore{generatedFixtureSupportStore: s.store.(*generatedFixtureSupportStore)}
			s.store = store
			switch mode {
			case "absent":
				a.observation = nil
			case "disabled":
				owner.collector = nil
			case "full":
				owner.collector.storedBytes = observationRetainedLimit()
			case "busy":
				owner.collector.mu.Lock()
			}
			var entropy []byte
			for _, id := range []contract.ID{ids.operation, ids.transition, ids.snapshot, ids.revision, ids.receipts, ids.receiptIndex} {
				entropy = append(entropy, id[:]...)
			}
			s.admission.entropy = bytes.NewReader(entropy)
			outcome := a.end(t.Context(), preview, nil)
			if mode == "busy" {
				owner.collector.mu.Unlock()
			}
			if outcome.Result.Outcome != EvidenceUnavailable || outcome.Result.Reason != WriteUncertain || store.creates != 1 || len(outcome.Receipt) != 0 {
				t.Fatal("End did not retain its write failure", outcome.Result, store.creates)
			}
			reads := store.keys
			for _, key := range missingKeys {
				if slices.Contains(reads, key) {
					t.Fatal("observation or End reopened discarded optional detail")
				}
			}
			if mode == "enabled" {
				baselineReads = append([]string(nil), reads...)
			} else if !reflect.DeepEqual(reads, baselineReads) {
				t.Fatal("observation added Store reads")
			}
			facts, status := a.observation.read()
			switch mode {
			case "enabled":
				if len(facts) != 1 || status.Accepted != 1 || facts[0].Change == nil {
					t.Fatal("exact End detail lost before write failure", outcome, status)
				}
				got := facts[0].Change
				if got.Source != owner.sourceFor(observationSource{Stage: observationCandidate, OperationID: outcome.OperationID}) || !got.HasChangedSubjects || len(got.Subjects) != 1 || len(got.Succession) != 0 || got.Result != (Result{}) {
					t.Fatal("End stage or source invented evidence", got)
				}
				q := candidate.head.EndWork
				expected := observationAdministrative{TargetGroupID: q.TargetGroupID, TargetOwnerID: q.TargetOwnerID, TargetID: q.TargetID, DispositionID: candidate.endWorkReceipt.AdministrativeDisposition, TargetKind: q.TargetKind, DutyKind: q.DutyKind, BeforeWarnings: q.BeforeWarningBits, AfterWarnings: q.AfterWarningBits, EvidenceSummary: q.SelectedEvidenceSummary}
				if got.Administrative == nil || *got.Administrative != expected || got.Descriptor != candidate.endWorkReceipt.ChangedSubjects || got.Candidate.PredecessorRevisionID != s.head.Core.Revision || got.Candidate.PredecessorDigest != contract.Hash(s.body) || got.Candidate.RevisionID.IsZero() || got.Candidate.SnapshotID.IsZero() {
					t.Fatal("End target/warning/evidence/commitment changed", got)
				}
				preimage := []byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00")
				preimage = append(preimage, q.DomainID[:]...)
				preimage = append(preimage, 9)
				preimage = append(preimage, q.TargetGroupID[:]...)
				preimage = append(preimage, q.TargetOwnerID[:]...)
				expectedSubject := observationSubject{Row: contract.ChangedSubjectIdentity{Kind: 9, Change: 2, Identity: contract.Hash(preimage)}, PrimaryID: q.TargetGroupID, SecondaryID: q.TargetOwnerID}
				if got.Subjects[0] != expectedSubject {
					t.Fatal("single removed selected-work row differs", got.Subjects)
				}
			case "absent", "disabled":
				if len(facts) != 0 || status != (observationStatus{}) {
					t.Fatal(status)
				}
			case "full":
				if len(facts) != 0 || status.DroppedFull != 1 {
					t.Fatal(status)
				}
			case "busy":
				if len(facts) != 0 || status.DroppedContention != 1 {
					t.Fatal(status)
				}
			}
		})
	}
}

type controlSuccessionStore struct {
	*generatedFixtureSupportStore
	creates int
}

func (s *controlSuccessionStore) Create(_ context.Context, key string, body []byte) contract.WriteResult {
	s.creates++
	s.objects[key] = bytes.Clone(body)
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}

// full_only: false
func TestReceiptFreeAuthoritySuccessionKeepsDetailAndCandidateOwner(t *testing.T) {
	var baselineReads []string
	var baselineRoot contract.Ref
	var baselineCreates int
	for _, mode := range []string{"enabled", "absent", "disabled", "full", "busy"} {
		t.Run(mode, func(t *testing.T) {
			s, permit, custody := controlSuccessionFixture(t)
			generatedVerifySelectedFixtureSlices(t, s)
			successor := testtrust.NewWithIdentity(t, contract.GCP, generatedVectorID(220), s.admission.trust, contract.NormalSigningRole)
			request := permit.request
			request.ChangeMask = contract.SuccessionChangeNormalSigner
			before := request.BeforeControl
			after := before
			after.AccessGeneration++
			after.NormalSigning = before.NormalSigning
			after.NormalSigning.BindingID = generatedVectorID(221)
			after.NormalSigning.SPKI = successor.PublicKey()
			after.NormalSigning.KeySelector = successor.KeySelector()
			after.NormalSigning.Fingerprint = contract.Hash(after.NormalSigning.SPKI)
			after.NormalSigning.Binding.PublicKey = after.NormalSigning.Fingerprint
			after.NormalSigning.Binding.Epoch++
			request.ProposedAfterControl = after
			request.ReplacementPlan = successionRolePlan(before, after, request.OperationKind, request.ChangeMask)
			permit.plan.recipientPages[0] = contract.ID{}
			request.IdentityPlan = identityPlan(&Comparison{session: s}, permit.plan)
			permit.request = request
			var err error
			permit.descriptor, err = contract.SuccessionRequestDescriptor(request)
			if err != nil {
				t.Fatal("normal signer request", err)
			}
			q, _, err := s.successionAccessRequest(t.Context(), request, permit.plan, permit.context, permit.source)
			if err != nil {
				t.Fatal("normal signer access context")
			}
			permit.context = q.Context
			if _, _, err := s.deriveSuccession(t.Context(), request, permit.plan, nil); err != nil {
				t.Fatal("normal signer fixture derivation", err)
			}
			// Keep the fixed common owner; only the operation-specific intent changed.
			store := &controlSuccessionStore{generatedFixtureSupportStore: s.store.(*generatedFixtureSupportStore)}
			s.store = store
			owner := permit.observation
			switch mode {
			case "absent":
				permit.observation = nil
			case "disabled":
				owner.collector = nil
			case "full":
				owner.collector.storedBytes = observationRetainedLimit()
			case "busy":
				owner.collector.mu.Lock()
			}
			candidate, result := s.prepareSuccession(t.Context(), permit, SuccessionSigners{Authorizer: testtrust.New(t, contract.GCP, s.admission.trust), NormalSuccessor: successor}, nil)
			if mode == "busy" {
				owner.collector.mu.Unlock()
			}
			if candidate == nil || result.Outcome != ObservedCurrent || candidate.observation != permit.observation || len(custody.calls) != 0 || store.creates == 0 {
				t.Fatal("receipt-free Authority succession failed", result, store.creates, successor.QualificationCalls(), successor.Calls())
			}
			if candidate.replacementState == nil || candidate.replacementState.root.Generated.ReceiptOrder != s.root.Generated.ReceiptOrder {
				t.Fatal("Authority succession changed retained receipt order")
			}
			for _, object := range candidate.objects {
				if object.ref.Kind != contract.RequiredSupportKind {
					continue
				}
				page, err := format.InspectRequiredSupportPage(object.body)
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range page.Records {
					if row.Kind == contract.MutationReceiptSupportKind {
						t.Fatal("Authority succession added a receipt")
					}
				}
			}
			if mode == "enabled" {
				baselineReads = append([]string(nil), store.keys...)
				baselineRoot = candidate.head.Core.Root
				baselineCreates = store.creates
			} else if !reflect.DeepEqual(store.keys, baselineReads) || candidate.head.Core.Root != baselineRoot || store.creates != baselineCreates {
				t.Fatal("observation changed Store work or successor commitment")
			}
			facts, status := permit.observation.read()
			switch mode {
			case "absent", "disabled":
				if len(facts) != 0 || status != (observationStatus{}) {
					t.Fatal(status)
				}
				return
			case "full":
				if len(facts) != 0 || status.DroppedFull != 2 {
					t.Fatal(status)
				}
				return
			case "busy":
				if len(facts) != 0 || status.DroppedContention != 2 {
					t.Fatal(status)
				}
				return
			}
			if len(facts) != 2 || status.Accepted != 2 || facts[0].Change == nil || facts[1].Change == nil {
				t.Fatal("succession did not retain its requested and candidate detail", status)
			}
			first, last := facts[0].Change, facts[1].Change
			expected := []observationSuccession{{BeforeBindingID: before.NormalSigning.BindingID, AfterBindingID: after.NormalSigning.BindingID, Purpose: 1, Role: contract.SuccessorNormalSigner}, {BeforeBindingID: before.NormalSigning.BindingID, AfterBindingID: after.NormalSigning.BindingID, Purpose: 2, Role: contract.SuccessorNormalSigner}}
			if !reflect.DeepEqual(first.Succession, expected) || !reflect.DeepEqual(last.Succession, expected) || !reflect.DeepEqual(first.Subjects, last.Subjects) || first.Descriptor != last.Descriptor || first.Descriptor.Count != 4 || first.Source.Stage != observationComparison || first.Candidate != (observationCandidateIdentity{}) || last.Source != permit.observation.sourceFor(observationSource{Stage: observationCandidate, OperationID: request.OperationID}) || last.Candidate != candidateObservationIdentity(candidate) || last.Result != (Result{}) {
				t.Fatal("K1/K2 purposes, whole vector, or honest candidate correlation differs", first, last)
			}
			// Recompute both commitment and validated candidate without an offer.
			beforeCount := status.Accepted
			if _, err := contract.SuccessionChangedSubjectDescriptor(request); err != nil {
				t.Fatal(err)
			}
			if !candidate.successionBasisReady(s, permit.descriptor) {
				t.Fatal("prepared succession candidate lost its qualified basis readiness")
			}
			if _, afterStatus := permit.observation.read(); afterStatus.Accepted != beforeCount {
				t.Fatal("pure validation duplicated observations")
			}
			// Selecting needs separate successor-basis admission. Refusal must retain
			// the earlier checked comparison and valid candidate facts.
			selected, selectionResult := s.selectCandidate(t.Context(), candidate)
			if selected != nil || selectionResult != refused(AdmissionInvalid) {
				t.Fatal("missing selection admission changed outcome", selectionResult)
			}
			afterFacts, _ := permit.observation.read()
			expectedSelection := changeObservation{Source: permit.observation.sourceFor(observationSource{Stage: observationSelection, OperationID: request.OperationID}), Candidate: candidateObservationIdentity(candidate), Result: refused(AdmissionInvalid)}
			if len(afterFacts) != 3 || !reflect.DeepEqual(afterFacts[:2], facts) || !reflect.DeepEqual(afterFacts[2].Change, &expectedSelection) {
				t.Fatal("later selection refusal removed or changed earlier detail")
			}
		})
	}

}
