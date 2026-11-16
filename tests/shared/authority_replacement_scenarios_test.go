package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// This DTO is a private fixture transport, independent of untrusted Store
// objects. Its bytes do not define another Product descriptor format.
type successionBasisInput struct {
	Control, Selection []byte
	Enrollment         []successionEnrollmentInput
}

type successionEnrollmentInput struct {
	ID     contract.ID
	Status uint8
	Name   string
}

func successionBasisTransport(b *qualifiedCurrentBasis) successionBasisInput {
	input := successionBasisInput{Control: bytes.Clone(b.control), Selection: bytes.Clone(b.selection)}
	for _, row := range b.enrollment {
		input.Enrollment = append(input.Enrollment, successionEnrollmentInput{ID: row.id, Status: row.status, Name: row.name})
	}
	return input
}

func (input successionBasisInput) owned() *qualifiedCurrentBasis {
	b := &qualifiedCurrentBasis{issued: true, control: bytes.Clone(input.Control), selection: bytes.Clone(input.Selection)}
	for _, row := range input.Enrollment {
		b.enrollment = append(b.enrollment, recipientEnrollment{id: row.ID, status: row.Status, name: row.Name})
	}
	return b
}

func deliverSuccessionBasis(t testing.TB, candidate *Candidate) OpenContext {
	t.Helper()
	if candidate == nil || candidate.succession == nil || candidate.succession.basis == nil || !candidate.succession.basis.issued {
		t.Fatal("unqualified owner basis")
	}
	input := successionBasisTransport(candidate.succession.basis)
	// The 256 enrollments each carry 256 IDs (at most 129 JSON bytes per ID),
	// a 256-byte name, and bounded control/selection. The carrier fits 10 MiB.
	body, err := json.Marshal(input)
	if err != nil || len(body) > 10<<20 {
		t.Fatal("owner fixture payload exceeds bound", err)
	}
	id := contract.Hash(body)
	dir := t.TempDir()
	// Reuse the owner artifact sink: exclusive write, file Sync, directory
	// Sync and exact bounded readback. The receipt is local test evidence.
	persistGenesisArtifact(t, dir, 1, id, body)
	read, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%x", id)))
	if err != nil || !bytes.Equal(read, body) {
		t.Fatal("owner basis readback differs", err)
	}
	var delivered successionBasisInput
	if err := json.Unmarshal(read, &delivered); err != nil {
		t.Fatal(err)
	}
	basis := delivered.owned()
	control, err := contract.DecodeControlCore(basis.control)
	if err != nil {
		t.Fatal(err)
	}
	a := candidate.session.admission
	a.current, a.descriptor = basis, nil
	a.observation = nil
	a.epoch, a.controlIncarnation, a.publicKey, a.trust = control.NormalSigning.Binding.Epoch,
		control.NormalSigning.Binding.ControlIncarnationID, bytes.Clone(control.NormalSigning.SPKI), control.NormalSigning.Binding.Trust
	if !a.valid(candidate.session.store) {
		t.Fatal("delivered current basis admission refused")
	}
	if _, ok := a.currentControl(); !ok {
		t.Fatal("delivered current public control refused")
	}
	candidate.succession.selectionAdmission = &a
	return OpenContext{admission: &a}
}

func admitAuthorityReplacement(t testing.TB, s *StateSession, keys *custody.Fixture, after contract.ControlCore, operation, approval, mask uint8, source contract.BindingTableRow) *AdmittedSuccession {
	t.Helper()
	var admission, session contract.ID
	if _, err := rand.Read(admission[:]); err != nil {
		t.Fatal(err)
	}
	if operation == contract.SuccessionReplaceAuthority && mask == contract.SuccessionChangeNormalSigner && approval == contract.RecoverySigningRole {
		fixtureInstalledRecoveryActor(t, s, after, admission)
	}
	if _, err := rand.Read(session[:]); err != nil {
		t.Fatal(err)
	}
	materialRole := uint8(contract.SuccessionMaterialNone)
	switch source.SubjectKind {
	case contract.OrdinaryWrapSubject:
		materialRole = contract.SuccessionMaterialAuthority
	case contract.RecoveryWrapSubject:
		materialRole = contract.SuccessionMaterialRecovery
	}
	request, plan, ok := s.planSuccession(t.Context(), after, operation, approval, mask, admission, materialRole)
	if !ok {
		t.Fatal("succession plan refused")
	}
	if s.installedReplacement != nil {
		if err := s.installedReplacement.pinPlan(s, plan); err != nil {
			t.Fatal(err)
		}
	}
	descriptor, err := contract.SuccessionRequestDescriptor(request)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	if s.installedReplacement != nil && signerOnlyRecovery(request) {
		deadline = s.installedReplacement.deadline
	}
	c := contract.ApplyContext{OperationClass: contract.CryptoAccessReplacementClass, AdmissionID: admission, SessionID: session, DomainID: s.admission.domain, CompatibilityID: contract.CompatibilityID(), Expiry: uint64(deadline.UnixNano()), PredecessorHEADDigest: contract.Hash(s.body), CurrentAccessRoot: s.root.CurrentAccess.AccessRoot, IntentDescriptor: descriptor}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(c.PredecessorRootRef[:], root)
	c.OriginalConditionDigest, err = contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		t.Fatal(err)
	}
	q, rows, err := s.successionAccessRequest(t.Context(), request, plan, c, source)
	if err != nil {
		t.Fatal("succession access request refused")
	}
	permit := &AdmittedSuccession{session: s, request: request, plan: plan, descriptor: descriptor, context: q.Context, source: source, deadline: deadline}
	if target, _, changed := successionTarget(request); changed {
		probe := contract.SuccessorKEKProbeCore{Schema: contract.CanonicalSchema, Profile: 2, Context: q.Context, SubjectKind: target.SubjectKind, SubjectID: target.SubjectID}
		if _, err := rand.Read(probe.ProbeID[:]); err != nil {
			t.Fatal(err)
		}
		probe.SuccessorBindingDigest, err = contract.PublicBindingDigest(target.Binding)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := contract.EncodeSuccessorKEKProbeCore(probe); err != nil {
			t.Fatal("successor private probe fixture", err)
		}
		if err := keys.AdmitSuccessionAccess(q, request, request.BeforeControl, source, probe, rows, deadline); err != nil {
			t.Fatal("succession private admission", err)
		}
		permit.probe, permit.crypto, permit.instance = probe, keys.Crypto(), keys.Crypto().InstanceID()
	}
	return permit
}

// full_only: false
func TestAuthorityReplacementSignerOnlyDoesNotUseCrypto(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
	after := currentControlOf(f.session)
	successor, binding := env.Trust.(*fixtureTrust).Successor(t, after.NormalSigning)
	after.NormalSigning = binding
	after.AccessGeneration++
	permit := admitAuthorityReplacement(t, f.session, keys, after, 1, 1, 1, contract.BindingTableRow{})
	public, private := keys.Calls()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, invalid := range []context.Context{nil, cancelled} {
		if candidate, result := f.session.PrepareSuccession(invalid, permit, SuccessionSigners{Authorizer: env.Trust, NormalSuccessor: successor}); candidate != nil || result != refused(AdmissionInvalid) || permit.used {
			t.Fatal("invalid original context consumed succession", result)
		}
	}
	if p, k := keys.Calls(); p != public || k != private {
		t.Fatal("invalid succession reached Crypto")
	}
	candidate, result := f.session.PrepareSuccession(context.Background(), permit, SuccessionSigners{Authorizer: env.Trust, NormalSuccessor: successor})
	if candidate == nil {
		t.Fatal("signer-only succession preparation", result)
	}
	if p, k := keys.Calls(); p != public || k != private {
		t.Fatal("signer-only succession called Crypto")
	}
	if candidate.succession == nil || candidate.succession.requiresCrypto || candidate.succession.claimed {
		t.Fatal("signer-only succession invented a Crypto claim")
	}
	beforeCAS := env.Store.(*memoryStore).cas
	result = f.session.Select(context.Background(), candidate)
	if result.Outcome != AdmissionRefused || env.Store.(*memoryStore).cas != beforeCAS {
		t.Fatal("succession selected without durable owner basis", result)
	}
}

// full_only: false
func TestAuthorityReplacementPreservesCurrentState(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, operation := range []uint8{1, 3} {
			masks := []uint8{1, 2, 3}
			if operation == 3 {
				masks = []uint8{4, 8, 12}
			}
			for _, mask := range masks {
				for _, approval := range []uint8{1, 2} {
					for _, material := range []bool{false, true} {
						t.Run(fmt.Sprintf("%d/operation-%d/mask-%d/approval-%d/material-%t", family, operation, mask, approval, material), func(t *testing.T) {
							runAuthorityReplacementCase(t, family, operation, mask, approval, material)
						})
					}
				}
			}
		}
	}
}

func runAuthorityReplacementCase(t *testing.T, family contract.Family, operation, mask, approval uint8, material bool) {
	t.Helper()
	ctx := context.Background()
	env, keys := genesisEnvironment(t, family, true)
	run := newScenarioRun(t, ctx, env)
	var f *environmentFixture
	run.phase("setup", func() { f = newEnvironmentFixture(t, ctx, run.env, []int{1}, false) })
	if material {
		run.phase("transition", func() {
			input := append(f.session.currentEntryInputs(), sharingSecret(t, env, "current authority replacement", []contract.ID{f.admission.admission.recipient}))
			run.suppliedSelection(f, input)
		})
	}
	before := f.session
	beforeImage := sessionStateImage(t, before)
	beforeWindows, err := before.receiptWindows(ctx)
	if err != nil {
		t.Fatal("succession predecessor receipt windows unavailable", err)
	}
	beforeWindows.Successes = slices.Clone(beforeWindows.Successes)
	beforeWindows.Failures = slices.Clone(beforeWindows.Failures)
	controlBody, err := contract.EncodeControlCore(currentControlOf(before))
	if err != nil {
		t.Fatal(err)
	}
	after, err := contract.DecodeControlCore(controlBody)
	if err != nil {
		t.Fatal(err)
	}
	after.AccessGeneration++
	normal := env.Trust.(*fixtureTrust).Signer
	recovery := env.Recovery.(*testtrust.Signer)
	signers := SuccessionSigners{Authorizer: run.env.Trust}
	if approval == 2 {
		signers.Authorizer = recovery
	}
	var retired, successor *testtrust.Signer
	if mask&1 != 0 {
		successor, after.NormalSigning = normal.Successor(t, after.NormalSigning)
		retired, signers.NormalSuccessor = normal, successor
	} else if mask&4 != 0 {
		successor, after.Recovery.Signing = recovery.Successor(t, after.Recovery.Signing)
		retired, signers.RecoverySuccessor = recovery, successor
	}
	// A lost signer is never used to qualify its successor or approve retirement.
	if retired != nil && retired.Identity() != signers.Authorizer.Identity() {
		retired.SetUnavailable(true)
	}
	var source, target contract.BindingTableRow
	if mask&(2|8) != 0 {
		source = contract.BindingTableRow{SubjectKind: 1, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}
		if approval == 2 {
			source = contract.BindingTableRow{SubjectKind: 2, SubjectID: after.Recovery.RoleID, Binding: after.Recovery.KMS}
		}
		if mask&2 != 0 {
			after.AuthorityKMSBinding = keys.KEKSuccessor(t, contract.SuccessorAuthorityKEK)
			target = contract.BindingTableRow{SubjectKind: 1, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}
		} else {
			after.Recovery.KMS = keys.KEKSuccessor(t, contract.SuccessorRecoveryKEK)
			target = contract.BindingTableRow{SubjectKind: 2, SubjectID: after.Recovery.RoleID, Binding: after.Recovery.KMS}
		}
		if source.SubjectID != target.SubjectID {
			keys.LoseRecipientPredecessor(target.SubjectID)
		}
	}
	permit := admitAuthorityReplacement(t, before, keys, after, operation, approval, mask, source)
	defer keys.RetireAccess()
	public, private := keys.Calls()
	var candidate *Candidate
	var admission OpenContext
	run.phase("transition", func() {
		var result Result
		candidate, result = before.PrepareSuccession(ctx, permit, signers)
		if candidate == nil {
			t.Fatal("current authority succession preparation", result)
		}
		wantAcceptances := 0
		if mask&(contract.SuccessionChangeNormalSigner|contract.SuccessionChangeRecoverySigner) != 0 {
			wantAcceptances = 1
		}
		if len(candidate.head.Succession.Acceptances) != wantAcceptances {
			t.Fatal("replacement omitted or added final-selection acceptance")
		}
		if wantAcceptances != 0 {
			binding, role := after.NormalSigning, uint8(contract.NormalSigningRole)
			if mask&contract.SuccessionChangeRecoverySigner != 0 {
				binding, role = after.Recovery.Signing, contract.RecoverySigningRole
			}
			digest, err := contract.SigningBindingDigest(binding)
			row := candidate.head.Succession.Acceptances[0]
			if err != nil || row.Role != role || row.BindingDigest != digest || row.Epoch != binding.Binding.Epoch {
				t.Fatal("acceptance did not identify the exact resulting signer", err)
			}
		}
		if mask&(2|8) == 0 {
			if p, k := keys.Calls(); p != public || k != private {
				t.Fatal("signer-only succession entered Crypto")
			}
		} else {
			// Calls counts route method invocations. The returned public-read
			// KeyUses still records AWS2/GCP3 and is checked by Core and Crypto.
			if p, k := keys.Calls(); p-public != 1 || k-private != 1+int(before.root.SecretCount) {
				t.Fatal("succession private probe or exact material opening count differs", p-public, k-private)
			}
		}
		if successor != nil && successor.QualificationCalls() != 1 {
			t.Fatal("successor signing route was not publicly qualified exactly once")
		}
		admission = deliverSuccessionBasis(t, candidate)
		if result = before.Select(ctx, candidate); result.Outcome != ObservedCurrent {
			t.Fatal("current authority succession selection", result)
		}
		selected, result := Open(ctx, admission, run.env.Store)
		if selected == nil {
			t.Fatal("current authority succession reopen", result)
		}
		f.admission, f.session = admission, selected
		if mask&(2|8) != 0 {
			if material {
				a := sessionConsumerSelection(t, before, before.admission.recipient, "secret")
				a.Binding = source
				b := sessionConsumerSelection(t, selected, selected.admission.recipient, "secret")
				b.Binding = target
				if !keys.MaterialPreserved(a, b) {
					t.Fatal("succession changed private D/C material")
				}
			}
			keys.RetireAccess()
			if err := keys.ActivateSuccessor(target.SubjectID); err != nil {
				t.Fatal(err)
			}
		}
		if retired != nil {
			retired.SetUnavailable(true)
		}
	})
	run.phase("verification", func() {
		selected := f.session
		gotControl := currentControlOf(selected)
		if !controlEqual(gotControl, after) {
			t.Fatal("selection did not install exact successor control")
		}
		for i, page := range beforeImage.Pages {
			if !reflect.DeepEqual(page, selected.pages[i]) || !reflect.DeepEqual(beforeImage.Root.ValueEntryPages[i], selected.root.ValueEntryPages[i]) {
				t.Fatal("succession rewrote immutable member bytes or references")
			}
		}
		if !reflect.DeepEqual(beforeImage.Root.Names, selected.root.Names) || beforeImage.Root.RawBytes != selected.root.RawBytes || beforeImage.Root.ValueEntryCount != selected.root.ValueEntryCount {
			t.Fatal("succession changed membership or payload")
		}
		if mask&(2|8) == 0 && !reflect.DeepEqual(beforeImage.Access, selected.access) {
			t.Fatal("signer-only succession changed access bytes")
		}
		window, err := selected.receiptWindows(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		wantSuccesses := slices.Clone(beforeWindows.Successes)
		if operation != contract.SuccessionReplaceAuthority {
			body := checkSuccessionReceipt(t, ctx, selected, permit)
			row, err := contract.InspectCompactMutationReceipt(body)
			if err != nil {
				t.Fatal("succession receipt could not be inspected", err)
			}
			wantSuccesses = append(wantSuccesses, row)
			if len(wantSuccesses) > contract.MutationReceiptWindowLimit {
				wantSuccesses = wantSuccesses[len(wantSuccesses)-contract.MutationReceiptWindowLimit:]
			}
		}
		if window.DomainID != beforeWindows.DomainID || !slices.Equal(window.Successes, wantSuccesses) || !slices.Equal(window.Failures, beforeWindows.Failures) {
			t.Fatal("succession receipt windows changed prior results, order or exact addition")
		}
		if operation == contract.SuccessionReplaceAuthority {
			if !slices.Equal(window.Order, beforeWindows.Order) {
				t.Fatal("Authority replacement changed common receipt order")
			}
		} else {
			assertSuccessReceiptOrder(t, beforeWindows, window, wantSuccesses[len(wantSuccesses)-1].OperationID)
		}
		if material {
			selection := sessionConsumerSelection(t, selected, selected.admission.recipient, "secret")
			check := keys.Consume(ctx, selection, custody.StandardValue)
			if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
				t.Fatal("current authority cannot consume after succession", check)
			}
		}
		if retired != nil {
			q, err := contract.NewSuccessorSignerProbeRequest(contract.SuccessorProbeCore{Schema: 1, EvidenceKind: 1, TargetRole: 1, DomainID: after.DomainID, CoordinateID: after.CoordinateID, AdmissionID: permit.request.AdmissionID, PredecessorFullHEADDigest: permit.request.PredecessorFullHEADDigest, RequestCoreDigest: permit.descriptor.Digest, SuccessorBindingDigest: permit.descriptor.Digest, ProbeAttemptID: fixtureID(after.DomainID, "retired signing refusal")})
			if err != nil {
				t.Fatal(err)
			}
			if retired.Sign(ctx, q).Reason != contract.ReasonAccess {
				t.Fatal("retired signing route became usable again")
			}
		}
	})
	run.phase("reopen", func() {
		a := admission.admission
		input := successionBasisTransport(a.current)
		process := selectedProcessFacts(t, admission, f.session)
		process.CurrentBasis, process.Objects = &input, env.Store.(*memoryStore).objects
		if material {
			process.Consumer = &successorConsumerInput{Binding: contract.BindingTableRow{SubjectKind: 1, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}, Name: "secret", Value: custody.StandardValue}
		}
		checkFreshProcessInput(t, process)
	})
}

func checkSuccessionReceipt(t testing.TB, ctx context.Context, selected *StateSession, permit *AdmittedSuccession) []byte {
	t.Helper()
	body, result := selected.MutationReceipt(ctx, permit.request.OperationID)
	if result.Outcome != ObservedCurrent || len(body) == 0 {
		t.Fatal("cold recovery receipt retrieval", result)
	}
	row, err := contract.InspectCompactMutationReceipt(body)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := contract.SuccessionChangedSubjectDescriptor(permit.request)
	if err != nil {
		t.Fatal(err)
	}
	wantAccess := uint32(0)
	if permit.request.ChangeMask&(2|8) != 0 {
		wantAccess = selected.root.AccessRecordCount
	}
	publicOperation := uint16(contract.OperationReplaceRecoveryKeysAndRoot)
	if row.OperationID != permit.request.OperationID || row.OperationKind != publicOperation || row.RequestIdentityDigest.IsZero() || row.PredecessorRevisionID != permit.request.PredecessorHeadRevisionID || row.RequestedRevisionID != permit.plan.revision || row.ObservedRevisionID != permit.plan.revision || row.StateResult != 1 || row.EvidenceCeiling != 1 || row.ChangedSubjects != changed || row.SummaryCounts[contract.ReceiptChangedAccessCount] != wantAccess || row.CanonicalOutcome != 1 {
		t.Fatal("closed recovery receipt lost exact request or result identity")
	}
	var access []contract.AccessChangeRow
	if wantAccess != 0 {
		for _, before := range permit.session.accessRecords() {
			after, ok := selected.materialAccess(before.MaterialKind, before.MaterialID)
			if !ok {
				t.Fatal("selected result lost changed access")
			}
			access = append(access, contract.AccessChangeRow{Before: before, After: after})
		}
	}
	changedAccess, err := contract.AccessChangeDescriptor(row.DomainID, access)
	if err != nil {
		t.Fatal(err)
	}
	projection := contract.CompactMutationReceiptPlan(row)
	projection.RequestIdentityDigest, projection.CompleteResult = contract.ID{}, contract.GeneratorDescriptor{}
	empty := contract.EmptyMutationResultDescriptors()
	complete, err := contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: projection,
		RequestCoreDigest: permit.descriptor.Digest, ChangedAccess: changedAccess, Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
	if err != nil || row.CompleteResult != complete {
		t.Fatal("receipt did not commit exact request and changed access", err)
	}
	other := *selected
	if repeated, result := other.MutationReceipt(ctx, permit.request.OperationID); result.Outcome != ObservedCurrent || !bytes.Equal(repeated, body) {
		t.Fatal("receipt lost across a valid invocation", result)
	}
	return body
}

// full_only: false
func TestAuthorityReplacementRepeatedReciprocalGenerations(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, family, true)
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
			run.phase("transition", func() {
				run.suppliedSelection(f, append(f.session.currentEntryInputs(), sharingSecret(t, env, "reciprocal current", []contract.ID{f.session.admission.recipient})))
			})
			normal, recovery := env.Trust.(*fixtureTrust).Signer, env.Recovery.(*testtrust.Signer)
			original := sessionStateImage(t, f.session)
			receipts := make(map[contract.ID][]byte)
			for generation := 0; generation < 4; generation++ {
				before := f.session
				encoded, err := contract.EncodeControlCore(currentControlOf(before))
				if err != nil {
					t.Fatal(err)
				}
				after, err := contract.DecodeControlCore(encoded)
				if err != nil {
					t.Fatal(err)
				}
				after.AccessGeneration++
				operation, mask, approval := uint8(1), uint8(3), uint8(2)
				var retired, successor *testtrust.Signer
				var target, source contract.BindingTableRow
				signers := SuccessionSigners{}
				if generation%2 == 0 {
					successor, after.NormalSigning = normal.Successor(t, after.NormalSigning)
					retired, signers.Authorizer, signers.NormalSuccessor = normal, recovery, successor
					source = contract.BindingTableRow{SubjectKind: 2, SubjectID: after.Recovery.RoleID, Binding: after.Recovery.KMS}
					after.AuthorityKMSBinding = keys.KEKSuccessor(t, contract.SuccessorAuthorityKEK)
					target = contract.BindingTableRow{SubjectKind: 1, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}
				} else {
					operation, mask, approval = 3, 12, 1
					successor, after.Recovery.Signing = recovery.Successor(t, after.Recovery.Signing)
					retired, signers.Authorizer, signers.RecoverySuccessor = recovery, normal, successor
					source = contract.BindingTableRow{SubjectKind: 1, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}
					after.Recovery.KMS = keys.KEKSuccessor(t, contract.SuccessorRecoveryKEK)
					target = contract.BindingTableRow{SubjectKind: 2, SubjectID: after.Recovery.RoleID, Binding: after.Recovery.KMS}
				}
				retired.SetUnavailable(true)
				keys.LoseRecipientPredecessor(target.SubjectID)
				permit := admitAuthorityReplacement(t, before, keys, after, operation, approval, mask, source)
				candidate, result := before.PrepareSuccession(ctx, permit, signers)
				if candidate == nil {
					t.Fatal("reciprocal successor preparation", generation, result)
				}
				admission := deliverSuccessionBasis(t, candidate)
				if result = before.Select(ctx, candidate); result.Outcome != ObservedCurrent {
					t.Fatal("reciprocal successor selection", generation, result)
				}
				selected, result := Open(ctx, admission, run.env.Store)
				if selected == nil {
					t.Fatal("reciprocal successor reopen", generation, result)
				}
				a := sessionConsumerSelection(t, before, before.admission.recipient, "secret")
				a.Binding = source
				b := sessionConsumerSelection(t, selected, selected.admission.recipient, "secret")
				b.Binding = target
				if !keys.MaterialPreserved(a, b) {
					t.Fatal("reciprocal replacement changed D/C", generation)
				}
				keys.RetireAccess()
				if err := keys.ActivateSuccessor(target.SubjectID); err != nil {
					t.Fatal(err)
				}
				if operation == 1 {
					normal = successor
				} else {
					recovery = successor
				}
				f.admission, f.session = admission, selected
				if !controlEqual(currentControlOf(selected), after) || !reflect.DeepEqual(original.Pages, selected.pages) {
					t.Fatal("reciprocal replacement changed current identity or payload", generation)
				}
				if operation == 3 {
					receipts[permit.request.OperationID] = checkSuccessionReceipt(t, ctx, selected, permit)
				}
				for id, want := range receipts {
					body, result := selected.MutationReceipt(ctx, id)
					if result.Outcome != ObservedCurrent || !bytes.Equal(body, want) {
						t.Fatal("later generation changed a retained receipt", generation, result)
					}
				}
				basis := successionBasisTransport(admission.admission.current)
				fresh := selectedProcessFacts(t, admission, selected)
				fresh.CurrentBasis, fresh.Objects = &basis, env.Store.(*memoryStore).objects
				fresh.Consumer = &successorConsumerInput{Binding: contract.BindingTableRow{SubjectKind: 1, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}, Name: "secret", Value: custody.StandardValue}
				checkFreshProcessInput(t, fresh)
			}
		})
	}
}

// full_only: false
func TestAuthorityReplacementRefusesUnqualifiedSuccessorSigner(t *testing.T) {
	for _, name := range []string{"provider", "target", "binding", "missing", "denied", "unknown", "limit", "success-with-access", "invalid-qualified"} {
		t.Run(name, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, false)
			f := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
			after := currentControlOf(f.session)
			successor, binding := env.Trust.(*fixtureTrust).Successor(t, after.NormalSigning)
			after.NormalSigning, after.AccessGeneration = binding, after.AccessGeneration+1
			permit := admitAuthorityReplacement(t, f.session, keys, after, 1, 1, 1, contract.BindingTableRow{})
			qualified := genesisQualificationTrust{QualifyingTrust: successor, alter: func(q contract.SigningQualificationResult) contract.SigningQualificationResult {
				switch name {
				case "provider":
					q.Provider = contract.AWS
				case "target":
					q.TargetRole = contract.RecoverySignerTarget
				case "binding":
					q.SigningBindingDigest = fixtureID(env.Domain, "other successor")
				case "missing":
					q.Qualified = 0
				case "denied":
					q.Qualified, q.Reason = 0, contract.ReasonAccess
				case "limit":
					q.Qualified, q.Reason = 0, contract.ReasonLimit
				case "success-with-access":
					q.Reason = contract.ReasonAccess
				case "invalid-qualified":
					q.Qualified, q.Reason = 2, contract.ReasonAccess
				case "unknown":
					q.Qualified, q.Reason = 0, contract.ReasonTransport
				}
				return q
			}}
			store := env.Store.(*memoryStore)
			creates, cas := store.creates, store.cas
			public, private := keys.Calls()
			candidate, result := f.session.PrepareSuccession(context.Background(), permit, SuccessionSigners{Authorizer: env.Trust, NormalSuccessor: qualified})
			want := failure(IntegrityFailure, InvalidProof)
			if name == "denied" || name == "unknown" || name == "limit" {
				want = failure(EvidenceUnavailable, SigningUnavailable)
			}
			if result != want {
				t.Fatalf("result=%+v want=%+v", result, want)
			}
			if candidate != nil || result.Outcome != IntegrityFailure && result.Outcome != EvidenceUnavailable || successor.Calls() != 0 || store.creates != creates || store.cas != cas {
				t.Fatal("unqualified successor reached signing or effects", result)
			}
			if p, k := keys.Calls(); p != public || k != private {
				t.Fatal("unqualified successor reached Crypto")
			}
		})
	}
}

// full_only: false
func TestRecoveryReceiptSurvivesSuppliedAndReaderReplacement(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	control, err := contract.EncodeControlCore(currentControlOf(f.session))
	if err != nil {
		t.Fatal(err)
	}
	after, err := contract.DecodeControlCore(control)
	if err != nil {
		t.Fatal(err)
	}
	successor, binding := env.Recovery.(*testtrust.Signer).Successor(t, after.Recovery.Signing)
	after.Recovery.Signing, after.AccessGeneration = binding, after.AccessGeneration+1
	permit := admitAuthorityReplacement(t, f.session, keys, after, 3, 1, 4, contract.BindingTableRow{})
	candidate, result := f.session.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: run.env.Trust, RecoverySuccessor: successor})
	if candidate == nil {
		t.Fatal("receipt predecessor prepare", result)
	}
	f.admission = deliverSuccessionBasis(t, candidate)
	if result = f.session.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("receipt predecessor select", result)
	}
	f.session, result = Open(ctx, f.admission, run.env.Store)
	if f.session == nil {
		t.Fatal("receipt predecessor open", result)
	}
	receipt := bytes.Clone(checkSuccessionReceipt(t, ctx, f.session, permit))
	captured := freshReceiptExpectations(t, f.session)
	position := slices.IndexFunc(f.session.support, func(page format.RequiredSupportPageView) bool {
		return slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool {
			return row.Kind == contract.MutationReceiptSupportKind && row.RecordID == permit.request.OperationID && bytes.Equal(row.Body, receipt)
		})
	})
	if position < 0 || position >= len(f.session.root.RequiredSupport) || f.session.support[position].Index != f.session.root.RequiredSupport[position].Index {
		t.Fatal("selected succession receipt has no exact support reference")
	}
	support := f.session.root.RequiredSupport[position]
	reader := fixtureID(env.Domain, "reader")
	recipients := []contract.ID{f.session.admission.recipient, reader}
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	run.suppliedSelection(f, append(f.session.currentEntryInputs(), sharingSecret(t, env, "receipt interaction", recipients)))
	checkFreshReceipts(t, ctx, f.session, captured)
	if !slices.Contains(f.session.root.RequiredSupport, support) {
		t.Fatal("supplied update rewrote receipt support")
	}
	nextReader := keys.RecipientSuccessor(t, reader)
	keys.LoseRecipientPredecessor(reader)
	readerPermit := admitReaderReplacement(t, f.session, keys, reader, nextReader)
	candidate, result = f.session.PrepareRecipientReplacement(ctx, readerPermit, run.env.Trust)
	if candidate == nil {
		t.Fatal("receipt reader prepare", result)
	}
	if result = f.session.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("receipt reader select", result)
	}
	keys.RetireAccess()
	if err := keys.ActivateRecipientSuccessor(reader); err != nil {
		t.Fatal(err)
	}
	f.session, result = Open(ctx, f.admission, run.env.Store)
	if f.session == nil {
		t.Fatal("receipt reader open", result)
	}
	replacementBody, read := f.session.MutationReceipt(ctx, readerPermit.plan.operation)
	if read.Outcome != ObservedCurrent {
		t.Fatal("Recipient replacement lost its own receipt", read)
	}
	replacement, err := contract.InspectCompactMutationReceipt(replacementBody)
	if err != nil || replacement.OperationKind != contract.OperationRotateRecipientKeyBinding {
		t.Fatal("Recipient replacement retained the wrong operation result", err)
	}
	captured = append(captured, receiptExpectation{OperationID: readerPermit.plan.operation, Body: bytes.Clone(replacementBody)})
	checkFreshReceipts(t, ctx, f.session, captured)
	a := f.admission.admission
	basis := successionBasisTransport(a.current)
	fresh := selectedProcessFacts(t, f.admission, f.session)
	fresh.CurrentBasis, fresh.Objects = &basis, env.Store.(*memoryStore).objects
	fresh.Consumer = &successorConsumerInput{Binding: contract.BindingTableRow{SubjectKind: 1, SubjectID: reader, Binding: nextReader}, Name: "secret", Value: custody.StandardValue}
	checkFreshProcessInput(t, fresh)
}

// full_only: false
func TestAuthorityReplacementRepeatedSignerThenOrdinaryWithOldRoutesUnavailable(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			env, keys := genesisEnvironment(t, family, true)
			f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
			normal, recovery := env.Trust.(*fixtureTrust).Signer, env.Recovery.(*testtrust.Signer)
			keys.SetUnavailable(true)
			public, private := keys.Calls()
			for generation := 0; generation < 3; generation++ {
				before := f.session
				after := currentControlOf(before)
				after.AccessGeneration++
				successor, binding := normal.Successor(t, after.NormalSigning)
				after.NormalSigning = binding
				normal.SetUnavailable(true)
				permit := admitAuthorityReplacement(t, before, keys, after, contract.SuccessionReplaceAuthority,
					contract.RecoverySigningRole, contract.SuccessionChangeNormalSigner, contract.BindingTableRow{})
				candidate, result := before.PrepareSuccession(t.Context(), permit, SuccessionSigners{Authorizer: recovery, NormalSuccessor: successor})
				if candidate == nil {
					t.Fatal("signer replacement", generation, result)
				}
				if len(candidate.head.Succession.Acceptances) != 1 || candidate.head.Succession.Acceptances[0].Role != contract.NormalSigningRole {
					t.Fatal("changed signer has no exact final-selection acceptance")
				}
				admission := deliverSuccessionBasis(t, candidate)
				if result = before.Select(t.Context(), candidate); result.Outcome != ObservedCurrent {
					t.Fatal("replacement selection", generation, result)
				}
				current, result := Open(t.Context(), admission, env.Store)
				if current == nil || !selectionAcceptanceValid(current.head, current.root) {
					t.Fatal("immediate replacement read", generation, result)
				}
				input := current.currentEntryInputs()
				input[0].InputBytes = []byte(fmt.Sprintf("ordinary generation %d", generation))
				comparison, result := current.Compare(t.Context(), input, admitSuppliedComparison(t, current, nil, input))
				if comparison == nil {
					t.Fatal("ordinary comparison", generation, result)
				}
				ordinary, result := current.Prepare(t.Context(), comparison, admit(t, current, comparison), successor)
				if ordinary == nil {
					t.Fatal("ordinary preparation", generation, result)
				}
				if result = current.Select(t.Context(), ordinary); result.Outcome != ObservedCurrent {
					t.Fatal("ordinary selection", generation, result)
				}
				fresh, result := Open(t.Context(), admission, env.Store)
				if fresh == nil {
					t.Fatal("later ordinary read", generation, result)
				}
				if c, result := fresh.Compare(t.Context(), input, admitSuppliedComparison(t, fresh, nil, input)); c != nil || result.Outcome != Unchanged {
					t.Fatal("later selected bytes differ", generation, result)
				}
				if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
					t.Fatal("signer or plain follow-on used unavailable custody")
				}
				f.admission, f.session, normal = admission, fresh, successor
			}
		})
	}
}

type selectionAnchorProbe struct {
	reason contract.Reason
	valid  bool
	calls  int
}

func (p *selectionAnchorProbe) QualifySigningBinding(_ context.Context, b contract.PublicSigningBinding) contract.SigningQualificationResult {
	p.calls++
	if !p.valid {
		return contract.SigningQualificationResult{Reason: p.reason}
	}
	digest, _ := contract.SigningBindingDigest(b)
	role := uint8(contract.NormalSignerTarget)
	if b.Role == contract.RecoverySigningRole {
		role = contract.RecoverySignerTarget
	}
	return contract.SigningQualificationResult{Qualified: 1, Provider: b.Provider, TargetRole: role, SigningBindingDigest: digest}
}

// full_only: false
func TestReconstructionAnchorSeparatesInvalidUnavailableAndUninstalled(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
	after := currentControlOf(f.session)
	successor, binding := env.Trust.(*fixtureTrust).Successor(t, after.NormalSigning)
	after.NormalSigning, after.AccessGeneration = binding, after.AccessGeneration+1
	permit := admitAuthorityReplacement(t, f.session, keys, after, contract.SuccessionReplaceAuthority, contract.RecoverySigningRole, contract.SuccessionChangeNormalSigner, contract.BindingTableRow{})
	candidate, res := f.session.PrepareSuccession(t.Context(), permit, SuccessionSigners{Authorizer: env.Recovery, NormalSuccessor: successor})
	if candidate == nil {
		t.Fatal("dual-anchor selection fixture", res)
	}
	var root format.Root
	for _, object := range candidate.objects {
		if object.ref == candidate.head.Core.Root {
			var err error
			root, err = format.DecodeRoot(object.body)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, role := range []uint8{contract.NormalSigningRole, contract.RecoverySigningRole} {
		if _, eligible := candidateSelectionSignature(candidate.head, root, role); !eligible {
			t.Fatalf("fixture lacks eligible role %d", role)
		}
	}
	for _, tc := range []struct {
		name                       string
		normal, recovery           *selectionAnchorProbe
		damage                     bool
		want                       Result
		normalCalls, recoveryCalls int
	}{
		{"invalid-unavailable", &selectionAnchorProbe{reason: contract.ReasonProof}, &selectionAnchorProbe{reason: contract.ReasonTransport}, false, failure(EvidenceUnavailable, SigningUnavailable), 1, 1},
		{"unavailable-invalid", &selectionAnchorProbe{reason: contract.ReasonTransport}, &selectionAnchorProbe{reason: contract.ReasonProof}, false, failure(EvidenceUnavailable, SigningUnavailable), 1, 1},
		{"all-invalid", &selectionAnchorProbe{reason: contract.ReasonProof}, &selectionAnchorProbe{reason: contract.ReasonProof}, false, failure(IntegrityFailure, InvalidProof), 1, 1},
		{"qualified-short-circuit", &selectionAnchorProbe{valid: true}, &selectionAnchorProbe{reason: contract.ReasonTransport}, false, Result{}, 1, 0},
		{"fallback-qualified", &selectionAnchorProbe{reason: contract.ReasonProof}, &selectionAnchorProbe{valid: true}, false, Result{}, 1, 1},
		{"eligible-uninstalled", nil, nil, false, failure(EvidenceUnavailable, SigningUnavailable), 0, 0},
		{"no-eligible-proof", &selectionAnchorProbe{valid: true}, &selectionAnchorProbe{valid: true}, true, failure(IntegrityFailure, InvalidProof), 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			head := candidate.head
			if tc.damage {
				head.AuthorizationSignature = nil
			}
			var normal, recovery candidateSigningQualifier
			if tc.normal != nil {
				normal = tc.normal
			}
			if tc.recovery != nil {
				recovery = tc.recovery
			}
			anchor, result := qualifyCandidateSelection(t.Context(), head, root, normal, recovery)
			if result != tc.want {
				t.Fatalf("result=%+v want=%+v", result, tc.want)
			}
			if result.Outcome != 0 && anchor.role != 0 {
				t.Fatal("failure returned partial anchor")
			}
			if tc.normal != nil && tc.normal.calls != tc.normalCalls || tc.recovery != nil && tc.recovery.calls != tc.recoveryCalls {
				t.Fatal("anchor calls differ")
			}
		})
	}
}
