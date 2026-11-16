package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type currentBasisFixture struct {
	env       fixtureEnvironment
	old       OpenContext
	current   OpenContext
	control   contract.ControlCore
	head      format.Head
	root      format.Root
	successor *testtrust.Signer
}

func currentBasisSign(t testing.TB, signer contract.Trust, q contract.SignRequest, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	r := signer.Sign(context.Background(), q)
	if r.Reason != 0 || len(r.Signature) == 0 {
		t.Fatal("fixture signing failed", r.Reason)
	}
	return r.Signature
}

// This fixture supplies an independently trusted parent's public admission.
// It tests the cold read boundary, not the production succession issuer.
func newCurrentBasisFixture(t *testing.T, family contract.Family, recovery bool) *currentBasisFixture {
	t.Helper()
	env, _ := genesisEnvironment(t, family, recovery)
	old := fixtureAdmission(env)
	init, _ := fixtureInitAdmission(t, env, old)
	before, res := Initialize(context.Background(), init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, env.Crypto)
	if before == nil || res.Outcome != ObservedCurrent {
		t.Fatal("fixture genesis failed", res)
	}
	control, ok := before.selectedControl()
	if !ok {
		t.Fatal("fixture control missing")
	}
	beforeDigest, err := contract.ControlCoreDigest(control)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := control.NormalSigning
	successor, successorBinding := env.Trust.(*fixtureTrust).Successor(t, control.NormalSigning)
	control.NormalSigning = successorBinding
	control.AccessGeneration++
	root := before.root
	root.Snapshot, root.Transition = testID("current-basis-root"), testID("current-basis-transition")
	root.CurrentAccess.Core.CurrentControl = control.CurrentControl
	root.CurrentAccess.AccessRoot, err = contract.AccessRoot(root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	afterDigest, err := contract.ControlCoreDigest(control)
	if err != nil {
		t.Fatal(err)
	}
	core := before.head.Core
	core.Form, core.Revision = format.SuccessorHead, testID("current-basis-revision")
	core.PreviousRevision, core.PreviousDigest, core.PreviousToken = before.head.Core.Revision, contract.Hash(before.body), before.token
	core.Epoch = control.NormalSigning.Binding.Epoch
	subject := contract.SuccessionSubject{Schema: contract.CanonicalSchema, OperationKind: 1, ApprovalRole: 1, ChangeMask: 1,
		OperationID: testID("current-basis-operation"), AdmissionID: testID("current-basis-admission"),
		RequestCoreDigest: testID("current-basis-request"), RequestIdentityDigest: testID("current-basis-final-request-identity"), IdentityPlanDigest: testID("current-basis-identities"), IdentityPlanLength: 162,
		BeforeControlDigest: beforeDigest, AfterControlDigest: afterDigest, BeforeAccessRoot: before.root.CurrentAccess.AccessRoot, AfterAccessRoot: root.CurrentAccess.AccessRoot,
		PreservedStateDigest: testID("current-basis-preserved"), CoverageDigest: testID("current-basis-coverage"), ReplacementPlanDigest: testID("current-basis-replacements"),
		ReceiptDeltaDigest: testID("current-basis-receipts"), ReplacementCount: 1, SuccessorEvidenceCount: 1}
	bd, err := contract.SigningBindingDigest(control.NormalSigning)
	if err != nil {
		t.Fatal(err)
	}
	probe := contract.SuccessorProbeCore{Schema: 1, EvidenceKind: 1, TargetRole: 1, DomainID: core.Domain, CoordinateID: core.Coordinate,
		AdmissionID: subject.AdmissionID, PredecessorFullHEADDigest: core.PreviousDigest, RequestCoreDigest: subject.RequestCoreDigest,
		SuccessorBindingDigest: bd, ProbeAttemptID: testID("current-basis-probe")}
	q, err := contract.NewSuccessorSignerProbeRequest(probe)
	evidence := []contract.SuccessorEvidenceRow{{EvidenceKind: 1, TargetRole: 1, Trust: contract.SuccessorTrustEvidence{
		SuccessorSignerFields: contract.SuccessorSignerFields{ProbeAttemptID: probe.ProbeAttemptID, SigningBindingDigest: bd}, Signature: currentBasisSign(t, successor, q, err)}}}
	subject.SuccessorEvidenceDigest, err = contract.SuccessorEvidenceDigest(evidence)
	if err != nil {
		t.Fatal(err)
	}
	f := &currentBasisFixture{env: env, old: old, control: control, root: root, successor: successor,
		head: format.Head{Core: core, AuthKind: format.SuccessionAuth, Succession: &format.SuccessionProof{Subject: subject, Authorizer: authorizer, Evidence: evidence}}}
	q, err = contract.NewBindingRequest(control.NormalSigning.Binding)
	f.head.K1 = currentBasisSign(t, successor, q, err)
	if recovery {
		q, err = contract.NewK3BasisRequest(control.Recovery.Signing)
		f.head.K3 = currentBasisSign(t, env.Recovery, q, err)
	}
	f.storeRootAndHead(t)
	encoded, err := contract.EncodeControlCore(control)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := make([]recipientEnrollment, 0, before.root.RecipientCount)
	for _, row := range before.registry() {
		enrollment = append(enrollment, recipientEnrollment{id: row.RecipientID, status: row.Status, name: row.DisplayName})
	}
	body, err := format.EncodeHead(f.head)
	if err != nil {
		t.Fatal(err)
	}
	a := *old.admission
	a.publicKey, a.epoch, a.descriptor = successor.PublicKey(), control.NormalSigning.Binding.Epoch, nil
	a.current = (&qualifiedCurrentBasis{issued: true, control: encoded, selection: body, enrollment: enrollment}).clone()
	f.current = OpenContext{admission: &a}
	return f
}

func (f *currentBasisFixture) storeRootAndHead(t testing.TB) {
	t.Helper()
	b, err := format.EncodeRoot(f.root)
	if err != nil {
		t.Fatal(err)
	}
	f.head.Core.Root, err = format.Reference(format.RootKind, f.root.Domain, f.root.Snapshot, 0, b)
	if err != nil {
		t.Fatal(err)
	}
	key, err := format.Key(f.env.Store.Descriptor().Prefix, f.head.Core.Root)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.env.Put(context.Background(), key, b); err != nil {
		t.Fatal(err)
	}
	core, err := format.EncodeHeadCore(f.head.Core)
	if err != nil {
		t.Fatal(err)
	}
	subject := &f.head.Succession.Subject
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(core), uint32(len(core))
	plan, err := format.EncodeConditionalPlan(conditional(f.head.Core, core))
	if err != nil {
		t.Fatal(err)
	}
	subject.ConditionalPlanDigest = contract.Hash(plan)
	q, err := contract.NewK2SuccessionRequest(*subject)
	f.head.AuthorizationSignature = currentBasisSign(t, f.env.Trust, q, err)
	binding := f.control.NormalSigning
	digest, err := contract.SigningBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	q, err = contract.NewSelectionAcceptanceRequest(contract.SelectionAcceptance{HeadCore: core,
		CurrentAccess: f.root.CurrentAccess, AccessRoot: f.root.CurrentAccess.AccessRoot,
		Succession: *subject, Authorizer: f.head.Succession.Authorizer, Evidence: f.head.Succession.Evidence,
		Accepting: binding, Role: contract.NormalSigningRole, Epoch: binding.Binding.Epoch})
	f.head.Succession.Acceptances = []format.SelectionAcceptanceProof{{Role: contract.NormalSigningRole,
		BindingDigest: digest, Epoch: binding.Binding.Epoch, Signature: currentBasisSign(t, f.successor, q, err)}}
	f.storeHead(t)
}

func (f *currentBasisFixture) storeHead(t testing.TB) {
	t.Helper()
	body, err := format.EncodeHead(f.head)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.env.Put(context.Background(), f.env.Store.Descriptor().HeadKey, body); err != nil {
		t.Fatal(err)
	}
}

func (f *currentBasisFixture) signK1(t testing.TB) {
	t.Helper()
	q, err := contract.NewBindingRequest(f.control.NormalSigning.Binding)
	f.head.K1 = currentBasisSign(t, f.successor, q, err)
}

func (f *currentBasisFixture) signK2(t testing.TB) {
	t.Helper()
	q, err := contract.NewK2SuccessionRequest(f.head.Succession.Subject)
	f.head.AuthorizationSignature = currentBasisSign(t, f.env.Trust, q, err)
}

func (f *currentBasisFixture) signSelectionAcceptance(t testing.TB) {
	t.Helper()
	if len(f.head.Succession.Acceptances) != 1 {
		t.Fatal("current basis fixture requires one successor acceptance")
	}
	core, err := format.EncodeHeadCore(f.head.Core)
	if err != nil {
		t.Fatal(err)
	}
	proof := &f.head.Succession.Acceptances[0]
	q, err := contract.NewSelectionAcceptanceRequest(contract.SelectionAcceptance{HeadCore: core,
		CurrentAccess: f.root.CurrentAccess, AccessRoot: f.root.CurrentAccess.AccessRoot,
		Succession: f.head.Succession.Subject, Authorizer: f.head.Succession.Authorizer,
		Evidence: f.head.Succession.Evidence, Accepting: f.control.NormalSigning, Role: proof.Role, Epoch: proof.Epoch})
	proof.Signature = currentBasisSign(t, f.successor, q, err)
}

func (f *currentBasisFixture) signK3(t testing.TB) {
	t.Helper()
	if f.control.Recovery == nil {
		t.Fatal("current basis has no recovery signer")
	}
	q, err := contract.NewK3BasisRequest(f.control.Recovery.Signing)
	f.head.K3 = currentBasisSign(t, f.env.Recovery, q, err)
}

// full_only: false
func TestCurrentBasisColdReadUsesOnlyCurrentPublicClosure(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("provider%d-recovery%t", family, recovery), func(t *testing.T) {
				f := newCurrentBasisFixture(t, family, recovery)
				f.env.Trust.(*fixtureTrust).SetUnavailable(true)
				f.successor.SetUnavailable(true)
				f.env.Custody.SetUnavailable(true)
				if recovery {
					f.env.Recovery.(*testtrust.Signer).SetUnavailable(true)
				}
				store := f.env.Store.(*memoryStore)
				allowed := map[string]bool{store.desc.HeadKey: true}
				rootKey, err := format.Key(store.desc.Prefix, f.head.Core.Root)
				if err != nil {
					t.Fatal(err)
				}
				allowed[rootKey] = true
				for _, ref := range append(append([]format.Ref{f.root.AdministrativeIndex}, f.root.AdministrativeIndexShards...), f.root.RequiredSupport...) {
					key, err := format.Key(store.desc.Prefix, ref)
					if err != nil {
						t.Fatal(err)
					}
					allowed[key] = true
				}
				for _, ref := range f.root.Recipients {
					if ref != nil {
						key, err := format.Key(store.desc.Prefix, *ref)
						if err != nil {
							t.Fatal(err)
						}
						allowed[key] = true
					}
				}
				store.readHook = func(key string, r contract.ReadResult) contract.ReadResult {
					if !allowed[key] {
						t.Fatal("cold open fetched historic or unselected object", key)
					}
					return r
				}
				pub, private := f.env.Custody.Calls()
				signs, successorSigns := f.env.Trust.(*fixtureTrust).signs, f.successor.Calls()
				creates, cas := store.creates, store.cas
				s, res := Open(context.Background(), f.current, store)
				if s == nil || res.Outcome != ObservedCurrent || s.head.Core.Epoch != 2 || !s.validSuccessionSelection() {
					t.Fatal("qualified current public basis refused", res)
				}
				if _, ok := s.admission.domainBasis(); ok {
					t.Fatal("current admission became a higher-epoch genesis descriptor")
				}
				gotPub, gotPrivate := f.env.Custody.Calls()
				if gotPub != pub || gotPrivate != private || f.env.Trust.(*fixtureTrust).signs != signs || f.successor.Calls() != successorSigns || store.creates != creates || store.cas != cas {
					t.Fatal("public cold open performed private work or writes")
				}
			})
		}
	}
}

// full_only: false
func TestCurrentBasisAcceptsAlternateOuterProofsForSameSelection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		recovery bool
		resign   func(*currentBasisFixture, testing.TB)
	}{
		{"k1", false, func(f *currentBasisFixture, t testing.TB) { f.signK1(t) }},
		{"k2", false, func(f *currentBasisFixture, t testing.TB) { f.signK2(t) }},
		{"k3", true, func(f *currentBasisFixture, t testing.TB) { f.signK3(t) }},
		{"acceptance", false, func(f *currentBasisFixture, t testing.TB) {
			core, err := format.EncodeHeadCore(f.head.Core)
			if err != nil {
				t.Fatal(err)
			}
			proof := &f.head.Succession.Acceptances[0]
			before := bytes.Clone(proof.Signature)
			q, err := contract.NewSelectionAcceptanceRequest(contract.SelectionAcceptance{HeadCore: core,
				CurrentAccess: f.root.CurrentAccess, AccessRoot: f.root.CurrentAccess.AccessRoot,
				Succession: f.head.Succession.Subject, Authorizer: f.head.Succession.Authorizer,
				Evidence: f.head.Succession.Evidence, Accepting: f.control.NormalSigning, Role: proof.Role, Epoch: proof.Epoch})
			proof.Signature = currentBasisSign(t, f.successor, q, err)
			if bytes.Equal(before, proof.Signature) || !selectionAcceptanceValid(f.head, f.root) {
				t.Fatal("fixture did not create a different valid acceptance signature")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCurrentBasisFixture(t, contract.GCP, tc.recovery)
			pinned, err := format.DecodeHead(f.current.admission.current.selection)
			if err != nil {
				t.Fatal(err)
			}
			tc.resign(f, t)
			body, err := format.EncodeHead(f.head)
			if err != nil || bytes.Equal(body, f.current.admission.current.selection) || f.head.Core != pinned.Core || f.head.Succession.Subject != pinned.Succession.Subject || !signingBindingEqual(f.head.Succession.Authorizer, pinned.Succession.Authorizer) {
				t.Fatal("alternate proof changed or reproduced the admitted semantic selection", err)
			}
			if len(f.head.Succession.Acceptances) != len(pinned.Succession.Acceptances) {
				t.Fatal("alternate proof changed acceptance row count")
			}
			for i, row := range f.head.Succession.Acceptances {
				before := pinned.Succession.Acceptances[i]
				if row.Role != before.Role || row.BindingDigest != before.BindingDigest || row.Epoch != before.Epoch {
					t.Fatal("alternate proof changed acceptance identity")
				}
			}
			f.storeHead(t)
			if s, res := Open(context.Background(), f.current, f.env.Store); s == nil || res.Outcome != ObservedCurrent || !s.validSuccessionSelection() {
				t.Fatal("valid alternate outer proof refused", res)
			}
		})
	}
}

// full_only: false
func TestCurrentBasisRefusesUnadmittedAndUnequalPublicDependencies(t *testing.T) {
	for name, change := range map[string]func(*currentBasisFixture, testing.TB){
		"missing independent basis":   func(f *currentBasisFixture, t testing.TB) { f.current.admission.current = nil },
		"unissued copied public rows": func(f *currentBasisFixture, t testing.TB) { f.current.admission.current.issued = false },
		"old genesis pins":            func(f *currentBasisFixture, t testing.TB) { f.current = f.old },
		"mixed genesis and current basis": func(f *currentBasisFixture, t testing.TB) {
			f.current.admission.descriptor = bytes.Clone(f.old.admission.descriptor)
		},
		"old epoch": func(f *currentBasisFixture, t testing.TB) { f.current.admission.epoch-- },
		"wrong current key": func(f *currentBasisFixture, t testing.TB) {
			f.current.admission.publicKey = bytes.Clone(f.old.admission.publicKey)
		},
		"wrong current trust": func(f *currentBasisFixture, t testing.TB) { f.current.admission.trust = testID("unrelated-trust") },
		"changed immutable control": func(f *currentBasisFixture, t testing.TB) {
			control, err := contract.DecodeControlCore(f.current.admission.current.control)
			if err != nil {
				t.Fatal(err)
			}
			changed := testID("different current-basis compatibility")
			if control.CompatibilityID == changed {
				t.Fatal("fixture compatibility counterexample is equal")
			}
			control.CompatibilityID = changed
			f.current.admission.current.control, err = contract.EncodeControlCore(control)
			if err != nil {
				t.Fatal(err)
			}
		},
		"corrupt trusted relation": func(f *currentBasisFixture, t testing.TB) {
			pinned, err := format.DecodeHead(f.current.admission.current.selection)
			if err != nil {
				t.Fatal(err)
			}
			pinned.Succession.Subject.ReceiptDeltaDigest = testID("different trusted receipt delta")
			q, err := contract.NewK2SuccessionRequest(pinned.Succession.Subject)
			pinned.AuthorizationSignature = currentBasisSign(t, f.env.Trust, q, err)
			f.current.admission.current.selection, err = format.EncodeHead(pinned)
			if err != nil || !f.current.admission.valid(f.env.Store) || pinned.Succession.Subject == f.head.Succession.Subject {
				t.Fatal("counterexample lacks a valid unequal trusted relation", err)
			}
		},
		"corrupt selected current signature": func(f *currentBasisFixture, t testing.TB) { f.head.K1[len(f.head.K1)-1] ^= 1 },
		"corrupt selected prior signature": func(f *currentBasisFixture, t testing.TB) {
			f.head.AuthorizationSignature[len(f.head.AuthorizationSignature)-1] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCurrentBasisFixture(t, contract.GCP, false)
			change(f, t)
			f.storeHead(t)
			if s, res := Open(context.Background(), f.current, f.env.Store); s != nil || res.Outcome == ObservedCurrent {
				t.Fatal("unadmitted or unequal current basis accepted", res)
			}
		})
	}
	t.Run("historical display metadata", func(t *testing.T) {
		f := newCurrentBasisFixture(t, contract.GCP, false)
		want := slices.Clone(f.current.admission.current.enrollment)
		if len(want) == 0 || want[0].name == "different historical recipient" {
			t.Fatal("fixture lacks a distinct historical display counterexample")
		}
		f.current.admission.current.enrollment[0].name = "different historical recipient"
		selected, result := Open(t.Context(), f.current, f.env.Store)
		if selected == nil || result.Outcome != ObservedCurrent {
			t.Fatal("historical display metadata refused", result)
		}
		var got []recipientEnrollment
		for _, row := range selected.registry() {
			got = append(got, recipientEnrollment{id: row.RecipientID, status: row.Status, name: row.DisplayName})
		}
		if !slices.Equal(got, want) {
			t.Fatal("historical display metadata changed authenticated current registry", got, want)
		}
	})
}

// full_only: false
func TestCurrentBasisRefusesChangedSubjectAndAuthorizer(t *testing.T) {
	for _, changedSubject := range []bool{false, true} {
		t.Run(fmt.Sprintf("subject%t", changedSubject), func(t *testing.T) {
			f := newCurrentBasisFixture(t, contract.GCP, false)
			pinnedSelection, pinnedControl := bytes.Clone(f.current.admission.current.selection), bytes.Clone(f.current.admission.current.control)
			if changedSubject {
				f.head.Succession.Subject.ReceiptDeltaDigest = testID("another-receipt-delta")
				f.signK2(t)
			} else {
				f.head.Succession.Authorizer = f.control.NormalSigning
				q, err := contract.NewK2SuccessionRequest(f.head.Succession.Subject)
				f.head.AuthorizationSignature = currentBasisSign(t, f.successor, q, err)
				if !successionProofValid(f.head) {
					t.Fatal("self-signed counterexample lacks a valid signature")
				}
			}
			f.signSelectionAcceptance(t)
			if !currentSigningProofs(f.head, f.control) || !successionProofValid(f.head) ||
				!successorEvidenceValid(f.head, f.control) || !selectionAcceptanceValid(f.head, f.root) ||
				qualifiedPredecessorSelected(f.current.admission.current, f.head) {
				t.Fatal("changed semantic counterexample requires valid public proofs outside the independent pin")
			}
			f.storeHead(t)
			f.env.Trust.(*fixtureTrust).SetUnavailable(true)
			f.successor.SetUnavailable(true)
			f.env.Custody.SetUnavailable(true)
			store := f.env.Store.(*memoryStore)
			reads, creates, cas := store.reads, store.creates, store.cas
			public, private := f.env.Custody.Calls()
			signs, successorSigns := f.env.Trust.(*fixtureTrust).signs, f.successor.Calls()
			store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
				if key != store.desc.HeadKey {
					t.Fatal("unqualified relation read selected children", key)
				}
				return result
			}
			if s, res := Open(context.Background(), f.current, store); s != nil || res != failure(EvidenceUnavailable, SigningUnavailable) {
				t.Fatal("different relation acquired current admission or an unsupported integrity classification", res)
			}
			gotPublic, gotPrivate := f.env.Custody.Calls()
			if store.reads != reads+1 || store.creates != creates || store.cas != cas || gotPublic != public || gotPrivate != private ||
				f.env.Trust.(*fixtureTrust).signs != signs || f.successor.Calls() != successorSigns ||
				!bytes.Equal(f.current.admission.current.selection, pinnedSelection) || !bytes.Equal(f.current.admission.current.control, pinnedControl) {
				t.Fatal("unqualified relation changed the independent basis or performed private work or writes")
			}
		})
	}
}

// full_only: false
func TestCurrentBasisRefusesInvalidRecoveryProof(t *testing.T) {
	f := newCurrentBasisFixture(t, contract.GCP, true)
	f.head.K3[len(f.head.K3)-1] ^= 1
	f.storeHead(t)
	if s, res := Open(context.Background(), f.current, f.env.Store); s != nil || res.Outcome != IntegrityFailure || res.Reason != InvalidProof {
		t.Fatal("invalid current recovery proof accepted", res)
	}
}

// full_only: false
func TestCurrentBasisRefusesAlteredEmbeddedSuccessorEvidence(t *testing.T) {
	f := newCurrentBasisFixture(t, contract.GCP, false)
	pinnedSelection, pinnedControl := bytes.Clone(f.current.admission.current.selection), bytes.Clone(f.current.admission.current.control)
	row := &f.head.Succession.Evidence[0]
	q, err := contract.NewSuccessorSignerProbeRequest(contract.SuccessorProbeCore{Schema: 1, EvidenceKind: contract.SuccessorSignerEvidence, TargetRole: row.TargetRole,
		DomainID: f.head.Core.Domain, CoordinateID: f.head.Core.Coordinate, AdmissionID: f.head.Succession.Subject.AdmissionID,
		PredecessorFullHEADDigest: f.head.Core.PreviousDigest, RequestCoreDigest: f.head.Succession.Subject.RequestCoreDigest,
		SuccessorBindingDigest: row.Trust.SigningBindingDigest, ProbeAttemptID: row.Trust.ProbeAttemptID})
	before := bytes.Clone(row.Trust.Signature)
	row.Trust.Signature = currentBasisSign(t, f.successor, q, err)
	if bytes.Equal(before, row.Trust.Signature) {
		t.Fatal("fixture did not create alternate embedded proof bytes")
	}
	f.head.Succession.Subject.SuccessorEvidenceDigest, err = contract.SuccessorEvidenceDigest(f.head.Succession.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	f.signK2(t)
	f.signSelectionAcceptance(t)
	if !currentSigningProofs(f.head, f.control) || !successionProofValid(f.head) ||
		!successorEvidenceValid(f.head, f.control) || !selectionAcceptanceValid(f.head, f.root) ||
		qualifiedPredecessorSelected(f.current.admission.current, f.head) {
		t.Fatal("altered evidence requires valid public proofs outside the independent pin")
	}
	f.storeHead(t)
	f.env.Trust.(*fixtureTrust).SetUnavailable(true)
	f.successor.SetUnavailable(true)
	f.env.Custody.SetUnavailable(true)
	store := f.env.Store.(*memoryStore)
	reads, creates, cas := store.reads, store.creates, store.cas
	public, private := f.env.Custody.Calls()
	signs, successorSigns := f.env.Trust.(*fixtureTrust).signs, f.successor.Calls()
	store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
		if key != store.desc.HeadKey {
			t.Fatal("unqualified successor evidence read selected children", key)
		}
		return result
	}
	if s, res := Open(context.Background(), f.current, store); s != nil || res != failure(EvidenceUnavailable, SigningUnavailable) {
		t.Fatal("different embedded evidence acquired current admission or an unsupported integrity classification", res)
	}
	gotPublic, gotPrivate := f.env.Custody.Calls()
	if store.reads != reads+1 || store.creates != creates || store.cas != cas || gotPublic != public || gotPrivate != private ||
		f.env.Trust.(*fixtureTrust).signs != signs || f.successor.Calls() != successorSigns ||
		!bytes.Equal(f.current.admission.current.selection, pinnedSelection) || !bytes.Equal(f.current.admission.current.control, pinnedControl) {
		t.Fatal("unqualified successor evidence changed the independent basis or performed private work or writes")
	}
}

// full_only: false
func TestCurrentBasisRefusesChangedBytesUnderObservedToken(t *testing.T) {
	f := newCurrentBasisFixture(t, contract.GCP, true)
	s, res := Open(context.Background(), f.current, f.env.Store)
	if s == nil || res.Outcome != ObservedCurrent {
		t.Fatal("current basis fixture refused", res)
	}
	f.signK1(t)
	f.signK2(t)
	f.signK3(t)
	changed, err := format.EncodeHead(f.head)
	if err != nil || bytes.Equal(changed, s.body) {
		t.Fatal("fixture did not create changed valid HEAD bytes", err)
	}
	store := f.env.Store.(*memoryStore)
	store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
		if key == store.desc.HeadKey {
			result.Body = bytes.Clone(changed)
		}
		return result
	}
	if next, result := s.readCurrent(context.Background()); next != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidFormat {
		t.Fatal("changed bytes reused an observed token", result)
	}
}

// full_only: false
func TestCurrentBasisNextTransitionUsesActualStoredHeadDigest(t *testing.T) {
	f := newCurrentBasisFixture(t, contract.GCP, true)
	pinned := bytes.Clone(f.current.admission.current.selection)
	f.signK1(t)
	f.signK2(t)
	f.signK3(t)
	f.storeHead(t)
	s, res := Open(context.Background(), f.current, f.env.Store)
	if s == nil || res.Outcome != ObservedCurrent || bytes.Equal(s.body, pinned) {
		t.Fatal("alternate current HEAD was not authenticated", res)
	}
	want := append(s.currentEntryInputs(), ApplyEntryInput{Name: "next", Recipients: []contract.ID{s.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte("value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	comparison, res := s.Compare(context.Background(), want, admitSuppliedComparison(t, s, nil, want))
	if comparison == nil || res.Outcome != ObservedCurrent {
		t.Fatal("next transition comparison", res)
	}
	candidate, res := s.Prepare(context.Background(), comparison, admit(t, s, comparison), f.successor)
	if candidate == nil || res.Outcome != ObservedCurrent {
		t.Fatal("next transition preparation", res)
	}
	if candidate.head.Core.PreviousDigest != contract.Hash(s.body) || candidate.head.Core.PreviousDigest == contract.Hash(pinned) {
		t.Fatal("next transition did not bind the actual authenticated full HEAD")
	}
}

// full_only: false
func TestCurrentBasisRefusesAccessGenerationBeforeQualification(t *testing.T) {
	f := newCurrentBasisFixture(t, contract.GCP, false)
	s, res := Open(context.Background(), f.current, f.env.Store)
	if s == nil || res.Outcome != ObservedCurrent {
		t.Fatal("qualified fixture refused", res)
	}
	// Changing the root invalidates its cached configuration validation. Keep
	// the selected support bytes so both modified images can be fully checked.
	for i, ref := range s.root.RequiredSupport {
		body, result := s.readObjectBorrowedUncached(t.Context(), ref)
		if result != (Result{}) {
			t.Fatal("access-generation fixture support read", result)
		}
		page, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal("access-generation fixture support", err)
		}
		s.support[i] = page
	}
	s.root.CurrentAccess.Core.AccessGeneration = f.control.AccessGeneration - 1
	var err error
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	generatedVerifySelectedFixtureSlices(t, s)
	if _, err := s.validateRelationsMode(t.Context(), false); err == nil {
		t.Fatal("current state predates its qualified control generation")
	}
	s.root.CurrentAccess.Core.AccessGeneration = f.control.AccessGeneration + 1
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal("advanced access root", err)
	}
	generatedVerifySelectedFixtureSlices(t, s)
	if _, err := s.validateRelationsMode(t.Context(), false); err != nil {
		t.Fatal("ordinary access-generation advancement refused", err)
	}
}

func (f *currentBasisFixture) pinSelectedHead(t testing.TB) {
	t.Helper()
	b, err := format.EncodeHead(f.head)
	if err != nil {
		t.Fatal(err)
	}
	f.current.admission.current.selection = b
}

func (f *currentBasisFixture) addReceipt(t testing.TB) (contract.CompactMutationReceipt, []byte, string) {
	t.Helper()
	selected, result := Open(t.Context(), f.current, f.env.Store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("receipt fixture lacks its authenticated configuration selection", result)
	}
	windows, err := selected.receiptWindows(t.Context())
	if err != nil {
		t.Fatal("receipt fixture predecessor windows", err)
	}
	r := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: 36,
		DomainID: f.control.DomainID, OperationID: testID("current-basis-receipt-operation"),
		RequestIdentityDigest: testID("current-basis-receipt-identity"),
		PredecessorRevisionID: testID("current-basis-receipt-before"), RequestedRevisionID: testID("current-basis-receipt-selected"), ObservedRevisionID: testID("current-basis-receipt-selected"),
		StateResult: 1, EvidenceCeiling: 1, CanonicalOutcome: 1,
		ChangedSubjects: contract.GeneratorDescriptor{Digest: testID("current-basis-receipt-subjects"), Length: 42, Count: 1},
		CompleteResult:  contract.GeneratorDescriptor{Digest: testID("current-basis-receipt-result"), Length: 655, Count: 1}}
	plan := contract.CompactMutationReceiptPlan(r)
	plan.RequestIdentityDigest = contract.ID{}
	delta := contract.MutationReceiptDeltaPlan{DomainID: r.DomainID, OperationKind: r.OperationKind, AddedCount: 1,
		Before: windows, NewReceipt: plan}
	indexes, err := selected.mutationReceiptPageIndexes(t.Context())
	if err != nil {
		t.Fatal("receipt fixture successor support indexes", err)
	}
	allocation := transitionPlan{snapshot: selected.root.Snapshot}
	for _, index := range indexes {
		allocation.supportPages[index] = fixtureID(r.OperationID, fmt.Sprintf("current-basis-receipt-support-%d", index))
	}
	storage, err := selected.encodeMutationReceiptSupport(t.Context(), allocation, delta, r.RequestIdentityDigest)
	if err != nil {
		t.Fatal("receipt fixture successor support", err)
	}
	for _, object := range storage.objects {
		key, err := format.Key(f.env.Store.Descriptor().Prefix, object.ref)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.env.Put(context.Background(), key, object.body); err != nil {
			t.Fatal(err)
		}
	}
	state := *selected
	storage.install(&state)
	ownSelectedSupportForMutationFixture(t, t.Context(), &state)
	indexObjects := installReceiptFixtureAdministrativeIndex(t, &state)
	for _, object := range indexObjects {
		key, err := format.Key(f.env.Store.Descriptor().Prefix, object.ref)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.env.Put(context.Background(), key, object.body); err != nil {
			t.Fatal(err)
		}
	}
	f.root = state.root
	f.storeRootAndHead(t)
	f.pinSelectedHead(t)
	for _, object := range storage.objects {
		page, err := format.InspectRequiredSupportPage(object.body)
		if err != nil {
			t.Fatal("receipt fixture stored support page", err)
		}
		if !slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool {
			return row.Kind == contract.MutationReceiptSupportKind && row.RecordID == r.OperationID
		}) {
			continue
		}
		key, err := format.Key(f.env.Store.Descriptor().Prefix, object.ref)
		if err != nil {
			t.Fatal(err)
		}
		return r, bytes.Clone(object.body), key
	}
	t.Fatal("receipt fixture appended row absent")
	return contract.CompactMutationReceipt{}, nil, ""
}

// full_only: false
func TestCurrentBasisReadsAuthenticatedReceiptPage(t *testing.T) {
	f := newCurrentBasisFixture(t, contract.GCP, true)
	before, result := Open(t.Context(), f.current, f.env.Store)
	if before == nil || result.Outcome != ObservedCurrent {
		t.Fatal("receipt control configuration selection", result)
	}
	predecessorRows := selectedSupportRecordsForCustodyFixture(t, before)
	beforeWindows, err := before.receiptWindows(t.Context())
	if err != nil || len(beforeWindows.Successes) == 0 {
		t.Fatal("receipt control lacks its retained initialization history", err)
	}
	beforeIndex, err := before.receiptIndexID()
	if err != nil {
		t.Fatal("receipt control retained index", err)
	}
	var replacedIndexes []contract.ID
	for _, fragment := range before.root.Generated.Fragments {
		if fragment.BlobID != beforeIndex {
			continue
		}
		id, err := contract.GeneratorFragmentID(fragment.BlobID, fragment.FragmentIndex)
		if err != nil {
			t.Fatal("receipt control retained index fragment", err)
		}
		replacedIndexes = append(replacedIndexes, id)
	}
	receipt, body, key := f.addReceipt(t)
	if len(beforeWindows.Successes) >= contract.MutationReceiptWindowLimit {
		t.Fatal("receipt retention fixture must not evict earlier outcomes")
	}
	afterWindows := contract.MutationReceiptWindows{DomainID: beforeWindows.DomainID,
		Successes: append(slices.Clone(beforeWindows.Successes), receipt), Failures: slices.Clone(beforeWindows.Failures), Order: append(slices.Clone(beforeWindows.Order), receipt.OperationID)}
	expectedStorage := mutationReceiptFixtureStorage(t, afterWindows)
	s, res := Open(context.Background(), f.current, f.env.Store)
	if s == nil || res.Outcome != ObservedCurrent || s.support == nil {
		t.Fatal("current receipt closure refused", res)
	}
	page, err := format.InspectRequiredSupportPage(body)
	if err != nil {
		t.Fatal(err)
	}
	var records []contract.SupportRecord
	for _, row := range predecessorRows {
		if row.Kind == contract.MutationReceiptSupportKind || row.Kind == contract.GeneratedFragmentSupportKind && slices.Contains(replacedIndexes, row.RecordID) {
			continue
		}
		records = append(records, row)
	}
	for _, page := range expectedStorage.pages {
		for _, row := range page.Records {
			records = append(records, contract.SupportRecord(row))
		}
	}
	slices.SortFunc(records, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	selectedRecords := selectedSupportRecordsForCustodyFixture(t, s)
	if len(selectedRecords) != len(records) {
		t.Fatal("receipt successor changed the complete support set", len(selectedRecords), len(records))
	}
	for i, row := range records {
		if selectedRecords[i].Kind != row.Kind || selectedRecords[i].RecordID != row.RecordID || !bytes.Equal(selectedRecords[i].Body, row.Body) {
			t.Fatal("receipt successor changed retained support bytes", i)
		}
	}
	retained, err := s.receiptWindows(t.Context())
	if err != nil || !slices.Equal(retained.Successes, afterWindows.Successes) || !slices.Equal(retained.Failures, afterWindows.Failures) || !slices.Equal(retained.Order, afterWindows.Order) {
		t.Fatal("receipt successor changed retained window history or order", err)
	}
	want, err := contract.RequiredSupportDescriptor(f.control.DomainID, records)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.supportDescriptor()
	if err != nil || got != want || got.Count != uint32(len(records)) || s.root.OutputConfiguration != before.root.OutputConfiguration {
		t.Fatal("receipt descriptor differs from the actual body", err)
	}
	projection, err := s.publicProjection()
	if err != nil || projection.RequiredSupport != want {
		t.Fatal("public state did not authenticate the actual receipt body", err)
	}
	position := slices.IndexFunc(s.root.RequiredSupport, func(ref format.Ref) bool { return ref.Index == page.Index })
	if position < 0 {
		t.Fatal("receipt page missing from selected support")
	}
	ref := s.root.RequiredSupport[position]
	cached := s.cache[ref]
	borrowed, err := format.InspectRequiredSupportPage(cached)
	if err != nil {
		t.Fatal("receipt immutable cache page", err)
	}
	rowSlot := slices.IndexFunc(borrowed.Records, func(row contract.SupportRecordView) bool {
		return row.Kind == contract.MutationReceiptSupportKind && row.RecordID == receipt.OperationID
	})
	if rowSlot < 0 || mustKey(t, s.admission.store.Prefix, ref) != key ||
		&s.support[position].Records[rowSlot].Body[0] != &borrowed.Records[rowSlot].Body[0] {
		t.Fatal("receipt view did not borrow immutable cache bytes")
	}
	clear(body)
	clear(f.current.admission.current.control)
	clear(f.current.admission.current.selection)
	f.current.admission.current.enrollment[0].name = "changed recipient"
	got, err = s.supportDescriptor()
	if err != nil || got != want || !s.admission.valid(s.store) {
		t.Fatal("session borrowed caller-owned admission or provider-returned page bytes")
	}
	if _, err := s.validateRelationsMode(t.Context(), false); err != nil {
		t.Fatal("session relation depends on caller-owned admission or provider-returned page bytes", err)
	}
	store := f.env.Store.(*memoryStore)
	reads := store.reads
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, invalid := range []context.Context{nil, cancelled} {
		if wire, result := s.MutationReceipt(invalid, receipt.OperationID); wire != nil || result != refused(AdmissionInvalid) {
			t.Fatal("invalid original context reached mutation receipt", result)
		}
	}
	if store.reads != reads {
		t.Fatal("invalid mutation receipt read Store")
	}
	wire, res := s.MutationReceipt(context.Background(), receipt.OperationID)
	wantWire, err := contract.EncodeCompactMutationReceipt(receipt)
	if err != nil || res.Outcome != ObservedCurrent || !bytes.Equal(wire, wantWire) {
		t.Fatal("cold receipt read changed original successful receipt", res, err)
	}
	rootKey, err := format.Key(store.desc.Prefix, s.head.Core.Root)
	if err != nil {
		t.Fatal(err)
	}
	s.cache = make(map[format.Ref][]byte)
	store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
		switch key {
		case store.desc.HeadKey:
			result.Token.Value = "999999"
		case rootKey:
			return contract.ReadResult{Status: contract.ReadMissing}
		}
		return result
	}
	if wire, res = s.MutationReceipt(context.Background(), receipt.OperationID); wire != nil || res.Outcome != EvidenceUnavailable || res.Reason != MissingSelectedObject {
		t.Fatal("changed HEAD observation reused a stale receipt closure", res)
	}
	store.readHook = nil
}

// full_only: false
func TestCurrentBasisRefusesMissingOrUnequalReceiptPage(t *testing.T) {
	for _, name := range []string{"missing", "body-digest", "page-index", "page-domain", "record-id", "record-kind", "duplicate-identity", "duplicate-snapshot", "duplicate-revision"} {
		t.Run(name, func(t *testing.T) {
			f := newCurrentBasisFixture(t, contract.GCP, true)
			receipt, body, key := f.addReceipt(t)
			position := slices.IndexFunc(f.root.RequiredSupport, func(ref format.Ref) bool {
				return mustKey(t, f.env.Store.Descriptor().Prefix, ref) == key
			})
			if position < 0 {
				t.Fatal("receipt damage target missing from selected support")
			}
			if name == "missing" {
				if err := f.env.Delete(context.Background(), key); err != nil {
					t.Fatal(err)
				}
			} else {
				switch name {
				case "body-digest":
					body[len(body)-1] ^= 1
				case "page-index":
					body[72] ^= 1
				case "page-domain":
					body[7] ^= 1
				case "record-id":
					body[76] ^= 1
				case "record-kind":
					body[75] = 6
				case "duplicate-identity", "duplicate-snapshot", "duplicate-revision":
					id := receipt.OperationID
					switch name {
					case "duplicate-identity":
						f.root.Transition = id
					case "duplicate-snapshot":
						f.root.Snapshot = id
					case "duplicate-revision":
						f.head.Core.Revision = id
					}
				}
				if err := f.env.Put(context.Background(), key, body); err != nil {
					t.Fatal(err)
				}
				if name != "body-digest" {
					f.root.RequiredSupport[position].Digest = contract.Hash(body)
					f.storeRootAndHead(t)
					f.pinSelectedHead(t)
				}
			}
			want := IntegrityFailure
			if name == "missing" {
				want = EvidenceUnavailable
			}
			if s, res := Open(context.Background(), f.current, f.env.Store); s != nil || res.Outcome != want {
				t.Fatal("invalid current receipt page accepted", res)
			}
		})
	}
}

// full_only: false
func TestCurrentBasisSelectionAcceptanceRefusesAlteredFinalSelection(t *testing.T) {
	for _, change := range []string{"root", "control", "access", "evidence", "wrong purpose", "corrupt signature"} {
		t.Run(change, func(t *testing.T) {
			f := newCurrentBasisFixture(t, contract.GCP, true)
			acceptance := bytes.Clone(f.head.Succession.Acceptances[0].Signature)
			switch change {
			case "root":
				f.root.Snapshot = testID("acceptance changed root")
			case "control":
				f.control.AccessGeneration++
				f.root.CurrentAccess.Core.CurrentControl = f.control.CurrentControl
				var err error
				f.head.Succession.Subject.AfterControlDigest, err = contract.ControlCoreDigest(f.control)
				if err != nil {
					t.Fatal(err)
				}
			case "access":
				ref := *f.root.Recipients[0]
				ref.Digest = testID("acceptance changed access")
				f.root.Recipients[0] = &ref
				var err error
				f.root.CurrentAccess.Core.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: f.root.Domain, Refs: []contract.Ref{ref}})
				if err != nil {
					t.Fatal(err)
				}
			case "evidence":
				row := &f.head.Succession.Evidence[0]
				q, err := contract.NewSuccessorSignerProbeRequest(contract.SuccessorProbeCore{Schema: 1,
					EvidenceKind: contract.SuccessorSignerEvidence, TargetRole: row.TargetRole,
					DomainID: f.head.Core.Domain, CoordinateID: f.head.Core.Coordinate,
					AdmissionID:               f.head.Succession.Subject.AdmissionID,
					PredecessorFullHEADDigest: f.head.Core.PreviousDigest,
					RequestCoreDigest:         f.head.Succession.Subject.RequestCoreDigest,
					SuccessorBindingDigest:    row.Trust.SigningBindingDigest, ProbeAttemptID: row.Trust.ProbeAttemptID})
				row.Trust.Signature = currentBasisSign(t, f.successor, q, err)
				f.head.Succession.Subject.SuccessorEvidenceDigest, err = contract.SuccessorEvidenceDigest(f.head.Succession.Evidence)
				if err != nil {
					t.Fatal(err)
				}
			case "wrong purpose":
				q, err := contract.NewBindingRequest(f.control.NormalSigning.Binding)
				acceptance = currentBasisSign(t, f.successor, q, err)
			case "corrupt signature":
				acceptance[len(acceptance)-1] ^= 1
			}
			if change == "control" || change == "access" {
				var err error
				f.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(f.root.CurrentAccess.Core)
				if err != nil {
					t.Fatal(err)
				}
				f.head.Succession.Subject.AfterAccessRoot = f.root.CurrentAccess.AccessRoot
			}
			f.storeRootAndHead(t)
			f.head.Succession.Acceptances[0].Signature = acceptance
			if !successionProofValid(f.head) || !currentSigningProofs(f.head, f.control) || !successorEvidenceValid(f.head, f.control) {
				t.Fatal("acceptance counterexample lacks valid predecessor and successor proofs")
			}
			if selectionAcceptanceValid(f.head, f.root) {
				t.Fatal("stale or wrong-purpose final acceptance remained valid")
			}
			f.storeHead(t)
			var err error
			f.current.admission.current.control, err = contract.EncodeControlCore(f.control)
			if err != nil {
				t.Fatal(err)
			}
			f.current.admission.current.selection, err = format.EncodeHead(f.head)
			if err != nil {
				t.Fatal(err)
			}
			if !f.current.admission.valid(f.env.Store) {
				t.Fatal("counterexample refused before selected proof read")
			}
			f.env.Trust.(*fixtureTrust).SetUnavailable(true)
			f.successor.SetUnavailable(true)
			f.env.Recovery.(*testtrust.Signer).SetUnavailable(true)
			f.env.Custody.SetUnavailable(true)
			store := f.env.Store.(*memoryStore)
			creates, cas := store.creates, store.cas
			if selected, result := Open(t.Context(), f.current, store); selected != nil || result != failure(IntegrityFailure, InvalidProof) {
				t.Fatal("altered final selection gained current admission", result)
			}
			if store.creates != creates || store.cas != cas {
				t.Fatal("refusal repaired selected proof")
			}
		})
	}
}

// full_only: false
func TestCurrentBasisSelectionAcceptanceRefusesMissingAndDuplicateStoredRows(t *testing.T) {
	for _, change := range []string{"missing", "duplicate"} {
		t.Run(change, func(t *testing.T) {
			f := newCurrentBasisFixture(t, contract.GCP, false)
			body, err := format.EncodeHead(f.head)
			if err != nil {
				t.Fatal(err)
			}
			const rowFixed = 1 + 32 + 8 + 4
			rowLength := rowFixed + len(f.head.Succession.Acceptances[0].Signature)
			suffix := len(body) - rowLength - 1
			bad := bytes.Clone(body[:suffix])
			if change == "missing" {
				bad = append(bad, 0)
			} else {
				bad = append(bad, 2)
				bad = append(bad, body[suffix+1:]...)
				bad = append(bad, body[suffix+1:]...)
			}
			store := f.env.Store.(*memoryStore)
			store.put(store.desc.HeadKey, bad)
			if selected, result := Open(t.Context(), f.current, store); selected != nil || result != failure(IntegrityFailure, InvalidFormat) {
				t.Fatal("invalid stored acceptance rows escaped codec", result)
			}
		})
	}
}
