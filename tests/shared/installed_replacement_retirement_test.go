package core

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// This fixture issues the private installed actor only for lower protocol tests.
// Public-operation evidence uses NewInstalledAuthorityReplacement below and the
// actual native composition matrix. No protected connection file grants roles.
func fixtureInstalledRecoveryActor(t testing.TB, s *StateSession, after contract.ControlCore, admission contract.ID) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	if s.admission.expires.Before(deadline) {
		deadline = s.admission.expires
	}
	goal := RoleReplacementGoal{ApprovalRole: contract.RecoverySigningRole, SigningSelector: after.NormalSigning.KeySelector}
	owner := &installedReplacement{target: ReplacementTargetAuthority, goal: goal, used: true}
	s.installedReplacement = &installedReplacementActor{session: s, owner: owner, ctx: t.Context(), deadline: deadline, target: ReplacementTargetAuthority, goal: goal,
		admission: admission, revision: s.head.Core.Revision, head: contract.Hash(s.body), root: s.head.Core.Root, token: s.token, access: s.root.CurrentAccess.AccessRoot,
		after: after, mask: contract.SuccessionChangeNormalSigner, ids: map[contract.ID]bool{admission: true, after.NormalSigning.BindingID: true}}
}

// This producer borrows an existing authenticated image. It uses the real
// installed parent, but its in-memory callback is not durability evidence.
func installedRecoverySignerFromSelected(t *testing.T, env fixtureEnvironment, before *StateSession) (*StateSession, *testtrust.Signer) {
	t.Helper()
	control := currentControlOf(before)
	successor, binding := env.Trust.(*fixtureTrust).Successor(t, control.NormalSigning)
	return installedRecoverySignerTo(t, env, before, successor, binding)
}

func installedRecoverySignerTo(t *testing.T, env fixtureEnvironment, before *StateSession, successor *testtrust.Signer, binding contract.PublicSigningBinding) (*StateSession, *testtrust.Signer) {
	t.Helper()
	control := currentControlOf(before)
	var delivered ReplacementSuccessor
	installation := ReplacementInstallation{ExpectedDomain: env.Domain, ExpectedStore: env.Store.Descriptor(), ExpectedControl: control,
		PublicBasis: before.admission.publicBasis(), Store: env.Store, CompositionID: before.admission.composition, FileIdentity: fixtureID(env.Domain, "retained image source"),
		SourceUnchanged: func(context.Context) error { return nil }, CloseInstalled: func() {},
		ResolvePublicGoal: func(_ context.Context, q ReplacementPublicRequest) (ReplacementPublicGoal, error) {
			if q.Provider != env.Store.Descriptor().Family || q.SigningRole != contract.NormalSigningRole || q.SigningSelector != binding.KeySelector || q.EncryptionSelector != "" {
				t.Fatal("changed public goal")
			}
			return ReplacementPublicGoal{Provider: binding.Provider, Signing: &ReplacementSigningKey{Selector: binding.KeySelector, SPKI: binding.SPKI, Fingerprint: binding.Fingerprint, Trust: binding.Binding.Trust, Profile: binding.SigningProfile}}, nil
		},
		ConstructSigners: func(_ context.Context, a contract.PublicSigningBinding, b *contract.PublicSigningBinding) (SuccessionSigners, func(), error) {
			if control.Recovery == nil || !signingBindingEqual(a, control.Recovery.Signing) || b == nil || b.KeySelector != binding.KeySelector || !bytes.Equal(b.SPKI, binding.SPKI) {
				t.Fatal("changed exact signer construction")
			}
			return SuccessionSigners{Authorizer: env.Recovery, NormalSuccessor: successor}, func() {}, nil
		},
		PublishSuccessor: func(_ context.Context, out ReplacementSuccessor) (ReplacementReadback, error) {
			delivered = out
			return ReplacementReadback{Basis: out.Basis, FileIdentity: fixtureID(env.Domain, "retained image source"), Control: out.Control, Recipients: out.Recipients, Correlation: out.Correlation}, nil
		},
	}
	engine, err := NewInstalledAuthorityReplacement(AuthorityReplacementInstallation{ReplacementInstallation: installation, Goal: RoleReplacementGoal{ApprovalRole: contract.RecoverySigningRole, SigningSelector: binding.KeySelector}})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	out := engine.Replace(ctx, fixtureID(before.head.Core.Revision, "installed retained image replacement"))
	if out.Result.Outcome != ObservedCurrent || out.OperationID.IsZero() || len(out.Receipt) != 0 {
		t.Fatal("installed retained image signer replacement", out.Result)
	}
	admitted, result := admitPublicNormal(ctx, env.Domain, env.Store.Descriptor(), delivered.Basis, env.Store, before.admission.composition, nil)
	if result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	var selected *StateSession
	if before.administrativeReceiptRead {
		selected, result = openAdministrative(ctx, admitted, env.Store)
	} else {
		selected, result = Open(ctx, admitted, env.Store)
	}
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("installed retained image cold open", result)
	}
	if selected.administrativeReceiptRead != before.administrativeReceiptRead {
		t.Fatal("installed retained image changed its read qualification")
	}
	return selected, successor
}

// full_only: false
func TestInstalledReplacementObservationSeparatesLaterSignerAndKnownCorruptProof(t *testing.T) {
	for _, mode := range []string{"later signer", "later corrupt known Recovery", "later contradicts unchanged Normal", "corrupt known Normal"} {
		t.Run(mode, func(t *testing.T) {
			f := replacementObservationPrepare(t, "authority-signer")
			f.selectCandidate(t)
			wantOutcome, wantReason := EvidenceUnavailable, SigningUnavailable
			if mode != "corrupt known Normal" {
				env := f.env
				env.Trust = &fixtureTrust{Signer: f.successor}
				latest, _ := installedRecoverySignerFromSelected(t, env, f.current)
				if latest.head.Core.Epoch != f.current.head.Core.Epoch+1 || latest.head.Core.Revision == f.current.head.Core.Revision {
					t.Fatal("later signer producer did not advance exact epoch")
				}
			}
			if mode != "later signer" {
				wantOutcome, wantReason = IntegrityFailure, InvalidProof
				store := f.env.Store.(*memoryStore)
				stored := store.objects[store.desc.HeadKey]
				head, err := format.DecodeHead(stored.Body)
				if err != nil {
					t.Fatal(err)
				}
				if head.Succession == nil || len(head.AuthorizationSignature) == 0 {
					t.Fatal("known proof fixture")
				}
				if mode == "later corrupt known Recovery" && head.Succession.Authorizer.Role != contract.RecoverySigningRole {
					t.Fatal("later proof does not use known Recovery")
				}
				if mode == "corrupt known Normal" && head.Succession.Authorizer.Role != contract.NormalSigningRole {
					t.Fatal("selected proof does not use known Normal")
				}
				if mode == "later contradicts unchanged Normal" {
					control := currentControlOf(f.current)
					head.Succession.Subject.ChangeMask = contract.SuccessionChangeAuthorityKEK
					head.Succession.Subject.MaterialSourceRole = contract.SuccessionMaterialAuthority
					binding, err := contract.PublicBindingDigest(control.AuthorityKMSBinding)
					if err != nil {
						t.Fatal(err)
					}
					head.Succession.Evidence = []contract.SuccessorEvidenceRow{{EvidenceKind: contract.SuccessorKEKEvidence, TargetRole: contract.SuccessorAuthorityKEK, KEK: contract.QualifiedSuccessorRow{ProbeID: generatedVectorID(244), QualifiedBindingFields: contract.QualifiedBindingFields{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: control.AuthorityRecipientID, BindingID: control.AuthorityKMSBinding.BindingID, PublicBindingDigest: binding, Provider: control.Provider, Qualified: 1}}}}
					head.Succession.Acceptances = nil
					head.Succession.Subject.SuccessorEvidenceDigest, err = contract.SuccessorEvidenceDigest(head.Succession.Evidence)
					if err != nil {
						t.Fatal(err)
					}
					head.Succession.Subject.BeforeControlDigest, err = contract.ControlCoreDigest(control)
					if err != nil {
						t.Fatal(err)
					}
					bound, err := contract.NewBindingRequest(control.NormalSigning.Binding)
					if err != nil {
						t.Fatal(err)
					}
					proof := f.successor.Sign(t.Context(), bound)
					if proof.Reason != contract.ReasonNone {
						t.Fatal(proof.Reason)
					}
					head.K1 = proof.Signature
					approved, err := contract.NewK3SuccessionRequest(head.Succession.Subject)
					if err != nil {
						t.Fatal(err)
					}
					proof = f.recovery.Sign(t.Context(), approved)
					if proof.Reason != contract.ReasonNone || head.Core.Epoch == control.NormalSigning.Binding.Epoch {
						t.Fatal("unchanged known Normal counterexample")
					}
					head.AuthorizationSignature = proof.Signature
				} else {
					head.AuthorizationSignature = bytes.Clone(head.AuthorizationSignature)
					head.AuthorizationSignature[len(head.AuthorizationSignature)-1] ^= 1
				}
				stored.Body, err = format.EncodeHead(head)
				if err != nil {
					t.Fatal(err)
				}
				store.objects[store.desc.HeadKey] = stored
			}
			if mode == "later contradicts unchanged Normal" {
				// The same owned HEAD has a positive contradiction under N1's
				// exact before control, while N0 cannot establish applicability.
				// These checks use fixture bytes and add no provider HEAD read.
				store := f.env.Store.(*memoryStore)
				stored := store.objects[store.desc.HeadKey]
				captured := contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(stored.Body), Token: stored.Token}
				reads := store.reads
				_, known := f.current.authenticateHeadResponse(t.Context(), captured)
				_, older := f.before.authenticateHeadResponse(t.Context(), captured)
				if known.Outcome != IntegrityFailure || known.Reason != InvalidProof || older.Outcome != EvidenceUnavailable || older.Reason != SigningUnavailable || store.reads != reads {
					t.Fatal("counterexample must separate applicable contradiction from older evidence limit", known, older)
				}
			}
			out, _ := f.query(t, "separate later binding and corrupt known proof "+mode)
			wantState := contract.ReaderUnavailable
			if wantOutcome == IntegrityFailure {
				wantState = contract.ReaderPositiveDefect
			}
			if out.Result.Outcome != wantOutcome || out.Result.Reason != wantReason || out.StateResult != wantState || out.Selection != nil || out.Receipt != nil || out.Query.Observation != nil || !out.Query.AuthenticatedBasisDigest.IsZero() || out.Result.CommitMayHaveOccurred {
				t.Fatal("public query merged unavailable binding and known defect", out.Result, out.StateResult)
			}
		})
	}
}

// full_only: false
func TestInstalledReplacementObservationLeavesUnselectedSameEpochSignerUnavailable(t *testing.T) {
	f := replacementObservationPrepare(t, "authority-signer")
	requestedControl, valid := f.admission.admission.currentControl()
	if !valid {
		t.Fatal("prepared output has no independently admitted control")
	}
	requestedSession := &StateSession{admission: *f.admission.admission, store: f.env.Store}
	// Keep the prepared N1 output unselected. A different authorized N2 wins
	// from the original N0 predecessor, so it has N1's epoch but another key.
	binding := requestedControl.NormalSigning
	signer := testtrust.NewWithIdentity(t, binding.Provider, fixtureID(f.env.Domain, "other same-epoch signer"), binding.Binding.Trust, contract.NormalSigningRole)
	binding.KeySelector, binding.SPKI = signer.KeySelector(), signer.PublicKey()
	binding.Fingerprint = contract.Hash(binding.SPKI)
	binding.Binding.PublicKey = binding.Fingerprint
	selected, signer := installedRecoverySignerTo(t, f.env, f.before, signer, binding)
	actual := currentControlOf(selected)
	if actual.NormalSigning.Binding.Epoch != requestedControl.NormalSigning.Binding.Epoch || actual.NormalSigning.KeySelector == requestedControl.NormalSigning.KeySelector || bytes.Equal(actual.NormalSigning.SPKI, requestedControl.NormalSigning.SPKI) {
		t.Fatal("counterexample requires a different independently selected signer at the same epoch")
	}
	f.current, f.ordinarySigner = selected, signer
	f.admission = OpenContext{admission: &selected.admission}
	f.ordinaryAdvance(t)
	if f.current.head.AuthKind != format.LifecycleAuth || f.current.head.Core.Epoch != requestedControl.NormalSigning.Binding.Epoch {
		t.Fatal("counterexample requires ordinary progress under the other same-epoch signer")
	}
	store := f.env.Store.(*memoryStore)
	stored := store.objects[store.desc.HeadKey]
	captured := contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(stored.Body), Token: stored.Token}
	reads := store.reads
	_, requested := requestedSession.authenticateHeadResponse(t.Context(), captured)
	_, original := f.before.authenticateHeadResponse(t.Context(), captured)
	if requested.Outcome != IntegrityFailure || requested.Reason != InvalidProof || original.Outcome != EvidenceUnavailable || original.Reason != SigningUnavailable || store.reads != reads {
		t.Fatal("unfamiliar same-epoch proof must not establish an applicable contradiction", requested, original)
	}
	private := signer.Calls()
	out, _ := f.query(t, "unselected output and other same-epoch signer progress")
	if out.Result.Outcome != EvidenceUnavailable || out.Result.Reason != SigningUnavailable || out.StateResult != contract.ReaderUnavailable || out.Selection != nil || out.Receipt != nil || out.Query.Observation != nil || !out.Query.AuthenticatedBasisDigest.IsZero() || out.Result.CommitMayHaveOccurred || signer.Calls() != private {
		t.Fatal("unproved same-epoch requested binding became a positive defect", out.Result, out.StateResult)
	}
}

// full_only: false
func TestInstalledReplacementObservationRetainsExactPublicReadFailure(t *testing.T) {
	for _, selected := range []bool{false, true} {
		for _, reason := range []contract.Reason{contract.ReasonAccess, contract.ReasonTransport} {
			t.Run(fmt.Sprintf("selected-%t/reason-%d", selected, reason), func(t *testing.T) {
				f := replacementObservationPrepare(t, "authority-signer")
				if selected {
					f.selectCandidate(t)
				}
				source := &replacementObservationSource{store: f.env.Store}
				source.hook = func(_ context.Context, key string) (contract.ReadResult, bool) {
					if key == source.Descriptor().HeadKey {
						return contract.ReadResult{Status: contract.ReadUnavailable, Reason: reason}, true
					}
					return contract.ReadResult{}, false
				}
				installation := f.installation
				installation.Source = source
				parent, err := NewInstalledReplacementObserver(installation)
				if err != nil {
					t.Fatal(err)
				}
				store := f.env.Store.(*memoryStore)
				creates, cas := store.creates, store.cas
				normal, recovery, successor := f.normal.Calls(), f.recovery.Calls(), f.successor.Calls()
				public, private := f.keys.Calls()
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				out := parent.Observe(ctx, testID("exact observed read failure"))
				if err := parent.Close(); err != nil {
					t.Fatal(err)
				}
				p, k := f.keys.Calls()
				expectedHeads := int64(1)
				// One logical capture retains the existing initial plus two transport retries.
				if reason == contract.ReasonTransport {
					expectedHeads = 3
				}
				if out.Result.Outcome != EvidenceUnavailable || out.Result.Reason != ReadUnavailable || out.Result.StoreReason != reason || out.StateResult != contract.ReaderUnavailable || out.Selection != nil || out.Receipt != nil || out.Result.CommitMayHaveOccurred || out.Query == nil || !out.Query.Valid() || source.heads.Load() != expectedHeads || source.closes.Load() != 1 || store.creates != creates || store.cas != cas || p != public || k != private || f.normal.Calls() != normal || f.recovery.Calls() != recovery || f.successor.Calls() != successor {
					t.Fatal("query replaced exact read cause or used private capabilities", out.Result)
				}
			})
		}
	}
}

// full_only: false
func TestInstalledReplacementObservationAcceptsEquivalentProofWithoutExactCandidate(t *testing.T) {
	f := replacementObservationPrepare(t, "authority-signer")
	f.selectCandidate(t)
	store := f.env.Store.(*memoryStore)
	stored := store.objects[store.desc.HeadKey]
	head, err := format.DecodeHead(stored.Body)
	if err != nil || head.Succession == nil {
		t.Fatal("selected succession", err)
	}
	request, err := contract.NewK2SuccessionRequest(head.Succession.Subject)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	for attempt := 0; attempt < 8; attempt++ {
		signed := f.normal.Sign(t.Context(), request)
		if signed.Reason != contract.ReasonNone || len(signed.Signature) == 0 {
			t.Fatal("independent valid authorization signature", signed.Reason)
		}
		if !bytes.Equal(signed.Signature, head.AuthorizationSignature) {
			head.AuthorizationSignature = signed.Signature
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("fixture did not generate a different valid outer proof")
	}
	altered, err := format.EncodeHead(head)
	if err != nil || bytes.Equal(altered, stored.Body) {
		t.Fatal("different valid proof bytes", err)
	}
	original, err := format.DecodeHead(f.candidate.body)
	if err != nil || head.Core != original.Core || head.Succession.Subject != original.Succession.Subject {
		t.Fatal("alternate proof changed semantic selection", err)
	}
	store.put(store.desc.HeadKey, altered)
	out, _ := f.query(t, "equivalent valid proof has public usability without exact candidate currentness")
	if out.StateResult != contract.ReaderSuccess || out.Result.Outcome != ObservedCurrent || out.Selection == nil || !out.Selection.SuccessorSourceUsable || out.Selection.CandidateSelected || out.Selection.EvidenceLimit != "historical-attribution-unavailable" || out.Receipt != nil || out.Result.ObservedRevision != f.candidate.head.Core.Revision {
		t.Fatal("query confused semantic usability and exact signed candidate", out.Result, out.Selection)
	}
}
