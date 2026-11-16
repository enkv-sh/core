package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestGCSigningSuccessionPreservesActiveAndPendingObligations(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "active"
		if pending {
			name = "pending"
		}
		t.Run(name, func(t *testing.T) {
			s, plan := gcStateFixture(t, false)
			_, progress, err := s.selectedGCPlan(plan.OperationID)
			if err != nil {
				t.Fatal("selected GC plan", err)
			}
			progress.Ordinal++
			progress.Targets[0].Consumed = 1
			s = gcTestSelectState(t, s, plan, progress, contract.GCReserve, true)
			progress.Ordinal++
			progress.Targets[0].Disposition = contract.GCTargetUnknown
			s = gcTestSelectState(t, s, plan, progress, contract.GCRecordProgress, true)
			if pending {
				s = gcTestSelectState(t, s, plan, progress, contract.GCClose, false)
			}
			beforePlan, beforeProgress, err := s.selectedGCPlan(plan.OperationID)
			if err != nil || !reflect.DeepEqual(beforePlan, plan) || beforeProgress.Targets[0].Consumed != 1 || beforeProgress.Targets[0].Disposition != contract.GCTargetUnknown {
				t.Fatal("GC predecessor lost its original plan or spent allowance", err)
			}
			beforePlanBytes, err := contract.EncodeGCPlan(beforePlan)
			if err != nil {
				t.Fatal(err)
			}
			active, owners := s.root.ActiveGC, s.root.GCPlans
			beforeControl := currentControlOf(s)
			successor := testtrust.NewWithIdentity(t, s.admission.store.Family, gcTestID("successor-key"), s.admission.trust, contract.NormalSigningRole)
			afterControl := beforeControl
			afterControl.AccessGeneration++
			afterControl.NormalSigning.BindingID = gcTestID("successor-signing-binding")
			afterControl.NormalSigning.KeySelector = successor.KeySelector()
			afterControl.NormalSigning.SPKI = successor.PublicKey()
			afterControl.NormalSigning.Fingerprint = contract.Hash(afterControl.NormalSigning.SPKI)
			afterControl.NormalSigning.Binding.PublicKey = afterControl.NormalSigning.Fingerprint
			afterControl.NormalSigning.Binding.Epoch++
			if bytes.Equal(afterControl.NormalSigning.SPKI, beforeControl.NormalSigning.SPKI) {
				t.Fatal("successor fixture reused the predecessor key")
			}
			deadline := time.Now().Add(time.Minute)
			if s.admission.expires.Before(deadline) {
				deadline = s.admission.expires
			}
			ctx, cancel := context.WithDeadline(t.Context(), deadline)
			defer cancel()
			request, identities, ok := s.planSuccession(ctx, afterControl, contract.SuccessionReplaceAuthority, contract.NormalSigningRole, contract.SuccessionChangeNormalSigner, gcTestID("succession-admission"), contract.SuccessionMaterialNone)
			if !ok {
				t.Fatal("signing replacement plan refused")
			}
			descriptor, err := contract.SuccessionRequestDescriptor(request)
			if err != nil {
				t.Fatal(err)
			}
			c := contract.ApplyContext{OperationClass: contract.CryptoAccessReplacementClass, AdmissionID: request.AdmissionID, SessionID: gcTestID("succession-session"), DomainID: s.admission.domain, CompatibilityID: contract.CompatibilityID(), Expiry: uint64(deadline.UnixNano()), PredecessorHEADDigest: contract.Hash(s.body), CurrentAccessRoot: s.root.CurrentAccess.AccessRoot, IntentDescriptor: descriptor}
			root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
			if err != nil {
				t.Fatal(err)
			}
			copy(c.PredecessorRootRef[:], root)
			c.OriginalConditionDigest, err = contract.CryptoConditionDigest(matchedCondition(s.token))
			if err != nil {
				t.Fatal(err)
			}
			access, _, err := s.successionAccessRequest(ctx, request, identities, c, contract.BindingTableRow{})
			if err != nil {
				t.Fatal("signing-only access context", err)
			}
			permit := &AdmittedSuccession{session: s, request: request, plan: identities, descriptor: descriptor, context: access.Context, deadline: deadline}
			store := s.store.(*observationSelectionStore)
			beforeCAS := store.sends
			authorizer := testtrust.New(t, s.admission.store.Family, s.admission.trust)
			candidate, result := s.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: authorizer, NormalSuccessor: successor})
			if candidate == nil || result.Outcome != ObservedCurrent || store.sends != beforeCAS || candidate.head.AuthKind != format.SuccessionAuth || candidate.succession == nil || candidate.succession.basis == nil {
				t.Fatal("signing replacement did not prepare its signed persistent successor", result)
			}
			if len(candidate.head.AuthorizationSignature) == 0 || successor.QualificationCalls() != 1 || successor.Calls() == 0 || authorizer.Calls() == 0 {
				t.Fatal("signing replacement lacks qualification or real signatures")
			}
			for _, object := range candidate.objects {
				key, err := format.Key(s.admission.store.Prefix, object.ref)
				if err != nil {
					t.Fatal(err)
				}
				read := store.Read(ctx, key, object.ref.Length)
				if read.Status != contract.ReadOK || !bytes.Equal(read.Body, object.body) {
					t.Fatal("replacement immutable object not persisted before selection", object.ref.Kind)
				}
			}
			basisAdmission := s.admission
			basisAdmission.current, basisAdmission.descriptor = candidate.succession.basis.clone(), nil
			admitted, result := admitPublicNormal(ctx, s.admission.domain, s.admission.store, basisAdmission.publicBasis(), s.store, s.admission.composition, s.admission.outputInterpreter)
			if result.Outcome != ObservedCurrent || admitted.admission == nil {
				t.Fatal("qualified successor basis admission refused", result)
			}
			candidate.succession.selectionAdmission = admitted.admission
			selected, result := s.selectCandidate(ctx, candidate)
			if selected == nil || result.Outcome != ObservedCurrent || store.sends != beforeCAS+1 {
				t.Fatal("signing replacement did not select one real HEAD transition", result)
			}
			cold, result := Open(ctx, admitted, store)
			if cold == nil || result.Outcome != ObservedCurrent || cold.head.Core.Revision != candidate.head.Core.Revision || !bytes.Equal(cold.admission.publicKey, successor.PublicKey()) || cold.head.Core.Epoch != beforeControl.NormalSigning.Binding.Epoch+1 {
				t.Fatal("selected successor did not cold-open with the new signing key", result)
			}
			afterPlan, afterProgress, err := cold.selectedGCPlan(plan.OperationID)
			if err != nil {
				t.Fatal("successor lost complete GC ownership", err)
			}
			afterPlanBytes, err := contract.EncodeGCPlan(afterPlan)
			if err != nil || !bytes.Equal(afterPlanBytes, beforePlanBytes) || !reflect.DeepEqual(afterPlan, beforePlan) || !contract.GCProgressEqual(afterProgress, beforeProgress) {
				t.Fatal("signing replacement changed original GC commitments or progress", err)
			}
			if afterProgress.Targets[0].Consumed != 1 || afterProgress.Targets[0].Disposition != contract.GCTargetUnknown || afterProgress.RemainingCount != 1 || cold.root.ActiveGC != active || cold.root.GCPlans != owners {
				t.Fatal("signing replacement reset GC rights or active-slot meaning")
			}
		})
	}
}
