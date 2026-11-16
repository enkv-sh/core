package core

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func configurationRecoveryReplace(t testing.TB, ctx context.Context, env *fixtureEnvironment, fixture *environmentFixture, history installedarchive.RecoveryReplacement, resources installedarchive.RecoveryResources) {
	t.Helper()
	normal := env.Trust.(*fixtureTrust).Signer
	var recovery *testtrust.Signer
	if env.Recovery != nil {
		recovery = env.Recovery.(*testtrust.Signer)
	}
	normalIndex, recoveryIndex := 0, 0
	for _, step := range history.Steps {
		before := fixture.session
		encoded, err := contract.EncodeControlCore(currentControlOf(before))
		if err != nil {
			t.Fatal(err)
		}
		after, err := contract.DecodeControlCore(encoded)
		if err != nil {
			t.Fatal(err)
		}
		after.AccessGeneration++
		signers := SuccessionSigners{Authorizer: normal}
		if step.Approval == 2 {
			if recovery == nil {
				t.Fatal("recovery authorizer disabled")
			}
			signers.Authorizer = recovery
		}
		var normalNext, recoveryNext *testtrust.Signer
		chosen := func(current *testtrust.Signer, binding contract.PublicSigningBinding, resource installedarchive.SigningResource) (*testtrust.Signer, contract.PublicSigningBinding) {
			_, after := current.Successor(t, binding)
			next := testtrust.NewWithIdentity(t, binding.Provider, resource.Material, current.Identity(), binding.Role)
			if next.KeySelector() != resource.Selector || !bytes.Equal(next.PublicKey(), resource.PublicKey) {
				t.Fatal("independently selected successor changed")
			}
			after.SPKI, after.KeySelector = next.PublicKey(), next.KeySelector()
			after.Fingerprint = contract.Hash(after.SPKI)
			after.Binding.PublicKey = after.Fingerprint
			return next, after
		}
		if step.Mask&1 != 0 {
			normalNext, after.NormalSigning = chosen(normal, after.NormalSigning, resources.NormalSuccessors[normalIndex])
			normalIndex++
			signers.NormalSuccessor = normalNext
		}
		if step.Mask&4 != 0 {
			if recovery == nil {
				t.Fatal("recovery successor disabled")
			}
			recoveryNext, after.Recovery.Signing = chosen(recovery, after.Recovery.Signing, resources.RecoverySuccessors[recoveryIndex])
			recoveryIndex++
			signers.RecoverySuccessor = recoveryNext
		}
		var source contract.BindingTableRow
		var target contract.ID
		if step.Mask&(2|8) != 0 {
			source = contract.BindingTableRow{SubjectKind: 1, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}
			if step.Approval == 2 {
				source = contract.BindingTableRow{SubjectKind: 2, SubjectID: after.Recovery.RoleID, Binding: after.Recovery.KMS}
			}
			if step.Mask&2 != 0 {
				target = after.AuthorityRecipientID
				after.AuthorityKMSBinding = env.Custody.KEKSuccessor(t, contract.SuccessorAuthorityKEK)
			} else {
				target = after.Recovery.RoleID
				after.Recovery.KMS = env.Custody.KEKSuccessor(t, contract.SuccessorRecoveryKEK)
			}
			if source.SubjectID != target {
				env.Custody.LoseRecipientPredecessor(target)
			}
		}
		permit := admitAuthorityReplacement(t, before, env.Custody, after, step.Operation, step.Approval, step.Mask, source)
		candidate, result := before.PrepareSuccession(ctx, permit, signers)
		if candidate == nil {
			t.Fatal("complete-loss predecessor replacement refused", result)
		}
		admission := deliverSuccessionBasis(t, candidate)
		if result = before.Select(ctx, candidate); result.Outcome != ObservedCurrent {
			t.Fatal("replacement selection refused", result)
		}
		env.Custody.RetireAccess()
		if !target.IsZero() {
			if err := env.Custody.ActivateSuccessor(target); err != nil {
				t.Fatal(err)
			}
		}
		if normalNext != nil {
			normal.SetUnavailable(true)
			normal = normalNext
			env.Trust = &fixtureTrust{Signer: normal}
		}
		if recoveryNext != nil {
			recovery.SetUnavailable(true)
			recovery = recoveryNext
			env.Recovery = recovery
		}
		selected, result := Open(ctx, admission, env.Store)
		if selected == nil || result.Outcome != ObservedCurrent {
			t.Fatal("replacement reopen refused", result)
		}
		for _, named := range before.root.Names {
			old, current := before.valueEntry(named.Slot), selected.valueEntry(named.Slot)
			if current == nil || old.Name != current.Name || old.Incarnation != current.Incarnation || old.Generated != current.Generated || !bytes.Equal(old.ValueBytes, current.ValueBytes) {
				t.Fatal("replacement changed selected value or generated settings")
			}
		}
		fixture.admission, fixture.session = admission, selected
	}
}
