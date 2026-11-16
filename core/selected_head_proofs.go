package core

import (
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// selectedHeadProofs checks the selected proof family with explicit selected
// control. A Genesis caller must supply a validated descriptor core; its
// selected artifact relation remains a separate closure check. This check
// does not admit an ordinary caller.
func selectedHeadProofs(head format.Head, control contract.ControlCore, genesis *contract.GenesisDescriptorCore) bool {
	if !currentSigningProofs(head, control) {
		return false
	}
	return selectedHeadAuthorizationProofs(head, control, genesis)
}

func ordinaryHeadRequest(head format.Head) (contract.SignRequest, error) {
	switch head.AuthKind {
	case format.LifecycleAuth:
		return contract.NewLifecycleRequest(head.Subject)
	case format.GeneratorAuth:
		if head.Generator != nil {
			return contract.NewGeneratorRequest(*head.Generator)
		}
	case format.AdministrativeAuth:
		if head.EndWork != nil {
			return contract.NewEndWorkRequest(*head.EndWork)
		}
	case format.OutputReserveAuth:
		if head.OutputReserve != nil {
			return contract.NewOutputReserveRequest(*head.OutputReserve)
		}
	case format.OutputCloseAuth:
		if head.OutputClose != nil {
			return contract.NewOutputCloseRequest(*head.OutputClose)
		}
	}
	return contract.SignRequest{}, contract.ErrSubject
}

func selectedHeadAuthorizationProofs(head format.Head, control contract.ControlCore, genesis *contract.GenesisDescriptorCore) bool {
	if head.AuthKind == format.SuccessionAuth {
		return successionProofValid(head)
	}
	normalKey, ok := publicKey(control.NormalSigning.SPKI)
	if !ok {
		return false
	}
	if head.AuthKind == format.GenesisAuth {
		if genesis == nil || head.Genesis == nil || genesis.DomainID != head.Core.Domain {
			return false
		}
		g := head.Genesis
		k2, err := contract.NewGenesisRequest(g.Subject)
		if err != nil || !verify(normalKey, k2, head.AuthorizationSignature) {
			return false
		}
		if genesis.Recovery != nil {
			recoveryKey, ok := publicKey(genesis.Recovery.Signing.SPKI)
			if !ok {
				return false
			}
			challenge, err := genesisChallenge(*genesis, g.Request, g.Plan)
			if err != nil {
				return false
			}
			q, err := contract.NewK3InitChallengeRequest(challenge)
			if err != nil || !verify(recoveryKey, q, g.K3Challenge) {
				return false
			}
		}
		return true
	}
	if head.AuthKind == format.GCAuth {
		if head.GC == nil {
			return false
		}
		request, err := contract.NewGCRequest(*head.GC)
		return err == nil && verify(normalKey, request, head.AuthorizationSignature)
	}
	if head.AuthKind == format.LifecycleAuth && head.Subject.Request != requestCommitment(head.Core, head.Subject) {
		return false
	}
	request, err := ordinaryHeadRequest(head)
	return err == nil && verify(normalKey, request, head.AuthorizationSignature)
}
