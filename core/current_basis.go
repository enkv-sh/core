package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type recipientEnrollment struct {
	id     contract.ID
	status uint8
	name   string
}

// qualifiedCurrentBasis is delivered by the private owner admission. Its one
// succession dependency was qualified from an independent predecessor; neither
// a stored HEAD nor a parsed public descriptor can create this capability.
type qualifiedCurrentBasis struct {
	issued     bool
	control    []byte
	selection  []byte
	enrollment []recipientEnrollment
}

func (b *qualifiedCurrentBasis) clone() *qualifiedCurrentBasis {
	if b == nil {
		return nil
	}
	n := *b
	n.control, n.selection = bytes.Clone(b.control), bytes.Clone(b.selection)
	n.enrollment = slices.Clone(b.enrollment)

	return &n
}

func signingBindingEqual(a, b contract.PublicSigningBinding) bool {
	x, err := contract.EncodePublicSigningBinding(a)
	if err != nil {
		return false
	}
	y, err := contract.EncodePublicSigningBinding(b)
	return err == nil && bytes.Equal(x, y)
}

// Access progress may advance without replacing the independent public basis.
// The remaining complete control, including the authority KEK, stays exact.
// CurrentControlMatches compares already-validated public controls. It does not
// authenticate either control or issue admission. A new access incarnation is
// permitted; generation cannot decrease within the same incarnation. All other
// control fields must remain exact.
func CurrentControlMatches(actual, expected contract.ControlCore) bool {
	if actual.AccessIncarnationID == expected.AccessIncarnationID && actual.AccessGeneration < expected.AccessGeneration {
		return false
	}
	expected.AccessIncarnationID = actual.AccessIncarnationID
	expected.AccessGeneration = actual.AccessGeneration
	return controlEqual(actual, expected)
}

func kmsBindingEqual(a, b contract.KMSBinding) bool {
	x, err := contract.EncodeKMSBinding(a)
	if err != nil {
		return false
	}
	y, err := contract.EncodeKMSBinding(b)
	return err == nil && bytes.Equal(x, y)
}

func controlEqual(a, b contract.ControlCore) bool {
	x, err := contract.EncodeControlCore(a)
	if err != nil {
		return false
	}
	y, err := contract.EncodeControlCore(b)
	return err == nil && bytes.Equal(x, y)
}

func (a openAdmission) currentControl() (contract.ControlCore, bool) {
	var control contract.ControlCore
	if a.observation != nil {
		if a.current != nil || len(a.descriptor) != 0 || a.observation.observation == nil {
			return control, false
		}
		control = a.observation.control
	} else if a.current == nil {
		d, ok := a.domainBasis()
		if !ok {
			return control, false
		}
		control.CurrentControl = d.CurrentControl()
		for _, row := range d.Recipients {
			if row.RecipientID == d.AuthorityRecipientID && row.CurrentBinding != nil {
				control.AuthorityKMSBinding = *row.CurrentBinding
			}
		}
	} else {
		if len(a.descriptor) != 0 || !a.current.issued {
			return control, false
		}
		var err error
		control, err = contract.DecodeControlCore(a.current.control)
		if err != nil {
			return contract.ControlCore{}, false
		}
		h, err := format.DecodeHead(a.current.selection)
		if err != nil || h.AuthKind != format.SuccessionAuth || h.Succession == nil {
			return contract.ControlCore{}, false
		}
		digest, err := contract.ControlCoreDigest(control)
		if err != nil || digest != h.Succession.Subject.AfterControlDigest || !currentSigningProofs(h, control) || !successionProofValid(h) || !successorEvidenceValid(h, control) {
			return contract.ControlCore{}, false
		}
		if h.Core.Domain != a.domain || h.Core.Store != a.store.Identity || h.Core.Coordinate != a.store.Coordinate || h.Core.NonBody != a.store.NonBody || h.Core.Interpretation != a.interpretation || h.Core.Trust != a.trust || h.Core.Epoch != a.epoch {
			return contract.ControlCore{}, false
		}
	}
	if control.DomainID != a.domain || control.Provider != a.store.Family || control.StoreID != a.store.Identity || control.CoordinateID != a.store.Coordinate || control.NonBodyID != a.store.NonBody || control.AuthorityRecipientID != a.recipient || control.TrustInterpretationID != contract.TrustInterpretationID() || control.CompatibilityID != contract.CompatibilityID() || control.CryptoSupportID != contract.CryptoSupportID() || control.NormalSigning.Binding != binding(a) || !bytes.Equal(control.NormalSigning.SPKI, a.publicKey) {
		return contract.ControlCore{}, false
	}
	_, err := contract.ControlCoreLength(control)
	return control, err == nil
}

func (s *StateSession) selectedControl() (contract.ControlCore, bool) {
	if s == nil {
		return contract.ControlCore{}, false
	}
	return selectedControlFrom(s.root, &s.recipients, s.admission.recipient)
}

func currentSigningProofs(h format.Head, control contract.ControlCore) bool {
	key, ok := publicKey(control.NormalSigning.SPKI)
	q, err := contract.NewBindingRequest(control.NormalSigning.Binding)
	if !ok || err != nil || !verify(key, q, h.K1) {
		return false
	}
	if control.Recovery == nil {
		return len(h.K3) == 0
	}
	key, ok = publicKey(control.Recovery.Signing.SPKI)
	q, err = contract.NewK3BasisRequest(control.Recovery.Signing)
	return ok && err == nil && verify(key, q, h.K3)
}

func successionProofValid(h format.Head) bool {
	if h.AuthKind != format.SuccessionAuth || h.Succession == nil {
		return false
	}
	p := h.Succession
	body, err := format.EncodeHeadCore(h.Core)
	if err != nil || p.Subject.HeadCoreDigest != contract.Hash(body) || p.Subject.HeadCoreLength != uint32(len(body)) {
		return false
	}
	condition, err := format.EncodeConditionalPlan(conditional(h.Core, body))
	if err != nil || p.Subject.ConditionalPlanDigest != contract.Hash(condition) || p.Subject.ApprovalRole != p.Authorizer.Role {
		return false
	}
	key, ok := publicKey(p.Authorizer.SPKI)
	if !ok {
		return false
	}
	q, err := contract.NewK2SuccessionRequest(p.Subject)
	if p.Subject.ApprovalRole == contract.RecoverySigningRole {
		q, err = contract.NewK3SuccessionRequest(p.Subject)
	}
	return err == nil && verify(key, q, h.AuthorizationSignature)
}

func successorEvidenceValid(h format.Head, after contract.ControlCore) bool {
	if h.Succession == nil {
		return false
	}
	subject := h.Succession.Subject
	digest, err := contract.SuccessorEvidenceDigest(h.Succession.Evidence)
	if err != nil || digest != subject.SuccessorEvidenceDigest || len(h.Succession.Evidence) != int(subject.SuccessorEvidenceCount) {
		return false
	}
	for _, row := range h.Succession.Evidence {
		if row.EvidenceKind == contract.SuccessorSignerEvidence {
			signer := after.NormalSigning
			if row.TargetRole == contract.SuccessorRecoverySigner {
				if after.Recovery == nil {
					return false
				}
				signer = after.Recovery.Signing
			}
			digest, err := contract.SigningBindingDigest(signer)
			if err != nil || digest != row.Trust.SigningBindingDigest {
				return false
			}
			q, err := contract.NewSuccessorSignerProbeRequest(contract.SuccessorProbeCore{Schema: 1, EvidenceKind: contract.SuccessorSignerEvidence, TargetRole: row.TargetRole, DomainID: h.Core.Domain, CoordinateID: h.Core.Coordinate, AdmissionID: subject.AdmissionID, PredecessorFullHEADDigest: h.Core.PreviousDigest, RequestCoreDigest: subject.RequestCoreDigest, SuccessorBindingDigest: digest, ProbeAttemptID: row.Trust.ProbeAttemptID})
			key, ok := publicKey(signer.SPKI)
			if err != nil || !ok || !verify(key, q, row.Trust.Signature) {
				return false
			}
		} else {
			binding, subjectID := after.AuthorityKMSBinding, after.AuthorityRecipientID
			if row.TargetRole == contract.SuccessorRecoveryKEK {
				if after.Recovery == nil {
					return false
				}
				binding, subjectID = after.Recovery.KMS, after.Recovery.RoleID
			}
			digest, err := contract.PublicBindingDigest(binding)
			if err != nil || row.KEK.SubjectID != subjectID || row.KEK.BindingID != binding.BindingID || row.KEK.PublicBindingDigest != digest || row.KEK.Provider != binding.Provider {
				return false
			}
		}
	}
	return true
}

// selectionAcceptanceValid authenticates each changed resulting signer over
// the final HEAD core and exact root access section. The caller must have
// already checked that the root bytes match HeadCore.Root.
func selectionAcceptanceValid(h format.Head, root format.Root) bool {
	if h.AuthKind != format.SuccessionAuth || h.Succession == nil {
		return false
	}
	core, err := format.EncodeHeadCore(h.Core)
	if err != nil {
		return false
	}
	proofs := h.Succession.Acceptances
	index := 0
	for _, evidence := range h.Succession.Evidence {
		if evidence.EvidenceKind != contract.SuccessorSignerEvidence {
			continue
		}
		if index >= len(proofs) {
			return false
		}
		proof := proofs[index]
		binding := root.CurrentAccess.Core.NormalSigning
		role := uint8(contract.NormalSigningRole)
		if evidence.TargetRole == contract.SuccessorRecoverySigner {
			if root.CurrentAccess.Core.Recovery == nil {
				return false
			}
			binding = root.CurrentAccess.Core.Recovery.Signing
			role = contract.RecoverySigningRole
		}
		digest, err := contract.SigningBindingDigest(binding)
		if err != nil || proof.Role != role || proof.BindingDigest != digest || proof.BindingDigest != evidence.Trust.SigningBindingDigest ||
			proof.Epoch != binding.Binding.Epoch {
			return false
		}
		request, err := contract.NewSelectionAcceptanceRequest(contract.SelectionAcceptance{HeadCore: core,
			CurrentAccess: root.CurrentAccess, AccessRoot: root.CurrentAccess.AccessRoot,
			Succession: h.Succession.Subject, Authorizer: h.Succession.Authorizer,
			Evidence: h.Succession.Evidence, Accepting: binding, Role: proof.Role, Epoch: proof.Epoch})
		key, ok := publicKey(binding.SPKI)
		if err != nil || !ok || !verify(key, request, proof.Signature) {
			return false
		}
		index++
	}
	return index == len(proofs)
}

func qualifyCurrentBasis(ctx context.Context, before *StateSession, candidate *Candidate,
	request contract.SuccessionRequestCore, next *StateSession) (*qualifiedCurrentBasis, error) {
	if before == nil || candidate == nil || candidate.session != before || next == nil {
		return nil, contract.ErrRecord
	}
	descriptor, err := contract.SuccessionRequestDescriptor(request)
	if err != nil || !candidate.successionBasisReady(before, descriptor) || !before.admission.valid(before.store) {
		return nil, contract.ErrRecord
	}
	control, ok := before.selectedControl()
	if !ok || !controlEqual(control, request.BeforeControl) || request.PredecessorHeadRevisionID != before.head.Core.Revision || request.PredecessorFullHEADDigest != contract.Hash(before.body) || request.Token != before.token || request.BeforeAccessRoot != before.root.CurrentAccess.AccessRoot || !before.successionActorMatches(request) {
		return nil, contract.ErrRecord
	}
	after := request.ProposedAfterControl
	if control.NormalSigning.Binding.Trust != after.NormalSigning.Binding.Trust || control.Recovery != nil && control.Recovery.Signing.Binding.Trust != after.Recovery.Signing.Binding.Trust {
		return nil, contract.ErrRecord
	}
	actualControl, actual := next.selectedControl()
	if !actual || !controlEqual(actualControl, after) || !successionRegistryPreserved(before, next, after) {
		return nil, contract.ErrRecord
	}
	if _, err := next.validateRelationsAgainst(ctx, after, signerOnlyRecovery(request)); err != nil {
		return nil, err
	}
	nextRoot, err := format.EncodeRoot(next.root)
	if err != nil {
		return nil, contract.ErrRecord
	}
	h, err := format.DecodeHead(candidate.body)
	if err != nil || h.AuthKind != format.SuccessionAuth || h.Succession == nil || h.Core != candidate.head.Core || h.Core.PreviousRevision != request.PredecessorHeadRevisionID || h.Core.PreviousDigest != request.PredecessorFullHEADDigest || h.Core.PreviousToken != request.Token || h.Core.Revision != request.IdentityPlan.Revision || h.Core.Root.Object != request.IdentityPlan.Snapshot || h.Core.Domain != request.DomainID || h.Core.Store != request.StoreID || h.Core.Coordinate != request.CoordinateID || h.Core.NonBody != request.NonBodyID || h.Core.Trust != after.NormalSigning.Binding.Trust || h.Core.Epoch != after.NormalSigning.Binding.Epoch || h.Core.Interpretation != after.NormalSigning.Binding.Interpretation {
		return nil, contract.ErrRecord
	}
	p := h.Succession
	authorizer := control.NormalSigning
	if request.ApprovalRole == contract.RecoverySigningRole {
		if control.Recovery == nil {
			return nil, contract.ErrRecord
		}
		authorizer = control.Recovery.Signing
	}
	identity, err := contract.IdentityPlanDescriptor(request.IdentityPlan)
	if err != nil || p.Subject.RequestIdentityDigest != candidate.requestIdentity || p.Subject.MaterialSourceRole != request.MaterialSourceRole || p.Subject.OperationKind != request.OperationKind || p.Subject.ChangeMask != request.ChangeMask || p.Subject.ApprovalRole != request.ApprovalRole || p.Subject.OperationID != request.OperationID || p.Subject.AdmissionID != request.AdmissionID || p.Subject.RequestCoreDigest != descriptor.Digest || p.Subject.IdentityPlanDigest != identity.Digest || uint64(p.Subject.IdentityPlanLength) != identity.Length || p.Subject.BeforeAccessRoot != request.BeforeAccessRoot || !signingBindingEqual(p.Authorizer, authorizer) {
		return nil, contract.ErrRecord
	}
	beforeDigest, err := contract.ControlCoreDigest(control)
	if err != nil || p.Subject.BeforeControlDigest != beforeDigest {
		return nil, contract.ErrRecord
	}
	afterDigest, err := contract.ControlCoreDigest(after)
	if err != nil || p.Subject.AfterControlDigest != afterDigest {
		return nil, contract.ErrRecord
	}
	plan, err := contract.SuccessionReplacementPlanDescriptor(request.ReplacementPlan)
	if err != nil || p.Subject.ReplacementPlanDigest != plan.Digest || uint32(p.Subject.ReplacementCount) != plan.Count || !currentSigningProofs(h, after) || !successionProofValid(h) || !successorEvidenceValid(h, after) || !selectionAcceptanceValid(h, next.root) {
		return nil, contract.ErrRecord
	}
	rootFound := false
	for _, object := range candidate.objects {
		if object.ref != h.Core.Root {
			continue
		}
		if !bytes.Equal(object.body, nextRoot) || format.CheckReference(object.ref, object.body) != nil || next.root.Transition != request.IdentityPlan.Transition || next.root.CurrentAccess.AccessRoot != p.Subject.AfterAccessRoot {
			return nil, contract.ErrRecord
		}
		rootFound = true
	}
	if !rootFound {
		return nil, contract.ErrRecord
	}
	encoded, err := contract.EncodeControlCore(after)
	if err != nil {
		return nil, contract.ErrRecord
	}
	enrollment := make([]recipientEnrollment, 0, next.root.RecipientCount)
	for _, row := range next.registry() {
		enrollment = append(enrollment, recipientEnrollment{id: row.RecipientID, status: row.Status, name: row.DisplayName})
	}
	b := &qualifiedCurrentBasis{issued: true, control: encoded, selection: bytes.Clone(candidate.body), enrollment: enrollment}
	return b.clone(), nil
}

func (s *StateSession) validSuccessionSelection() bool {
	if !s.admission.successionSelected(s.head) {
		return false
	}
	control, ok := s.selectedControl()
	return ok && intrinsicSuccessionSelection(s.head, s.root, control)
}

// Ordinary admission retains its independently qualified predecessor pin.
// The complete-loss reader cannot create or infer this private basis.
func qualifiedPredecessorSelected(current *qualifiedCurrentBasis, head format.Head) bool {
	if current == nil || !current.issued || head.Succession == nil {
		return false
	}
	return savedSuccessionSelected(current.selection, head)
}

func savedSuccessionSelected(selection []byte, head format.Head) bool {
	if head.AuthKind != format.SuccessionAuth || head.Succession == nil {
		return false
	}
	pinned, err := format.DecodeHead(selection)
	return err == nil && pinned.Succession != nil && pinned.Core == head.Core &&
		pinned.Succession.Subject == head.Succession.Subject &&
		signingBindingEqual(pinned.Succession.Authorizer, head.Succession.Authorizer)
}

// These relations bind the selected successor without an ordinary predecessor
// admission. The caller must first authenticate the complete HEAD and root.
func intrinsicSuccessionSelection(head format.Head, root format.Root, control contract.ControlCore) bool {
	if head.AuthKind != format.SuccessionAuth || head.Succession == nil {
		return false
	}
	digest, err := contract.ControlCoreDigest(control)
	return err == nil && digest == head.Succession.Subject.AfterControlDigest &&
		root.CurrentAccess.AccessRoot == head.Succession.Subject.AfterAccessRoot &&
		successorEvidenceValid(head, control) && selectionAcceptanceValid(head, root)
}

func (a openAdmission) successionSelected(head format.Head) bool {
	if a.observation != nil {
		return a.observation.successionSelected(head)
	}
	return qualifiedPredecessorSelected(a.current, head)
}

func (a openAdmission) publicBasis() PublicBasis {
	if a.observation != nil && a.observation.observation != nil {
		return *a.observation.observation
	}
	if a.current == nil {
		return PublicBasis{Descriptor: a.descriptor}
	}
	p := PublicBasis{Control: a.current.control, Selection: a.current.selection, Enrollment: make([]PublicEnrollment, len(a.current.enrollment))}
	for i, row := range a.current.enrollment {
		p.Enrollment[i] = PublicEnrollment{RecipientID: row.id, Status: row.status, DisplayName: row.name}
	}
	return p
}

func successionRegistryPreserved(before, after *StateSession, control contract.ControlCore) bool {
	current, next := before.registry(), after.registry()
	if len(current) != len(next) {
		return false
	}
	for i, row := range current {
		proposed := next[i]
		if row.RecipientID != proposed.RecipientID || row.Status != proposed.Status || row.DisplayName != proposed.DisplayName || row.CurrentBinding == nil || proposed.CurrentBinding == nil {
			return false
		}
		binding := *row.CurrentBinding
		if row.RecipientID == control.AuthorityRecipientID {
			binding = control.AuthorityKMSBinding
		}
		if !kmsBindingEqual(binding, *proposed.CurrentBinding) {
			return false
		}
	}
	return true
}
