package format

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"enkv.sh/core/contract"
)

const successionGraphLimit = 512 << 10

// SuccessionIdentityPlan contains the typed, proof-free candidate. The caller
// admits its predecessor and validates all referenced child bodies first.
// Snapshot contains the receipt page's typed hole-projection digest, never a
// zero reference digest. AccessPlan validates the access descriptors; its bytes
// enter the graph only through those existing descriptors.
type SuccessionIdentityPlan struct {
	Request                          contract.SuccessionRequestCore
	Snapshot                         Root
	Head                             HeadPlan
	Conditional                      ConditionalRequestPlan
	Authorization                    contract.SuccessionAuthorizationPlan
	Evidence                         []contract.SuccessorEvidencePlanRow
	AccessPlan                       contract.AccessReplacementPlanCore
	Coverage, Unchanged, AfterAccess contract.DescriptorVector
}

type SuccessionIdentity struct {
	RequestIdentityDigest                ID
	PhaseEntry, TransitionBinding, Graph contract.DescriptorVector
}

func DeriveSuccessionIdentity(p SuccessionIdentityPlan) (SuccessionIdentity, error) {
	parts, err := p.parts()
	if err != nil {
		return SuccessionIdentity{}, err
	}
	entry := newSuccessionIdentityHash("succession-phase-entry-v1")
	entry.blob(parts.request)
	binding := newSuccessionIdentityHash("succession-transition-binding-v1")
	binding.blob(parts.identity)
	binding.blob(parts.head)
	binding.blob(parts.conditional)
	result := SuccessionIdentity{PhaseEntry: entry.descriptor(), TransitionBinding: binding.descriptor()}
	graph := newSuccessionIdentityHash("succession-transition-graph-v1")
	graph.vector(result.PhaseEntry)
	graph.blob(parts.snapshot)
	graph.vector(result.TransitionBinding)
	graph.blob(parts.authorization)
	graph.blob(parts.evidence)
	graph.vector(p.Coverage)
	graph.vector(p.Unchanged)
	graph.vector(p.AfterAccess)
	if graph.length >= successionGraphLimit {
		return SuccessionIdentity{}, ErrFormat
	}
	result.Graph = graph.descriptor()
	var identity successionIdentityHash
	if p.Request.OperationKind == contract.SuccessionReplaceAuthority {
		identity = newSuccessionIdentityHash("authority-succession-request-identity-v2")
		identity.id(contract.Hash(parts.request))
		identity.id(result.PhaseEntry.Digest)
		identity.id(result.TransitionBinding.Digest)
		identity.id(result.Graph.Digest)
		identity.id(p.Request.IdentityPlan.Revision)
	} else {
		identity = newSuccessionIdentityHash("mutation-request-identity-v1")
		identity.id(contract.Hash(parts.request))
		identity.write([]byte{0, 0, 0, 0})
		identity.id(p.Request.IdentityPlan.Revision)
		identity.id(result.Graph.Digest)
	}
	result.RequestIdentityDigest = identity.descriptor().Digest
	return result, nil
}

type successionIdentityHash struct {
	h      hash.Hash
	length uint64
}

func newSuccessionIdentityHash(purpose string) successionIdentityHash {
	w := successionIdentityHash{h: sha256.New()}
	w.write([]byte("ENKV/CRYPTO/v2/" + purpose + "\x00"))
	return w
}
func (w *successionIdentityHash) write(b []byte) { _, _ = w.h.Write(b); w.length += uint64(len(b)) }
func (w *successionIdentityHash) id(id ID)       { w.write(id[:]) }
func (w *successionIdentityHash) blob(b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	w.write(n[:])
	w.write(b)
}
func (w *successionIdentityHash) vector(d contract.DescriptorVector) {
	w.id(d.Digest)
	var n [12]byte
	binary.BigEndian.PutUint64(n[:8], d.Length)
	binary.BigEndian.PutUint32(n[8:], d.Count)
	w.write(n[:])
}
func (w *successionIdentityHash) descriptor() contract.DescriptorVector {
	var digest ID
	w.h.Sum(digest[:0])
	return contract.DescriptorVector{Digest: digest, Length: w.length, Count: 1}
}

type successionIdentityParts struct{ request, identity, snapshot, head, conditional, authorization, evidence []byte }

func (p SuccessionIdentityPlan) parts() (successionIdentityParts, error) {
	var out successionIdentityParts
	var err error
	if out.request, err = contract.EncodeSuccessionRequestCore(p.Request); err != nil {
		return out, err
	}
	if out.snapshot, err = EncodeRoot(p.Snapshot); err != nil {
		return out, err
	}
	if out.head, err = EncodeHeadPlan(p.Head); err != nil {
		return out, err
	}
	if out.conditional, err = EncodeConditionalRequestPlan(p.Conditional); err != nil {
		return out, err
	}
	if out.authorization, err = contract.EncodeSuccessionAuthorizationPlan(p.Authorization); err != nil {
		return out, err
	}
	if out.evidence, err = contract.EncodeSuccessorEvidencePlanCore(p.Evidence); err != nil {
		return out, err
	}
	if out.identity, err = contract.EncodeIdentityPlan(p.Request.IdentityPlan); err != nil {
		return out, err
	}
	q, h, c := p.Request, HeadCore(p.Head), ConditionalPlan(p.Conditional)
	if p.Snapshot.Domain != q.DomainID || p.Snapshot.Snapshot != q.IdentityPlan.Snapshot || p.Snapshot.Transition != q.IdentityPlan.Transition ||
		h.Domain != q.DomainID || h.Revision != q.IdentityPlan.Revision || h.PreviousRevision != q.PredecessorHeadRevisionID || h.PreviousDigest != q.PredecessorFullHEADDigest || h.PreviousToken != q.Token ||
		h.Root.Object != p.Snapshot.Snapshot || h.Root.Length != uint32(len(out.snapshot)) || h.Store != q.StoreID || h.Coordinate != q.CoordinateID || h.NonBody != q.NonBodyID ||
		h.Trust != q.ProposedAfterControl.NormalSigning.Binding.Trust || h.Epoch != q.ProposedAfterControl.NormalSigning.Binding.Epoch || h.Interpretation != q.ProposedAfterControl.NormalSigning.Binding.Interpretation ||
		c.Family != q.Token.Family || c.Store != h.Store || c.Coordinate != h.Coordinate || c.NonBody != h.NonBody || c.HeadCoreLength != uint32(len(out.head)) {
		return out, ErrFormat
	}
	token, ok := c.Condition.Token()
	if !ok || token != q.Token || !p.assignedPagesMatch() {
		return out, ErrFormat
	}
	before, err := contract.EncodeControlCore(q.BeforeControl)
	if err != nil {
		return out, err
	}
	after, err := contract.EncodeControlCore(q.ProposedAfterControl)
	if err != nil {
		return out, err
	}
	snapshotControl, err := contract.EncodeControlCore(contract.ControlCore{CurrentControl: p.Snapshot.CurrentAccess.Core.CurrentControl, AuthorityKMSBinding: q.ProposedAfterControl.AuthorityKMSBinding})
	if err != nil || !bytes.Equal(after, snapshotControl) {
		return out, ErrFormat
	}
	authorizer := q.BeforeControl.NormalSigning
	if q.ApprovalRole == contract.RecoverySigningRole {
		authorizer = q.BeforeControl.Recovery.Signing
	}
	authorizerBytes, err := contract.EncodePublicSigningBinding(authorizer)
	if err != nil {
		return out, err
	}
	claimedAuthorizer, err := contract.EncodePublicSigningBinding(p.Authorization.Authorizer)
	if err != nil || !bytes.Equal(authorizerBytes, claimedAuthorizer) {
		return out, ErrFormat
	}
	replacement, err := contract.SuccessionReplacementPlanDescriptor(q.ReplacementPlan)
	if err != nil {
		return out, err
	}
	s := p.Authorization.Subject
	if s.Schema != q.Schema || s.OperationKind != q.OperationKind || s.ApprovalRole != q.ApprovalRole || s.OperationID != q.OperationID || s.AdmissionID != q.AdmissionID ||
		s.MaterialSourceRole != q.MaterialSourceRole || s.RequestCoreDigest != contract.Hash(out.request) || s.IdentityPlanDigest != contract.Hash(out.identity) || s.IdentityPlanLength != uint32(len(out.identity)) || s.HeadCoreLength != uint32(len(out.head)) ||
		s.BeforeControlDigest != contract.Hash(before) || s.AfterControlDigest != contract.Hash(after) || s.BeforeAccessRoot != q.BeforeAccessRoot || s.AfterAccessRoot != p.Snapshot.CurrentAccess.AccessRoot ||
		s.ReplacementPlanDigest != replacement.Digest || s.ReplacementCount != uint16(replacement.Count) || s.ChangeMask != q.ChangeMask ||
		s.SuccessorEvidenceDigest != contract.Hash(out.evidence) || s.SuccessorEvidenceCount != uint8(len(p.Evidence)) || s.CoverageDigest != p.Coverage.Digest || s.CoverageCount != p.Coverage.Count {
		return out, ErrFormat
	}
	if !p.evidenceMatches() || !p.accessMatches(contract.Hash(out.request)) {
		return out, ErrFormat
	}
	return out, nil
}

func (p SuccessionIdentityPlan) assignedPagesMatch() bool {
	for _, page := range p.Request.IdentityPlan.Pages {
		var ref *Ref
		switch page.Kind {
		case ValueEntryPageKind:
			ref = p.Snapshot.ValueEntryPages[page.Index]
		case RecipientKind:
			ref = p.Snapshot.Recipients[page.Index]
		case AccessKind:
			for i := range p.Snapshot.CurrentAccess.Core.AccessPageRefs {
				v := &p.Snapshot.CurrentAccess.Core.AccessPageRefs[i]
				if v.Index == page.Index {
					ref = v
					break
				}
			}
		case contract.RequiredSupportKind:
			for i := range p.Snapshot.RequiredSupport {
				v := &p.Snapshot.RequiredSupport[i]
				if v.Index == page.Index {
					ref = v
					break
				}
			}
		default:
			return false
		}
		if ref == nil || ref.Object != page.Object {
			return false
		}
	}
	if p.Request.OperationKind != contract.SuccessionReplaceAuthority {
		for _, page := range p.Request.IdentityPlan.Pages {
			if page.Kind == contract.RequiredSupportKind {
				return true
			}
		}
		return false
	}
	return true
}

func (p SuccessionIdentityPlan) evidenceMatches() bool {
	if len(p.Evidence) != len(p.Request.ReplacementPlan.Rows) {
		return false
	}
	for i, row := range p.Evidence {
		target := p.Request.ReplacementPlan.Rows[i]
		if row.TargetRole != target.TargetRole {
			return false
		}
		if row.EvidenceKind == contract.SuccessorSignerEvidence {
			digest, err := contract.SigningBindingDigest(target.AfterSigning)
			if err != nil || digest != row.Trust.SigningBindingDigest {
				return false
			}
		} else {
			digest, err := contract.PublicBindingDigest(target.AfterKMS)
			kind, subject := contract.OrdinaryWrapSubject, p.Request.BeforeControl.AuthorityRecipientID
			if row.TargetRole == contract.SuccessorRecoveryKEK {
				kind, subject = contract.RecoveryWrapSubject, p.Request.BeforeControl.Recovery.RoleID
			}
			if err != nil || row.KEK.SubjectKind != kind || row.KEK.SubjectID != subject || row.KEK.BindingID != target.AfterKMS.BindingID || row.KEK.PublicBindingDigest != digest || row.KEK.Provider != target.AfterKMS.Provider {
				return false
			}
		}
	}
	return true
}

func (p SuccessionIdentityPlan) accessMatches(request ID) bool {
	a, q := p.AccessPlan, p.Request
	if a.DomainID != q.DomainID || a.BeforeAccessRoot != q.BeforeAccessRoot || a.RequestCoreDigest != request {
		return false
	}
	d, err := contract.AccessReplacementPlanDescriptor(a)
	if err != nil {
		return false
	}
	kek := q.ChangeMask&(contract.SuccessionChangeAuthorityKEK|contract.SuccessionChangeRecoveryKEK) != 0
	if !kek {
		if len(a.BindingTable) != 0 || len(a.Replacements) != 0 || p.Coverage.Count != 0 {
			return false
		}
	} else {
		if len(a.Replacements) != 1 || p.Coverage.Count != p.Snapshot.AccessRecordCount {
			return false
		}
		kind, subject, before, after := contract.OrdinaryWrapSubject, q.BeforeControl.AuthorityRecipientID, q.BeforeControl.AuthorityKMSBinding, q.ProposedAfterControl.AuthorityKMSBinding
		if q.ChangeMask&contract.SuccessionChangeRecoveryKEK != 0 {
			kind, subject, before, after = contract.RecoveryWrapSubject, q.BeforeControl.Recovery.RoleID, q.BeforeControl.Recovery.KMS, q.ProposedAfterControl.Recovery.KMS
		}
		row := a.Replacements[0]
		beforeDigest, err := contract.PublicBindingDigest(before)
		if err != nil || row.SubjectKind != kind || row.SubjectID != subject || row.BeforeBindingDigest != beforeDigest {
			return false
		}
		target := a.BindingTable[row.SuccessorBindingIndex]
		want, err := contract.EncodeKMSBinding(after)
		if err != nil {
			return false
		}
		got, err := contract.EncodeKMSBinding(target.Binding)
		if err != nil || !bytes.Equal(want, got) {
			return false
		}
	}
	count := uint64(p.Coverage.Count)
	if count > contract.AccessMaterialLimit || p.AfterAccess.Count != p.Coverage.Count || p.Unchanged.Count != p.Coverage.Count ||
		p.Coverage.Digest.IsZero() || p.AfterAccess.Digest.IsZero() || p.Unchanged.Digest.IsZero() {
		return false
	}
	if count == 0 {
		projection, err := contract.NewAccessProjection(contract.AccessProjectionMetadata{DomainID: q.DomainID, BeforeAccessRoot: q.BeforeAccessRoot, RequestCoreDigest: request}, d, 0)
		if err != nil {
			return false
		}
		coverage, after, unchanged, err := projection.Descriptors()
		return err == nil && coverage == p.Coverage && after == p.AfterAccess && unchanged == p.Unchanged
	}
	// Nonempty digests come from the caller's full record traversal. These exact
	// scalar lengths check their available relation to the complete snapshot.
	var accessBytes uint64
	for _, ref := range p.Snapshot.CurrentAccess.Core.AccessPageRefs {
		if ref.Length < contract.AccessPageHeaderLength {
			return false
		}
		accessBytes += uint64(ref.Length) - contract.AccessPageHeaderLength
	}
	coverage, output, unchanged, err := contract.AccessProjectionLengths(uint32(count), accessBytes)
	return err == nil && p.Coverage.Length == coverage && p.Unchanged.Length == unchanged && p.AfterAccess.Length == output
}
