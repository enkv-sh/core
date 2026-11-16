package crypto

import (
	"bytes"
	"context"
	"time"

	"enkv.sh/core/contract"
)

type successionAccess struct {
	probe                     contract.SuccessorKEKProbeCore
	publicRoute, privateRoute contract.ID
}

func sameAccessBinding(a, b contract.BindingTableRow) bool {
	return a.SubjectKind == b.SubjectKind && a.SubjectID == b.SubjectID && sameApplyBinding(a.Binding, b.Binding)
}

// admitSuccessionAccess receives independently admitted predecessor control,
// one surviving current source and the exact successor's private probe route.
func (r *Runtime) admitSuccessionAccess(q contract.CryptoAccessReplaceRequest, request contract.SuccessionRequestCore, admittedBefore contract.ControlCore, source contract.BindingTableRow, probe contract.SuccessorKEKProbeCore, rows []contract.CompactRow, sourceRoute, publicRoute, privateRoute contract.ID, deadline time.Time) error {
	_, err := r.admitSuccessionAccessOwned(q, request, admittedBefore, source, probe, rows, sourceRoute, publicRoute, privateRoute, deadline)
	return err
}

func (r *Runtime) admitSuccessionAccessOwned(q contract.CryptoAccessReplaceRequest, request contract.SuccessionRequestCore, admittedBefore contract.ControlCore, source contract.BindingTableRow, probe contract.SuccessorKEKProbeCore, rows []contract.CompactRow, sourceRoute, publicRoute, privateRoute contract.ID, deadline time.Time) (*accessAdmission, error) {
	if r == nil || !validDeadline(deadline) || q.Context.Expiry != uint64(deadline.UnixNano()) || request.Token.Family != r.family || q.Context.OperationClass != contract.CryptoAccessReplacementClass {
		return nil, ErrAdmission
	}
	descriptor, err := contract.SuccessionRequestDescriptor(request)
	if err != nil || descriptor != q.Context.IntentDescriptor || request.DomainID != q.Context.DomainID || request.CompatibilityID != q.Context.CompatibilityID || request.CompatibilityID != contract.CompatibilityID() || request.CryptoSupportID != contract.CryptoSupportID() || request.AdmissionID != q.Context.AdmissionID || request.PredecessorFullHEADDigest != q.Context.PredecessorHEADDigest || request.BeforeAccessRoot != q.Context.CurrentAccessRoot {
		return nil, ErrAdmission
	}
	condition, err := contract.MatchHeadCondition(request.Token)
	if err != nil {
		return nil, ErrAdmission
	}
	conditionDigest, err := contract.CryptoConditionDigest(condition)
	if err != nil || conditionDigest != q.Context.OriginalConditionDigest {
		return nil, ErrAdmission
	}
	beforeBytes, err := contract.EncodeControlCore(admittedBefore)
	if err != nil {
		return nil, ErrAdmission
	}
	requestBefore, err := contract.EncodeControlCore(request.BeforeControl)
	if err != nil || !bytes.Equal(beforeBytes, requestBefore) {
		return nil, ErrAdmission
	}
	authority := contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: admittedBefore.AuthorityRecipientID, Binding: admittedBefore.AuthorityKMSBinding}
	var recovery contract.BindingTableRow
	if admittedBefore.Recovery != nil {
		recovery = contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: admittedBefore.Recovery.RoleID, Binding: admittedBefore.Recovery.KMS}
	}
	switch request.MaterialSourceRole {
	case contract.SuccessionMaterialAuthority:
		if !sameAccessBinding(source, authority) {
			return nil, ErrAdmission
		}
	case contract.SuccessionMaterialRecovery:
		if admittedBefore.Recovery == nil || !sameAccessBinding(source, recovery) {
			return nil, ErrAdmission
		}
	default:
		return nil, ErrAdmission
	}
	if !sameAccessBinding(source, authority) && (admittedBefore.Recovery == nil || !sameAccessBinding(source, recovery)) {
		return nil, ErrAdmission
	}
	var before, successor contract.BindingTableRow
	for _, row := range request.ReplacementPlan.Rows {
		var target contract.BindingTableRow
		switch row.TargetRole {
		case contract.SuccessorAuthorityKEK:
			target = authority
		case contract.SuccessorRecoveryKEK:
			target = recovery
		default:
			continue
		}
		if !before.SubjectID.IsZero() || target.SubjectID.IsZero() || !sameApplyBinding(row.BeforeKMS, target.Binding) {
			return nil, ErrAdmission
		}
		before = target
		successor = contract.BindingTableRow{SubjectKind: target.SubjectKind, SubjectID: target.SubjectID, Binding: row.AfterKMS}
	}
	if before.SubjectID.IsZero() {
		return nil, ErrAdmission
	}
	body, err := contract.EncodeCryptoAccessReplaceRequest(q)
	if err != nil {
		return nil, ErrAdmission
	}
	owned, err := contract.DecodeCryptoAccessReplaceRequest(body)
	if err != nil || len(q.Replacements) != 1 {
		return nil, ErrAdmission
	}
	replacement := q.Replacements[0]
	beforeDigest, err := contract.PublicBindingDigest(before.Binding)
	if err != nil || replacement.SubjectKind != before.SubjectKind || replacement.SubjectID != before.SubjectID || replacement.BeforeBindingDigest != beforeDigest || !sameAccessBinding(q.BindingTable[replacement.SuccessorBindingIndex], successor) {
		return nil, ErrAdmission
	}
	sourceIndex, beforeIndex, authorityCount, recoveryCount := -1, -1, 0, 0
	for i, row := range q.BindingTable {
		if row.Binding.Provider != r.family {
			return nil, ErrAdmission
		}
		for _, prior := range q.BindingTable[:i] {
			if prior.Binding.BindingID == row.Binding.BindingID {
				return nil, ErrAdmission
			}
			if prior.SubjectKind == row.SubjectKind && prior.SubjectID == row.SubjectID && (row.SubjectKind != before.SubjectKind || row.SubjectID != before.SubjectID) {
				return nil, ErrAdmission
			}
		}
		if i == int(replacement.SuccessorBindingIndex) {
			continue
		}
		if sameAccessBinding(row, source) {
			sourceIndex = i
		}
		if sameAccessBinding(row, before) {
			beforeIndex = i
		}
		if row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == authority.SubjectID {
			if !sameAccessBinding(row, authority) {
				return nil, ErrAdmission
			}
			authorityCount++
		}
		if row.SubjectKind == contract.RecoveryWrapSubject {
			if admittedBefore.Recovery == nil || !sameAccessBinding(row, recovery) {
				return nil, ErrAdmission
			}
			recoveryCount++
		}
	}
	if sourceIndex < 0 || beforeIndex < 0 || authorityCount != 1 || admittedBefore.Recovery == nil && recoveryCount != 0 || admittedBefore.Recovery != nil && recoveryCount != 1 {
		return nil, ErrAdmission
	}
	successorDigest, err := contract.PublicBindingDigest(successor.Binding)
	if err != nil || probe.Context != q.Context || probe.SubjectKind != successor.SubjectKind || probe.SubjectID != successor.SubjectID || probe.SuccessorBindingDigest != successorDigest {
		return nil, ErrAdmission
	}
	if _, err := contract.EncodeSuccessorKEKProbeCore(probe); err != nil {
		return nil, ErrAdmission
	}
	plan, err := contract.AccessReplacementPlanDescriptor(q.Plan())
	if err != nil {
		return nil, ErrAdmission
	}
	projection, err := contract.NewAccessProjection(contract.AccessProjectionMetadata{DomainID: q.Context.DomainID, BeforeAccessRoot: q.Context.CurrentAccessRoot, RequestCoreDigest: descriptor.Digest}, plan, q.ExpectedCoverageDescriptor.Count)
	if err != nil {
		return nil, ErrAdmission
	}
	identity, err := contract.IdentityPlanDescriptor(request.IdentityPlan)
	if err != nil {
		return nil, ErrAdmission
	}
	a := &accessAdmission{request: owned, requestDigest: contract.Hash(body), requestLength: len(body), sourceIndex: uint16(sourceIndex), beforeIndex: uint16(beforeIndex), authority: admittedBefore.AuthorityRecipientID, routeID: sourceRoute, stage: contract.CryptoAccessReplace, plan: plan, projection: projection, identity: contract.DigestLength{Digest: identity.Digest, Length: identity.Length}, succession: &successionAccess{probe: probe, publicRoute: publicRoute, privateRoute: privateRoute}}
	if !a.admitCoverage(rows) {
		return nil, ErrAdmission
	}
	if err := r.installAccess(a, deadline); err != nil {
		return nil, err
	}
	return a, nil
}

func probeSuccessorKEK(ctx context.Context, probe contract.SuccessorKEKProbeCore, row contract.BindingTableRow, route KeyAccess) (contract.CryptoResultCode, KeyUses) {
	material, err := contract.SuccessorKEKProbeMaterialContextDigest(probe)
	if err != nil {
		return contract.CryptoInvalidInput, KeyUses{}
	}
	core := contract.WrapCore{Schema: contract.CanonicalSchema, Profile: 2, DomainID: probe.Context.DomainID, CompatibilityID: probe.Context.CompatibilityID, CryptoSupportID: contract.CryptoSupportID(), MaterialKind: contract.ProofMaterialKind, MaterialID: probe.ProbeID, MaterialContextDigest: material, SubjectKind: row.SubjectKind, SubjectID: row.SubjectID, BindingID: row.Binding.BindingID, BindingSerial: row.Binding.BindingSerial, PublicBindingDigest: probe.SuccessorBindingDigest, Provider: row.Binding.Provider, WrapProfile: 2, PacketKind: 4, PacketLength: contract.SingleKeyMaterialPacketLength}
	return probeKEK(ctx, core, row.Binding, route)
}
