package core

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
)

func successionTarget(q contract.SuccessionRequestCore) (contract.BindingTableRow, contract.KMSBinding, bool) {
	if q.ChangeMask&contract.SuccessionChangeAuthorityKEK != 0 {
		return contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: q.BeforeControl.AuthorityRecipientID, Binding: q.ProposedAfterControl.AuthorityKMSBinding}, q.BeforeControl.AuthorityKMSBinding, true
	}
	if q.ChangeMask&contract.SuccessionChangeRecoveryKEK != 0 && q.BeforeControl.Recovery != nil && q.ProposedAfterControl.Recovery != nil {
		return contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: q.BeforeControl.Recovery.RoleID, Binding: q.ProposedAfterControl.Recovery.KMS}, q.BeforeControl.Recovery.KMS, true
	}
	return contract.BindingTableRow{}, contract.KMSBinding{}, false
}

func sameBindingRow(a, b contract.BindingTableRow) bool {
	if a.SubjectKind != b.SubjectKind || a.SubjectID != b.SubjectID {
		return false
	}
	x, err := contract.EncodeKMSBinding(a.Binding)
	if err != nil {
		return false
	}
	y, err := contract.EncodeKMSBinding(b.Binding)
	return err == nil && bytes.Equal(x, y)
}

func (s *StateSession) successionAccessRequest(ctx context.Context, request contract.SuccessionRequestCore, p transitionPlan, c contract.ApplyContext, source contract.BindingTableRow) (contract.CryptoAccessReplaceRequest, []contract.CompactRow, error) {
	var q contract.CryptoAccessReplaceRequest
	if s != nil && s.installedReplacement != nil && request.ChangeMask&(contract.SuccessionChangeAuthorityKEK|contract.SuccessionChangeRecoveryKEK) != 0 && !sameBindingRow(source, s.installedReplacement.source) {
		return q, nil, contract.ErrRecord
	}
	if err := s.successionRequestValid(ctx, request, p); err != nil {
		return q, nil, err
	}
	descriptor, err := contract.SuccessionRequestDescriptor(request)
	if err != nil {
		return q, nil, err
	}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil {
		return q, nil, err
	}
	condition, err := contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		return q, nil, err
	}
	if c.OperationClass != contract.CryptoAccessReplacementClass || c.AdmissionID != request.AdmissionID || c.DomainID != request.DomainID ||
		c.CompatibilityID != request.CompatibilityID || c.PredecessorHEADDigest != request.PredecessorFullHEADDigest || c.OriginalConditionDigest != condition || !bytes.Equal(c.PredecessorRootRef[:], root) || c.CurrentAccessRoot != request.BeforeAccessRoot {
		return q, nil, contract.ErrRecord
	}
	c.IntentDescriptor = descriptor
	q.Context = c
	target, before, changed := successionTarget(request)
	if !changed {
		return q, nil, nil
	}
	eligible := sameBindingRow(source, contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: request.BeforeControl.AuthorityRecipientID, Binding: request.BeforeControl.AuthorityKMSBinding})
	if r := request.BeforeControl.Recovery; r != nil {
		eligible = eligible || sameBindingRow(source, contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: r.RoleID, Binding: r.KMS})
	}
	if !eligible {
		return contract.CryptoAccessReplaceRequest{}, nil, contract.ErrRecord
	}
	q.BindingTable, err = s.currentBindings()
	if err != nil {
		return contract.CryptoAccessReplaceRequest{}, nil, err
	}
	q.BindingTable = append(q.BindingTable, target)
	orderBindings(q.BindingTable)
	sourceIndex, targetIndex := -1, -1
	for i, row := range q.BindingTable {
		if sameBindingRow(row, source) {
			sourceIndex = i
		}
		if sameBindingRow(row, target) {
			targetIndex = i
		}
	}
	if sourceIndex < 0 || targetIndex < 0 {
		return contract.CryptoAccessReplaceRequest{}, nil, contract.ErrRecord
	}
	beforeDigest, err := contract.PublicBindingDigest(before)
	if err != nil {
		return contract.CryptoAccessReplaceRequest{}, nil, err
	}
	q.Replacements = []contract.ReplacementRow{{SubjectKind: target.SubjectKind, SubjectID: target.SubjectID, BeforeBindingDigest: beforeDigest, SuccessorBindingIndex: uint16(targetIndex)}}
	rows, err := s.replacementMaterialRows(ctx, uint16(sourceIndex), uint16(targetIndex), target)
	if err != nil {
		return contract.CryptoAccessReplaceRequest{}, nil, err
	}
	projection, err := replacementProjection(q, uint32(len(rows)))
	if err != nil {
		return contract.CryptoAccessReplaceRequest{}, nil, err
	}
	for _, row := range rows {
		if err := projection.Add(row, contract.AccessOutputRow{MaterialKind: row.Coverage.MaterialKind, MaterialID: row.Coverage.MaterialID, BeforeAccessDigest: row.Coverage.BeforeAccessDigest, AfterAccessRecord: row.BeforeAccessRecord}); err != nil {
			return contract.CryptoAccessReplaceRequest{}, nil, err
		}
	}
	q.ExpectedCoverageDescriptor, _, _, err = projection.Descriptors()
	return q, rows, err
}

func replacementProjection(q contract.CryptoAccessReplaceRequest, count uint32) (*contract.AccessProjection, error) {
	plan, err := contract.AccessReplacementPlanDescriptor(q.Plan())
	if err != nil {
		return nil, err
	}
	return contract.NewAccessProjection(contract.AccessProjectionMetadata{DomainID: q.Context.DomainID, BeforeAccessRoot: q.Context.CurrentAccessRoot, RequestCoreDigest: q.Context.IntentDescriptor.Digest}, plan, count)
}

type preparedReplacement struct {
	op         *cryptoOperation
	projection *contract.AccessProjection
	transcript contract.ID
	after      map[materialIdentity]contract.AccessRecord
}

// prepareReplacementRows uses one ordered, bounded material walk for reader
// and authority replacements. The selected target is fixed before any batch.
func prepareReplacementRows(ctx context.Context, op *cryptoOperation, q contract.CryptoAccessReplaceRequest, rows []contract.CompactRow, target contract.BindingTableRow) (*preparedReplacement, Result) {
	projection, err := replacementProjection(q, uint32(len(rows)))
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	plan, err := contract.AccessReplacementPlanDescriptor(q.Plan())
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	transcript, err := contract.AccessTranscriptStartDigest(op.instance, op.operationRef, q.Context, plan, q.ExpectedCoverageDescriptor)
	if err != nil {
		return nil, refused(AdmissionInvalid)
	}
	after := make(map[materialIdentity]contract.AccessRecord, len(rows))
	offset, batch := 0, uint32(0)
	for {
		end, inputLength, outputLength := offset, 4, 4
		for end < len(rows) {
			input, output, err := contract.AccessInputRowLengths(rows[end])
			if err != nil {
				return nil, refused(InvalidFormat)
			}
			if inputLength+input > contract.AccessBatchLimit || outputLength+output > contract.AccessBatchLimit {
				break
			}
			inputLength += input
			outputLength += output
			end++
		}
		if end == offset && offset < len(rows) {
			return nil, refused(CapacityExceeded)
		}
		final := uint8(0)
		if end == len(rows) {
			final = 1
		}
		request := contract.CryptoAccessPrepareRequest{OperationRef: op.operationRef, Context: q.Context, BatchIndex: batch, Final: final, Rows: rows[offset:end]}
		body, err := contract.EncodeCryptoAccessPrepareRequest(request)
		if err != nil {
			return nil, refused(AdmissionInvalid)
		}
		op.sourceCount = uint32(len(request.Rows))
		op.wrapCounts[target.Binding.BindingID] = uint32(len(request.Rows))
		reply, res := op.exchange(ctx, contract.CryptoPrepare, body)
		if res.Outcome != 0 {
			return nil, res
		}
		result, err := contract.DecodeCryptoAccessPrepareResult(reply.Body)
		if err != nil || contract.ValidateAccessBatchResult(request, result) != nil {
			return nil, refused(AdmissionInvalid)
		}
		for i, row := range request.Rows {
			output := result.Rows[i]
			if !preservesReplacementWraps(row.BeforeAccessRecord, output.AfterAccessRecord, target) {
				return nil, refused(AdmissionInvalid)
			}
			if err := projection.Add(row, output); err != nil {
				return nil, refused(AdmissionInvalid)
			}
			after[materialIdentity{output.MaterialKind, output.MaterialID}] = output.AfterAccessRecord
		}
		transcript, err = contract.AccessTranscriptStepDigest(transcript, batch, final, result.InputBatchDescriptor, result.OutputBatchDescriptor)
		if err != nil {
			return nil, refused(AdmissionInvalid)
		}
		offset = end
		batch++
		if final == 1 {
			break
		}
	}
	return &preparedReplacement{op: op, projection: projection, transcript: transcript, after: after}, Result{}
}
