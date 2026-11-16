package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"math"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type cryptoOperation struct {
	observation                              *operationObservation
	source                                   observationSource
	adapter                                  contract.Crypto
	instance, operationRef, comparisonDigest contract.ID
	authority                                contract.ID
	accessSource                             *contract.BindingTableRow
	probeBinding                             contract.ID
	context                                  contract.ApplyContext
	deadline                                 time.Time
	bindings                                 []contract.BindingTableRow
	sourceCount                              uint32
	wrapCounts                               map[contract.ID]uint32
	qualificationCounts                      map[contract.ID]uint32
	terminal                                 bool
}

func validPrivateDeadline(t time.Time) bool {
	return t.After(time.Unix(0, 0)) && !t.After(time.Unix(0, math.MaxInt64)) && time.Now().Before(t)
}

func (s *StateSession) comparisonRequest(c *Comparison, admitted contract.ApplyContext) (contract.CryptoCompareRequest, bool) {
	if c == nil || c.session != s || admitted.OperationClass != contract.CryptoOrdinaryLifecycle || admitted.AdmissionID.IsZero() || admitted.SessionID.IsZero() || admitted.DomainID != s.admission.domain || admitted.CompatibilityID != contract.CompatibilityID() {
		return contract.CryptoCompareRequest{}, false
	}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil {
		return contract.CryptoCompareRequest{}, false
	}
	condition, err := contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil || !bytes.Equal(root, admitted.PredecessorRootRef[:]) || admitted.PredecessorHEADDigest != contract.Hash(s.body) || admitted.OriginalConditionDigest != condition || admitted.CurrentAccessRoot != s.root.CurrentAccess.AccessRoot || admitted.IntentDescriptor != (contract.DescriptorVector{Digest: c.desired, Length: c.desiredLength, Count: uint32(len(c.desiredEntries))}) {
		return contract.CryptoCompareRequest{}, false
	}
	bindings, err := s.currentBindings()
	if err != nil {
		return contract.CryptoCompareRequest{}, false
	}
	for _, row := range c.recipients {
		if s.recipientRecord(row.Recipient.RecipientID) == nil {
			bindings = append(bindings, contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: row.Recipient.RecipientID, Binding: *row.Recipient.CurrentBinding})
		}
	}
	orderBindings(bindings)
	q := contract.CryptoCompareRequest{Context: admitted, Intent: c.intent, Recipients: c.recipients, Bindings: bindings, SecretAccess: c.secretAccess, Retirement: c.retirement}
	for _, entry := range s.root.Names {
		m := s.valueEntry(entry.Slot)
		if m == nil {
			return contract.CryptoCompareRequest{}, false
		}
		if m.ConfidentialityClass != format.Secret {
			continue
		}
		_, _, access, ok := s.selectedValue(entry.Slot)
		if !ok {
			return contract.CryptoCompareRequest{}, false
		}
		entryBytes, err := contract.EncodeValueEntry(*m)
		if err != nil {
			return contract.CryptoCompareRequest{}, false
		}
		access.Wraps = slices.DeleteFunc(slices.Clone(access.Wraps), func(w contract.WrapRow) bool {
			return w.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(m.Recipients, w.SubjectID)
		})
		accessBody, err := contract.EncodeAccessRecord(access)
		if err != nil {
			return contract.CryptoCompareRequest{}, false
		}
		q.Current = append(q.Current, contract.CryptoCurrentSecret{Slot: entry.Slot, EntryBytes: entryBytes, AccessRecord: accessBody})
	}
	for _, value := range c.desiredEntries {
		if value.ConfidentialityClass == format.Secret && value.ValueSource == format.Supplied && value.Retained == nil {
			q.SealedInputs = append(q.SealedInputs, contract.CryptoSealedInput{Name: value.Name, EnvelopeBytes: value.InputBytes})
		}
	}
	return q, true
}

func custodyFailure(code contract.CryptoResultCode) Result {
	switch code {
	case contract.CryptoInvalidInput, contract.CryptoSourceAuthenticationFailed:
		return refused(InvalidIntent)
	case contract.CryptoAlreadyUsed:
		return refused(AlreadyUsed)
	case contract.CryptoCustodyUnavailable, contract.CryptoResponseUnknown:
		return failure(EvidenceUnavailable, CustodyUnavailable)
	case contract.CryptoCapacityExceeded:
		return refused(CapacityExceeded)
	case contract.CryptoStoredAuthenticationFailed:
		return failure(IntegrityFailure, InvalidProof)
	default:
		return refused(AdmissionInvalid)
	}
}

func (op *cryptoOperation) exchange(ctx context.Context, kind contract.CryptoKind, body []byte) (contract.CryptoResponse, Result) {
	if op == nil || op.terminal || ctx == nil || ctx.Err() != nil || !validPrivateDeadline(op.deadline) || op.adapter == nil || op.adapter.InstanceID() != op.instance {
		if op != nil {
			op.terminal = true
		}
		return contract.CryptoResponse{}, refused(AdmissionInvalid)
	}
	var id contract.ID
	if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
		op.terminal = true
		return contract.CryptoResponse{}, refused(AdmissionInvalid)
	}
	q := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: kind, RequestID: id, CustodyInstanceID: op.instance, Body: body}
	reply := op.adapter.Exchange(ctx, q)
	if ctx.Err() != nil || !validPrivateDeadline(op.deadline) || op.adapter.InstanceID() != op.instance || contract.ValidateCryptoExchange(q, reply) != nil || !op.keyUsesValid(kind, reply.ResultCode, reply.KeyUseRows) {
		op.terminal = true
		return contract.CryptoResponse{}, refused(AdmissionInvalid)
	}
	op.observation.offerExchange(ctx, exchangeObservation{Source: op.source, RequestID: q.RequestID, Kind: q.Kind,
		CustodyInstanceID: q.CustodyInstanceID, ResultCode: reply.ResultCode, Rows: reply.KeyUseRows})
	if reply.ResultCode != contract.CryptoSuccess {
		op.terminal = true
		return reply, custodyFailure(reply.ResultCode)
	}
	if kind == contract.CryptoClaim || kind == contract.CryptoDiscard {
		op.terminal = true
	}
	return reply, Result{}
}

func (op *cryptoOperation) keyUsesValid(kind contract.CryptoKind, result contract.CryptoResultCode, uses []contract.KeyUseRow) bool {
	opened := uint64(0)
	qualified := uint64(0)
	qualificationExpected := uint64(0)
	probed := uint64(0)
	wrapped := make(map[contract.ID]uint64, len(op.wrapCounts))
	qualifiedBindings := make(map[contract.ID]uint64, len(op.qualificationCounts))
	for _, use := range uses {
		index := slices.IndexFunc(op.bindings, func(row contract.BindingTableRow) bool {
			return row.Binding.BindingID == use.BindingID && row.SubjectKind == use.SubjectKind && row.SubjectID == use.SubjectID
		})
		if index < 0 {
			return false
		}
		row := op.bindings[index]
		digest, err := contract.PublicBindingDigest(row.Binding)
		if err != nil || digest != use.PublicBindingDigest || row.Binding.Provider != use.Provider {
			return false
		}
		if result == contract.CryptoSuccess && use.Outcome != contract.KeyUseCompleted {
			return false
		}
		switch kind {
		case contract.CryptoAccessReplace:
			if op.context.OperationClass != contract.CryptoAccessReplacementClass || op.wrapCounts[use.BindingID] == 0 ||
				(use.Purpose != contract.KeyUsePublicKeyRead && (use.Purpose != contract.KeyUsePrivateRoleProbe || op.probeBinding.IsZero() || use.BindingID != op.probeBinding)) {
				return false
			}
			qualificationExpected = 2
			if row.Binding.Provider == contract.GCP {
				qualificationExpected = 3
			}
		case contract.CryptoCompare:
			if use.Purpose == contract.KeyUsePublicKeyRead {
				expected := op.qualificationCounts[use.BindingID]
				if row.SubjectKind != contract.OrdinaryWrapSubject || expected == 0 {
					return false
				}
				qualifiedBindings[use.BindingID] += uint64(use.Count)
				if qualifiedBindings[use.BindingID] > uint64(expected) {
					return false
				}
				qualificationExpected += uint64(expected)
			} else if use.Purpose != contract.KeyUseMaterialOpen || row.SubjectKind != contract.OrdinaryWrapSubject || row.SubjectID != op.authority {
				return false
			}
		case contract.CryptoPrepare:
			source := row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == op.authority
			if op.accessSource != nil {
				source = row.SubjectKind == op.accessSource.SubjectKind && row.SubjectID == op.accessSource.SubjectID && row.Binding.BindingID == op.accessSource.Binding.BindingID
			}
			if use.Purpose != contract.KeyUseMaterialWrap && (use.Purpose != contract.KeyUseMaterialOpen || !source) {
				return false
			}
		default:
			return false
		}
		switch use.Purpose {
		case contract.KeyUsePrivateRoleProbe:
			probed += uint64(use.Count)
			if probed > 1 {
				return false
			}
		case contract.KeyUsePublicKeyRead:
			qualified += uint64(use.Count)
			if qualified > qualificationExpected {
				return false
			}
		case contract.KeyUseMaterialOpen:
			opened += uint64(use.Count)
			if opened > uint64(op.sourceCount) {
				return false
			}
		case contract.KeyUseMaterialWrap:
			wrapped[use.BindingID] += uint64(use.Count)
			if wrapped[use.BindingID] > uint64(op.wrapCounts[use.BindingID]) {
				return false
			}
		}
	}
	if op.context.OperationClass == contract.CryptoAccessReplacementClass && result == contract.CryptoSuccess {
		if kind == contract.CryptoAccessReplace && (qualificationExpected == 0 || qualified != qualificationExpected) {
			return false
		}
		if kind == contract.CryptoAccessReplace && ((!op.probeBinding.IsZero() && probed != 1) || (op.probeBinding.IsZero() && probed != 0)) {
			return false
		}
		if kind == contract.CryptoPrepare {
			if opened != uint64(op.sourceCount) {
				return false
			}
			for binding, expected := range op.wrapCounts {
				if wrapped[binding] != uint64(expected) {
					return false
				}
			}
		}
	}
	if (op.context.OperationClass == contract.CryptoOrdinaryLifecycle || op.context.OperationClass == contract.CryptoGeneratedClass) &&
		result == contract.CryptoSuccess && (kind == contract.CryptoCompare || kind == contract.CryptoPrepare) {
		if opened != uint64(op.sourceCount) {
			return false
		}
		if kind == contract.CryptoCompare {
			for binding, expected := range op.qualificationCounts {
				if qualifiedBindings[binding] != uint64(expected) {
					return false
				}
			}
		}
		if kind == contract.CryptoPrepare {
			for binding, expected := range op.wrapCounts {
				if wrapped[binding] != uint64(expected) {
					return false
				}
			}
		}
	}
	return true
}
