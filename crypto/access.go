package crypto

import (
	"context"
	"crypto/rand"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
	"enkv.sh/telemetry"
)

type accessAdmission struct {
	*session
	request                  contract.CryptoAccessReplaceRequest
	requestDigest            contract.ID
	requestLength            int
	sourceIndex, beforeIndex uint16
	authority                contract.ID
	succession               *successionAccess
	routeID                  contract.ID
	successorPublic          PublicKeyQualifier
	stage                    contract.CryptoKind
	busy                     bool
	operation, transcript    contract.ID
	plan                     contract.DescriptorVector
	identity                 contract.DigestLength
	projection               *contract.AccessProjection
	coverage                 []contract.CoverageRow
	batch, count             uint32
	frozen                   contract.CryptoAccessClaimRequest
}

// admitAccess installs the exact ordinary request after the private parent
// authenticated the predecessor and admitted its target and surviving route.
func (r *Runtime) admitAccess(q contract.CryptoAccessReplaceRequest, intent contract.RecipientReplacementIntent, request contract.RequestCore, control contract.ControlCore, rows []contract.CompactRow, routeID contract.ID, successorPublic PublicKeyQualifier, deadline time.Time) error {
	_, err := r.admitAccessOwned(q, intent, request, control, rows, routeID, successorPublic, deadline)
	return err
}

func (r *Runtime) admitAccessOwned(q contract.CryptoAccessReplaceRequest, intent contract.RecipientReplacementIntent, request contract.RequestCore, control contract.ControlCore, rows []contract.CompactRow, routeID contract.ID, successorPublic PublicKeyQualifier, deadline time.Time) (*accessAdmission, error) {
	if r == nil || successorPublic == nil || successorPublic.Family() != r.family || successorPublic.CredentialRoute().IsZero() || !validDeadline(deadline) || q.Context.Expiry != uint64(deadline.UnixNano()) || control.AuthorityRecipientID == intent.RecipientID || control.Provider != r.family || control.DomainID != q.Context.DomainID || routeID.IsZero() {
		return nil, ErrAdmission
	}
	if intent.Schema != contract.CanonicalSchema || intent.Profile != 2 || intent.DomainID != q.Context.DomainID || intent.CompatibilityID != q.Context.CompatibilityID || intent.CryptoSupportID != contract.CryptoSupportID() || intent.BeforeAccessRoot != q.Context.CurrentAccessRoot || intent.Before.Provider != r.family || intent.Successor.Provider != r.family || intent.Before.BindingID == intent.Successor.BindingID || !contract.IncarnationCounterStep(intent.Before.BindingIncarnationID, intent.Before.BindingSerial, intent.Successor.BindingIncarnationID, intent.Successor.BindingSerial) {
		return nil, ErrAdmission
	}
	intentDescriptor, err := contract.RecipientReplacementIntentDescriptor(intent)
	if err != nil {
		return nil, ErrAdmission
	}
	requestBytes, err := contract.EncodeRequestCore(request)
	if err != nil || contract.Hash(requestBytes) != q.Context.IntentDescriptor.Digest || uint64(len(requestBytes)) != q.Context.IntentDescriptor.Length || request.Intent != (contract.DigestLength{Digest: intentDescriptor.Digest, Length: intentDescriptor.Length}) {
		return nil, ErrAdmission
	}
	if request.Domain != q.Context.DomainID || request.PreviousDigest != q.Context.PredecessorHEADDigest {
		return nil, ErrAdmission
	}
	condition, err := contract.MatchHeadCondition(request.PreviousToken)
	if err != nil {
		return nil, ErrAdmission
	}
	conditionDigest, err := contract.CryptoConditionDigest(condition)
	if err != nil || conditionDigest != q.Context.OriginalConditionDigest || request.Store != control.StoreID || request.Coordinate != control.CoordinateID || request.NonBody != control.NonBodyID || request.Trust != control.NormalSigning.Binding.Trust || request.Epoch != control.NormalSigning.Binding.Epoch {
		return nil, ErrAdmission
	}
	if _, err := contract.EncodeControlCore(control); err != nil {
		return nil, ErrAdmission
	}
	body, err := contract.EncodeCryptoAccessReplaceRequest(q)
	if err != nil {
		return nil, ErrAdmission
	}
	owned, err := contract.DecodeCryptoAccessReplaceRequest(body)
	if err != nil {
		return nil, ErrAdmission
	}
	if len(q.BindingTable) < 3 || len(q.Replacements) != 1 {
		return nil, ErrAdmission
	}
	replacement := q.Replacements[0]
	beforeDigest, err := contract.PublicBindingDigest(intent.Before)
	if err != nil || replacement.SubjectKind != contract.OrdinaryWrapSubject || replacement.SubjectID != intent.RecipientID || replacement.BeforeBindingDigest != beforeDigest {
		return nil, ErrAdmission
	}
	successor := q.BindingTable[replacement.SuccessorBindingIndex]
	if !sameApplyBinding(successor.Binding, intent.Successor) {
		return nil, ErrAdmission
	}
	authority, before := -1, -1
	for i, row := range q.BindingTable {
		if row.Binding.Provider != r.family {
			return nil, ErrAdmission
		}
		if row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == control.AuthorityRecipientID {
			if authority >= 0 || !sameApplyBinding(row.Binding, control.AuthorityKMSBinding) {
				return nil, ErrAdmission
			}
			authority = i
		}
		if row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == intent.RecipientID && sameApplyBinding(row.Binding, intent.Before) {
			before = i
		}
		for _, prior := range q.BindingTable[:i] {
			if prior.Binding.BindingID == row.Binding.BindingID {
				return nil, ErrAdmission
			}
		}
	}
	if authority < 0 || before < 0 {
		return nil, ErrAdmission
	}
	plan, err := contract.AccessReplacementPlanDescriptor(q.Plan())
	if err != nil {
		return nil, ErrAdmission
	}
	projection, err := contract.NewAccessProjection(contract.AccessProjectionMetadata{DomainID: q.Context.DomainID, BeforeAccessRoot: q.Context.CurrentAccessRoot, RequestCoreDigest: q.Context.IntentDescriptor.Digest}, plan, q.ExpectedCoverageDescriptor.Count)
	if err != nil {
		return nil, ErrAdmission
	}
	a := &accessAdmission{request: owned, requestDigest: contract.Hash(body), requestLength: len(body), sourceIndex: uint16(authority), beforeIndex: uint16(before), authority: control.AuthorityRecipientID, routeID: routeID, successorPublic: successorPublic, stage: contract.CryptoAccessReplace, plan: plan, projection: projection, identity: request.IdentityPlan}
	if !a.admitCoverage(rows) {
		return nil, ErrAdmission
	}
	if err := r.installAccess(a, deadline); err != nil {
		return nil, err
	}
	return a, nil
}

func (r *Runtime) installAccess(a *accessAdmission, deadline time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.slot != nil {
		return ErrAdmission
	}
	routeIDs := []contract.ID{a.routeID}
	if a.succession != nil {
		routeIDs = append(routeIDs, a.succession.publicRoute, a.succession.privateRoute)
	}
	for _, id := range routeIDs {
		route := r.routes[id]
		if id.IsZero() || route == nil || route.Family() != r.family || route.CredentialRoute() != id {
			return ErrAdmission
		}
	}
	a.session = r.installSession(a.request.Context.AdmissionID, deadline, nil, func() {
		a.request = contract.CryptoAccessReplaceRequest{}
		a.succession = nil
		a.successorPublic = nil
		a.projection = nil
		a.coverage = nil
		a.frozen = contract.CryptoAccessClaimRequest{}
	})
	if a.session == nil {
		return ErrAdmission
	}
	r.access = a
	return nil
}

func (r *Runtime) accessExchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	return r.accessExchangeOwned(ctx, q, nil)
}

func (r *Runtime) accessExchangeOwned(ctx context.Context, q contract.CryptoRequest, expected *accessAdmission) (out contract.CryptoResponse) {
	out = contract.CryptoResponse{Schema: contract.CryptoSchema, Kind: q.Kind, RequestID: q.RequestID, CustodyInstanceID: r.InstanceID(), ResultCode: contract.CryptoInvalidAdmission}
	if r == nil || ctx == nil || q.CustodyInstanceID != r.id {
		return out
	}
	callerDone := ctx.Done()
	r.mu.Lock()
	a := r.access
	if r.closed || a == nil || expected != nil && a != expected {
		r.mu.Unlock()
		return out
	}
	if a.terminal || a.busy {
		r.mu.Unlock()
		out.ResultCode = contract.CryptoAlreadyUsed
		return out
	}
	// The observer closes admission under this lock before joining work.
	// A late stage must not register across that Wait and cleanup boundary.
	if code := sessionCancellationObserved(callerDone, a.session); code != contract.CryptoSuccess {
		a.terminal = true
		a.cancel()
		r.mu.Unlock()
		out.ResultCode = code
		return out
	}
	if a.used {
		r.mu.Unlock()
		out.ResultCode = contract.CryptoAlreadyUsed
		return out
	}
	if q.Kind != a.stage && (q.Kind != contract.CryptoDiscard || a.stage == contract.CryptoAccessReplace) {
		a.terminal = true
		a.cancel()
		r.mu.Unlock()
		out.ResultCode = contract.CryptoAlreadyUsed
		return out
	}
	a.busy = true
	a.work.Add(1)
	route := r.routes[a.routeID]
	publicRoute := a.successorPublic
	var privateProbeRoute KeyAccess
	if a.succession != nil {
		publicRoute = r.routes[a.succession.publicRoute]
		privateProbeRoute = r.routes[a.succession.privateRoute]
	}
	r.mu.Unlock()
	defer a.work.Done()
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if code := sessionCancellationObserved(callerDone, a.session); code != contract.CryptoSuccess {
			out.ResultCode = code
		}
		a.busy = false
		if out.ResultCode != contract.CryptoSuccess || q.Kind == contract.CryptoClaim || q.Kind == contract.CryptoDiscard {
			if out.ResultCode != contract.CryptoSuccess {
				out.Body = nil
			}
			a.terminal = true
			a.cancel()
		}
	}()
	stop := context.AfterFunc(ctx, a.cancel)
	defer stop()
	privateCtx := telemetry.PrivateContext(a.ctx, ctx)
	if code := sessionCancellation(ctx, a.session); code != contract.CryptoSuccess {
		out.ResultCode = code
		return out
	}
	if q.Schema != contract.CryptoSchema || q.RequestID.IsZero() || len(q.Body) > contract.CryptoRequestLimit-71 {
		out.ResultCode = contract.CryptoInvalidInput
		return out
	}
	switch q.Kind {
	case contract.CryptoAccessReplace:
		if len(q.Body) != a.requestLength || contract.Hash(q.Body) != a.requestDigest {
			return out
		}
		successor := a.request.BindingTable[a.request.Replacements[0].SuccessorBindingIndex]
		qualified := publicRoute.Qualify(privateCtx, successor.Binding)
		expected := contract.PublicKeyQualificationUseCount(successor.Binding.Provider)
		if !appendKeyUses(&out, successor, contract.KeyUsePublicKeyRead, qualified.Uses, uint64(expected)) {
			out.ResultCode = contract.CryptoResponseUnknown
			return out
		}
		if qualified.Status != KeyOK {
			out.ResultCode = keyResultCode(qualified.Status)
			return out
		}
		if qualified.Uses != (KeyUses{Completed: expected}) {
			out.ResultCode = contract.CryptoResponseUnknown
			return out
		}
		var proofs []contract.CryptoQualifiedSuccessor
		if a.succession != nil {
			code, uses := probeSuccessorKEK(privateCtx, a.succession.probe, successor, privateProbeRoute)
			if !appendKeyUses(&out, successor, contract.KeyUsePrivateRoleProbe, uses, 1) {
				out.ResultCode = contract.CryptoResponseUnknown
				return out
			}
			if code != contract.CryptoSuccess {
				out.ResultCode = code
				return out
			}
			fields, err := qualifiedBinding(successor)
			if err != nil {
				return out
			}
			proofs = []contract.CryptoQualifiedSuccessor{{BindingIndex: a.request.Replacements[0].SuccessorBindingIndex, Qualification: contract.QualifiedSuccessorRow{ProbeID: a.succession.probe.ProbeID, QualifiedBindingFields: fields}}}
		}
		if _, err := rand.Read(a.operation[:]); err != nil || a.operation.IsZero() {
			out.ResultCode = contract.CryptoCustodyUnavailable
			return out
		}
		var err error
		a.transcript, err = contract.AccessTranscriptStartDigest(r.id, a.operation, a.request.Context, a.plan, a.request.ExpectedCoverageDescriptor)
		if err != nil {
			return out
		}
		out.Body, err = contract.EncodeCryptoAccessReplaceResult(contract.CryptoAccessReplaceResult{OperationRef: a.operation, Qualified: proofs})
		if err != nil {
			return out
		}
		a.stage = contract.CryptoPrepare
	case contract.CryptoPrepare:
		batch, err := contract.DecodeCryptoAccessPrepareRequest(q.Body)
		if err != nil {
			out.ResultCode = contract.CryptoInvalidInput
			return out
		}
		if batch.Context != a.request.Context || batch.OperationRef != a.operation {
			return out
		}
		out.ResultCode = a.prepareAccess(privateCtx, batch, route, &out)
		return out
	case contract.CryptoFreeze:
		v, err := contract.DecodeCryptoAccessFreezeRequest(q.Body)
		if err != nil {
			out.ResultCode = contract.CryptoInvalidInput
			return out
		}
		coverage, after, unchanged, err := a.projection.Descriptors()
		if err != nil || v.Context != a.request.Context || v.OperationRef != a.operation || v.ExpectedCoverageDescriptor != coverage || v.AfterAccessRowsDescriptor != after || v.UnchangedMaterialDescriptor != unchanged || v.FinalTranscriptDigest != a.transcript || v.IdentityPlanDescriptor.Digest != a.identity.Digest || v.IdentityPlanDescriptor.Length != a.identity.Length {
			return out
		}
		digest, err := contract.CryptoAccessFactDigest(r.id, v)
		if err != nil {
			return out
		}
		a.frozen = contract.CryptoAccessClaimRequest{CryptoAccessFreezeRequest: v, FactDigest: digest}
		out.Body, err = contract.EncodeCryptoFreezeResult(contract.CryptoFreezeResult{FactDigest: digest})
		if err != nil {
			return out
		}
		a.stage = contract.CryptoClaim
	case contract.CryptoClaim:
		v, err := contract.DecodeCryptoAccessClaimRequest(q.Body)
		if err != nil || v != a.frozen {
			return out
		}
	case contract.CryptoDiscard:
		v, err := contract.DecodeCryptoDiscardRequest(q.Body)
		if err != nil || v.Context != a.request.Context || v.OperationRef != a.operation {
			return out
		}
	default:
		return out
	}
	out.ResultCode = contract.CryptoSuccess
	return out
}

func (a *accessAdmission) prepareAccess(ctx context.Context, q contract.CryptoAccessPrepareRequest, route KeyAccess, out *contract.CryptoResponse) contract.CryptoResultCode {
	if q.BatchIndex != a.batch || a.count+uint32(len(q.Rows)) > a.request.ExpectedCoverageDescriptor.Count || len(q.Rows) == 0 && a.count != a.request.ExpectedCoverageDescriptor.Count {
		return contract.CryptoInvalidAdmission
	}
	if err := a.projection.ValidateBatch(q.Rows); err != nil {
		if err == contract.ErrCryptoCapacity {
			return contract.CryptoCapacityExceeded
		}
		return contract.CryptoInvalidAdmission
	}
	for i, row := range q.Rows {
		index := int(a.count) + i
		if index >= len(a.coverage) || !sameAccessCoverage(row.Coverage, a.coverage[index]) || !a.accessRowAdmitted(row) {
			return contract.CryptoInvalidAdmission
		}
	}
	result := contract.CryptoAccessPrepareResult{BatchIndex: q.BatchIndex, Final: q.Final, Rows: make([]contract.AccessOutputRow, 0, len(q.Rows))}
	for _, row := range q.Rows {
		after, code := a.rewrap(ctx, route, row, out)
		if code != contract.CryptoSuccess {
			return code
		}
		if err := a.projection.Add(row, after); err != nil {
			return contract.CryptoInvalidAdmission
		}
		result.Rows = append(result.Rows, after)
	}
	a.count += uint32(len(q.Rows))
	a.batch++
	var err error
	result.InputBatchDescriptor, err = contract.AccessInputBatchDescriptor(q.Rows)
	if err != nil {
		return contract.CryptoInvalidInput
	}
	result.OutputBatchDescriptor, err = contract.AccessOutputBatchDescriptor(result.Rows)
	if err != nil {
		return contract.CryptoCapacityExceeded
	}
	a.transcript, err = contract.AccessTranscriptStepDigest(a.transcript, q.BatchIndex, q.Final, result.InputBatchDescriptor, result.OutputBatchDescriptor)
	if err != nil {
		return contract.CryptoInvalidAdmission
	}
	if q.Final == 1 {
		coverage, _, _, err := a.projection.Descriptors()
		if err != nil || coverage != a.request.ExpectedCoverageDescriptor {
			return contract.CryptoInvalidAdmission
		}
		a.stage = contract.CryptoFreeze
	}
	out.Body, err = contract.EncodeCryptoAccessPrepareResult(result)
	if err != nil {
		return contract.CryptoCapacityExceeded
	}
	return contract.CryptoSuccess
}

// The private parent supplies the complete selected rows independently of
// later exchange batches. Retain their coverage only after its full commitment
// agrees with the admitted request.
func (a *accessAdmission) admitCoverage(rows []contract.CompactRow) bool {
	if uint64(len(rows)) != uint64(a.request.ExpectedCoverageDescriptor.Count) {
		return false
	}
	projection, err := contract.NewAccessProjection(contract.AccessProjectionMetadata{
		DomainID: a.request.Context.DomainID, BeforeAccessRoot: a.request.Context.CurrentAccessRoot,
		RequestCoreDigest: a.request.Context.IntentDescriptor.Digest,
	}, a.plan, a.request.ExpectedCoverageDescriptor.Count)
	if err != nil {
		return false
	}
	coverage := make([]contract.CoverageRow, 0, len(rows))
	for _, row := range rows {
		if !a.accessRowAdmitted(row) {
			return false
		}
		if err := projection.Add(row, contract.AccessOutputRow{
			MaterialKind: row.Coverage.MaterialKind, MaterialID: row.Coverage.MaterialID,
			BeforeAccessDigest: row.Coverage.BeforeAccessDigest, AfterAccessRecord: row.BeforeAccessRecord,
		}); err != nil {
			return false
		}
		owned := row.Coverage
		owned.TargetBindingIndices = slices.Clone(owned.TargetBindingIndices)
		coverage = append(coverage, owned)
	}
	descriptor, _, _, err := projection.Descriptors()
	if err != nil || descriptor != a.request.ExpectedCoverageDescriptor {
		return false
	}
	a.coverage = coverage
	return true
}

func sameAccessCoverage(a, b contract.CoverageRow) bool {
	return a.MaterialKind == b.MaterialKind && a.MaterialID == b.MaterialID &&
		a.MaterialContextDigest == b.MaterialContextDigest && a.ImmutableBodyDigest == b.ImmutableBodyDigest &&
		a.BeforeAccessDigest == b.BeforeAccessDigest && a.RequiredConsumerDigest == b.RequiredConsumerDigest &&
		a.SourceBindingIndex == b.SourceBindingIndex && slices.Equal(a.TargetBindingIndices, b.TargetBindingIndices)
}

func (a *accessAdmission) accessRowAdmitted(row contract.CompactRow) bool {
	c := row.Coverage
	if int(c.SourceBindingIndex) >= len(a.request.BindingTable) || len(c.TargetBindingIndices) != 1 || c.TargetBindingIndices[0] != a.request.Replacements[0].SuccessorBindingIndex {
		return false
	}
	if c.SourceBindingIndex != a.sourceIndex {
		return false
	}
	domain, compatibility, support := row.ValueCore.DomainID, row.ValueCore.CompatibilityID, row.ValueCore.CryptoSupportID
	if c.MaterialKind == contract.OperationSeedMaterialKind {
		domain, compatibility, support = row.OperationMaterialCore.DomainID, row.OperationMaterialCore.CompatibilityID, row.OperationMaterialCore.CryptoSupportID
	}
	if domain != a.request.Context.DomainID || compatibility != a.request.Context.CompatibilityID || support != contract.CryptoSupportID() {
		return false
	}
	foundSource, foundTarget := false, false
	for _, wrap := range row.BeforeAccessRecord.Wraps {
		if c.MaterialKind == contract.OperationSeedMaterialKind && wrap.SubjectKind == contract.OrdinaryWrapSubject && wrap.SubjectID != a.authority {
			return false
		}
		index := slices.IndexFunc(a.request.BindingTable, func(binding contract.BindingTableRow) bool {
			return binding.SubjectKind == wrap.SubjectKind && binding.SubjectID == wrap.SubjectID && binding.Binding.BindingID == wrap.BindingID
		})
		if index < 0 || index == int(c.TargetBindingIndices[0]) {
			return false
		}
		core, err := replacementWrapCore(row, a.request.BindingTable[index])
		if err != nil || !applyWrapMatches(wrap, core) {
			return false
		}
		if index == int(c.SourceBindingIndex) {
			foundSource = true
		}
		before := a.request.BindingTable[a.beforeIndex]
		if wrap.SubjectKind == before.SubjectKind && wrap.SubjectID == before.SubjectID {
			if index != int(a.beforeIndex) {
				return false
			}
			foundTarget = true
		}
	}
	return foundSource && foundTarget
}

func replacementWrapCore(row contract.CompactRow, binding contract.BindingTableRow) (contract.WrapCore, error) {
	if row.Coverage.MaterialKind == contract.OperationSeedMaterialKind {
		return custody.SeedWrapCore(row.OperationMaterialCore, binding)
	}
	return custody.ValueWrapCore(row.ValueCore, binding)
}

func (a *accessAdmission) rewrap(ctx context.Context, route KeyAccess, row contract.CompactRow, out *contract.CryptoResponse) (contract.AccessOutputRow, contract.CryptoResultCode) {
	if ctx.Err() != nil {
		return contract.AccessOutputRow{}, contract.CryptoCancelled
	}
	source := a.request.BindingTable[row.Coverage.SourceBindingIndex]
	index := slices.IndexFunc(row.BeforeAccessRecord.Wraps, func(w contract.WrapRow) bool { return w.BindingID == source.Binding.BindingID })
	core, err := replacementWrapCore(row, source)
	if err != nil || index < 0 {
		return contract.AccessOutputRow{}, contract.CryptoInvalidAdmission
	}
	packetContext, err := contract.RSAPacketContextDigest(core)
	if err != nil {
		return contract.AccessOutputRow{}, contract.CryptoInvalidAdmission
	}
	private := route.Decrypt(ctx, source.Binding, row.BeforeAccessRecord.Wraps[index].RSACiphertext, core.PacketLength)
	if private.Packet != nil {
		defer clear(private.Packet[:cap(private.Packet)])
	}
	if !appendKeyUses(out, source, contract.KeyUseMaterialOpen, private.Uses, 1) {
		return contract.AccessOutputRow{}, contract.CryptoResponseUnknown
	}
	if ctx.Err() != nil {
		return contract.AccessOutputRow{}, contract.CryptoCancelled
	}
	keys, code := privatePacketKeys(private, core.PacketKind, packetContext, contract.CryptoStoredAuthenticationFailed)
	if code != contract.CryptoSuccess {
		return contract.AccessOutputRow{}, code
	}
	var check contract.ID
	if core.PacketKind == 3 {
		check, err = custody.SeedCheck(row.OperationMaterialCore, keys)
	} else {
		check, err = custody.PackageCheck(row.ValueCore, keys)
	}
	if err != nil || check != row.BeforeAccessRecord.PackageCheck {
		return contract.AccessOutputRow{}, contract.CryptoStoredAuthenticationFailed
	}
	successor := a.request.BindingTable[row.Coverage.TargetBindingIndices[0]]
	wc, err := replacementWrapCore(row, successor)
	if err != nil {
		return contract.AccessOutputRow{}, contract.CryptoInvalidAdmission
	}
	wrap, err := custody.Wrap(wc, successor.Binding, keys)
	uses := KeyUses{Completed: 1}
	if err != nil {
		uses = KeyUses{Failed: 1}
	}
	if !appendKeyUses(out, successor, contract.KeyUseMaterialWrap, uses, 1) {
		return contract.AccessOutputRow{}, contract.CryptoResponseUnknown
	}
	if err != nil {
		return contract.AccessOutputRow{}, contract.CryptoCustodyUnavailable
	}
	after := row.BeforeAccessRecord
	after.Wraps = slices.Clone(after.Wraps)
	for i, w := range after.Wraps {
		if w.SubjectKind == successor.SubjectKind && w.SubjectID == successor.SubjectID {
			after.Wraps[i] = wrap
		}
	}
	if ctx.Err() != nil {
		return contract.AccessOutputRow{}, contract.CryptoCancelled
	}
	return contract.AccessOutputRow{MaterialKind: row.Coverage.MaterialKind, MaterialID: row.Coverage.MaterialID, BeforeAccessDigest: row.Coverage.BeforeAccessDigest, AfterAccessRecord: after}, contract.CryptoSuccess
}

func (r *Runtime) retireAccess() {
	if r == nil {
		return
	}
	r.mu.Lock()
	a := r.access
	r.mu.Unlock()
	if a != nil {
		r.retireSession(a.session)
	}
}
