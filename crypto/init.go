package crypto

import (
	"bytes"
	"context"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type initAdmission struct {
	*session
	body                        []byte
	support                     contract.ID
	publicRoutes, privateRoutes map[contract.ID]KeyAccess
}

func (r *Runtime) admitInit(q contract.CryptoQualifyInitKeysRequest, support contract.ID, public, private map[contract.ID]contract.ID, deadline time.Time) error {
	_, err := r.installInit(q, support, public, private, deadline)
	return err
}

func (r *Runtime) installInit(q contract.CryptoQualifyInitKeysRequest, support contract.ID, public, private map[contract.ID]contract.ID, deadline time.Time) (*initAdmission, error) {
	if r == nil || support != contract.CryptoSupportID() || q.Context.CompatibilityID != contract.CompatibilityID() || !validDeadline(deadline) || q.Context.Expiry != uint64(deadline.UnixNano()) || len(public) != len(q.Bindings) || len(private) != len(q.Probes) {
		return nil, ErrAdmission
	}
	body, err := contract.EncodeCryptoQualifyInitKeysRequest(q)
	if err != nil {
		return nil, ErrAdmission
	}
	if len(q.Probes) == 2 {
		first := slices.IndexFunc(q.Bindings, func(row contract.BindingTableRow) bool { return row.Binding.BindingID == q.Probes[0].BindingID })
		second := slices.IndexFunc(q.Bindings, func(row contract.BindingTableRow) bool { return row.Binding.BindingID == q.Probes[1].BindingID })
		if first < 0 || second < 0 || !contract.IndependentKMSBindings(q.Bindings[first].Binding, q.Bindings[second].Binding) {
			return nil, ErrAdmission
		}
	}
	a := &initAdmission{body: body, support: support, publicRoutes: make(map[contract.ID]KeyAccess, len(public)), privateRoutes: make(map[contract.ID]KeyAccess, len(private))}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.slot != nil {
		return nil, ErrAdmission
	}
	for _, row := range q.Bindings {
		if row.Binding.Provider != r.family {
			return nil, ErrAdmission
		}
		route, ok := r.routes[public[row.Binding.BindingID]]
		if !ok {
			return nil, ErrAdmission
		}
		a.publicRoutes[row.Binding.BindingID] = route
	}
	for _, probe := range q.Probes {
		route, ok := r.routes[private[probe.BindingID]]
		if !ok {
			return nil, ErrAdmission
		}
		a.privateRoutes[probe.BindingID] = route
	}
	a.session = r.installSession(q.Context.AdmissionID, deadline, nil, func() {
		clear(a.body)
		a.body = nil
		a.publicRoutes = nil
		a.privateRoutes = nil
	})
	if a.session == nil {
		return nil, ErrAdmission
	}
	r.init = a
	return a, nil
}

// retireInit is called only by the private parent after the previous operation
// is no longer needed. All private work is joined before its slot is reused.
func (r *Runtime) retireInit() {
	if r == nil {
		return
	}
	r.mu.Lock()
	a := r.init
	r.mu.Unlock()
	if a == nil {
		return
	}
	r.retireSession(a.session)
}

func (r *Runtime) qualifyInit(ctx context.Context, q contract.CryptoRequest, expected *initAdmission) contract.CryptoResponse {
	reply := contract.CryptoResponse{Schema: contract.CryptoSchema, Kind: q.Kind, RequestID: q.RequestID,
		CustodyInstanceID: r.InstanceID(), ResultCode: contract.CryptoInvalidAdmission}
	if r == nil || r.id.IsZero() || q.CustodyInstanceID != r.id || ctx == nil {
		return reply
	}
	if q.Schema != contract.CryptoSchema || q.RequestID.IsZero() || q.Kind != contract.CryptoQualifyInitKeys {
		reply.ResultCode = contract.CryptoInvalidInput
		return reply
	}
	if len(q.Body) > contract.CryptoInitRequestLimit {
		reply.ResultCode = contract.CryptoCapacityExceeded
		return reply
	}
	decoded, err := contract.DecodeCryptoQualifyInitKeysRequest(q.Body)
	if err != nil {
		reply.ResultCode = contract.CryptoInvalidInput
		return reply
	}
	r.mu.Lock()
	a := r.init
	if r.closed || a == nil || expected != nil && (a != expected || r.slot != expected.session) || decoded.Context.AdmissionID != a.id {
		r.mu.Unlock()
		return reply
	}
	if a.terminal {
		r.mu.Unlock()
		reply.ResultCode = contract.CryptoAlreadyUsed
		return reply
	}
	if a.ctx.Err() != nil || !time.Now().Before(a.deadline) {
		r.mu.Unlock()
		reply.ResultCode = contract.CryptoExpired
		return reply
	}
	if a.used {
		r.mu.Unlock()
		reply.ResultCode = contract.CryptoAlreadyUsed
		return reply
	}
	if !bytes.Equal(q.Body, a.body) {
		r.mu.Unlock()
		return reply
	}
	a.used = true
	a.work.Add(1)
	r.mu.Unlock()
	defer a.work.Done()
	defer r.finishSession(a.session)
	stop := context.AfterFunc(ctx, a.cancel)
	defer stop()
	privateCtx := telemetry.PrivateContext(a.ctx, ctx)
	qualified := contract.GenesisQualifiedKeysCore{InitID: decoded.Context.InitID, DescriptorDigest: decoded.Context.DescriptorDigest, RequestCoreDigest: decoded.Context.RequestDescriptor.Digest, GenesisPlanDigest: decoded.Context.GenesisPlanDigest}
	for _, row := range decoded.Bindings {
		if code := sessionCancellation(ctx, a.session); code != contract.CryptoSuccess {
			reply.ResultCode = code
			return reply
		}
		result := a.publicRoutes[row.Binding.BindingID].Qualify(privateCtx, row.Binding)
		expected := contract.PublicKeyQualificationUseCount(row.Binding.Provider)
		if expected == 0 || !appendKeyUses(&reply, row, contract.KeyUsePublicKeyRead, result.Uses, uint64(expected)) {
			reply.ResultCode = contract.CryptoResponseUnknown
			return reply
		}
		if result.Status != KeyOK {
			reply.ResultCode = keyResultCode(result.Status)
			return reply
		}
		if result.Uses != (KeyUses{Completed: expected}) {
			reply.ResultCode = contract.CryptoResponseUnknown
			return reply
		}
		fields, err := qualifiedBinding(row)
		if err != nil {
			reply.ResultCode = contract.CryptoInvalidInput
			return reply
		}
		qualified.Public = append(qualified.Public, fields)
	}
	for _, probe := range decoded.Probes {
		if code := sessionCancellation(ctx, a.session); code != contract.CryptoSuccess {
			reply.ResultCode = code
			return reply
		}
		index := slices.IndexFunc(decoded.Bindings, func(row contract.BindingTableRow) bool { return row.Binding.BindingID == probe.BindingID })
		if index < 0 {
			return reply
		}
		row := decoded.Bindings[index]
		code, uses := probeInit(privateCtx, decoded.Context, a.support, probe, row, a.privateRoutes[probe.BindingID])
		if !appendKeyUses(&reply, row, contract.KeyUsePrivateRoleProbe, uses, 1) {
			reply.ResultCode = contract.CryptoResponseUnknown
			return reply
		}
		if code != contract.CryptoSuccess {
			reply.ResultCode = code
			return reply
		}
		fields, err := qualifiedBinding(row)
		if err != nil {
			reply.ResultCode = contract.CryptoInvalidInput
			return reply
		}
		qualified.Private = append(qualified.Private, contract.QualifiedSuccessorRow{ProbeID: probe.ProbeID, QualifiedBindingFields: fields})
	}
	if code := sessionCancellation(ctx, a.session); code != contract.CryptoSuccess {
		reply.ResultCode = code
		return reply
	}
	reply.Body, err = contract.EncodeCryptoQualifyInitKeysResult(qualified)
	if err != nil {
		reply.Body = nil
		reply.ResultCode = contract.CryptoResponseUnknown
		return reply
	}
	reply.ResultCode = contract.CryptoSuccess
	return reply
}

func qualifiedBinding(row contract.BindingTableRow) (contract.QualifiedBindingFields, error) {
	digest, err := contract.PublicBindingDigest(row.Binding)
	if err != nil {
		return contract.QualifiedBindingFields{}, err
	}
	return contract.QualifiedBindingFields{SubjectKind: row.SubjectKind, SubjectID: row.SubjectID, BindingID: row.Binding.BindingID, PublicBindingDigest: digest, Provider: row.Binding.Provider, Qualified: 1}, nil
}

func keyResultCode(status KeyStatus) contract.CryptoResultCode {
	switch status {
	case KeyCancelled:
		return contract.CryptoCancelled
	case KeyUnknown:
		return contract.CryptoResponseUnknown
	case KeyUnavailable:
		return contract.CryptoCustodyUnavailable
	default:
		return contract.CryptoPrivateRouteUnavailable
	}
}

func appendKeyUses(reply *contract.CryptoResponse, row contract.BindingTableRow, purpose uint8, uses KeyUses, limit uint64) bool {
	usesByOutcome := [...]struct {
		count   uint32
		outcome uint8
	}{
		{uses.Completed, contract.KeyUseCompleted},
		{uses.Denied, contract.KeyUseDenied},
		{uses.Failed, contract.KeyUseFailed},
		{uses.Unknown, contract.KeyUseUnknown},
	}
	var total uint64
	for _, use := range usesByOutcome {
		total += uint64(use.count)
	}
	if total > limit {
		return false
	}
	digest, err := contract.PublicBindingDigest(row.Binding)
	if err != nil {
		return false
	}
	for _, counted := range usesByOutcome {
		n := counted.count
		if n > 0 {
			use := contract.KeyUseRow{BindingID: row.Binding.BindingID, PublicBindingDigest: digest, SubjectKind: row.SubjectKind, SubjectID: row.SubjectID, Provider: row.Binding.Provider, Purpose: purpose, Outcome: counted.outcome, Count: n}
			found := false
			for j, previous := range reply.KeyUseRows {
				previous.Count = n
				if previous != use {
					continue
				}
				count := uint64(reply.KeyUseRows[j].Count) + uint64(n)
				if count > 1<<32-1 {
					return false
				}
				reply.KeyUseRows[j].Count = uint32(count)
				found = true
				break
			}
			if !found {
				reply.KeyUseRows = append(reply.KeyUseRows, use)
			}
		}
	}
	slices.SortFunc(reply.KeyUseRows, func(a, b contract.KeyUseRow) int {
		for _, pair := range [][2]contract.ID{{a.BindingID, b.BindingID}, {a.PublicBindingDigest, b.PublicBindingDigest}} {
			if n := bytes.Compare(pair[0][:], pair[1][:]); n != 0 {
				return n
			}
		}
		if a.SubjectKind != b.SubjectKind {
			return int(a.SubjectKind) - int(b.SubjectKind)
		}
		if n := bytes.Compare(a.SubjectID[:], b.SubjectID[:]); n != 0 {
			return n
		}
		if a.Provider != b.Provider {
			return int(a.Provider) - int(b.Provider)
		}
		if a.Purpose != b.Purpose {
			return int(a.Purpose) - int(b.Purpose)
		}
		return int(a.Outcome) - int(b.Outcome)
	})
	maximum := contract.KeyUseRowsMaxCount
	if reply.Kind == contract.CryptoQualifyInitKeys {
		maximum = contract.InitKeyUseRowsMaxCount
	}
	return len(reply.KeyUseRows) <= maximum
}

func probeInit(ctx context.Context, admitted contract.InitKeyContext, support contract.ID, probe contract.InitProbePlanRow, row contract.BindingTableRow, route KeyAccess) (contract.CryptoResultCode, KeyUses) {
	material, err := contract.GenesisKEKProbeMaterialDigest(contract.GenesisKEKProbeCore{Schema: contract.CanonicalSchema, Profile: 2, ProbeID: probe.ProbeID, Context: admitted, SubjectKind: probe.SubjectKind, SubjectID: probe.SubjectID, PublicBindingDigest: probe.PublicBindingDigest})
	if err != nil {
		return contract.CryptoInvalidInput, KeyUses{}
	}
	core := contract.WrapCore{Schema: contract.CanonicalSchema, Profile: 2, DomainID: admitted.DomainID, CompatibilityID: admitted.CompatibilityID, CryptoSupportID: support, MaterialKind: contract.ProofMaterialKind, MaterialID: probe.ProbeID, MaterialContextDigest: material, SubjectKind: probe.SubjectKind, SubjectID: probe.SubjectID, BindingID: row.Binding.BindingID, BindingSerial: row.Binding.BindingSerial, PublicBindingDigest: probe.PublicBindingDigest, Provider: row.Binding.Provider, WrapProfile: 2, PacketKind: 4, PacketLength: contract.SingleKeyMaterialPacketLength}
	return probeKEK(ctx, core, row.Binding, route)
}
