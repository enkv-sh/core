package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (c *Comparison) secretPages() (pages [contract.MaxValueEntryPages]bool) {
	var occupied [contract.MaxValueEntryPages]bool
	for i, v := range c.desiredEntries {
		if v.ConfidentialityClass == format.Secret {
			index := c.slots[i] / format.PageSlots
			occupied[index] = true
			if slices.Contains(c.changed, c.slots[i]) {
				pages[index] = true
			}
		}
	}
	for _, slot := range c.removed {
		if c.session.valueEntry(slot).ConfidentialityClass == format.Secret {
			pages[slot/format.PageSlots] = true
		}
	}
	for i := range pages {
		pages[i] = pages[i] && occupied[i]
	}
	return pages
}

// The private parent fixes the plan before Crypto creates canonical material.
// Its later lifecycle admission binds these exact public preparation facts.
func (s *StateSession) prepareCompared(ctx context.Context, c *Comparison, p transitionPlan) Result {
	if c == nil || c.session != s || c.operation == nil || c.operation.terminal || !c.preparedPlan.Digest.IsZero() {
		return refused(AdmissionInvalid)
	}
	if err := s.validPlan(ctx, c, p); err != nil {
		if readFailure, ok := selectedReadResult(err); ok {
			return readFailure
		}
		return refused(AdmissionInvalid)
	}
	plan := identityPlan(c, p)
	identity, err := contract.IdentityPlanDescriptor(plan)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	planBody, err := contract.EncodeIdentityPlan(plan)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	q := contract.CryptoPrepareRequest{OperationRef: c.operation.operationRef, Context: c.operation.context, IdentityPlan: planBody}
	body, err := contract.EncodeCryptoPrepareRequest(q)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	opens, wraps, ok := prepareKeyUseCounts(c, p)
	if !ok {
		c.operation.terminal = true
		return refused(AdmissionInvalid)
	}
	c.operation.source.OperationID = plan.Operation
	c.operation.sourceCount, c.operation.wrapCounts = opens, wraps
	reply, res := c.operation.exchange(ctx, contract.CryptoPrepare, body)
	if res.Outcome != 0 {
		return res
	}
	view, err := contract.InspectCryptoPrepareResult(reply.Body)
	if err != nil {
		c.operation.terminal = true
		return refused(AdmissionInvalid)
	}
	rows, err := view.Own()
	if err != nil || !preparedMatches(c, p, rows) {
		c.operation.terminal = true
		return refused(AdmissionInvalid)
	}
	c.preparedRows, c.preparedPlan = rows, identity
	return Result{}
}

func prepareKeyUseCounts(c *Comparison, p transitionPlan) (uint32, map[contract.ID]uint32, bool) {
	if c == nil || c.session == nil || c.operation == nil {
		return 0, nil, false
	}
	wraps := make(map[contract.ID]uint32, len(c.operation.bindings))
	var opens uint32
	for i, intent := range c.intent {
		if intent.ConfidentialityClass != format.Secret || !slices.Contains(c.changed, c.slots[i]) {
			continue
		}
		slot := c.slots[i]
		if _, fresh := p.values[slot]; fresh {
			opens++
			for _, binding := range c.operation.bindings {
				if binding.SubjectKind == contract.RecoveryWrapSubject || slices.Contains(intent.Recipients, binding.SubjectID) {
					wraps[binding.Binding.BindingID]++
				}
			}
			continue
		}
		before := c.session.valueEntry(slot)
		if before == nil {
			return 0, nil, false
		}
		opens++
		var selected contract.AccessRecord
		if c.support != nil {
			_, _, old, ok := c.session.selectedValue(slot)
			if !ok {
				return 0, nil, false
			}
			selected = old
		}
		for _, binding := range c.operation.bindings {
			preserved := slices.Contains(before.Recipients, binding.SubjectID)
			if c.support != nil {
				preserved = slices.ContainsFunc(selected.Wraps, func(w contract.WrapRow) bool {
					return w.SubjectKind == binding.SubjectKind && w.SubjectID == binding.SubjectID
				})
			}
			if binding.SubjectKind == contract.OrdinaryWrapSubject && slices.Contains(intent.Recipients, binding.SubjectID) && !preserved {
				wraps[binding.Binding.BindingID]++
			}
		}
	}
	return opens, wraps, true
}

func preparedMatches(c *Comparison, p transitionPlan, rows []contract.CryptoPreparedSecret) bool {
	index := 0
	for i, intent := range c.intent {
		if intent.ConfidentialityClass != format.Secret || !slices.Contains(c.changed, c.slots[i]) {
			continue
		}
		if index >= len(rows) {
			return false
		}
		row := rows[index]
		index++
		if row.Name != intent.Name || row.Slot != c.slots[i] {
			return false
		}
		m, err := contract.DecodeValueEntry(row.EntryBytes)
		incarnation, added := p.incarnations[row.Slot]
		if !added {
			incarnation = c.session.valueEntry(row.Slot).Incarnation
		}
		if err != nil || m.Name != intent.Name || m.ValueSource != intent.ValueSource || m.ConfidentialityClass != intent.ConfidentialityClass || m.InputEncoding != intent.InputEncoding || m.OutputEncoding != intent.OutputEncoding || !slices.Equal(m.Recipients, intent.Recipients) || m.Incarnation != incarnation {
			return false
		}
		if value, fresh := p.values[row.Slot]; fresh {
			if m.ValueState != value || m.OriginSnapshot != p.snapshot || m.OriginTransition != p.transition {
				return false
			}
			if m.ValueSource == contract.Generated {
				old := c.session.valueEntry(row.Slot)
				if old == nil || old.ValueSource != contract.Generated {
					return false
				}
				expected := old.Generated
				expected.GenerationID = value
				if m.Generated != expected {
					return false
				}
			}
		} else if !retainedSecretMatches(c.session, row, m) {
			return false
		}
		payload, err := contract.DecodeCanonicalPayload(m.ValueBytes)
		if err != nil || payload.ContentLength != intent.ContentLength || payload.DataKeyEpoch != 1 || payload.CommitmentKeyEpoch != 1 || payload.CryptoSupportID != contract.CryptoSupportID() {
			return false
		}
	}
	return index == len(rows)
}

func retainedSecretMatches(s *StateSession, row contract.CryptoPreparedSecret, after contract.ValueEntry) bool {
	before := s.valueEntry(row.Slot)
	if before == nil || before.Generated != after.Generated || before.ValueState != after.ValueState || before.OriginSnapshot != after.OriginSnapshot || before.OriginTransition != after.OriginTransition || !bytes.Equal(before.ValueBytes, after.ValueBytes) {
		return false
	}
	_, _, oldAccess, ok := s.selectedValue(row.Slot)
	access, err := contract.DecodeAccessRecord(row.AccessRecord)
	if !ok || err != nil || oldAccess.MaterialKind != access.MaterialKind || oldAccess.MaterialID != access.MaterialID || oldAccess.MaterialContextDigest != access.MaterialContextDigest || oldAccess.PackageCheck != access.PackageCheck {
		return false
	}
	for _, old := range oldAccess.Wraps {
		if old.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(after.Recipients, old.SubjectID) {
			continue
		}
		i := slices.IndexFunc(access.Wraps, func(wrap contract.WrapRow) bool {
			return wrap.SubjectKind == old.SubjectKind && wrap.SubjectID == old.SubjectID
		})
		if i < 0 {
			return false
		}
		wrap := access.Wraps[i]
		if wrap.BindingID != old.BindingID || wrap.BindingSerial != old.BindingSerial || wrap.PublicBindingDigest != old.PublicBindingDigest || !bytes.Equal(wrap.RSACiphertext, old.RSACiphertext) {
			return false
		}
	}
	return true
}

func (next *StateSession) deriveAccess(c *Comparison, p transitionPlan) bool {
	if c.operation != nil {
		identity, err := contract.IdentityPlanDescriptor(identityPlan(c, p))
		if err != nil || identity != c.preparedPlan || !preparedMatches(c, p, c.preparedRows) {
			return false
		}
	} else if len(c.preparedRows) != 0 {
		return false
	}
	if c.support != nil {
		return next.deriveNormalGeneratedAccess(c, p)
	}
	for i, value := range c.desiredEntries {
		if value.ConfidentialityClass != format.Secret {
			continue
		}
		slot := c.slots[i]
		index := slot / format.PageSlots
		if p.accessPages[index].IsZero() {
			next.access[index] = c.session.access[index]
			if next.access[index] == nil {
				return false
			}
			continue
		}
		var record contract.AccessRecord
		prepared := slices.IndexFunc(c.preparedRows, func(row contract.CryptoPreparedSecret) bool { return row.Name == value.Name })
		if prepared >= 0 {
			var err error
			record, err = contract.DecodeAccessRecord(c.preparedRows[prepared].AccessRecord)
			if err != nil {
				return false
			}
		} else {
			var ok bool
			_, _, record, ok = c.session.selectedValue(slot)
			if !ok {
				return false
			}
		}
		if next.access[index] == nil {
			next.access[index] = &format.AccessPage{Domain: next.admission.domain, Object: p.accessPages[index], Index: index}
		}
		next.access[index].Records = append(next.access[index].Records, record)
	}
	var records []contract.AccessRecord
	next.root.CurrentAccess.Core.AccessPageRefs = nil
	for index, page := range next.access {
		if page == nil {
			continue
		}
		if !p.accessPages[index].IsZero() {
			slices.SortFunc(page.Records, func(a, b contract.AccessRecord) int { return bytes.Compare(a.MaterialID[:], b.MaterialID[:]) })
		}
		body, err := format.EncodeAccessPage(*page)
		if err != nil {
			return false
		}
		ref, err := format.Reference(format.AccessKind, next.admission.domain, page.Object, page.Index, body)
		if err != nil {
			return false
		}
		next.root.CurrentAccess.Core.AccessPageRefs = append(next.root.CurrentAccess.Core.AccessPageRefs, ref)
		next.root.ChildCount++
		records = append(records, page.Records...)
	}
	slices.SortFunc(records, func(a, b contract.AccessRecord) int { return bytes.Compare(a.MaterialID[:], b.MaterialID[:]) })
	d, err := contract.AccessRecordsDescriptor(next.admission.domain, records)
	if err != nil {
		return false
	}
	next.root.AccessRecordCount = uint32(len(records))
	next.root.CurrentAccess.Core.AccessRecordsDescriptor = d
	before, err := contract.EncodeCurrentAccessCore(c.session.root.CurrentAccess.Core)
	if err != nil {
		return false
	}
	// Compare access meaning at the predecessor generation. The selected
	// generation changes once even when several access fields change together.
	next.root.CurrentAccess.Core.AccessGeneration = c.session.root.CurrentAccess.Core.AccessGeneration
	after, err := contract.EncodeCurrentAccessCore(next.root.CurrentAccess.Core)
	if err != nil {
		return false
	}
	if !bytes.Equal(before, after) {
		if err := contract.AdvanceAccessGeneration(&next.root.CurrentAccess.Core, p.transition); err != nil {
			return false
		}
	}
	next.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(next.root.CurrentAccess.Core)
	return err == nil
}

func (s *StateSession) publicProjection() (contract.PublicState, error) {
	return s.publicStateProjection()
}

func (s *StateSession) freezeAndClaim(ctx context.Context, c *Comparison, p transitionPlan, next *StateSession, authority lifecycleAuthority) Result {
	op := c.operation
	public, err := next.publicProjection()
	if err != nil {
		return refused(AdmissionInvalid)
	}
	publicBody, err := contract.EncodePublicState(public)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	publicDescriptor, err := contract.PublicStateDescriptor(public)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	canonical, err := contract.CryptoPreparedRowsDescriptor(c.preparedRows)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	exclusions, err := contract.EncodeExclusions(s.admission.domain, authority.exclusion.Rows)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	exclusionDescriptor, err := contract.ExclusionDescriptor(s.admission.domain, authority.exclusion.Rows)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	identity, err := contract.IdentityPlanDescriptor(identityPlan(c, p))
	if err != nil || identity != c.preparedPlan {
		return refused(AdmissionInvalid)
	}
	q := contract.CryptoFreezeRequest{OperationRef: op.operationRef, Context: op.context, IdentityPlanDescriptor: identity, CanonicalRowsDescriptor: canonical, CandidatePublicState: publicBody, Exclusions: exclusions, Recipients: next.registry()}
	body, err := contract.EncodeCryptoFreezeRequest(q)
	if err != nil {
		return refused(AdmissionInvalid)
	}
	reply, res := op.exchange(ctx, contract.CryptoFreeze, body)
	if res.Outcome != 0 {
		return res
	}
	frozen, err := contract.DecodeCryptoFreezeResult(reply.Body)
	if err != nil {
		op.terminal = true
		return refused(AdmissionInvalid)
	}
	facts := contract.CryptoFactsPreimage{CustodyInstanceID: op.instance, OperationRef: op.operationRef, Context: op.context, ComparisonOrCoverageDigest: op.comparisonDigest, IdentityPlanDescriptor: identity, CandidatePublicStateDescriptor: publicDescriptor, CanonicalRowsDescriptor: canonical, ExclusionDescriptor: exclusionDescriptor}
	digest, err := contract.CryptoFactsDigest(facts)
	if err != nil || frozen.FactDigest != digest {
		op.terminal = true
		return refused(AdmissionInvalid)
	}
	claim := contract.CryptoClaimRequest{OperationRef: op.operationRef, Context: op.context, IdentityPlanDescriptor: identity, CandidatePublicStateDescriptor: publicDescriptor, CanonicalRowsDescriptor: canonical, ExclusionDescriptor: exclusionDescriptor, FactDigest: digest}
	body, err = contract.EncodeCryptoClaimRequest(claim)
	if err != nil {
		op.terminal = true
		return refused(AdmissionInvalid)
	}
	_, res = op.exchange(ctx, contract.CryptoClaim, body)
	return res
}
