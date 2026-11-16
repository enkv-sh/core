package crypto

import (
	"bytes"
	"slices"
	"strings"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (a *applyAdmission) checkIdentityPlan(plan contract.IdentityPlan, currentRows []applyCurrent) bool {
	if a.request.SecretAccess != nil {
		target := a.request.SecretAccess.Target
		if len(plan.Rows) != 1 || plan.Rows[0].Name != target.Name || plan.Rows[0].Slot != target.Slot || plan.Rows[0].Incarnation != target.Incarnation {
			return false
		}
	}
	if a.request.Retirement != nil && !a.checkRetirementIdentityPlan(plan, currentRows) {
		return false
	}
	if a.request.SecretAccess != nil || a.request.Retirement != nil {
		for _, current := range currentRows {
			if plan.Snapshot == current.entry.OriginSnapshot || plan.Transition == current.entry.OriginTransition {
				return false
			}
		}
	}
	if a.registryChanged {
		rows := make([]contract.RecipientRecord, len(a.request.Recipients))
		for i, input := range a.request.Recipients {
			rows[i] = input.Recipient
		}
		if _, _, err := format.ApplyRecipientPages(a.request.Context.DomainID, rows, plan); err != nil {
			return false
		}
	} else if slices.ContainsFunc(plan.Pages, func(page contract.IdentityPage) bool { return page.Kind == contract.RecipientKind }) {
		return false
	}
	beforeRows := slices.Clone(a.plainBefore)
	for _, current := range currentRows {
		beforeRows = append(beforeRows, contract.MembershipRow{Name: current.entry.Name, Slot: current.row.Slot, Incarnation: current.entry.Incarnation, EntryDigest: current.entryDigest, Recipients: current.entry.Recipients})
		for _, proposed := range plan.Rows {
			if proposed.ValueState == current.entry.ValueState {
				return false
			}
		}
	}
	predecessor, err := contract.DecodeRef(a.request.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil || plan.Snapshot == predecessor.Object {
		return false
	}
	for i, row := range plan.Rows {
		if !slices.ContainsFunc(a.request.Intent, func(intent contract.CryptoIntentRow) bool { return intent.Name == row.Name }) || row.OriginSnapshot != plan.Snapshot || row.OriginTransition != plan.Transition {
			return false
		}
		before := slices.IndexFunc(beforeRows, func(before contract.MembershipRow) bool { return before.Name == row.Name })
		if before >= 0 {
			if row.Slot != beforeRows[before].Slot {
				return false
			}
			changed := a.sourceChanged(row.Name)
			if changed {
				if a.supportTransition == nil || row.Incarnation == beforeRows[before].Incarnation {
					return false
				}
				current := slices.IndexFunc(a.supportTransition.CurrentGenerated, func(c contract.GeneratedSupportCurrent) bool {
					m, err := contract.InspectValueEntry(c.EntryBytes)
					return err == nil && string(m.Name) == row.Name && m.Incarnation == beforeRows[before].Incarnation && m.ValueSource == contract.Generated
				})
				if current < 0 {
					return false
				}
				m, _ := contract.InspectValueEntry(a.supportTransition.CurrentGenerated[current].EntryBytes)
				switch m.Generated.SemanticLifecycleMode() {
				case contract.GeneratorLifecycleNone:
				case contract.GeneratorLifecycleManaged:
					if !slices.ContainsFunc(a.supportTransition.Handoffs, func(h contract.GeneratedSupportHandoff) bool { return int(h.Current) == current }) {
						return false
					}
				default:
					return false
				}
			} else if row.Incarnation != beforeRows[before].Incarnation {
				return false
			}
		}
		for _, prior := range plan.Rows[:i] {
			if row.Incarnation == prior.Incarnation || row.ValueState == prior.ValueState {
				return false
			}
		}
		for _, prior := range beforeRows {
			if (prior.Name != row.Name || a.sourceChanged(row.Name)) && row.Incarnation == prior.Incarnation {
				return false
			}
			if prior.Name != row.Name && row.Slot == prior.Slot && slices.ContainsFunc(a.request.Intent, func(intent contract.CryptoIntentRow) bool { return intent.Name == prior.Name }) {
				return false
			}
		}
	}
	for _, intent := range a.request.Intent {
		fresh := slices.ContainsFunc(plan.Rows, func(row contract.IdentityRow) bool { return row.Name == intent.Name })
		before := slices.ContainsFunc(beforeRows, func(row contract.MembershipRow) bool { return row.Name == intent.Name })
		if !fresh && !before {
			return false
		}
		if a.request.Retirement != nil {
			continue
		}
		if intent.ConfidentialityClass == contract.Secret {
			if a.request.SecretAccess != nil {
				if fresh != (intent.Name == a.request.SecretAccess.Target.Name) {
					return false
				}
				continue
			}
			index := slices.IndexFunc(a.comparison, func(row contract.CryptoComparisonRow) bool { return row.Name == intent.Name })
			if index < 0 {
				return false
			}
			row := a.comparison[index]
			if fresh != (a.sourceChanged(intent.Name) || row.Relation == contract.CryptoAdded || row.Relation == contract.CryptoChanged || !row.ExclusionPathDigest.IsZero()) {
				return false
			}
		}
	}
	return true
}

func (a *applyAdmission) expectedExclusions(currentRows []applyCurrent) ([]contract.ExclusionRow, error) {
	var rows []contract.ExclusionRow
	for _, before := range a.plainBefore {
		index := slices.IndexFunc(a.request.Intent, func(intent contract.CryptoIntentRow) bool { return intent.Name == before.Name })
		var after []contract.ID
		if index >= 0 {
			after = a.request.Intent[index].Recipients
		}
		var removed []contract.ID
		for _, recipient := range before.Recipients {
			if !slices.Contains(after, recipient) {
				removed = append(removed, recipient)
			}
		}
		if len(removed) == 0 {
			continue
		}
		path, err := contract.PlainExclusionDigest(contract.PlainExclusionPath{Domain: a.request.Context.DomainID, Name: before.Name, Slot: before.Slot, Incarnation: before.Incarnation, EntryDigest: before.EntryDigest, RemovedRecipients: removed})
		if err != nil {
			return nil, err
		}
		rows = append(rows, contract.ExclusionRow{MembershipRow: contract.MembershipRow{Name: before.Name, Slot: before.Slot, Incarnation: before.Incarnation, EntryDigest: before.EntryDigest, Recipients: removed}, Path: path})
	}
	for _, current := range currentRows {
		removed := a.removedRecipients(current.entry)
		if len(removed) == 0 {
			continue
		}
		index := slices.IndexFunc(a.comparison, func(row contract.CryptoComparisonRow) bool { return row.Name == current.entry.Name })
		if index < 0 || a.comparison[index].ExclusionPathDigest.IsZero() {
			return nil, contract.ErrRecord
		}
		rows = append(rows, contract.ExclusionRow{MembershipRow: contract.MembershipRow{Name: current.entry.Name, Slot: current.row.Slot, Incarnation: current.entry.Incarnation, EntryDigest: current.entryDigest, Recipients: removed}, Path: a.comparison[index].ExclusionPathDigest})
	}
	slices.SortFunc(rows, func(a, b contract.ExclusionRow) int { return strings.Compare(a.Name, b.Name) })
	return rows, nil
}

func (a *applyAdmission) freeze(instance contract.ID, q contract.CryptoFreezeRequest, reply *contract.CryptoResponse) contract.CryptoResultCode {
	if a.receiptRequired && a.receipt == nil {
		return contract.CryptoInvalidAdmission
	}
	if q.IdentityPlanDescriptor != a.identityDescriptor || q.CanonicalRowsDescriptor != a.preparedDescriptor || !a.candidateRecipientsEqual(q.Recipients) {
		return contract.CryptoInvalidAdmission
	}
	publicView, err := contract.InspectPublicState(q.CandidatePublicState, q.Context.DomainID)
	if err != nil {
		return contract.CryptoInvalidInput
	}
	public, err := publicView.Own()
	if err != nil || public.AccessRoot.IsZero() || len(public.Rows) != len(a.request.Intent) {
		return contract.CryptoInvalidInput
	}
	expectedSupport := a.requiredSupport
	if a.supportTransition != nil {
		rows, err := a.supportTransition.SupportAfter(a.plan, a.request.Intent)
		if err != nil {
			return contract.CryptoInvalidInput
		}
		expectedSupport, err = contract.RequiredSupportDescriptorFromDigests(q.Context.DomainID, rows.Facts)
		if err != nil {
			return contract.CryptoInvalidInput
		}
		access, err := a.supportTransition.AccessAfter(a.request.Intent, a.request.Current, a.prepared)
		if err != nil {
			return contract.CryptoInvalidInput
		}
		core, _, err := a.supportTransition.AccessCoreAfter(access, a.plan)
		if err != nil {
			return contract.CryptoInvalidInput
		}
		if a.registryChanged {
			_, refs, err := format.ApplyRecipientPages(q.Context.DomainID, q.Recipients, a.plan)
			if err != nil {
				return contract.CryptoInvalidInput
			}
			descriptor, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: q.Context.DomainID, Refs: refs})
			if err != nil {
				return contract.CryptoInvalidInput
			}
			if core.RecipientRefsDescriptor != descriptor {
				core.RecipientRefsDescriptor = descriptor
				if core.AccessRecordsDescriptor == a.supportTransition.BeforeAccess.AccessRecordsDescriptor {
					if err := contract.AdvanceAccessGeneration(&core, a.plan.Transition); err != nil {
						return contract.CryptoInvalidInput
					}
				}
			}
		}
		root, err := contract.AccessRoot(core)
		if err != nil || root != public.AccessRoot {
			return contract.CryptoInvalidInput
		}
	}
	if a.receipt != nil {
		descriptor, err := contract.PublicStateDescriptor(public)
		if err != nil || descriptor != a.receipt.candidate {
			return contract.CryptoInvalidInput
		}
		expectedSupport = a.receipt.support
	}
	if public.RequiredSupport != expectedSupport {
		return contract.CryptoInvalidInput
	}
	currentRows, ok := a.currentRows()
	if !ok {
		return contract.CryptoInvalidInput
	}
	for i, row := range public.Rows {
		intent := a.request.Intent[i]
		if row.Name != intent.Name || row.EntryDigest.IsZero() {
			return contract.CryptoInvalidInput
		}
		if intent.ConfidentialityClass == contract.Secret {
			index := slices.IndexFunc(a.prepared, func(prepared contract.CryptoPreparedSecret) bool { return prepared.Name == row.Name })
			if index < 0 {
				found := false
				for _, current := range currentRows {
					if current.entry.Name != row.Name || row.Slot != current.row.Slot || !slices.Equal(intent.Recipients, current.entry.Recipients) {
						continue
					}
					expected := current.entry
					expected.OutputEncoding = intent.OutputEncoding
					digest, err := contract.PublicValueEntryDigest(q.Context.DomainID, row.Slot, expected)
					if err != nil {
						return contract.CryptoInvalidInput
					}
					found = row.EntryDigest == digest
					break
				}
				if !found {
					return contract.CryptoInvalidInput
				}
				continue
			}
			if row.Slot != a.prepared[index].Slot {
				return contract.CryptoInvalidInput
			}
			entry, err := contract.DecodeValueEntry(a.prepared[index].EntryBytes)
			if err != nil {
				return contract.CryptoCustodyUnavailable
			}
			digest, err := contract.PublicValueEntryDigest(q.Context.DomainID, row.Slot, entry)
			if err != nil || digest != row.EntryDigest {
				return contract.CryptoInvalidInput
			}
			continue
		}
		identity := slices.IndexFunc(a.plan.Rows, func(identity contract.IdentityRow) bool { return identity.Name == row.Name })
		before := slices.IndexFunc(a.plainBefore, func(before contract.MembershipRow) bool { return before.Name == row.Name })
		if identity >= 0 {
			if row.Slot != a.plan.Rows[identity].Slot {
				return contract.CryptoInvalidInput
			}
		} else if before < 0 || row.Slot != a.plainBefore[before].Slot {
			return contract.CryptoInvalidInput
		}
		if a.request.SecretAccess != nil && row.EntryDigest != a.plainBefore[before].EntryDigest {
			return contract.CryptoInvalidInput
		}
		if a.request.Retirement != nil {
			changed := slices.Contains(a.plainBefore[before].Recipients, a.request.Retirement.RecipientID)
			if (row.EntryDigest != a.plainBefore[before].EntryDigest) != changed {
				return contract.CryptoInvalidInput
			}
		}
		// Core checks complete plain bodies, input digests and membership. Crypto
		// binds the supplied exact public digest; it does not reconstruct omitted
		// plain bodies or authenticate the Root/access-page closure here.
	}
	expected, err := a.expectedExclusions(currentRows)
	if err != nil {
		return contract.CryptoInvalidInput
	}
	exclusionBody, err := contract.EncodeExclusions(q.Context.DomainID, expected)
	if err != nil || !bytes.Equal(exclusionBody, q.Exclusions) {
		return contract.CryptoInvalidInput
	}
	exclusion, err := contract.ExclusionDescriptor(q.Context.DomainID, expected)
	if err != nil {
		return contract.CryptoInvalidInput
	}
	facts := contract.CryptoFactsPreimage{CustodyInstanceID: instance, OperationRef: a.operationRef, Context: a.request.Context, ComparisonOrCoverageDigest: a.comparisonDigest, IdentityPlanDescriptor: a.identityDescriptor, CandidatePublicStateDescriptor: publicView.Descriptor, CanonicalRowsDescriptor: a.preparedDescriptor, ExclusionDescriptor: exclusion}
	digest, err := contract.CryptoFactsDigest(facts)
	if err != nil {
		return contract.CryptoInvalidInput
	}
	body, err := contract.EncodeCryptoFreezeResult(contract.CryptoFreezeResult{FactDigest: digest})
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	a.frozen = contract.CryptoClaimRequest{OperationRef: a.operationRef, Context: a.request.Context, IdentityPlanDescriptor: a.identityDescriptor, CandidatePublicStateDescriptor: publicView.Descriptor, CanonicalRowsDescriptor: a.preparedDescriptor, ExclusionDescriptor: exclusion, FactDigest: digest}
	reply.Body = body
	return contract.CryptoSuccess
}
