package crypto

import (
	"context"
	"crypto/rand"
	"slices"
	"strings"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func (a *applyAdmission) openSealedInput(ctx context.Context, route KeyAccess, index int, reply *contract.CryptoResponse) ([]byte, contract.CryptoResultCode) {
	if ctx.Err() != nil {
		return nil, contract.CryptoCancelled
	}
	if route == nil || route.Family() != a.control.Provider || route.CredentialRoute() != a.routeID {
		return nil, contract.CryptoPrivateRouteUnavailable
	}
	view, err := contract.InspectSealedInputEnvelope(a.request.SealedInputs[index].EnvelopeBytes)
	if err != nil {
		return nil, contract.CryptoSourceAuthenticationFailed
	}
	authority := a.request.Bindings[a.authorityIndex]
	core := a.sealedInputCores[index]
	envelope := contract.SealedInputEnvelope{Core: core, Nonce: view.Nonce, Ciphertext: view.Ciphertext, AuthorityWrap: contract.WrapRow(view.AuthorityWrap)}
	plain, uses, code := authenticatedSealedValue(ctx, route, authority, core, envelope)
	if !appendKeyUses(reply, authority, contract.KeyUseMaterialOpen, uses, 1) {
		if plain != nil {
			clear(plain[:cap(plain)])
		}
		return nil, contract.CryptoResponseUnknown
	}
	return plain, code
}

func (a *applyAdmission) compare(ctx context.Context, route KeyAccess, reply *contract.CryptoResponse) contract.CryptoResultCode {
	rows := make([]contract.CryptoComparisonRow, 0, len(a.request.Current)+len(a.sealedInputCores))
	used := make([]bool, len(a.request.SealedInputs))
	for _, before := range a.request.Current {
		current, ok := a.current(before)
		if !ok {
			return contract.CryptoStoredAuthenticationFailed
		}
		if !a.currentPrivateTarget(current) {
			continue
		}
		inputIndex := slices.IndexFunc(a.request.SealedInputs, func(row contract.CryptoSealedInput) bool { return row.Name == current.entry.Name })
		row, code := a.compareCurrent(ctx, route, current, inputIndex, reply)
		if code != contract.CryptoSuccess {
			return code
		}
		if inputIndex >= 0 {
			used[inputIndex] = true
		}
		rows = append(rows, row)
	}
	for inputIndex, source := range a.request.SealedInputs {
		if used[inputIndex] {
			continue
		}
		plain, code := a.openSealedInput(ctx, route, inputIndex, reply)
		if plain != nil {
			clear(plain[:cap(plain)])
		}
		if code != contract.CryptoSuccess {
			return code
		}
		index := slices.IndexFunc(a.request.Intent, func(intent contract.CryptoIntentRow) bool { return intent.Name == source.Name })
		intent := a.request.Intent[index]
		rows = append(rows, contract.CryptoComparisonRow{Name: intent.Name, AfterPresent: true, Relation: contract.CryptoAdded, SourceDigest: intent.PayloadDigest, AfterRawLength: intent.ContentLength})
	}
	slices.SortFunc(rows, func(a, b contract.CryptoComparisonRow) int { return strings.Compare(a.Name, b.Name) })
	descriptor, err := contract.CryptoComparisonDescriptor(rows)
	if err != nil {
		return contract.CryptoInvalidInput
	}
	var operation contract.ID
	_, _ = rand.Read(operation[:])
	if operation.IsZero() {
		return contract.CryptoCustodyUnavailable
	}
	body, err := contract.EncodeCryptoCompareResult(contract.CryptoCompareResult{OperationRef: operation, Rows: rows, ComparisonDigest: descriptor.Digest})
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	a.operationRef, a.comparisonDigest, a.comparison = operation, descriptor.Digest, rows
	reply.Body = body
	return contract.CryptoSuccess
}

func (a *applyAdmission) compareCurrent(ctx context.Context, route KeyAccess, current applyCurrent, inputIndex int, reply *contract.CryptoResponse) (contract.CryptoComparisonRow, contract.CryptoResultCode) {
	row := contract.CryptoComparisonRow{Name: current.entry.Name, BeforePresent: true, Relation: contract.CryptoRemoved, BeforePublicEntryDigest: current.entryDigest}
	keys, code := a.openCurrent(ctx, route, current, reply)
	if keys != nil {
		defer clear(keys[:cap(keys)])
	}
	if code != contract.CryptoSuccess {
		return row, code
	}
	if inputIndex >= 0 {
		plain, code := a.openSealedInput(ctx, route, inputIndex, reply)
		if plain != nil {
			defer clear(plain[:cap(plain)])
		}
		if code != contract.CryptoSuccess {
			return row, code
		}
		equal, err := custody.EqualValue(current.core, current.payload, keys, plain)
		if err != nil {
			return row, contract.CryptoStoredAuthenticationFailed
		}
		intentIndex := slices.IndexFunc(a.request.Intent, func(intent contract.CryptoIntentRow) bool { return intent.Name == row.Name })
		if intentIndex < 0 {
			return row, contract.CryptoInvalidAdmission
		}
		intent := a.request.Intent[intentIndex]
		equal = equal && intent.InputEncoding == current.core.InputEncoding && intent.ContentLength == current.core.ContentLength && intent.RetainedLength == current.core.RetainedLength
		if !equal && slices.Contains(a.equalOnlySources, current.entry.Name) {
			return row, contract.CryptoInvalidInput
		}
		row.AfterPresent, row.Relation = true, contract.CryptoChanged
		if equal {
			row.Relation = contract.CryptoEqual
		}
		index := slices.IndexFunc(a.request.Intent, func(intent contract.CryptoIntentRow) bool { return intent.Name == row.Name })
		row.SourceDigest, row.AfterRawLength = a.request.Intent[index].PayloadDigest, a.request.Intent[index].ContentLength
	} else {
		index := slices.IndexFunc(a.request.Intent, func(intent contract.CryptoIntentRow) bool {
			return intent.Name == row.Name && (intent.ValueSource == contract.Generated || intent.Retained != (contract.RetainedSecretInput{}))
		})
		if index >= 0 {
			row.AfterPresent, row.Relation = true, contract.CryptoEqual
			row.SourceDigest, row.AfterRawLength = a.request.Intent[index].PayloadDigest, a.request.Intent[index].ContentLength
		}
	}
	removed := a.removedRecipients(current.entry)
	if len(removed) != 0 {
		var err error
		row.ExclusionPathDigest, err = contract.SecretExclusionDigest(contract.SecretExclusionPath{Core: current.core, EntryDigest: current.entryDigest, SemanticCommitment: current.payload.SemanticCommitment, RemovedRecipients: removed, ActingRecipient: a.control.AuthorityRecipientID, BeforeAccessRoot: a.request.Context.CurrentAccessRoot})
		if err != nil {
			return row, contract.CryptoStoredAuthenticationFailed
		}
	}
	return row, contract.CryptoSuccess
}

func (a *applyAdmission) prepare(ctx context.Context, route KeyAccess, q contract.CryptoPrepareRequest, reply *contract.CryptoResponse) contract.CryptoResultCode {
	plan, err := contract.DecodeIdentityPlan(q.IdentityPlan)
	if err != nil {
		return contract.CryptoInvalidInput
	}
	currentRows, ok := a.currentRows()
	if !ok || !a.checkIdentityPlan(plan, currentRows) {
		return contract.CryptoInvalidInput
	}
	descriptor, err := contract.IdentityPlanDescriptor(plan)
	if err != nil {
		return contract.CryptoInvalidInput
	}
	prepared := make([]contract.CryptoPreparedSecret, 0, len(a.sealedInputCores))
	inputIndex := 0
	for _, intent := range a.request.Intent {
		if intent.ConfidentialityClass != contract.Secret {
			continue
		}
		index := slices.IndexFunc(plan.Rows, func(row contract.IdentityRow) bool { return row.Name == intent.Name })
		if index < 0 {
			for _, current := range currentRows {
				if current.entry.Name != intent.Name {
					continue
				}
				if slices.Equal(current.entry.Recipients, intent.Recipients) {
					break
				}
				row, code := a.prepareGrant(ctx, route, current, intent, reply)
				if code != contract.CryptoSuccess {
					return code
				}
				prepared = append(prepared, row)
				break
			}
			if intent.ValueSource == contract.Supplied && intent.Retained == (contract.RetainedSecretInput{}) {
				inputIndex++
			}
			continue
		}
		row, code := a.prepareSecretEntry(ctx, route, inputIndex, intent, plan.Rows[index], currentRows, reply)
		if code != contract.CryptoSuccess {
			return code
		}
		prepared = append(prepared, row)
		if intent.ValueSource == contract.Supplied && intent.Retained == (contract.RetainedSecretInput{}) {
			inputIndex++
		}
	}
	canonical, err := contract.CryptoPreparedRowsDescriptor(prepared)
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	body, err := contract.EncodeCryptoPrepareResult(contract.CryptoPrepareResult{Rows: prepared})
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	a.plan, a.identityDescriptor, a.preparedDescriptor, a.prepared = plan, descriptor, canonical, prepared
	reply.Body = body
	return contract.CryptoSuccess
}

func (a *applyAdmission) prepareSecretEntry(ctx context.Context, route KeyAccess, index int, intent contract.CryptoIntentRow, identity contract.IdentityRow, currentRows []applyCurrent, reply *contract.CryptoResponse) (contract.CryptoPreparedSecret, contract.CryptoResultCode) {
	var plain []byte
	var code contract.CryptoResultCode
	var generated contract.GeneratedEntryMetadata
	if intent.ValueSource == contract.Generated || intent.Retained != (contract.RetainedSecretInput{}) {
		i := slices.IndexFunc(currentRows, func(c applyCurrent) bool { return c.entry.Name == intent.Name })
		if i < 0 || intent.ValueSource == contract.Generated && a.supportTransition == nil {
			return contract.CryptoPreparedSecret{}, contract.CryptoInvalidAdmission
		}
		current := currentRows[i]
		keys, c := a.openCurrent(ctx, route, current, reply)
		if keys != nil {
			defer clear(keys[:cap(keys)])
		}
		code = c
		if code == contract.CryptoSuccess {
			var err error
			plain, err = custody.OpenValue(current.core, current.payload, keys)
			if err != nil {
				code = contract.CryptoStoredAuthenticationFailed
			}
		}
		if intent.ValueSource == contract.Generated {
			generated = current.entry.Generated
			generated.GenerationID = identity.ValueState
		}
	} else {
		plain, code = a.openSealedInput(ctx, route, index, reply)
	}
	if plain != nil {
		defer clear(plain[:cap(plain)])
	}
	if code != contract.CryptoSuccess {
		return contract.CryptoPreparedSecret{}, code
	}
	core := contract.ValueCore{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: a.request.Context.CompatibilityID, CryptoSupportID: a.control.CryptoSupportID, DomainID: a.request.Context.DomainID, Name: intent.Name, EntryIncarnationID: identity.Incarnation, ValueStateID: identity.ValueState, OriginSnapshotID: identity.OriginSnapshot, OriginTransitionID: identity.OriginTransition, DataKeyEpoch: 1, CommitmentKeyEpoch: 1, ContentLength: intent.ContentLength, InputEncoding: intent.InputEncoding, RetainedLength: intent.RetainedLength, ValueSource: intent.ValueSource}
	if intent.ValueSource == contract.Generated {
		var err error
		core.GeneratedBindingDigest, err = contract.GeneratedBindingDigest(generated)
		if err != nil {
			return contract.CryptoPreparedSecret{}, contract.CryptoInvalidInput
		}
		core.DataKeyID, core.CommitmentKeyID, err = contract.GeneratorValueKeyIDs(identity.ValueState)
		if err != nil {
			return contract.CryptoPreparedSecret{}, contract.CryptoInvalidInput
		}
	} else {
		_, _ = rand.Read(core.DataKeyID[:])
		_, _ = rand.Read(core.CommitmentKeyID[:])
	}
	if core.DataKeyID.IsZero() || core.CommitmentKeyID.IsZero() || core.DataKeyID == core.CommitmentKeyID || intent.ValueSource == contract.Supplied && intent.Retained == (contract.RetainedSecretInput{}) && (core.DataKeyID == a.sealedInputCores[index].DataKeyID || core.CommitmentKeyID == a.sealedInputCores[index].DataKeyID) {
		return contract.CryptoPreparedSecret{}, contract.CryptoCustodyUnavailable
	}
	for _, current := range currentRows {
		for _, id := range []contract.ID{current.core.DataKeyID, current.core.CommitmentKeyID} {
			if core.DataKeyID == id || core.CommitmentKeyID == id {
				return contract.CryptoPreparedSecret{}, contract.CryptoCustodyUnavailable
			}
		}
	}
	entry, access, code := sealValueForRecipients(ctx, core, generated, intent.OutputEncoding, intent.Recipients, a.request.Bindings, plain, reply)
	if code != contract.CryptoSuccess {
		return contract.CryptoPreparedSecret{}, code
	}
	entryBytes, err := contract.EncodeValueEntry(entry)
	if err != nil {
		return contract.CryptoPreparedSecret{}, contract.CryptoCustodyUnavailable
	}
	accessBody, err := contract.EncodeAccessRecord(access)
	if err != nil {
		return contract.CryptoPreparedSecret{}, contract.CryptoCustodyUnavailable
	}
	return contract.CryptoPreparedSecret{Name: intent.Name, Slot: identity.Slot, EntryBytes: entryBytes, AccessRecord: accessBody}, contract.CryptoSuccess
}
