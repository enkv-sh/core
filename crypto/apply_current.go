package crypto

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

type applyCurrent struct {
	row           contract.CryptoCurrentSecret
	entry         contract.ValueEntry
	core          contract.ValueCore
	payload       contract.CanonicalPayload
	access        contract.AccessRecord
	entryDigest   contract.ID
	wrapIndex     int
	packetContext contract.ID
}

func (a *applyAdmission) currentRows() ([]applyCurrent, bool) {
	rows := make([]applyCurrent, 0, len(a.request.Current))
	for _, row := range a.request.Current {
		current, ok := a.current(row)
		if !ok {
			return nil, false
		}
		rows = append(rows, current)
	}
	return rows, true
}

func (a *applyAdmission) retainedCurrent(intent contract.CryptoIntentRow) (applyCurrent, bool) {
	for _, row := range a.request.Current {
		entry, err := contract.InspectValueEntry(row.EntryBytes)
		if err != nil || string(entry.Name) != intent.Name {
			continue
		}
		current, ok := a.current(row)
		if !ok || current.entry.ValueSource != contract.Supplied || current.entry.Incarnation != intent.Retained.Incarnation ||
			current.entry.ValueState != intent.Retained.Material || current.payload.ContentLength != intent.ContentLength ||
			len(current.entry.ValueBytes) != int(intent.PayloadLength) || contract.Hash(current.entry.ValueBytes) != intent.PayloadDigest {
			return applyCurrent{}, false
		}
		return current, true
	}
	return applyCurrent{}, false
}

// All byte slices borrow the admitted request. Only bounded public metadata is
// copied; no second current-state byte image is retained.
func (a *applyAdmission) current(row contract.CryptoCurrentSecret) (applyCurrent, bool) {
	value := applyCurrent{row: row, wrapIndex: -1}
	m, err := contract.InspectValueEntry(row.EntryBytes)
	if err != nil || m.ConfidentialityClass != contract.Secret {
		return value, false
	}
	value.entry = contract.ValueEntry{Name: string(m.Name), Incarnation: m.Incarnation, ValueState: m.ValueState, OriginSnapshot: m.OriginSnapshot, OriginTransition: m.OriginTransition, ValueSource: m.ValueSource, ConfidentialityClass: m.ConfidentialityClass, InputEncoding: m.InputEncoding, OutputEncoding: m.OutputEncoding, ContentLength: m.ContentLength, RetainedLength: m.RetainedLength, ValueBytes: m.ValueBytes, Generated: m.Generated}
	for i := 0; i < m.RecipientCount(); i++ {
		id, _ := m.RecipientID(i)
		value.entry.Recipients = append(value.entry.Recipients, id)
	}
	if !applyRecipientsAdmitted(value.entry.Recipients, a.control.AuthorityRecipientID, a.request.Bindings) {
		return value, false
	}
	p, err := contract.InspectCanonicalPayload(m.ValueBytes)
	if err != nil || p.CryptoSupportID != a.control.CryptoSupportID {
		return value, false
	}
	value.payload = contract.CanonicalPayload(p)
	value.core, err = contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, value.entry)
	if err != nil {
		return value, false
	}
	access, err := contract.InspectAccessRecord(row.AccessRecord)
	if err != nil {
		return value, false
	}
	material, err := contract.ValueMaterialContextDigest(value.core)
	if err != nil || access.MaterialKind != contract.ValueMaterialKind || access.MaterialID != m.ValueState || access.MaterialContextDigest != material || access.PackageCheck != p.PackageCheck {
		return value, false
	}
	value.access = contract.AccessRecord{Schema: access.Schema, MaterialKind: access.MaterialKind, MaterialID: access.MaterialID, MaterialContextDigest: access.MaterialContextDigest, PackageCheck: access.PackageCheck}
	index := 0
	for _, binding := range a.request.Bindings {
		if binding.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(value.entry.Recipients, binding.SubjectID) {
			continue
		}
		wrap, ok := access.Wrap(index)
		wc, err := custody.ValueWrapCore(value.core, binding)
		if !ok || err != nil || !applyWrapMatches(contract.WrapRow(wrap), wc) {
			return value, false
		}
		value.access.Wraps = append(value.access.Wraps, contract.WrapRow(wrap))
		if binding.SubjectKind == contract.OrdinaryWrapSubject && binding.SubjectID == a.control.AuthorityRecipientID {
			value.wrapIndex = index
			value.packetContext, err = contract.RSAPacketContextDigest(wc)
			if err != nil {
				return value, false
			}
		}
		index++
	}
	if index != access.WrapCount() || value.wrapIndex < 0 {
		return value, false
	}
	value.entryDigest, err = contract.PublicValueEntryDigest(a.request.Context.DomainID, row.Slot, value.entry)
	return value, err == nil
}

func (a *applyAdmission) openCurrent(ctx context.Context, route KeyAccess, current applyCurrent, reply *contract.CryptoResponse) ([]byte, contract.CryptoResultCode) {
	if !a.currentPrivateTarget(current) {
		return nil, contract.CryptoInvalidAdmission
	}
	if ctx.Err() != nil {
		return nil, contract.CryptoCancelled
	}
	if route == nil || route.Family() != a.control.Provider || route.CredentialRoute() != a.routeID {
		return nil, contract.CryptoPrivateRouteUnavailable
	}
	authority := a.request.Bindings[a.authorityIndex]
	keys, uses, code := authenticatedCurrentKeys(ctx, route, authority, current.access.Wraps[current.wrapIndex].RSACiphertext, current.packetContext, current.core, current.payload)
	if !appendKeyUses(reply, authority, contract.KeyUseMaterialOpen, uses, 1) {
		if keys != nil {
			clear(keys[:cap(keys)])
		}
		return nil, contract.CryptoResponseUnknown
	}
	return keys, code
}

func (a *applyAdmission) removedRecipients(before contract.ValueEntry) []contract.ID {
	var after []contract.ID
	for _, intent := range a.request.Intent {
		if intent.Name == before.Name {
			if intent.ValueSource != before.ValueSource {
				return slices.Clone(before.Recipients)
			}
			after = intent.Recipients
			break
		}
	}
	var removed []contract.ID
	for _, id := range before.Recipients {
		if !slices.Contains(after, id) {
			removed = append(removed, id)
		}
	}
	return removed
}

func (a *applyAdmission) sourceChanged(name string) bool {
	i := slices.IndexFunc(a.request.Intent, func(row contract.CryptoIntentRow) bool { return row.Name == name })
	if i < 0 {
		return false
	}
	for _, row := range a.request.Current {
		m, err := contract.InspectValueEntry(row.EntryBytes)
		if err == nil && string(m.Name) == name {
			return m.ValueSource != a.request.Intent[i].ValueSource
		}
	}
	return false
}
