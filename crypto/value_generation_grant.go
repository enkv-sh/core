package crypto

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/internal/custody"
)

// The public membership before this operation comes from the independently
// admitted output census. A retained canonical row may already grant the
// same material to a reader outside the current entry.
func (a *generatedAdmission) checkpointGrantReaders(slot uint16, name string, material contract.ID) ([]contract.ID, error) {
	final := a.purpose.final
	if final == nil {
		return nil, nil
	}
	i := slices.IndexFunc(a.before.Rows, func(row contract.PublicStateRow) bool { return row.Name == name && row.Slot == slot })
	if i < 0 {
		return nil, nil
	}
	if a.purpose.output == nil || i >= len(a.purpose.output.EntryBodies) {
		return nil, contract.ErrRecord
	}
	before, err := contract.InspectValueEntry(a.purpose.output.EntryBodies[i])
	if err != nil || !bytes.Equal(before.Name, []byte(name)) {
		return nil, contract.ErrRecord
	}
	if before.ConfidentialityClass != contract.Secret {
		return nil, nil
	}
	plan := slices.IndexFunc(a.graph.ValueEntryPlans, func(p contract.GeneratorValueEntryPlan) bool { return p.Slot == slot && p.Name == name })
	if plan < 0 || plan >= len(final.plan.recipients) {
		return nil, contract.ErrRecord
	}
	var existing map[contract.ID]bool
	if before.ValueState == material {
		for _, pin := range final.canonicalAccess {
			if pin.access.MaterialID != material {
				continue
			}
			existing = make(map[contract.ID]bool, len(pin.access.Wraps))
			for _, w := range pin.access.Wraps {
				if w.SubjectKind == contract.OrdinaryWrapSubject {
					existing[w.SubjectID] = true
				}
			}
			break
		}
	}
	for n := 0; n < before.RecipientCount(); n++ {
		if existing == nil {
			existing = make(map[contract.ID]bool, before.RecipientCount())
		}
		id, ok := before.RecipientID(n)
		if !ok {
			return nil, contract.ErrRecord
		}
		existing[id] = true
	}
	var added []contract.ID
	for _, id := range final.plan.recipients[plan] {
		if !existing[id] {
			added = append(added, id)
		}
	}
	return added, nil
}

func (a *generatedAdmission) protectCheckpointGrant(slot uint16, index int, material, context contract.ID, w contract.WrapRow) error {
	f := a.purpose.final
	if len(f.grantSeals) >= contract.MaxSelectedGrantRows || w.SubjectKind != contract.OrdinaryWrapSubject {
		return contract.ErrRecord
	}
	if f.grantControl.IsZero() {
		digest, err := contract.GeneratedFinalPreparationBindingDigest(a.control, a.bindings)
		if err != nil {
			return err
		}
		f.grantControl = digest
	}
	c := custody.GeneratedGrantContext{OperationMaterial: a.material.Core.OperationMaterialID, Domain: a.request.Context.DomainID, Operation: a.graph.Header.OperationID, Phase: f.materializationPhaseID, Control: f.grantControl, Material: material, MaterialContext: context, Slot: slot, Index: uint16(index)}
	seal, masked, err := custody.SealGeneratedGrant(c, a.seed, w)
	if err != nil {
		return err
	}
	copy(w.RSACiphertext, masked)
	f.grantSeals = append(f.grantSeals, seal)
	return nil
}

func (a *generatedAdmission) protectSuppliedGrants(rows []contract.CryptoPreparedSecret) error {
	if len(a.purpose.final.entryPreparations) == 0 {
		return nil // A direct Final has no preparation checkpoint.
	}
	for _, row := range rows {
		access, err := contract.InspectAccessRecord(row.AccessRecord)
		if err != nil {
			return err
		}
		added, err := a.checkpointGrantReaders(row.Slot, row.Name, access.MaterialID)
		if err != nil {
			return err
		}
		for j := 0; len(added) != 0 && j < access.WrapCount(); j++ {
			w, ok := access.Wrap(j)
			if !ok {
				return contract.ErrRecord
			}
			if w.SubjectKind == contract.OrdinaryWrapSubject && slices.Contains(added, w.SubjectID) {
				if err := a.protectCheckpointGrant(row.Slot, j, access.MaterialID, access.MaterialContextDigest, contract.WrapRow(w)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (a *generatedAdmission) openCheckpointGrants(image *contract.GeneratedFinalPreparationImage) ([]byte, error) {
	if image == nil {
		return nil, contract.ErrRecord
	}
	opened := make([]byte, 0, len(image.GrantSeals)*contract.RSACiphertextLength)
	err := image.VisitGrantWraps(func(seal contract.GeneratedGrantSeal, material, context contract.ID, w contract.WrapRow) error {
		c := custody.GeneratedGrantContext{OperationMaterial: a.material.Core.OperationMaterialID, Domain: image.DomainID, Operation: image.OperationID, Phase: image.MaterializationPhaseID, Control: image.ControlBindingDigest, Material: material, MaterialContext: context, Slot: seal.Slot, Index: seal.Wrap}
		plain, err := custody.OpenGeneratedGrant(c, a.seed, w, seal)
		if err != nil {
			return err
		}
		opened = append(opened, plain...)
		copy(w.RSACiphertext, plain)
		clear(plain)
		return nil
	})
	if err != nil {
		clear(opened)
		return nil, err
	}
	return opened, nil
}

// Check both references against the private admission's predecessor membership.
// Reconstruct each logical page from the independently checked access records.
func (a *generatedAdmission) candidateGrantsMatch(c generatedCandidate, head format.HeadCore, root *format.Root) bool {
	final := a.purpose.final
	if final == nil || final.nonselecting || c.Subject.Purpose != contract.GeneratorAuthorityFinal {
		return head.GrantDigest.IsZero() && len(c.GrantWraps) == 0 && (root == nil || len(root.GrantPages) == 0)
	}
	grants := make(map[contract.ID][]contract.ID)
	count := 0
	for _, row := range c.Entries {
		if row.Entry.ConfidentialityClass != contract.Secret {
			continue
		}
		ids, err := a.checkpointGrantReaders(row.Slot, row.Entry.Name, row.Entry.ValueState)
		if err != nil {
			return false
		}
		if len(ids) != 0 {
			grants[row.Entry.ValueState] = ids
			count += len(ids)
		}
	}
	if len(c.GrantWraps) != count*format.GrantWrapLength {
		return false
	}
	if count == 0 {
		return head.GrantDigest.IsZero() && (root == nil || len(root.GrantPages) == 0)
	}
	if root == nil {
		return false
	}
	sources, err := root.GrantSources(format.Head{Core: head, AuthKind: format.GeneratorAuth, Generator: &c.Subject, GrantWraps: c.GrantWraps})
	if err != nil {
		return false
	}
	remaining := c.AccessRecords
	for _, ref := range c.CurrentAccess.AccessPageRefs {
		length, n := contract.AccessPageHeaderLength, 0
		for length < int(ref.Length) && n < len(remaining) {
			size, err := contract.AccessRecordLength(remaining[n])
			if err != nil {
				return false
			}
			length += size
			n++
		}
		if n == 0 || length != int(ref.Length) {
			return false
		}
		page := format.AccessPage{Domain: ref.Domain, Object: ref.Object, Index: ref.Index, Records: remaining[:n]}
		remaining = remaining[n:]
		body, err := format.EncodeAccessPage(page)
		if err != nil || format.CheckReference(ref, body) != nil {
			return false
		}
		base, rows, err := format.SplitGrantPage(page, grants)
		source, found := sources[ref]
		if err != nil || found != (len(rows) != 0) || !bytes.Equal(source.Rows, rows) {
			return false
		}
		if found {
			body, err := format.EncodeAccessPage(base)
			if err != nil || format.CheckReference(source.Base, body) != nil {
				return false
			}
		}
	}
	return len(remaining) == 0
}
