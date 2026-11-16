package core

import (
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"slices"
)

// All projections use the shared canonical writers. Invalid internal entry inputs
// yield a zero descriptor, which cannot pass parent or lifecycle admission.
func entryInputCommitment(domain contract.ID, desiredEntries []ApplyEntryInput) (contract.ID, uint64) {
	_, d, err := buildEntryIntent(domain, desiredEntries)
	if err != nil {
		return contract.ID{}, 0
	}
	return d.Digest, d.Length
}
func buildEntryIntent(domain contract.ID, desiredEntries []ApplyEntryInput) ([]contract.CryptoIntentRow, contract.DescriptorVector, error) {
	rows := make([]contract.CryptoIntentRow, len(desiredEntries))
	for i, v := range desiredEntries {
		var raw uint32
		var err error
		retained := uint32(len(v.InputBytes))
		var digest contract.ID
		if v.ValueSource == contract.Generated || v.Retained != nil {
			view, e := contract.InspectCanonicalPayload(v.InputBytes)
			if e != nil {
				return nil, contract.DescriptorVector{}, e
			}
			raw, retained, digest = view.ContentLength, view.RetainedLength, contract.Hash(v.InputBytes)
			if view.InputEncoding != v.InputEncoding {
				return nil, contract.DescriptorVector{}, contract.ErrRecord
			}
		} else if v.ConfidentialityClass == format.Secret {
			view, e := contract.InspectSealedInputEnvelope(v.InputBytes)
			if e != nil {
				return nil, contract.DescriptorVector{}, e
			}
			raw, retained = view.Core.ContentLength, view.Core.RetainedLength
			if view.Core.InputEncoding != v.InputEncoding {
				return nil, contract.DescriptorVector{}, contract.ErrRecord
			}
			digest, err = contract.SealedInputDigest(v.InputBytes)
		} else {
			raw, err = contract.InputContentLength(v.InputEncoding, v.InputBytes)
			if err != nil {
				return nil, contract.DescriptorVector{}, err
			}
			digest, err = contract.PlainInputDigest(v.InputBytes)
		}
		if err != nil {
			return nil, contract.DescriptorVector{}, err
		}
		rows[i] = contract.CryptoIntentRow{Name: v.Name, Recipients: v.Recipients, ValueSource: v.ValueSource, ConfidentialityClass: v.ConfidentialityClass, ContentLength: raw, RetainedLength: retained, InputEncoding: v.InputEncoding, OutputEncoding: v.OutputEncoding, PayloadDigest: digest, PayloadLength: uint32(len(v.InputBytes))}
		if v.Retained != nil {
			rows[i].Retained = *v.Retained
		}
	}
	d, err := contract.CryptoIntentDescriptor(domain, rows)
	return rows, d, err
}
func publicEntryDigest(domain contract.ID, slot uint16, m *format.ValueEntry) contract.ID {
	if m == nil {
		return contract.ID{}
	}
	id, err := contract.PublicValueEntryDigest(domain, slot, *m)
	if err != nil {
		return contract.ID{}
	}
	return id
}
func (s *StateSession) publicStateProjection() (contract.PublicState, error) {
	support, err := s.supportDescriptor()
	if err != nil {
		return contract.PublicState{}, err
	}
	return s.publicStateWithSupport(support)
}

// A prospective normal successor has validated SupportAfter facts before its
// administrative index exists. Its authority uses those facts; a completed
// selected image still obtains them through publicStateProjection above.
func (s *StateSession) publicStateWithSupport(support contract.DescriptorVector) (contract.PublicState, error) {
	return s.selectedImage().publicStateWithSupport(support)
}
func (s *selectedImage) publicStateWithSupport(support contract.DescriptorVector) (contract.PublicState, error) {
	if s == nil {
		return contract.PublicState{}, contract.ErrRecord
	}
	v := contract.PublicState{Domain: s.root.Domain, AccessRoot: s.root.CurrentAccess.AccessRoot, RequiredSupport: support, Rows: make([]contract.PublicStateRow, len(s.root.Names))}
	for i, e := range s.root.Names {
		entry := s.valueEntry(e.Slot)
		if entry == nil || entry.Name != e.Name {
			return contract.PublicState{}, contract.ErrRecord
		}
		digest, err := contract.PublicValueEntryDigest(s.root.Domain, e.Slot, *entry)
		if err != nil {
			return contract.PublicState{}, err
		}
		v.Rows[i] = contract.PublicStateRow{Name: e.Name, Slot: e.Slot, EntryDigest: digest}
	}
	return v, nil
}

func (s *StateSession) publicState() contract.DigestLength {
	v, err := s.publicStateProjection()
	if err != nil {
		return contract.DigestLength{}
	}
	d, err := contract.PublicStateDescriptor(v)
	if err != nil {
		return contract.DigestLength{}
	}
	return contract.DigestLength{Digest: d.Digest, Length: d.Length}
}
func requestCore(h format.HeadCore, s contract.LifecycleSubject) contract.RequestCore {
	return contract.RequestCore{RequestCoreFields: contract.RequestCoreFields{Domain: h.Domain, Store: h.Store, Trust: h.Trust, Coordinate: h.Coordinate, NonBody: h.NonBody, Interpretation: h.Interpretation, Epoch: h.Epoch, PreviousRevision: h.PreviousRevision, PreviousDigest: h.PreviousDigest, Intent: s.Normal.Intent, IdentityPlan: s.IdentityPlan}, PreviousToken: h.PreviousToken}
}
func requestCommitment(h format.HeadCore, s contract.LifecycleSubject) contract.ID {
	d, err := contract.RequestDigest(requestCore(h, s))
	if err != nil {
		return contract.ID{}
	}
	return d
}

func identityPlan(c *Comparison, p transitionPlan) contract.IdentityPlan {
	v := contract.IdentityPlan{Operation: p.operation, Transition: p.transition, Snapshot: p.snapshot, Revision: p.revision}
	for i, row := range c.desiredEntries {
		slot := c.slots[i]
		value, changed := p.values[slot]
		if !changed {
			continue
		}
		incarnation, added := p.incarnations[slot]
		if !added {
			incarnation = c.session.valueEntry(slot).Incarnation
		}
		v.Rows = append(v.Rows, contract.IdentityRow{Name: row.Name, Slot: slot, Incarnation: incarnation, ValueState: value, OriginSnapshot: p.snapshot, OriginTransition: p.transition})
	}
	for i, id := range p.pages {
		if !id.IsZero() {
			v.Pages = append(v.Pages, contract.IdentityPage{Kind: format.ValueEntryPageKind, Index: uint16(i), Object: id})
		}
	}
	for i, id := range p.accessPages {
		if !id.IsZero() {
			v.Pages = append(v.Pages, contract.IdentityPage{Kind: format.AccessKind, Index: uint16(i), Object: id})
		}
	}
	for i, id := range p.recipientPages {
		if !id.IsZero() {
			v.Pages = append(v.Pages, contract.IdentityPage{Kind: format.RecipientKind, Index: uint16(i), Object: id})
		}
	}
	for i, id := range p.supportPages {
		if !id.IsZero() {
			v.Pages = append(v.Pages, contract.IdentityPage{Kind: contract.RequiredSupportKind, Index: uint16(i), Object: id})
		}
	}
	slices.SortFunc(v.Pages, func(a, b contract.IdentityPage) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return int(a.Index) - int(b.Index)
	})
	return v
}
func identityCommitment(c *Comparison, p transitionPlan) contract.DigestLength {
	d, err := contract.IdentityPlanDescriptor(identityPlan(c, p))
	if err != nil {
		return contract.DigestLength{}
	}
	return contract.DigestLength{Digest: d.Digest, Length: d.Length}
}

type membershipRow = contract.MembershipRow
type exclusionRow = contract.ExclusionRow

func membership(domain contract.ID, slot uint16, m *format.ValueEntry) membershipRow {
	return membershipRow{Name: m.Name, Slot: slot, Incarnation: m.Incarnation, Recipients: slices.Clone(m.Recipients), EntryDigest: publicEntryDigest(domain, slot, m)}
}
func membershipEqual(a, b membershipRow) bool {
	return a.Name == b.Name && a.Slot == b.Slot && a.Incarnation == b.Incarnation && a.EntryDigest == b.EntryDigest && slices.Equal(a.Recipients, b.Recipients)
}
func exclusionEqual(a, b exclusionRow) bool {
	return a.Path == b.Path && membershipEqual(a.MembershipRow, b.MembershipRow)
}
func grantCommitment(domain contract.ID, rows []membershipRow) contract.DescriptorVector {
	d, err := contract.GrantDescriptor(domain, rows)
	if err != nil {
		return contract.DescriptorVector{}
	}
	return d
}
func exclusionCommitment(domain contract.ID, rows []exclusionRow) contract.DescriptorVector {
	d, err := contract.ExclusionDescriptor(domain, rows)
	if err != nil {
		return contract.DescriptorVector{}
	}
	return d
}
func retirementCommitment(domain contract.ID) contract.DescriptorVector {
	d, err := contract.RetirementDescriptor(domain, nil)
	if err != nil {
		return contract.DescriptorVector{}
	}
	return d
}
func (s *StateSession) plainPath(row membershipRow) contract.ID {
	d, err := contract.PlainExclusionDigest(contract.PlainExclusionPath{Domain: s.admission.domain, Name: row.Name, Slot: row.Slot, Incarnation: row.Incarnation, EntryDigest: row.EntryDigest, RemovedRecipients: row.Recipients})
	if err != nil {
		return contract.ID{}
	}
	return d
}
func (s *StateSession) lifecycleVectors(next *StateSession) (contract.DescriptorVector, []membershipRow, []exclusionRow, uint32) {
	var grants []membershipRow
	var exclusions []exclusionRow
	var rows []contract.UnionRow
	var changed uint32
	before, after := s.root.Names, next.root.Names
	for i, j := 0, 0; i < len(before) || j < len(after); {
		var old, new *membershipRow
		if i < len(before) && (j == len(after) || before[i].Name < after[j].Name) {
			r := membership(s.admission.domain, before[i].Slot, s.valueEntry(before[i].Slot))
			old = &r
			i++
		} else if j < len(after) && (i == len(before) || after[j].Name < before[i].Name) {
			r := membership(s.admission.domain, after[j].Slot, next.valueEntry(after[j].Slot))
			new = &r
			j++
		} else {
			a := membership(s.admission.domain, before[i].Slot, s.valueEntry(before[i].Slot))
			b := membership(s.admission.domain, after[j].Slot, next.valueEntry(after[j].Slot))
			old, new = &a, &b
			i++
			j++
		}
		row := contract.UnionRow{BeforePresent: old != nil, AfterPresent: new != nil}
		if old != nil {
			row.Name = old.Name
			row.Before = old.Side()
		}
		if new != nil {
			row.Name = new.Name
			row.After = new.Side()
		}
		rows = append(rows, row)
		if old == nil {
			grants = append(grants, *new)
			changed++
		} else if new == nil {
			exclusions = append(exclusions, exclusionRow{MembershipRow: *old, Path: s.plainPath(*old)})
			changed++
		} else if !membershipEqual(*old, *new) {
			changed++
			var added, removed []contract.ID
			if old.Incarnation != new.Incarnation {
				grants = append(grants, *new)
				exclusions = append(exclusions, exclusionRow{MembershipRow: *old, Path: s.plainPath(*old)})
				continue
			}
			for _, id := range new.Recipients {
				if !slices.Contains(old.Recipients, id) {
					added = append(added, id)
				}
			}
			for _, id := range old.Recipients {
				if !slices.Contains(new.Recipients, id) {
					removed = append(removed, id)
				}
			}
			if len(added) > 0 {
				row := *new
				row.Recipients = added
				grants = append(grants, row)
			}
			if len(removed) > 0 {
				row := *old
				row.Recipients = removed
				exclusions = append(exclusions, exclusionRow{MembershipRow: row, Path: s.plainPath(row)})
			}
		}
	}
	d, err := contract.UnionDescriptor(s.admission.domain, rows)
	if err != nil {
		return contract.DescriptorVector{}, nil, nil, 0
	}
	return d, grants, exclusions, changed
}

func (s *selectedImage) publicState() contract.DigestLength {
	support, err := s.supportDescriptor()
	if err != nil {
		return contract.DigestLength{}
	}
	v, err := s.publicStateWithSupport(support)
	if err != nil {
		return contract.DigestLength{}
	}
	d, err := contract.PublicStateDescriptor(v)
	if err != nil {
		return contract.DigestLength{}
	}
	return contract.DigestLength{Digest: d.Digest, Length: d.Length}
}
