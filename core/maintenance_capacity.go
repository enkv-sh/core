package core

import (
	"slices"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type maintenanceMaterialBounds struct {
	pages [contract.MaxValueEntryPages]uint32
}

// Bound the complete output before either read or mutation custody. Source
// bytes are charged in full even when edits remove or replace some of them.
func (s *StateSession) maintenanceOutputCapacity(m *MaintenanceInstallation, c *Comparison) bool {
	const limit = uint64(contract.MaxConfigurationPairLength)
	var total uint64
	add := func(n uint64) bool {
		if n > limit-total {
			return false
		}
		total += n
		return true
	}
	base64 := func(n uint64) bool { return add(4 * ((n + 2) / 3)) }
	// 8192 covers all fixed keys, IDs, lengths, pretty-print indentation,
	// optional generation facts, and insertion separators. Variable text is
	// charged at JSON's six-byte worst escape per input byte. Each pin row
	// gets another 512 bytes for four IDs, keys, braces and indentation.
	if !add(m.SourcePins.EditableLength) || !add(m.SourcePins.GeneratedLength) || !add(8192+6*(uint64(len(m.OutputPath))+256)) || !base64(contract.MaxHeadLength) {
		return false
	}
	var bounds maintenanceMaterialBounds
	for _, named := range s.root.Names {
		entry := s.valueEntry(named.Slot)
		if entry == nil {
			return false
		}
		target := c.secretAccess != nil && c.secretAccess.Target.Slot == named.Slot
		delta := c.retirement != nil && entry.ValueSource == contract.Supplied && entry.ConfidentialityClass == contract.Secret && slices.Contains(entry.Recipients, c.retirement.RecipientID)
		if !target && !delta {
			continue
		}
		if entry.ValueSource == contract.Supplied && !add(512+6*uint64(len(entry.Name))) {
			return false
		}
		if target && !add(12*uint64(len(entry.Name))) {
			return false
		}
		index := named.Slot / format.PageSlots
		ref := s.root.ValueEntryPages[index]
		if ref == nil || ref.Length > contract.MaxValueEntryPageLength {
			return false
		}
		bounds.pages[index] = ref.Length
	}
	needed := false
	for _, length := range bounds.pages {
		if length != 0 {
			needed = true
			for range 2 {
				if !base64(uint64(length)) {
					return false
				}
			}
			if !add(256) {
				return false
			}
		}
	}
	if needed && (!base64(contract.MaxHeadLength) || !base64(contract.MaxRootLength) || !base64(contract.MaxRootLength)) {
		return false
	}
	m.materialBounds = bounds
	return true
}

func maintenanceCorrelationCapacity(c MaintenanceSuccessor, source AdministrativeSourcePins, path string) bool {
	if len(c.SignedCandidate) > contract.MaxHeadLength || len(c.PredecessorHead) > contract.MaxHeadLength || len(c.CandidateRoot) > contract.MaxRootLength || len(c.PredecessorRoot) > contract.MaxRootLength || len(c.CandidatePages) > contract.MaxValueEntryPages || len(c.PredecessorPages) > contract.MaxValueEntryPages || len(c.PinDeltas) > contract.CryptoMaxValueEntries || len(path) > 4096 || len(c.Name) > contract.CryptoMaxName {
		return false
	}
	const limit = uint64(contract.MaxConfigurationPairLength)
	var total uint64
	add := func(n uint64) bool {
		if n > limit-total {
			return false
		}
		total += n
		return true
	}
	base64 := func(n int) bool { return add(4 * ((uint64(n) + 2) / 3)) }
	if !add(source.EditableLength) || !add(source.GeneratedLength) || !add(8192+6*(uint64(len(path))+256)) || !base64(len(c.SignedCandidate)) || !base64(len(c.PredecessorHead)) || !base64(len(c.PredecessorRoot)) || !base64(len(c.CandidateRoot)) {
		return false
	}
	for _, delta := range c.PinDeltas {
		if len(delta.Name) > contract.CryptoMaxName || !utf8.ValidString(delta.Name) || !add(512+6*uint64(len(delta.Name))) {
			return false
		}
	}
	if c.RekeyTarget != nil && (len(c.RekeyTarget.Name) > contract.CryptoMaxName || !add(12*uint64(len(c.RekeyTarget.Name)))) {
		return false
	}
	for _, rows := range [][]MaintenanceValuePage{c.PredecessorPages, c.CandidatePages} {
		for _, row := range rows {
			if len(row.Body) > contract.MaxValueEntryPageLength || !base64(len(row.Body)) || !add(128) {
				return false
			}
		}
	}
	return true
}
