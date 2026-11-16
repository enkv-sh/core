package contract

import (
	"bytes"
	"slices"
	"strings"

	protocol "enkv.sh/sdk/protocols/output"
)

func writeOutputDestinationTo(v OutputDestination, w *outputWriter) error {
	if !outputIdentifierValid(v.ConfigContractID) || !outputIdentifierValid(v.ServiceContractID) || len(v.CanonicalSettings) > MaxOutputDestinationSettings || !protocol.ValidCanonicalSettings(v.CanonicalSettings) || !v.Capabilities.Valid() {
		return ErrRecord
	}
	return writeOutputDestinationFieldsTo(v, w)
}

func writeOutputDestinationFieldsTo(v OutputDestination, w *outputWriter) error {
	w.text(v.ConfigContractID)
	w.text(v.ServiceContractID)
	w.text(string(v.CanonicalSettings))
	if err := writeOutputPolicyBlobTo(v.Policy, w); err != nil {
		return err
	}
	w.u8(uint8(v.Capabilities))
	return nil
}
func OutputDestinationLength(v OutputDestination) (int, error) {
	w := newOutputWriter(false, 0)
	err := writeOutputDestinationTo(v, &w)
	return w.length, err
}
func cloneOutputDestination(v OutputDestination) OutputDestination {
	v.ConfigContractID = strings.Clone(v.ConfigContractID)
	v.ServiceContractID = strings.Clone(v.ServiceContractID)
	v.CanonicalSettings = bytes.Clone(v.CanonicalSettings)
	v.Policy = cloneOutputPolicy(v.Policy)
	return v
}

func writeOutputGroupsTo(groups [][]ID, w *outputWriter) error {
	if len(groups) > CryptoMaxValueEntries {
		return ErrRecordCapacity
	}
	w.u16(uint16(len(groups)))
	seen := make(map[ID]bool)
	var previous ID
	for i, group := range groups {
		if len(group) == 0 || len(group) > CryptoMaxValueEntries || len(seen)+len(group) > CryptoMaxValueEntries || i > 0 && bytes.Compare(previous[:], group[0][:]) >= 0 {
			return ErrRecord
		}
		w.u16(uint16(len(group)))
		for j, id := range group {
			if id.IsZero() || seen[id] || j > 0 && bytes.Compare(group[j-1][:], id[:]) >= 0 {
				return ErrRecord
			}
			seen[id] = true
			w.id(id)
		}
		previous = group[0]
	}
	return nil
}

func cloneOutputGroups(groups [][]ID) [][]ID {
	groups = slices.Clone(groups)
	for i := range groups {
		groups[i] = slices.Clone(groups[i])
	}
	return groups
}
