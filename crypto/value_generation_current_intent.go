package crypto

import (
	"slices"

	"enkv.sh/core/contract"
)

func (a *generatedAdmission) currentIntentMatches(selected contract.GeneratedCurrentIntentSelection,
	plan contract.GeneratorValueEntryPlan, meta contract.GeneratorDeclaredGeneration, logical contract.GeneratorLogicalSlice) bool {
	c := a.request.Context
	index := slices.Index(a.before.Rows, selected.Row)
	if selected.DomainID != c.DomainID || selected.HEADDigest != c.PredecessorHEADDigest || selected.AccessRoot != c.CurrentAccessRoot ||
		selected.Row.Name != plan.Name || selected.Row.Slot != plan.Slot || selected.Row.EntryDigest.IsZero() ||
		index < 0 || selected.Incarnation != plan.EntryIncarnationID ||
		selected.Intent != logical || selected.Generated.IntentDigest != plan.IntentDigest || selected.Generated.Epoch != plan.Epoch ||
		selected.Generated.RetirementMode != plan.RetirementMode || meta.Epoch != selected.Generated.Epoch ||
		meta.ConfigContractID != selected.Generated.ConfigContractID || meta.ResourceContractID != selected.Generated.ResourceContractID ||
		meta.LifecycleMode != selected.Generated.LifecycleMode || meta.CompletionClass != selected.Generated.CompletionClass ||
		meta.RetirementMode != selected.Generated.RetirementMode || selected.HEADRevision.IsZero() {
		return false
	}
	if _, err := contract.GeneratedEntryMetadataLength(selected.Generated); err != nil {
		return false
	}
	if a.purpose.output == nil || index >= len(a.purpose.output.EntryBodies) {
		return false
	}
	entry, err := contract.InspectValueEntry(a.purpose.output.EntryBodies[index])
	if err != nil || entry.ValueSource != contract.Generated || entry.ConfidentialityClass != contract.Secret ||
		entry.InputEncoding != plan.InputEncoding || entry.Incarnation != selected.Incarnation || entry.Generated != selected.Generated {
		return false
	}
	root, err := contract.DecodeRef(c.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil || root != selected.Root || a.purpose.reservation != nil && selected.HEADRevision != a.graph.Request.PredecessorRevisionID {
		return false
	}
	condition, err := contract.MatchHeadCondition(selected.HEADToken)
	if err != nil {
		return false
	}
	digest, err := contract.CryptoConditionDigest(condition)
	return err == nil && digest == c.OriginalConditionDigest
}
