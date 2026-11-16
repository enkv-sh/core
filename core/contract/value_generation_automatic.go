package contract

// GeneratedAutomaticRetirementIndices selects only explicitly requested
// rotations of the exact same generated entry. Old stored policy cannot arm
// removal, source conversion, or a policy-only edit.
func GeneratedAutomaticRetirementIndices(graph GeneratorPlanBundle) []uint16 {
	var out []uint16
	for index, lineage := range graph.Lineages {
		if lineage.Purpose != GeneratorLineageRetirement || lineage.TemplateCount != 1 {
			continue
		}
		for _, plan := range graph.ValueEntryPlans {
			if plan.Name == lineage.Name && plan.ValueSource == Generated && plan.ChangeMask&GeneratorValueChangeContent != 0 &&
				plan.RetirementMode == GeneratedRetirementAuto && plan.EntryIncarnationID == lineage.EntryIncarnationID &&
				plan.Epoch > lineage.Epoch && !plan.LineageID.IsZero() {
				out = append(out, uint16(index))
				break
			}
		}
	}
	return out
}
