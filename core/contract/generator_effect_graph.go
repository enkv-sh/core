package contract

// ValidateGeneratorEffectGraph adds whole-continuation coverage to structural
// graph validation. An inactive create branch can still produce owned residue,
// so its exact result-slot cleanup must be reserved before any effect enters.
// This supplies no authority, profile qualification or dispatch permission.
func ValidateGeneratorEffectGraph(v GeneratorPlanBundle) error {
	if _, err := GeneratorPlanBundleLength(v); err != nil {
		return err
	}
	cleanups := make(map[ID]bool)
	for _, lineage := range v.Lineages {
		if lineage.Purpose != GeneratorLineageCleanup {
			continue
		}
		x := lineage.Templates[0]
		if x.TargetKind != GeneratorTargetResultResourceSlot {
			continue
		}
		if cleanups[x.TargetSourceID] {
			return ErrRecord
		}
		cleanups[x.TargetSourceID] = true
	}
	for _, lineage := range v.Lineages {
		if lineage.Purpose != GeneratorLineageCreate {
			continue
		}
		for _, x := range lineage.Templates[:lineage.TemplateCount] {
			if x.SemanticLifecycleMode() == GeneratorLifecycleNone {
				continue
			}
			if !cleanups[x.ResultID] {
				return ErrRecord
			}
		}
	}
	return nil
}
