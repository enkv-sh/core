package contract

// ClassifyGeneratedPlanningEntry derives the action, retirement consequence and
// intrinsic blockers from populated current/proposed facts. It excludes observed
// work blockers and does not validate the row.
func ClassifyGeneratedPlanningEntry(row GeneratedPlanningEntry) (GeneratedPlanningAction, GeneratedPlanningRetirement, uint16) {
	intentFields := uint16(GeneratedPlanningConfigContract | GeneratedPlanningResourceContract | GeneratedPlanningLifecycle | GeneratedPlanningContentIntent | GeneratedPlanningCompletion)
	var blockers uint16
	if row.CurrentSource == Generated && row.ProposedSource == Generated {
		if row.RequestedEpoch < row.CurrentEpoch {
			blockers |= GeneratedPlanningStaleEpoch
		}
		if row.RequestedEpoch == row.CurrentEpoch && row.ChangedFields&(intentFields|GeneratedPlanningRetirementPolicy) != 0 {
			blockers |= GeneratedPlanningIntentConflict
		}
	}
	if row.ProposedSource == Generated && row.CurrentSource != Generated && row.RequestedEpoch != 0 {
		blockers |= GeneratedPlanningInitialEpoch
	}
	if row.CurrentSource != 0 && row.ProposedSource != 0 && row.CurrentClass != row.ProposedClass {
		blockers |= GeneratedPlanningClassConflict
	}
	action, retirement := GeneratedPlanningUnchanged, GeneratedPlanningNoRetirement
	switch {
	case row.ProposedSource == 0:
		action = GeneratedPlanningRemoval
		if row.CurrentLifecycleMode == GeneratorLifecycleManaged {
			retirement = GeneratedPlanningRetireAfterRemoval
		}
	case row.CurrentSource == 0:
		action = GeneratedPlanningCreate
	case row.CurrentSource != row.ProposedSource:
		action = GeneratedPlanningSourceChange
		if row.CurrentSource == Generated && row.CurrentLifecycleMode == GeneratorLifecycleManaged {
			retirement = GeneratedPlanningRetireAfterSuccessor
		}
	case row.ChangedFields&(intentFields|GeneratedPlanningEpoch) != 0:
		action = GeneratedPlanningRotate
		if row.CurrentLifecycleMode == GeneratorLifecycleManaged {
			retirement = GeneratedPlanningRetireAfterSuccessor
		}
	case row.ChangedFields&GeneratedPlanningRetirementPolicy != 0 && row.ChangedFields&GeneratedPlanningMemberships != 0:
		action = GeneratedPlanningPolicyAccessChange
	case row.ChangedFields&GeneratedPlanningRetirementPolicy != 0:
		action = GeneratedPlanningPolicyChange
	case row.ChangedFields&GeneratedPlanningMemberships != 0:
		action = GeneratedPlanningAccessChange
	}
	return action, retirement, blockers
}
