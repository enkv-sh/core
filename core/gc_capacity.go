package core

import "enkv.sh/core/contract"

type gcCapacityCharge struct {
	Targets, PlanBytes, FramedPlanBytes, PlanPageBytes, ProgressBytes uint64
}

// The target vector and progress row count cannot grow after selection. This
// account is shared by public continuation inspection and fresh GC admission.
func gcPlanCapacity(plan contract.GCPlan) (gcCapacityCharge, error) {
	var charge gcCapacityCharge
	length, err := contract.GCPlanEncodedLength(plan)
	if err != nil {
		return charge, err
	}
	charge.PlanBytes = uint64(length)
	if len(plan.Targets) == 0 {
		return charge, nil
	}
	progress, err := gcInitialProgress(plan)
	if err != nil {
		return charge, err
	}
	encoded, err := contract.EncodeGCProgress(progress)
	if err != nil {
		return charge, err
	}
	charge.Targets = uint64(len(plan.Targets))
	charge.ProgressBytes = uint64(len(encoded))
	charge.FramedPlanBytes = charge.PlanBytes + contract.SupportRecordOverhead
	charge.PlanPageBytes = charge.FramedPlanBytes + contract.RequiredSupportPageHeaderLength
	return charge, nil
}

func validateSelectedGCCapacity(states map[contract.ID]selectedGCObligation, image *selectedImage, bound selectedCapacityBound) error {
	if image == nil || uint32(len(states)) != image.root.GCPlans.Count {
		return contract.ErrRecord
	}
	var plans, progressBytes uint64
	for _, state := range states {
		if state.plan == nil || !state.progress.Valid() {
			return contract.ErrRecord
		}
		charge, err := gcPlanCapacity(*state.plan)
		if err != nil {
			return err
		}
		progress, err := contract.EncodeGCProgress(state.progress)
		if err != nil || uint64(len(progress)) != charge.ProgressBytes {
			return contract.ErrRecord
		}
		plans += charge.FramedPlanBytes
		progressBytes += charge.ProgressBytes
	}
	if bound.Groups[contract.GeneratorCapacityAuxiliary].MaxFramedBytes < plans || bound.AdministrativeIndexBytes < progressBytes {
		return contract.ErrRecord
	}
	return nil
}
