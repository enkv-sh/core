package compositionfull

import (
	"enkv.sh/core/contract"
	"strconv"
	"strings"
)

func generatedPlanningAction(action contract.GeneratedPlanningAction) string {
	switch action {
	case contract.GeneratedPlanningCreate:
		return "create"
	case contract.GeneratedPlanningRotate:
		return "rotate"
	case contract.GeneratedPlanningUnchanged:
		return "unchanged"
	case contract.GeneratedPlanningPolicyChange:
		return "policy-change"
	case contract.GeneratedPlanningAccessChange:
		return "access-change"
	case contract.GeneratedPlanningPolicyAccessChange:
		return "policy-and-access-change"
	case contract.GeneratedPlanningSourceChange:
		return "source-change"
	case contract.GeneratedPlanningRemoval:
		return "removal"
	}
	return ""
}

func generatedPlanningRetirement(value contract.GeneratedPlanningRetirement) string {
	switch value {
	case contract.GeneratedPlanningNoRetirement:
		return "none"
	case contract.GeneratedPlanningRetireAfterSuccessor:
		return "after-successor-selection"
	case contract.GeneratedPlanningRetireAfterRemoval:
		return "after-absence-selection"
	}
	return ""
}

func generatedPlanningPolicy(policy uint8) *string {
	var value string
	switch policy {
	case contract.GeneratedRetirementManual:
		value = "manual"
	case contract.GeneratedRetirementAuto:
		value = "auto"
	default:
		return nil
	}
	return &value
}

func validGeneratedPlanningEntries(rows []contract.GeneratedPlanningEntry) bool {
	if len(rows) > contract.MaxGeneratedPlanningEntries {
		return false
	}
	current, proposed := 0, 0
	for at, row := range rows {
		if !boundedReaderText(row.Name, contract.CryptoMaxName) || at > 0 && rows[at-1].Name >= row.Name || !validGeneratedPlanningEntry(row) {
			return false
		}
		if row.CurrentSource == contract.Generated {
			current++
		}
		if row.ProposedSource == contract.Generated {
			proposed++
		}
	}
	return current <= contract.GeneratedCurrentEntryLimit && proposed <= contract.GeneratedCurrentEntryLimit
}

func validGeneratedPlanningPolicy(mode contract.GeneratorLifecycleMode, policy uint8) bool {
	return mode == contract.GeneratorLifecycleNone && policy == 0 || mode == contract.GeneratorLifecycleManaged && generatedPlanningPolicy(policy) != nil
}

func validGeneratedPlanningEntry(row contract.GeneratedPlanningEntry) bool {
	if row.ChangedFields & ^uint16(contract.GeneratedPlanningAllFields) != 0 || row.Blockers & ^uint16(contract.GeneratedPlanningAllBlockers) != 0 || generatedPlanningAction(row.Action) == "" || generatedPlanningRetirement(row.Retirement) == "" {
		return false
	}
	validSide := func(source, class uint8) bool {
		return source == 0 && class == 0 || (source == contract.Supplied || source == contract.Generated) && (class == contract.Plain || class == contract.Secret)
	}
	if !validSide(row.CurrentSource, row.CurrentClass) || !validSide(row.ProposedSource, row.ProposedClass) || row.CurrentSource != contract.Generated && row.ProposedSource != contract.Generated || (row.CurrentSource == 0) != row.CurrentIncarnation.IsZero() {
		return false
	}
	if row.CurrentSource == contract.Generated {
		if row.CurrentGeneration.IsZero() || !validGeneratedPlanningPolicy(row.CurrentLifecycleMode, row.CurrentPolicy) {
			return false
		}
	} else if !row.CurrentGeneration.IsZero() || row.CurrentEpoch != 0 || row.CurrentPolicy != 0 || row.CurrentLifecycleMode != 0 {
		return false
	}
	if row.ProposedSource == contract.Generated {
		if !validGeneratedPlanningPolicy(row.ProposedLifecycleMode, row.ProposedPolicy) {
			return false
		}
	} else if row.RequestedEpoch != 0 || row.ProposedPolicy != 0 || row.ProposedLifecycleMode != 0 {
		return false
	}
	if row.RetiringDutyID.IsZero() {
		if !row.RetiringIncarnation.IsZero() || !row.RetiringResource.IsZero() || !row.RetiringOriginalOperation.IsZero() || !row.RetiringOriginalAttempt.IsZero() || row.RetiringEpoch != 0 || row.Blockers&contract.GeneratedPlanningRetiring != 0 {
			return false
		}
	} else if row.RetiringIncarnation.IsZero() || row.RetiringResource.IsZero() || row.RetiringOriginalOperation.IsZero() || row.RetiringOriginalAttempt.IsZero() || row.Blockers&contract.GeneratedPlanningRetiring == 0 {
		return false
	}
	if row.ActiveOperation.IsZero() != (row.Blockers&contract.GeneratedPlanningActiveOperation == 0) {
		return false
	}
	bothGenerated := row.CurrentSource == contract.Generated && row.ProposedSource == contract.Generated
	if row.CurrentSource == 0 || row.ProposedSource == 0 {
		if row.ChangedFields != contract.GeneratedPlanningPresence {
			return false
		}
	} else {
		if row.ChangedFields&contract.GeneratedPlanningPresence != 0 || (row.ChangedFields&contract.GeneratedPlanningSource != 0) != (row.CurrentSource != row.ProposedSource) || (row.ChangedFields&contract.GeneratedPlanningClass != 0) != (row.CurrentClass != row.ProposedClass) {
			return false
		}
		if bothGenerated && ((row.ChangedFields&contract.GeneratedPlanningEpoch != 0) != (row.CurrentEpoch != row.RequestedEpoch) || (row.ChangedFields&contract.GeneratedPlanningRetirementPolicy != 0) != (row.CurrentPolicy != row.ProposedPolicy)) {
			return false
		}
	}
	action, retirement, blockers := contract.ClassifyGeneratedPlanningEntry(row)
	return row.Action == action && row.Retirement == retirement && row.Blockers&^uint16(contract.GeneratedPlanningRetiring|contract.GeneratedPlanningActiveOperation) == blockers
}

func generatedPlanningID(id contract.ID) *string {
	if id.IsZero() {
		return nil
	}
	value := readerID(id)
	return &value
}

func generatedPlanningSource(source uint8) *string {
	var value string
	switch source {
	case contract.Supplied:
		value = "supplied"
	case contract.Generated:
		value = "generated"
	default:
		return nil
	}
	return &value
}

func generatedPlanningClass(class uint8) *string {
	var value string
	switch class {
	case contract.Plain:
		value = "plain"
	case contract.Secret:
		value = "secret"
	default:
		return nil
	}
	return &value
}

func generatedPlanningMask(mask uint16, fields bool) []string {
	var values []string
	if fields {
		values = []string{"presence", "class", "source", "memberships", "epoch", "config_contract", "resource_contract", "lifecycle", "content_intent", "retirement", "completion"}
	} else {
		values = []string{"stale-generated-epoch", "initial-generated-epoch-not-zero", "generated-intent-conflict", "confidentiality-conversion", "retiring-generation-present", "active-operation-present"}
	}
	out := make([]string, 0, len(values))
	for at, value := range values {
		if mask&(1<<at) != 0 {
			out = append(out, value)
		}
	}
	return out
}

func renderGeneratedPlanningEntries(w *readerResultWriter, rows []contract.GeneratedPlanningEntry, human bool) {
	if !human {
		w.literal(`,"generated_entries":[`)
	} else if len(rows) != 0 {
		w.literal("Generated intent:\n")
	}
	for at, row := range rows {
		if human {
			writeGeneratedPlanningHuman(w, row)
			continue
		}
		var currentEpoch, requestedEpoch, retiringEpoch *uint64
		if row.CurrentSource == contract.Generated {
			currentEpoch = &row.CurrentEpoch
		}
		if row.ProposedSource == contract.Generated {
			requestedEpoch = &row.RequestedEpoch
		}
		if !row.RetiringDutyID.IsZero() {
			retiringEpoch = &row.RetiringEpoch
		}
		record := struct {
			Name                string   `json:"name"`
			Action              string   `json:"requested_action"`
			CurrentSource       *string  `json:"current_source"`
			ProposedSource      *string  `json:"requested_source"`
			CurrentClass        *string  `json:"current_confidentiality"`
			ProposedClass       *string  `json:"requested_confidentiality"`
			CurrentIncarnation  *string  `json:"current_incarnation_id"`
			CurrentGeneration   *string  `json:"current_generation_id"`
			CurrentEpoch        *uint64  `json:"current_epoch"`
			RequestedEpoch      *uint64  `json:"requested_epoch"`
			CurrentLifecycle    any      `json:"current_lifecycle_mode"`
			ProposedLifecycle   any      `json:"requested_lifecycle_mode"`
			CurrentPolicy       *string  `json:"current_retirement_policy"`
			ProposedPolicy      *string  `json:"requested_retirement_policy"`
			Changed             []string `json:"changed_public_fields"`
			Retirement          string   `json:"retirement_consequence"`
			Blockers            []string `json:"observed_blockers"`
			ActiveOperation     *string  `json:"active_operation_id"`
			RetiringDuty        *string  `json:"retiring_duty_id"`
			RetiringIncarnation *string  `json:"retiring_incarnation_id"`
			RetiringGeneration  *string  `json:"retiring_generation_id"`
			RetiringEpoch       *uint64  `json:"retiring_epoch"`
			RetiringResource    *string  `json:"retiring_resource_id"`
			RetiringOperation   *string  `json:"retiring_original_operation_id"`
			RetiringAttempt     *string  `json:"retiring_original_attempt_id"`
			FutureContent       string   `json:"future_content"`
			SecretContent       string   `json:"public_secret_content"`
		}{Name: row.Name, Action: generatedPlanningAction(row.Action), CurrentSource: generatedPlanningSource(row.CurrentSource), ProposedSource: generatedPlanningSource(row.ProposedSource),
			CurrentClass: generatedPlanningClass(row.CurrentClass), ProposedClass: generatedPlanningClass(row.ProposedClass), CurrentIncarnation: generatedPlanningID(row.CurrentIncarnation), CurrentGeneration: generatedPlanningID(row.CurrentGeneration),
			CurrentEpoch: currentEpoch, RequestedEpoch: requestedEpoch, CurrentLifecycle: generatedLifecycle(row.CurrentLifecycleMode), ProposedLifecycle: generatedLifecycle(row.ProposedLifecycleMode), CurrentPolicy: generatedPlanningPolicy(row.CurrentPolicy), ProposedPolicy: generatedPlanningPolicy(row.ProposedPolicy),
			Changed: generatedPlanningMask(row.ChangedFields, true), Retirement: generatedPlanningRetirement(row.Retirement), Blockers: generatedPlanningMask(row.Blockers, false),
			ActiveOperation: generatedPlanningID(row.ActiveOperation), RetiringDuty: generatedPlanningID(row.RetiringDutyID), RetiringIncarnation: generatedPlanningID(row.RetiringIncarnation), RetiringEpoch: retiringEpoch,
			RetiringResource: generatedPlanningID(row.RetiringResource), RetiringOperation: generatedPlanningID(row.RetiringOriginalOperation), RetiringAttempt: generatedPlanningID(row.RetiringOriginalAttempt), FutureContent: "unavailable", SecretContent: "unchecked"}
		if at != 0 {
			w.literal(",")
		}
		// The row allowance includes the larger human prefix and newline,
		// so JSON commas also fit without expanding the vector allowance.
		w.json(record, contract.MaxGeneratedPlanningRowJSONBytes-len("generated_entry: ")-1)
	}
	if !human {
		w.literal("]")
	}
}

func planningOptionalText(text *string) string {
	if text == nil {
		return "unavailable"
	}
	return *text
}

func writeGeneratedPlanningHuman(w *readerResultWriter, row contract.GeneratedPlanningEntry) {
	start := w.at
	w.literal("Generated entry ")
	w.comparisonHumanString(row.Name)
	w.literal(": " + generatedPlanningAction(row.Action) + "\n")
	for _, side := range []struct {
		label         string
		source, class uint8
		epoch         uint64
		mode          contract.GeneratorLifecycleMode
		policy        uint8
	}{{"Current", row.CurrentSource, row.CurrentClass, row.CurrentEpoch, row.CurrentLifecycleMode, row.CurrentPolicy},
		{"Requested", row.ProposedSource, row.ProposedClass, row.RequestedEpoch, row.ProposedLifecycleMode, row.ProposedPolicy}} {
		w.literal("  " + side.label + ": ")
		if side.source == 0 {
			w.literal("absent\n")
			continue
		}
		w.literal(planningOptionalText(generatedPlanningSource(side.source)) + " " + planningOptionalText(generatedPlanningClass(side.class)))
		if side.source == contract.Generated {
			mode, _ := generatedLifecycle(side.mode).(string)
			w.literal("; epoch " + strconv.FormatUint(side.epoch, 10) + "; lifecycle " + mode + "; retirement " + planningOptionalText(generatedPlanningPolicy(side.policy)))
		} else {
			w.literal("; generated epoch, lifecycle and retirement: not applicable")
		}
		w.literal("\n")
	}
	w.literal("  Changed public fields: " + strings.Join(generatedPlanningMask(row.ChangedFields, true), ", ") + "\n")
	w.literal("  Retirement consequence: " + generatedPlanningRetirement(row.Retirement) + "\n")
	blockers := generatedPlanningMask(row.Blockers, false)
	if len(blockers) == 0 {
		w.literal("  Observed blockers: none\n")
	} else {
		w.literal("  Observed blockers: " + strings.Join(blockers, ", ") + "\n")
	}
	for _, identity := range []struct {
		label string
		id    contract.ID
	}{{"Current incarnation", row.CurrentIncarnation}, {"Current generation", row.CurrentGeneration}, {"Active operation", row.ActiveOperation},
		{"Retiring duty", row.RetiringDutyID}, {"Retiring incarnation", row.RetiringIncarnation}, {"Retiring resource", row.RetiringResource},
		{"Retiring original operation", row.RetiringOriginalOperation}, {"Retiring original attempt", row.RetiringOriginalAttempt}} {
		text := "unavailable"
		if !identity.id.IsZero() {
			text = readerID(identity.id)
		}
		w.literal("  " + identity.label + ": " + text + "\n")
	}
	if !row.RetiringDutyID.IsZero() {
		w.literal("  Retiring epoch: " + strconv.FormatUint(row.RetiringEpoch, 10) + "; generation: unavailable\n")
	} else {
		w.literal("  Retiring epoch and generation: unavailable\n")
	}
	w.literal("  Future content: unavailable; public secret content: unchecked.\n")
	if w.at-start > contract.MaxGeneratedPlanningRowJSONBytes {
		w.failed = true
	}
}
