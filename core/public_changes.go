package core

import (
	"reflect"
	"slices"
	"strings"

	"enkv.sh/core/contract"
)

func comparisonPath(subject contract.DiagnosticSubject, field contract.DiagnosticField) []contract.DiagnosticField {
	if subject.Kind == contract.SubjectEntry {
		switch field {
		case contract.FieldEpoch, contract.FieldResourceContract, contract.FieldConfigContract, contract.FieldLifecycle, contract.FieldContentIntent, contract.FieldRetirement, contract.FieldCompletion:
			return []contract.DiagnosticField{contract.FieldGenerated, field}
		}
	}
	return []contract.DiagnosticField{field}
}

func comparisonValueSupported(kind contract.ComparisonValueType, value reflect.Value) bool {
	if !value.IsValid() {
		return false
	}
	switch kind {
	case contract.ComparisonTypeBoolean:
		return value.Kind() == reflect.Bool
	case contract.ComparisonTypeUint:
		return value.Kind() >= reflect.Uint && value.Kind() <= reflect.Uint64
	case contract.ComparisonTypeText:
		return value.Kind() == reflect.String
	case contract.ComparisonTypeBytes:
		if value.Type() == reflect.TypeFor[comparisonPlainValue]() {
			_, err := value.Interface().(comparisonPlainValue).contentLength()
			return err == nil
		}
		return value.Type() == reflect.TypeFor[[]byte]()
	case contract.ComparisonTypeID:
		return value.Type() == reflect.TypeFor[contract.ID]()
	case contract.ComparisonTypeIDSet:
		return value.Type() == reflect.TypeFor[[]contract.ID]()
	case contract.ComparisonTypeTextSet:
		return value.Type() == reflect.TypeFor[[]string]() || value.Type() == reflect.TypeFor[[]contract.PublicOutputTarget]()
	case contract.ComparisonTypeGroups:
		return value.Type() == reflect.TypeFor[[][]string]()
	case contract.ComparisonTypeDestination:
		return value.Type() == reflect.TypeFor[contract.OutputDestination]()
	case contract.ComparisonTypePolicy:
		return value.Type() == reflect.TypeFor[contract.OutputPolicy]()
	case contract.ComparisonTypeBounds:
		return value.Type() == reflect.TypeFor[contract.OutputPayloadBounds]()
	}
	return false
}

func ownComparisonBytes(value []byte) []byte {
	owned := make([]byte, len(value))
	copy(owned, value)
	return owned
}

func ownComparisonStrings(value []string) []string {
	owned := make([]string, len(value))
	for at := range value {
		owned[at] = strings.Clone(value[at])
	}
	return owned
}

func ownComparisonPolicy(value contract.OutputPolicy) contract.OutputPolicy {
	return contract.OutputPolicy{ContractID: strings.Clone(value.ContractID), Data: ownComparisonBytes(value.Data)}
}

func (b *publicComparisonBuilder) ownValue(kind contract.ComparisonValueType, subject contract.DiagnosticSubject, field contract.DiagnosticField, value, other reflect.Value, after bool) contract.ComparisonValue {
	switch kind {
	case contract.ComparisonTypeBoolean:
		return contract.ComparisonBoolean(value.Bool())
	case contract.ComparisonTypeUint:
		return contract.ComparisonUint(value.Uint())
	case contract.ComparisonTypeText:
		if field == contract.FieldDisplayName {
			labels := b.payload.BeforeRecipients
			if after {
				labels = b.payload.AfterRecipients
			}
			at, found := slices.BinarySearchFunc(labels, subject.RecipientID, func(label contract.ComparisonRecipientLabel, id contract.ID) int {
				return comparePublicIDs(label.RecipientID, id)
			})
			if found && labels[at].DisplayName != nil {
				return contract.ComparisonText(*labels[at].DisplayName)
			}
		}
		return contract.ComparisonText(strings.Clone(value.String()))
	case contract.ComparisonTypeBytes:
		if value.Type() == reflect.TypeFor[comparisonPlainValue]() {
			return value.Interface().(comparisonPlainValue).ownApplicationBytes()
		}
		return contract.ComparisonBytes(ownComparisonBytes(value.Bytes()))
	case contract.ComparisonTypeID:
		return contract.ComparisonID(value.Interface().(contract.ID))
	case contract.ComparisonTypeIDSet:
		ids := value.Interface().([]contract.ID)
		var otherIDs []contract.ID
		if other.IsValid() {
			otherIDs = other.Interface().([]contract.ID)
		}
		members := make(contract.ComparisonIDSet, len(ids))
		for at, id := range ids {
			change := contract.ComparisonMemberRemoved
			if after {
				change = contract.ComparisonMemberAdded
			}
			if _, found := slices.BinarySearchFunc(otherIDs, id, comparePublicIDs); found {
				change = contract.ComparisonMemberUnchanged
			}
			members[at] = contract.ComparisonMember{ID: id, Change: change}
		}
		return members
	case contract.ComparisonTypeTextSet:
		if value.Type() == reflect.TypeFor[[]string]() {
			return contract.ComparisonTextSet(ownComparisonStrings(value.Interface().([]string)))
		}
		targets := value.Interface().([]contract.PublicOutputTarget)
		names := make(contract.ComparisonTextSet, len(targets))
		for at := range targets {
			names[at] = strings.Clone(targets[at].EntryName)
		}
		return names
	case contract.ComparisonTypeGroups:
		groups := value.Interface().([][]string)
		owned := make(contract.ComparisonGroups, len(groups))
		for at := range groups {
			owned[at] = ownComparisonStrings(groups[at])
		}
		return owned
	case contract.ComparisonTypeDestination:
		destination := value.Interface().(contract.OutputDestination)
		destination.ConfigContractID = strings.Clone(destination.ConfigContractID)
		destination.ServiceContractID = strings.Clone(destination.ServiceContractID)
		destination.CanonicalSettings = ownComparisonBytes(destination.CanonicalSettings)
		destination.Policy = ownComparisonPolicy(destination.Policy)
		return contract.ComparisonDestination(destination)
	case contract.ComparisonTypePolicy:
		return contract.ComparisonPolicy(ownComparisonPolicy(value.Interface().(contract.OutputPolicy)))
	case contract.ComparisonTypeBounds:
		return contract.ComparisonBounds(value.Interface().(contract.OutputPayloadBounds))
	}
	return nil
}

func comparisonRecipientLabels(rows contract.PublicField[[]contract.PublicRecipient]) []contract.ComparisonRecipientLabel {
	if rows.State != contract.PublicPresent {
		return nil
	}
	labels := make([]contract.ComparisonRecipientLabel, len(rows.Value))
	for at, row := range rows.Value {
		labels[at].RecipientID = row.RecipientID
		if row.DisplayName.State == contract.PublicPresent {
			label := strings.Clone(row.DisplayName.Value)
			labels[at].DisplayName = &label
		}
	}
	return labels
}

func comparePublicChanges(a, b contract.ComparisonChange) int {
	if c := strings.Compare(string(a.Subject.Kind), string(b.Subject.Kind)); c != 0 {
		return c
	}
	if c := comparePublicSubjects(a.Subject, b.Subject); c != 0 {
		return c
	}
	return slices.Compare(a.Path, b.Path)
}

func (b *publicComparisonBuilder) withAbsence(want, actual bool, visit func()) {
	oldWant, oldActual := b.wantAbsent, b.actualAbsent
	b.wantAbsent, b.actualAbsent = want, actual
	visit()
	b.wantAbsent, b.actualAbsent = oldWant, oldActual
}

func incompleteComparison(p *contract.ComparisonPayload) {
	p.DiagnosticsComplete, p.Verdict = false, contract.ComparisonUnable
	diagnostic := contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonDiagnosticsIncomplete}
	if len(p.Diagnostics) != 0 {
		p.Diagnostics[len(p.Diagnostics)-1] = diagnostic
		return
	}
	if len(p.Changes) != 0 {
		at := len(p.Changes) - 1
		p.Changes[at] = contract.ComparisonChange{}
		p.Changes = p.Changes[:at]
	}
	p.Diagnostics = []contract.Diagnostic{diagnostic}
}
