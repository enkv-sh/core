package core

import (
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func administrativeEffectStateEvidence(state uint8) (uint16, error) {
	switch state {
	case contract.GeneratedEffectNotStarted, contract.GeneratedEffectPrepared, contract.GeneratedEffectTransmitted:
		return contract.AdministrativeEvidenceMissing, nil
	case contract.GeneratedEffectSucceeded, contract.GeneratedEffectConfirmedNoEffect:
		// The matching selected result establishes ACK versus confirmation.
		return 0, nil
	case contract.GeneratedEffectFailedTerminal:
		return contract.AdministrativeEvidenceTerminalFailure, nil
	case contract.GeneratedEffectUnknown:
		return contract.AdministrativeEvidenceQualifiedUnknown, nil
	case contract.GeneratedEffectPossibleLive, contract.GeneratedEffectClosedWithResidue:
		return contract.AdministrativeEvidencePossibleLive, nil
	}
	return 0, contract.ErrRecord
}

func administrativeResultEvidence(disposition uint8) (uint16, error) {
	switch disposition {
	case contract.GeneratorDispositionCompleteCreate:
		return contract.AdministrativeEvidenceAcknowledged, nil
	case contract.GeneratorDispositionOwnedUnusableCreate:
		return contract.AdministrativeEvidenceTerminalFailure, nil
	case contract.GeneratorDispositionConfirmedNoEffect:
		return contract.AdministrativeEvidenceConfirmed, nil
	case contract.GeneratorDispositionRetirementAcknowledged:
		return contract.AdministrativeEvidenceAcknowledged, nil
	case contract.GeneratorDispositionUnknown:
		return contract.AdministrativeEvidenceQualifiedUnknown, nil
	case contract.GeneratorDispositionScopedUnusability:
		return contract.AdministrativeEvidenceConfirmed, nil
	case contract.GeneratorDispositionContinuedUsability, contract.GeneratorDispositionConflictingBinding:
		return contract.AdministrativeEvidenceContradiction, nil
	}
	return 0, contract.ErrRecord
}

func publicationCoordinateEvidence(coordinate contract.PublicationCoordinate) uint16 {
	var bits uint16
	switch coordinate.OwnerState {
	case contract.PublicationOwnerNone:
		bits = contract.AdministrativeEvidenceMissing
	case contract.PublicationOwnerUncertainCreate:
		bits = contract.AdministrativeEvidenceQualifiedUnknown
	case contract.PublicationOwnerQualified:
		bits = contract.AdministrativeEvidenceAcknowledged
	}
	if coordinate.PossibleRemoteObject != 0 || coordinate.LateEffectRisk != 0 {
		bits |= contract.AdministrativeEvidencePossibleLive
	}
	return bits
}

// The complete selected image supplies these bits. A partial administrative
// image uses the authenticated group summary and never reads optional detail.
func administrativeSelectedEvidence(index format.AdministrativeIndex, pages []format.RequiredSupportPageView, retained ...map[generatedRecordKey]selectedPublicationRecord) ([]uint16, error) {
	var publication map[generatedRecordKey]selectedPublicationRecord
	if len(retained) > 1 {
		return nil, contract.ErrRecord
	}
	if len(retained) == 1 {
		publication = retained[0]
	}
	if len(index.Pages) != len(pages) {
		return nil, contract.ErrRecord
	}
	attempts := make(map[contract.ID]contract.GeneratedAttemptRecord)
	var carriers []contract.SupportRecord
	for _, page := range pages {
		for _, row := range page.Records {
			if row.Kind == contract.GeneratorVectorSupportKind {
				carriers = append(carriers, contract.SupportRecord(row))
			}
			if row.Kind != contract.GeneratedAttemptSupportKind {
				continue
			}
			attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil || attempt.DomainID != index.Domain || attempt.AttemptID != row.RecordID || !attempts[attempt.AttemptID].AttemptID.IsZero() {
				return nil, contract.ErrRecord
			}
			attempts[attempt.AttemptID] = attempt
		}
	}
	vectors, err := newGeneratedVectorSet(index.Domain, carriers)
	if err != nil {
		return nil, err
	}
	summary := make([]uint16, len(index.Groups))
	for i, group := range index.Groups {
		if group.OwnerKind == format.AdministrativeGC {
			if group.GC == nil {
				return nil, contract.ErrRecord
			}
			summary[i] = group.GC.EvidenceSummary()
		}
	}
	for i, indexed := range index.Pages {
		if indexed.Ref.Index != pages[i].Index {
			return nil, contract.ErrRecord
		}
		selected := 0
		for _, span := range indexed.Spans {
			if selected+int(span.Count) > len(pages[i].Records) {
				return nil, contract.ErrRecord
			}
			for _, row := range pages[i].Records[selected : selected+int(span.Count)] {
				var bits uint16
				var err error
				switch row.Kind {
				case contract.GeneratedAttemptSupportKind:
					attempt := attempts[row.RecordID]
					bits, err = administrativeEffectStateEvidence(attempt.State)
					if err == nil {
						var facts uint16
						facts, err = administrativeAttemptFactsEvidence(attempt, vectors, pages, index.Groups, span.GroupIndexes)
						bits |= facts
					}
				case contract.GeneratedDutySupportKind:
					var duty contract.GeneratedDutyRecord
					duty, err = contract.InspectGeneratedDutyRecord(row.Body)
					if err == nil {
						bits, err = administrativeEffectStateEvidence(duty.Status)
					}
				case contract.GeneratedHazardSupportKind:
					if _, err = contract.InspectGeneratedHazardRecord(row.Body); err == nil {
						bits = contract.AdministrativeEvidencePossibleLive
					}
				case contract.GeneratedResultSupportKind:
					var result contract.GeneratedResultRecordView
					result, err = contract.InspectGeneratedResultRecord(row.Body)
					if err == nil {
						_, ok := attempts[result.Core.AttemptID]
						if !ok {
							return nil, contract.ErrRecord
						}
						bits, err = administrativeResultEvidence(result.Disposition())
					}
				case contract.GeneratedCreateEvidenceSupportKind:
					var evidence contract.GeneratedCreateEvidenceView
					evidence, err = contract.InspectGeneratedCreateEvidence(row.Body)
					if err == nil {
						var facts contract.GeneratorSafeFactsView
						facts, err = contract.InspectGeneratorSafeFacts(evidence.SafeFacts)
						if err == nil {
							if facts.Disposition == contract.GeneratorDispositionConfirmedNoEffect {
								return nil, contract.ErrRecord
							}
							core, errRead := contract.InspectGeneratedResultCore(evidence.ResultCore)
							if errRead != nil {
								return nil, errRead
							}
							bits, err = administrativeResultEvidence(core.Disposition(facts.Disposition))
						}
					}
				case contract.PendingInboxReleaseSupportKind:
					var release contract.PendingInboxReleaseRecord
					release, err = contract.InspectPendingInboxReleaseRecord(row.Body)
					if err == nil {
						switch release.State {
						case contract.GeneratedReleasePending:
							bits = contract.AdministrativeEvidenceReleasePending
						case contract.GeneratedReleaseUnknown:
							bits = contract.AdministrativeEvidenceReleaseUnknown
						case contract.GeneratedReleaseUnobserved:
							bits = contract.AdministrativeEvidenceReleaseUnobserved
						}
					}
				case contract.PublicationCoordinateSupportKind:
					var coordinate contract.PublicationCoordinate
					fact, inspectErr := publicationRecordWithFacts(index.Domain, contract.SupportRecord(row), publication)
					err = inspectErr
					if err == nil {
						coordinate = *fact.coordinate
					}
					if err == nil && coordinate.CoordinateID != row.RecordID {
						err = contract.ErrRecord
					}
					if err == nil {
						bits = publicationCoordinateEvidence(coordinate)
					}
				case contract.PublicationMarkerSupportKind:
					var marker contract.PublicationMarker
					fact, inspectErr := publicationRecordWithFacts(index.Domain, contract.SupportRecord(row), publication)
					err = inspectErr
					if err == nil {
						marker = *fact.marker
					}
					if err == nil && marker.AttemptID != row.RecordID {
						err = contract.ErrRecord
					}
					if err == nil {
						switch marker.State {
						case contract.PublicationMayHaveEntered, contract.PublicationUnknown:
							bits = contract.AdministrativeEvidenceQualifiedUnknown
						case contract.PublicationAcknowledged:
							bits = contract.AdministrativeEvidenceAcknowledged
						case contract.PublicationQualifiedNoEffectState:
							bits = contract.AdministrativeEvidenceConfirmed
						}
						if marker.LateEffectRisk != 0 {
							bits |= contract.AdministrativeEvidencePossibleLive
						}
					}
				}
				if err != nil {
					return nil, err
				}
				for _, group := range span.GroupIndexes {
					if int(group) >= len(summary) {
						return nil, contract.ErrRecord
					}
					summary[group] |= bits
				}
			}
			selected += int(span.Count)
		}
		if selected != len(pages[i].Records) {
			return nil, contract.ErrRecord
		}
	}
	for i := range summary {
		if summary[i]&(contract.AdministrativeEvidenceMissing|contract.AdministrativeEvidenceQualifiedUnknown|
			contract.AdministrativeEvidenceTerminalFailure|contract.AdministrativeEvidenceAcknowledged|
			contract.AdministrativeEvidenceContradiction|contract.AdministrativeEvidenceConfirmed|
			contract.AdministrativeEvidencePossibleLive) == 0 {
			summary[i] |= contract.AdministrativeEvidenceMissing
		}
		if !contract.AdministrativeEvidenceValid(summary[i]) {
			return nil, contract.ErrRecord
		}
	}
	return summary, nil
}

func administrativeAttemptFactsEvidence(attempt contract.GeneratedAttemptRecord, vectors generatedVectorSet, pages []format.RequiredSupportPageView, groups []format.AdministrativeGroup, owners []uint16) (uint16, error) {
	rows, err := vectors.borrow(contract.GeneratedAttemptSupportKind, attempt.AttemptID, contract.GeneratorVectorFacts, attempt.Facts)
	if err != nil || len(rows) > 1 {
		return 0, contract.ErrRecord
	}
	if len(rows) == 0 {
		return 0, nil
	}
	row, err := contract.InspectGeneratorFactsRow(rows[0])
	if err != nil || row.ResultID != attempt.ResultID {
		return 0, contract.ErrRecord
	}
	facts, err := contract.InspectGeneratorAttemptFacts(row.Facts)
	if err != nil || facts.RequestDigest != attempt.RequestDigest || facts.LifecycleMode != attempt.LifecycleMode || facts.ResourceContractID != attempt.ResourceContractID {
		return 0, contract.ErrRecord
	}
	if facts.Action != contract.GeneratorActionDelete || !facts.RetirementRejected && facts.Disposition != contract.GeneratorDispositionUnknown {
		return 0, nil
	}
	var source contract.GeneratedDeleteSource
	found := false
	for _, page := range pages {
		for _, record := range page.Records {
			if record.Kind != contract.GeneratedDutySupportKind && record.Kind != contract.GeneratedHazardSupportKind {
				continue
			}
			candidate, err := contract.InspectGeneratedDeleteSource(contract.SupportRecord(record))
			if err != nil {
				return 0, err
			}
			if candidate.OwnerID != attempt.OwnerID {
				continue
			}
			if found {
				return 0, contract.ErrRecord
			}
			source, found = candidate, true
		}
	}
	if !found {
		if facts.RetirementRejected {
			return 0, contract.ErrRecord
		}
		var release contract.PendingInboxReleaseRecord
		for _, page := range pages {
			for _, record := range page.Records {
				if record.Kind == contract.GeneratedResultSupportKind && record.RecordID == attempt.ResultID {
					return 0, contract.ErrRecord
				}
				if record.Kind != contract.PendingInboxReleaseSupportKind || record.RecordID != attempt.InboxID {
					continue
				}
				if !release.InboxID.IsZero() {
					return 0, contract.ErrRecord
				}
				release, err = contract.InspectPendingInboxReleaseRecord(record.Body)
				if err != nil {
					return 0, err
				}
			}
		}
		if release.DomainID != attempt.DomainID || release.InboxID != attempt.InboxID || release.OriginalResultID != attempt.ResultID || release.State != contract.GeneratedReleaseUnobserved ||
			attempt.Stage != contract.GeneratedStageTerminal || attempt.RetryUsed != 0 || attempt.State != contract.GeneratedEffectUnknown && attempt.State != contract.GeneratedEffectClosedWithResidue ||
			attempt.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) || facts.Reason == contract.GeneratorReasonIdentityConflict {
			return 0, contract.ErrRecord
		}
		owned := false
		for _, owner := range owners {
			if int(owner) >= len(groups) {
				return 0, contract.ErrRecord
			}
			group := groups[owner]
			owned = owned || group.OwnerKind == format.AdministrativeInboxRelease && group.GroupID == release.InboxID && group.OwnerID == release.InboxID && group.TargetID == release.OriginalResultID
		}
		history, err := vectors.borrow(contract.GeneratedAttemptSupportKind, attempt.AttemptID, contract.GeneratorVectorHistory, attempt.History)
		if !owned || err != nil || len(history) != 1 {
			return 0, contract.ErrRecord
		}
		actual, err := contract.InspectGeneratorHistory(history[0])
		want := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: attempt.AttemptID, OwnerID: attempt.OwnerID, Outcome: attempt.State}
		if err != nil || actual != want {
			return 0, contract.ErrRecord
		}
		return contract.AdministrativeEvidenceQualifiedUnknown, nil
	}
	if source.DomainID != attempt.DomainID || source.ResourceID != attempt.ResourceID ||
		source.DescriptorID != attempt.DescriptorID || source.ConfigContractID != attempt.ConfigContractID ||
		source.ExecutorID != attempt.ExecutorID || source.CredentialRouteID != attempt.CredentialRouteID ||
		source.ResourceContractID != attempt.ResourceContractID || source.CompletionClass != attempt.CompletionClass ||
		source.Record.Kind == contract.GeneratedDutySupportKind && source.Duty.Kind != contract.GeneratedDutyRetirement && source.Duty.Kind != contract.GeneratedDutyUnselectedCleanup {
		return 0, contract.ErrRecord
	}
	targetRows, err := vectors.borrow(source.Record.Kind, source.SourceID, contract.GeneratorVectorTargets, source.Target)
	if err != nil || len(targetRows) != 1 {
		return 0, contract.ErrRecord
	}
	target, err := contract.InspectGeneratorTarget(targetRows[0])
	if err != nil || target.ResourceID != source.ResourceID || target.ConfigContractID != source.ConfigContractID || target.ResourceContractID != source.ResourceContractID || target.CompletionClass != source.CompletionClass {
		return 0, contract.ErrRecord
	}
	original, err := generatedCreateResultID(attempt.DomainID, target.OriginalOperationID, target.OriginalAttemptID)
	if err != nil {
		return 0, err
	}
	var originalFacts contract.GeneratorSafeFactsView
	found = false
	for _, page := range pages {
		for _, record := range page.Records {
			if record.RecordID != original {
				continue
			}
			var core contract.GeneratedResultCore
			switch record.Kind {
			case contract.GeneratedCreateEvidenceSupportKind:
				evidence, err := contract.InspectGeneratedCreateEvidence(record.Body)
				if err != nil {
					return 0, err
				}
				core, err = contract.InspectGeneratedResultCore(evidence.ResultCore)
				if err != nil {
					return 0, err
				}
				originalFacts, err = contract.InspectGeneratorSafeFacts(evidence.SafeFacts)
				if err != nil {
					return 0, err
				}
			case contract.GeneratedResultSupportKind:
				result, err := contract.InspectGeneratedResultRecord(record.Body)
				if err != nil {
					return 0, err
				}
				core, originalFacts = result.Core, result.SafeFacts
			default:
				continue
			}
			if core.DomainID != attempt.DomainID || core.OperationID != target.OriginalOperationID || core.AttemptID != target.OriginalAttemptID || core.ResultID != original || core.ConfigContractID != target.ConfigContractID || core.ResultContractID != target.ResultContractID ||
				originalFacts.Action != contract.GeneratorActionCreate || originalFacts.LifecycleMode != target.LifecycleMode || originalFacts.ResourceContractID != target.ResourceContractID ||
				originalFacts.Disposition != contract.GeneratorDispositionCompleteCreate && originalFacts.Disposition != contract.GeneratorDispositionOwnedUnusableCreate || !generatedResourceFactsMatch(originalFacts.GeneratorSafeFacts, target.ResourceDigest) || originalFacts.IntentDigest != facts.IntentDigest {
				return 0, contract.ErrRecord
			}
			found = true
		}
	}
	if !found {
		return 0, contract.ErrRecord
	}
	same := generatedResourceFactsMatch(facts.GeneratorSafeFacts, target.ResourceDigest)
	if facts.RetirementRejected {
		if same || attempt.State != contract.GeneratedEffectUnknown || attempt.Stage != contract.GeneratedStageTerminal {
			return 0, contract.ErrRecord
		}
		return contract.AdministrativeEvidenceContradiction, nil
	}
	if facts.Reason == contract.GeneratorReasonIdentityConflict || !same {
		return contract.AdministrativeEvidenceQualifiedUnknown | contract.AdministrativeEvidenceContradiction, nil
	}
	return contract.AdministrativeEvidenceQualifiedUnknown, nil
}
