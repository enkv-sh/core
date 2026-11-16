package core

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"slices"

	"enkv.sh/core/contract"
)

type publicationCurrent func(context.Context) (*StateSession, contract.Trust, Result)

type publicationOperationResult struct {
	state                   Result
	output                  contract.PublicationOutcomeVector
	summary                 uint8
	executableCleanupFailed bool
}

func (plan *publicationPlan) executePublication(ctx context.Context, private publicationPrivate, current publicationCurrent) publicationOperationResult {
	result := publicationOperationResult{state: plan.session.observed(ObservedCurrent), output: plan.vector}
	priority := func(state Result) uint8 {
		switch state.Outcome {
		case IntegrityFailure:
			return 6
		case UnresolvedCommit:
			return 5
		case EvidenceUnavailable:
			return 4
		case Contention:
			return 3
		case RootLossUnsupported:
			return 2
		case AdmissionRefused:
			return 1
		}
		if state.Reason != NoReason {
			return 1
		}
		return 0
	}
	recordState := func(next Result) {
		previous := result.state
		nextPriority, previousPriority := priority(next), priority(previous)
		if nextPriority != previousPriority {
			if nextPriority > previousPriority {
				result.state = next
			}
			return
		}
		if nextPriority == 0 {
			result.state = next
			return
		}
		possibleOrder := 0
		if next.CommitMayHaveOccurred != previous.CommitMayHaveOccurred {
			possibleOrder = 1
			if next.CommitMayHaveOccurred {
				possibleOrder = -1
			}
		}
		order := cmp.Or(cmp.Compare(next.Reason, previous.Reason), cmp.Compare(next.StoreReason, previous.StoreReason),
			cmp.Compare(previous.Outcome, next.Outcome), possibleOrder,
			bytes.Compare(next.RequestedRevision[:], previous.RequestedRevision[:]),
			bytes.Compare(next.ObservedRevision[:], previous.ObservedRevision[:]),
			bytes.Compare(next.ObservedSnapshotID[:], previous.ObservedSnapshotID[:]), cmp.Compare(next.Evidence, previous.Evidence))
		if order < 0 {
			result.state = next
		}
	}
	retirementFailed := false
	retire := func(preparation *publicationPreparation) {
		err := preparation.retire(ctx)
		if err == nil {
			return
		}
		retirementFailed = true
		var cleanup publicationExecutableCleanupFailure
		if errors.As(err, &cleanup) && cleanup.ExecutableCleanupFailed() {
			result.executableCleanupFailed = true
		}
	}
	if current == nil {
		result.state = refused(AdmissionInvalid)
		result.summary = contract.SummarizePublication(result.output.Entries)
		return result
	}
	for targetIndex, p := range plan.targets {
		if len(p.actions) == 0 || p.refusal != 0 {
			continue
		}
		for actionIndex, action := range p.actions {
			s, trust, state := current(ctx)
			if s == nil || trust == nil || trust.Identity() != s.admission.trust || trust.Family() != s.admission.store.Family || !publicationNormalAdmission(ctx, s, plan.input.deadline) {
				if state.Outcome == 0 || state.Outcome == ObservedCurrent || state.Outcome == Unchanged {
					state = refused(AdmissionInvalid)
				}
				recordState(state)
				reason := state.Reason
				if reason == NoReason {
					reason = AdmissionInvalid
				}
				result.output.Entries[targetIndex].Actions[actionIndex].CoreReason = uint16(reason)
				break
			}
			result.output.DomainWideWarning |= s.publicationDomainWideWarning()
			candidate, preparation, state := plan.reserveCandidate(ctx, s, p, action, private)
			if candidate == nil {
				recordState(state)
				result.output.Entries[targetIndex].Actions[actionIndex].CoreReason = uint16(state.Reason)
				break
			}
			// Retire occurs after close, so only the original armed process can own the
			// validated result. Every failure path positively joins its private owner.
			persisted, state := s.persistCandidate(ctx, candidate, trust)
			if persisted == nil {
				recordState(state)
				result.output.Entries[targetIndex].Actions[actionIndex].CoreReason = uint16(state.Reason)
				retire(preparation)
				break
			}
			selected, state := s.selectCandidate(ctx, persisted)
			if selected != nil {
				result.output.DomainWideWarning |= selected.publicationDomainWideWarning()
			}
			recordState(state)
			preparation.mu.Lock()
			armed := preparation.armed
			preparation.mu.Unlock()
			row := &result.output.Entries[targetIndex].Actions[actionIndex]
			if !armed {
				markerSelected := false
				if selected != nil {
					facts, err := selectedPublicationRelation(selected.selectedImage())
					if err == nil {
						marker, present := facts.markers[preparation.original.marker.AttemptID]
						markerSelected = present && marker == preparation.original.marker
					}
				}
				if markerSelected || state.CommitMayHaveOccurred {
					unknown := publicationUnknownResult(preparation.original)
					*row = publicationResultOutcome(preparation.original, unknown, contract.PublicationOutcomeUnknown, p.blockers)
				} else {
					row.CoreReason = uint16(state.Reason)
					if row.CoreReason == 0 {
						row.CoreReason = uint16(DifferentSelection)
					}
				}
				retire(preparation)
				break
			}
			wire, code := preparation.send(ctx)
			if code != contract.CryptoSuccess || contract.ValidatePublicationResult(preparation.original.dispatch, wire) != nil {
				wire = publicationUnknownResult(preparation.original)
			}
			*row = publicationResultOutcome(preparation.original, publicationUnknownResult(preparation.original), contract.PublicationOutcomeUnknown, p.blockers)
			closer, closeTrust, closeState := current(ctx)
			if closer != nil && closeTrust != nil && closeTrust.Identity() == closer.admission.trust && closeTrust.Family() == closer.admission.store.Family {
				result.output.DomainWideWarning |= closer.publicationDomainWideWarning()
				closeCandidate, closeState := plan.closeCandidate(ctx, closer, preparation, wire)
				if closeCandidate != nil {
					closedCandidate, persistState := closer.persistCandidate(ctx, closeCandidate, closeTrust)
					closeState = persistState
					if closedCandidate != nil {
						closed, selectState := closer.selectCandidate(ctx, closedCandidate)
						closeState = selectState
						if closed != nil {
							result.output.DomainWideWarning |= closed.publicationDomainWideWarning()
							facts, e := selectedPublicationRelation(closed.selectedImage())
							if e == nil {
								marker, present := facts.markers[preparation.original.marker.AttemptID]
								if present && marker.AuthoritySubjectDigest == preparation.original.reservationAdmissionDigest && marker.State != contract.PublicationMayHaveEntered {
									disposition := uint8(contract.PublicationOutcomeUnknown)
									if marker.State == contract.PublicationAcknowledged {
										disposition = contract.PublicationOutcomeAcknowledged
									}
									if marker.State == contract.PublicationQualifiedNoEffectState {
										disposition = contract.PublicationOutcomeQualifiedNoEffect
									}
									wire.Evidence = marker.Evidence
									*row = publicationResultOutcome(preparation.original, wire, disposition, p.blockers)
									row.LateWriteRisk = marker.LateEffectRisk
									row.RemoteValueMayRemain = facts.coordinates[p.coordinate].PossibleRemoteObject
								}
							}
						}
					}
				}
				recordState(closeState)
			} else {
				recordState(closeState)
			}
			retire(preparation)
			if row.Disposition != contract.PublicationOutcomeAcknowledged {
				break
			}
			// The next fixed action consumes only selected birth evidence. It gets a
			// fresh Check, normal admission, distinct marker and direct selection arm.
			// Retire joins the prior owner even when disposal reports an error;
			// continuation preserves that failure at operation scope.
		}
	}
	if _, err := contract.EncodePublicationOutcomeVector(result.output); err != nil {
		recordState(refused(InvalidRelation))
	}
	if retirementFailed {
		recordState(refused(CustodyUnavailable))
	}
	result.summary = contract.SummarizePublication(result.output.Entries)
	return result
}

func publicationResultOutcome(original publicationOriginalResultOwner, result contract.PublicationResult, disposition uint8, blockers []contract.ID) contract.PublicationOutcome {
	return contract.PublicationOutcome{Action: original.dispatch.Projection.Action, ProjectionCommitment: original.dispatch.ProjectionCommitment, AttemptID: original.dispatch.AttemptID, Disposition: disposition, RemoteValueMayRemain: 1, LateWriteRisk: original.marker.LateEffectRisk, BlockerIDs: slices.Clone(blockers), Evidence: result.Evidence}
}
