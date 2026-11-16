package main

import (
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
)

func resultCode(r core.Result) int {
	switch r.Outcome {
	case core.ObservedCurrent, core.Unchanged:
		return 0
	case core.EvidenceUnavailable, core.UnresolvedCommit, core.Contention:
		return 3
	}
	return 2
}

func applyPublicationResultCode(r core.PublicApplyPublicationResult) int {
	apply := compositionfull.MutationExitCode(r.Apply)
	if r.Publication.Stage == "evaluated" && r.Publication.Result != nil {
		publication := compositionfull.PublicationExitCode(*r.Publication.Result)
		if apply == 3 || publication == 3 {
			return 3
		}
		if apply != 0 || publication != 0 {
			return 2
		}
		return 0
	}
	if apply == 3 || r.Publication.Reason == "selection-unavailable" || r.Publication.Reason == "deadline-expired" {
		return 3
	}
	return 2
}
