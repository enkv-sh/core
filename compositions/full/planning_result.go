package compositionfull

import (
	"strconv"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func RenderPlanningJSON(r ConfigurationPlanningResult) ([]byte, error) {
	return renderPlanning(r, false, false)
}
func RenderPlanningHuman(r ConfigurationPlanningResult) ([]byte, error) {
	return renderPlanning(r, true, false)
}

// RenderPlanningCommandJSON includes the final command framing in the same backing.
func RenderPlanningCommandJSON(r ConfigurationPlanningResult) ([]byte, error) {
	return renderPlanning(r, false, true)
}
func PlanningExitCode(r ConfigurationPlanningResult) int {
	if r.SourceFailure != nil && (r.PrivateComplete || len(r.PrivateEntries) != 0 || r.SelectedRecords != 0 || r.CompletedRecords != 0 || r.DisplayDelivery != contract.PlanningNotRequested) {
		return 2
	}
	if !validInstallationRequirementComparison(r.InstallationRequirements) || !validPlanningResult(r.PlanningResult) {
		return 2
	}
	return ComparisonExitCode(ConfigurationComparisonResult{PublicComparisonResult: core.PublicComparisonResult{StateResult: r.StateResult, ComparisonPayload: r.ComparisonPayload}, InstallationRequirements: r.InstallationRequirements})
}
func validPlanningResult(r core.PlanningResult) bool {
	if !validComparisonFacts(r.ComparisonPayload) || !validPublicationPreview(r.ComparisonPayload) || r.Context.Operation != contract.PlanningOperation || !validReaderState(r.StateResult) || len(r.Diagnostics) > contract.MaxPublicDiagnostics || len(r.Changes) > contract.MaxPublicDiagnostics-len(r.Diagnostics) || r.EvidenceLimit != contract.PlanningEvidenceLimit || len(r.CheckedScope) > 12 || !validGeneratedPlanningEntries(r.GeneratedEntries) || len(r.GeneratedEntries) != 0 && r.Observation == nil {
		return false
	}
	if r.StateResult == contract.ReaderSuccess {
		if !r.PrivateComplete || !r.DiagnosticsComplete || r.Observation == nil || r.Verdict != contract.ComparisonMatch && r.Verdict != contract.ComparisonMismatch || r.DisplayDelivery != contract.PlanningNotRequested && r.DisplayDelivery != contract.PlanningDeliveryComplete {
			return false
		}
	} else if r.Verdict != contract.ComparisonUnable {
		return false
	}
	if r.Observation != nil && (r.Observation.DomainID.IsZero() || r.Observation.HeadRevisionID.IsZero() || r.Observation.SnapshotID.IsZero()) {
		return false
	}
	for _, scope := range r.CheckedScope {
		if !validReaderScope(scope) {
			return false
		}
	}
	verifiedDifference := len(r.Changes) != 0
	for _, diagnostic := range r.Diagnostics {
		if _, ok := readerDiagnostic(diagnostic); !ok {
			return false
		}
		if diagnostic.Outcome != contract.DiagnosticUnable {
			return false
		}
		if r.StateResult == contract.ReaderSuccess && diagnostic.Outcome == contract.DiagnosticUnable {
			return false
		}
	}
	if len(r.PrivateEntries) > contract.CryptoMaxValueEntries || r.SelectedRecords > contract.CryptoMaxValueEntries || r.CompletedRecords > r.SelectedRecords || (r.PrivateComplete || r.DisplayDelivery == contract.PlanningDeliveryComplete || r.CompletedRecords > 0) && r.SelectedRecords > uint32(len(r.PrivateEntries)) {
		return false
	}
	switch r.DisplayDelivery {
	case contract.PlanningNotRequested:
		if r.SelectedRecords != 0 || r.CompletedRecords != 0 {
			return false
		}
	case contract.PlanningDeliveryNone:
		if r.CompletedRecords != 0 {
			return false
		}
	case contract.PlanningDeliveryComplete:
		if !r.PrivateComplete || r.SelectedRecords == 0 || r.CompletedRecords != r.SelectedRecords {
			return false
		}
	case contract.PlanningDeliveryIncomplete:
	default:
		return false
	}
	for at, row := range r.PrivateEntries {
		if !boundedReaderText(row.Name, contract.CryptoMaxName) || at > 0 && r.PrivateEntries[at-1].Name >= row.Name || row.Form != contract.PlanningSealed && row.Form != contract.PlanningRetained {
			return false
		}
		if row.Form == contract.PlanningRetained && row.Code == contract.CryptoSuccess && row.Relation != contract.PlanningEqual {
			return false
		}
		switch row.Relation {
		case contract.PlanningEqual, contract.PlanningChanged, contract.PlanningNew:
			if row.Code != contract.CryptoSuccess {
				return false
			}
		case contract.PlanningUnchecked:
			if row.Code != 0 && row.Code != contract.CryptoSuccess {
				return false
			}
		case contract.PlanningFailed:
			if !row.Code.Valid() || row.Code == contract.CryptoSuccess {
				return false
			}
		default:
			return false
		}
		if row.Relation == contract.PlanningChanged || row.Relation == contract.PlanningNew {
			verifiedDifference = true
		}
		if r.PrivateComplete && (row.Relation == contract.PlanningFailed || row.Code != contract.CryptoSuccess) {
			return false
		}
	}
	if r.StateResult == contract.ReaderSuccess && (r.Verdict == contract.ComparisonMismatch) != verifiedDifference {
		return false
	}
	return true
}
func planningRelationReason(row contract.PlanningRelation) string {
	if row.Relation == contract.PlanningUnchecked && row.Code == contract.CryptoSuccess {
		return "unsupported-comparison"
	}
	if row.Code == 0 {
		return "unchecked"
	}
	switch row.Code {
	case contract.CryptoSuccess:
		return "none"
	case contract.CryptoExpired:
		return string(contract.ReasonExpired)
	case contract.CryptoCancelled:
		return string(contract.ReasonCancelled)
	case contract.CryptoCapacityExceeded:
		return string(contract.ReasonLimitExceeded)
	case contract.CryptoStoredAuthenticationFailed:
		return string(contract.ReasonSelectedObjectInvalid)
	case contract.CryptoCustodyUnavailable, contract.CryptoPrivateRouteUnavailable, contract.CryptoResponseUnknown:
		return string(contract.ReasonEvidenceUnavailable)
	}
	return string(contract.ReasonInvalidInput)
}
func renderPlanning(r ConfigurationPlanningResult, human, command bool) ([]byte, error) {
	if !validConfigurationSourceFailure(r.SourceFailure) || !validSourceFailureDiagnostics(r.SourceFailure, r.Diagnostics) || r.SourceFailure != nil && (!validSourceFailureReaderState(r.Result, r.StateResult) || r.PreAdmission == nil || !validSourceAdmissionStage(r.PreAdmission.Stage) || r.Observation != nil || r.Verdict != contract.ComparisonUnable || r.StateResult == contract.ReaderSuccess || !validSourceFailureComparison(r.ComparisonPayload) || len(r.InstallationRequirements.Differences) != 0) {
		return nil, ErrReaderResult
	}
	if r.SourceFailure != nil && (r.PrivateComplete || len(r.PrivateEntries) != 0 || r.SelectedRecords != 0 || r.CompletedRecords != 0 || r.DisplayDelivery != contract.PlanningNotRequested) {
		return nil, ErrReaderResult
	}
	if !validInstallationRequirementComparison(r.InstallationRequirements) || !validPlanningResult(r.PlanningResult) {
		return nil, ErrReaderResult
	}
	h := readerResultHeader{Schema: "ProductResult/v1", Operation: contract.PlanningOperation, State: r.StateResult, Effect: "not-applicable", Output: "not-applicable", Context: readerContext(r.Context)}
	if r.PreAdmission != nil {
		identity, ok := preAdmissionIdentity(h.Operation, r.Context.OperationID, r.PreAdmission)
		if !ok || r.StateResult == contract.ReaderSuccess || r.Observation != nil || r.Verdict != contract.ComparisonUnable {
			return nil, ErrReaderResult
		}
		h.OperationID, h.RequestIdentity, h.ReplayIdentity = readerID(r.Context.OperationID), &identity, "none"
	}
	if r.Observation != nil {
		if r.Observation.DomainID.IsZero() || r.Observation.HeadRevisionID.IsZero() || r.Observation.SnapshotID.IsZero() {
			return nil, ErrReaderResult
		}
		h.Observation = readerObservation(r.Observation.DomainID, r.Observation.HeadRevisionID, r.Observation.SnapshotID)
	}
	maximum := contract.MaxComparisonResultJSONBytes
	if r.PublicationRequested {
		maximum = contract.MaxPublicationPlanningResultJSONBytes
	}
	return renderComparisonResultBound(maximum+configurationRequirementResultAllowance, !human && (!command || r.DisplayDelivery != contract.PlanningDeliveryComplete), func(w *readerResultWriter) {
		framingStart := w.at
		terminal := command && r.DisplayDelivery == contract.PlanningDeliveryComplete
		if terminal {
			w.literal(`{"kind":"plan-result","result":`)
		}
		framingBytes := w.at - framingStart
		if human {
			writePlanningHumanHeader(w, h, r.ComparisonPayload)
		} else {
			w.header(h, false)
		}
		w.sourceFailure(r.SourceFailure, human)
		if !human {
			w.literal(`,"payload":{"schema":"PlanningPayload/v1","verdict":`)
			w.json(r.Verdict, 128)
			w.literal(`,"diagnostics_complete":` + strconv.FormatBool(r.DiagnosticsComplete) + `,"evidence_limit":`)
			w.json(r.EvidenceLimit, 4096)
			w.literal(`,"checked_scope":[`)
		}
		for i, scope := range r.CheckedScope {
			if !validReaderScope(scope) {
				w.failed = true
				return
			}
			if human {
				w.literal("Checked scope " + string(scope.Family) + ": " + string(scope.Status) + "\n")
				continue
			} else if i != 0 {
				w.literal(",")
			}
			w.json(struct {
				Family contract.ComparisonFieldFamily `json:"family"`
				Status contract.ComparisonScopeStatus `json:"status"`
			}{scope.Family, scope.Status}, 4096)
		}
		if !human {
			w.literal(`],"diagnostics":[`)
		}
		for i, d := range r.Diagnostics {
			record, ok := readerDiagnostic(d)
			if !ok {
				w.failed = true
				return
			}
			if human {
				writeDiagnosticHuman(readerHumanFacts{w}, d)
				continue
			} else if i != 0 {
				w.literal(",")
			}
			w.json(record, 4096)
		}

		if !human {
			w.literal("]")
		}
		renderProposedChanges(w, r.ComparisonPayload, human)
		renderGeneratedPlanningEntries(w, r.GeneratedEntries, human)
		renderPublicationPreview(w, r.Publication, human)
		if !human {
			w.literal(`,"private_entries":[`)
		} else if r.PrivateComplete {
			w.literal("Private checks: complete.\n")
		} else {
			w.literal("Private checks: incomplete.\n")
		}
		for at, row := range r.PrivateEntries {
			record := struct {
				Name     string                           `json:"name"`
				Form     contract.PlanningSourceForm      `json:"input_form"`
				Relation contract.PlanningPrivateRelation `json:"relation"`
				Reason   string                           `json:"reason"`
			}{row.Name, row.Form, row.Relation, planningRelationReason(row)}
			if human {
				w.literal("Supplied secret ")
				w.comparisonHumanString(row.Name)
				w.literal(": " + string(row.Relation) + "; input " + string(row.Form) + "; reason " + planningRelationReason(row) + "\n")
				continue
			} else if at != 0 {
				w.literal(",")
			}
			w.json(record, 4096)
		}
		if human {
			w.literal("Secret display: " + string(r.DisplayDelivery) + "; selected " + strconv.FormatUint(uint64(r.SelectedRecords), 10) + "; completed " + strconv.FormatUint(uint64(r.CompletedRecords), 10) + "\n")
			w.literal("No changes were applied or published.\n")
		} else {
			w.literal(`],"private_complete":` + strconv.FormatBool(r.PrivateComplete) + `,"display_delivery":`)
			w.json(r.DisplayDelivery, 128)
			w.literal(`,"selected_records":` + strconv.FormatUint(uint64(r.SelectedRecords), 10) + `,"completed_records":` + strconv.FormatUint(uint64(r.CompletedRecords), 10) + "}")
		}
		domainBytes := w.at - framingBytes
		requirementStart := w.at
		renderInstallationRequirementComparison(w, r.InstallationRequirements, human)
		requirementBytes := w.at - requirementStart
		if !human {
			w.literal("}")
			domainBytes++
		}
		if terminal {
			w.literal("}")
			framingBytes++
		}
		if command {
			w.literal("\n")
			framingBytes++
		}
		if domainBytes > maximum || requirementBytes+framingBytes > configurationRequirementResultAllowance {
			w.failed = true
		}
	})
}
