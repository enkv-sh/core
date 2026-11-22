package compositionfull

import (
	"context"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// ContinueConfigurationApply uses the source only for trusted construction.
// Accepted declaration, recipients and generated targets come from selected state.
func ContinueConfigurationApply(ctx context.Context, requestID contract.ID, pair *configuration.Pair, operationID contract.ID) (out ConfigurationApplyResult) {
	out.PublicApplyResult = configurationGeneratedMutation(ctx, requestID, pair, func(e *core.InstalledApply) core.PublicApplyResult { return e.Continue(ctx, requestID, operationID) }, openConfigurationApply, configurationMutationResultFacts{&out.SourceFailure, &out.storeLocation})
	return out
}
func ContinueConfigurationApplyFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format, operationID contract.ID) (out ConfigurationApplyResult) {
	return configurationGeneratedMutationFile(ctx, requestID, path, format, func(pair *configuration.Pair) ConfigurationApplyResult {
		return ContinueConfigurationApply(ctx, requestID, pair, operationID)
	})
}
func RetireConfigurationGenerated(ctx context.Context, requestID contract.ID, pair *configuration.Pair, request core.GeneratedRetirementRequest) (out ConfigurationApplyResult) {
	out.PublicApplyResult = configurationGeneratedMutation(ctx, requestID, pair, func(e *core.InstalledApply) core.PublicApplyResult { return e.RetireGenerated(ctx, requestID, request) }, openConfigurationApply, configurationMutationResultFacts{&out.SourceFailure, &out.storeLocation})
	return out
}
func ContinueConfigurationGeneratedRetirement(ctx context.Context, requestID contract.ID, pair *configuration.Pair, request core.GeneratedRetirementContinuationRequest) (out ConfigurationApplyResult) {
	out.PublicApplyResult = configurationGeneratedMutation(ctx, requestID, pair, func(e *core.InstalledApply) core.PublicApplyResult {
		return e.ContinueGeneratedRetirement(ctx, requestID, request)
	}, openConfigurationApply, configurationMutationResultFacts{&out.SourceFailure, &out.storeLocation})
	return out
}
func AcceptConfigurationGeneratedRetirementRisk(ctx context.Context, requestID contract.ID, pair *configuration.Pair, request core.GeneratedRetirementRiskRequest) (out ConfigurationApplyResult) {
	out.PublicApplyResult = configurationGeneratedMutation(ctx, requestID, pair, func(e *core.InstalledApply) core.PublicApplyResult {
		return e.AcceptGeneratedRetirementRisk(ctx, requestID, request)
	}, openConfigurationApply, configurationMutationResultFacts{&out.SourceFailure, &out.storeLocation})
	return out
}

func CleanupConfigurationGenerated(ctx context.Context, requestID contract.ID, pair *configuration.Pair) (out ConfigurationApplyResult) {
	out.PublicApplyResult = configurationGeneratedMutation(ctx, requestID, pair, func(e *core.InstalledApply) core.PublicApplyResult { return e.CleanupGenerated(ctx, requestID) }, openConfigurationApply, configurationMutationResultFacts{&out.SourceFailure, &out.storeLocation})
	return out
}
func ReleaseConfigurationGeneratedInbox(ctx context.Context, requestID contract.ID, pair *configuration.Pair, inboxID contract.ID) (out ConfigurationApplyResult) {
	if inboxID.IsZero() {
		var format configuration.Format
		if pair != nil {
			format = pair.Format
		}
		var err error
		out.PublicApplyResult, err = newConfigurationApplyResult(requestID, format)
		if err != nil {
			out.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.CustodyUnavailable}
		}
		return out
	}
	out.PublicApplyResult = configurationGeneratedMutation(ctx, requestID, pair, func(e *core.InstalledApply) core.PublicApplyResult {
		return e.ReleaseGeneratedInbox(ctx, requestID, inboxID)
	}, openConfigurationApply, configurationMutationResultFacts{&out.SourceFailure, &out.storeLocation})
	return out
}
func ContinueConfigurationGeneratedCleanup(ctx context.Context, requestID contract.ID, pair *configuration.Pair, request core.GeneratedCleanupContinuationRequest) (out ConfigurationApplyResult) {
	out.PublicApplyResult = configurationGeneratedMutation(ctx, requestID, pair, func(e *core.InstalledApply) core.PublicApplyResult {
		return e.ContinueGeneratedCleanup(ctx, requestID, request)
	}, openConfigurationApply, configurationMutationResultFacts{&out.SourceFailure, &out.storeLocation})
	return out
}
func CleanupConfigurationGeneratedFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format) (out ConfigurationApplyResult) {
	return configurationGeneratedMutationFile(ctx, requestID, path, format, func(pair *configuration.Pair) ConfigurationApplyResult {
		return CleanupConfigurationGenerated(ctx, requestID, pair)
	})
}
func ReleaseConfigurationGeneratedInboxFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format, inboxID contract.ID) (out ConfigurationApplyResult) {
	if inboxID.IsZero() {
		var err error
		out.PublicApplyResult, err = newConfigurationApplyResult(requestID, format)
		if err != nil {
			out.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.CustodyUnavailable}
		}
		return out
	}
	return configurationGeneratedMutationFile(ctx, requestID, path, format, func(pair *configuration.Pair) ConfigurationApplyResult {
		return ReleaseConfigurationGeneratedInbox(ctx, requestID, pair, inboxID)
	})
}
func ContinueConfigurationGeneratedCleanupFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format, request core.GeneratedCleanupContinuationRequest) (out ConfigurationApplyResult) {
	return configurationGeneratedMutationFile(ctx, requestID, path, format, func(pair *configuration.Pair) ConfigurationApplyResult {
		return ContinueConfigurationGeneratedCleanup(ctx, requestID, pair, request)
	})
}
func RetireConfigurationGeneratedFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format, request core.GeneratedRetirementRequest) (out ConfigurationApplyResult) {
	return configurationGeneratedMutationFile(ctx, requestID, path, format, func(pair *configuration.Pair) ConfigurationApplyResult {
		return RetireConfigurationGenerated(ctx, requestID, pair, request)
	})
}
func ContinueConfigurationGeneratedRetirementFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format, request core.GeneratedRetirementContinuationRequest) (out ConfigurationApplyResult) {
	return configurationGeneratedMutationFile(ctx, requestID, path, format, func(pair *configuration.Pair) ConfigurationApplyResult {
		return ContinueConfigurationGeneratedRetirement(ctx, requestID, pair, request)
	})
}
func AcceptConfigurationGeneratedRetirementRiskFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format, request core.GeneratedRetirementRiskRequest) (out ConfigurationApplyResult) {
	return configurationGeneratedMutationFile(ctx, requestID, path, format, func(pair *configuration.Pair) ConfigurationApplyResult {
		return AcceptConfigurationGeneratedRetirementRisk(ctx, requestID, pair, request)
	})
}

func configurationAcceptedGeneratedInput(m *configuration.Model) (core.ApplyInstallation, error) {
	if m == nil {
		return core.ApplyInstallation{}, contract.ErrRecord
	}
	// Only independently trusted authority and Store construction are relevant.
	// The general input adapter still checks their exact selected public basis.
	trusted := *m
	trusted.Entries = nil
	trusted.Recipients = nil
	trusted.Outputs = nil
	trusted.Plugins = nil
	trusted.Public = contract.PublicConfiguration{}
	i, _, err := configurationApplyInput(&trusted)
	return i, err
}
func configurationGeneratedMutation(ctx context.Context, requestID contract.ID, pair *configuration.Pair, invoke func(*core.InstalledApply) core.PublicApplyResult, open func(context.Context, *configuration.Model, core.ApplyInstallation) (*core.InstalledApply, error), resultFacts ...configurationMutationResultFacts) core.PublicApplyResult {
	var format configuration.Format
	if pair != nil {
		format = pair.Format
	}
	out, err := newConfigurationApplyResult(requestID, format)
	if err != nil {
		return out
	}
	refuse := func(stage string, err error) core.PublicApplyResult {
		return configurationApplyFailure(ctx, out, stage, err, mutationSourceFailureTarget(resultFacts))
	}

	m, err := configuration.ParseForAcceptedWork(ctx, pair)
	if err != nil {
		return refuse("parse", err)
	}
	i, err := configurationAcceptedGeneratedInput(m)
	if err != nil {
		return refuse("declaration", err)
	}
	if ctx == nil || ctx.Err() != nil || requestID.IsZero() || open == nil || invoke == nil {
		return refuse("context", nil)
	}
	if deadline, finite := ctx.Deadline(); !finite || !time.Now().Before(deadline) {
		return refuse("context", &configuration.Diagnostic{Reason: "expired"})
	}
	e, err := open(ctx, m, i)
	if err != nil || e == nil {
		return configurationAccessMutationUnavailable(ctx, out)
	}
	releaseConfigurationBasis(m)
	defer e.Close()
	result := invoke(e)
	if result.RequestIdentity.IsZero() {
		if result.OperationID.IsZero() {
			result.OperationID = out.OperationID
		}
		out.PreAdmission.Stage = "observation"
		out.PreAdmission.Code = string(configurationMutationObservationReason(ctx, result.Result))
		result.PreAdmission = out.PreAdmission
	}
	retainMutationStoreLocation(resultFacts, m, result)
	return result
}
func configurationGeneratedMutationFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format, invoke func(*configuration.Pair) ConfigurationApplyResult) (out ConfigurationApplyResult) {
	raw, err := newConfigurationApplyResult(requestID, format)
	out.PublicApplyResult = raw
	if err != nil {
		return out
	}
	pair, err := configuration.Capture(ctx, path, format)
	if err != nil {
		out.PublicApplyResult = configurationApplyFailure(ctx, raw, "capture", err, &out.SourceFailure)
		return out
	}
	defer func() {
		if err := pair.Close(); err != nil {
			out.AddCleanupDiagnostic()
			if out.Cleanup != nil {
				if err := core.RefreshGeneratedCleanupResult(&out.PublicApplyResult); err != nil {
					out.Diagnostics = append(out.Diagnostics, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonSelectedRelationInvalid})
				}
			}
		}
	}()
	return invoke(pair)
}

func NewGeneratedReader(ctx context.Context, c ReaderConfig) (*core.InstalledGeneratedReader, error) {
	if !validReaderConfig(c) {
		return nil, ErrCell
	}
	return newProviderGeneratedReader(ctx, c, false)
}
func NewDefaultGeneratedReader(ctx context.Context, c ReaderConfig) (*core.InstalledGeneratedReader, error) {
	if !validReaderConfig(c) {
		return nil, ErrCell
	}
	return newProviderGeneratedReader(ctx, c, true)
}
func ListConfigurationGenerated(ctx context.Context, requestID contract.ID, pair *configuration.Pair) ConfigurationGeneratedListResult {
	return listConfigurationGenerated(ctx, requestID, pair, NewDefaultGeneratedReader)
}
func listConfigurationGenerated(ctx context.Context, requestID contract.ID, pair *configuration.Pair, open func(context.Context, ReaderConfig) (*core.InstalledGeneratedReader, error)) ConfigurationGeneratedListResult {
	out := ConfigurationGeneratedListResult{PublicGeneratedListResult: core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: requestID}, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}, StateResult: contract.ReaderRefused, FailureReason: contract.ReasonInvalidInput}}
	m, err := configuration.Parse(ctx, pair)
	if err != nil {
		out.SourceFailure, out.sourceStage = configurationSourceFailure("source", err), "parse"
		return out
	}
	out.Context.ExpectedDomain = m.DomainID
	if !m.Resolved || ctx == nil || ctx.Err() != nil || requestID.IsZero() || open == nil {
		return out
	}
	c, err := configurationReaderConfig(m)
	if err != nil {
		return out
	}
	e, err := open(ctx, c)
	if err != nil || e == nil {
		out.Result = core.Result{Outcome: core.EvidenceUnavailable}
		out.StateResult = contract.ReaderUnavailable
		out.FailureReason = contract.ReasonEvidenceUnavailable
		return out
	}
	defer e.Close()
	out.PublicGeneratedListResult = e.List(ctx, requestID)
	if out.View != nil {
		out.storeLocation = newResultStoreLocation(m, out.View.DomainID, out.Result)
	}
	return out
}
func ListConfigurationGeneratedFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format) (out ConfigurationGeneratedListResult) {
	pair, err := configuration.Capture(ctx, path, format)
	if err != nil {
		return ConfigurationGeneratedListResult{SourceFailure: configurationSourceFailure("source", err), sourceStage: "capture", PublicGeneratedListResult: core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: requestID}, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}, StateResult: contract.ReaderRefused, FailureReason: contract.ReasonInvalidInput}}
	}
	defer func() {
		if err := pair.Close(); err != nil {
			out.View = nil
			out.storeLocation = nil
			out.Result = core.Result{Outcome: core.EvidenceUnavailable}
			out.StateResult = contract.ReaderUnavailable
			out.FailureReason = contract.ReasonEvidenceUnavailable
		}
	}()
	return ListConfigurationGenerated(ctx, requestID, pair)
}
