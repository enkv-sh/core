package compositionfull

import "enkv.sh/core"

// ConfigurationGeneratedListResult retains source admission facts beside the
// authenticated Core result. Rendering does not reopen the source or Store.
type ConfigurationGeneratedListResult struct {
	core.PublicGeneratedListResult
	SourceFailure *ConfigurationSourceFailure
	sourceStage   string
	storeLocation *resultStoreLocation
}

func (r ConfigurationGeneratedListResult) RenderJSON() ([]byte, error) {
	return renderGeneratedList(r.PublicGeneratedListResult, false, r.SourceFailure, r.sourceStage, r.storeLocation)
}

func (r ConfigurationGeneratedListResult) RenderHuman() ([]byte, error) {
	return renderGeneratedList(r.PublicGeneratedListResult, true, r.SourceFailure, r.sourceStage, r.storeLocation)
}

func validGeneratedListSourceFailure(r core.PublicGeneratedListResult, f *ConfigurationSourceFailure, stage string) bool {
	if f == nil {
		return true
	}
	return validConfigurationSourceFailure(f) && (f.SourceID == "source" || f.SourceID == "source.generated") &&
		(stage == "capture" || stage == "parse" || stage == "declaration") && r.View == nil && r.Context.OperationID.IsZero() && validUnadmittedSourceResult(r.Result) &&
		(r.Result.Outcome == core.AdmissionRefused && r.StateResult == "refused" || r.Result.Outcome == core.EvidenceUnavailable && r.StateResult == "unavailable")
}
