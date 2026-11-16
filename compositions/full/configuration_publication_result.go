package compositionfull

import "enkv.sh/core"

type ConfigurationPublicationResult struct {
	core.PublicPublicationResult
	SourceFailure *ConfigurationSourceFailure
	sourceStage   string
}

func (r ConfigurationPublicationResult) RenderJSON() ([]byte, error) {
	return renderPublication(r.PublicPublicationResult, false, r.SourceFailure, r.sourceStage)
}
func (r ConfigurationPublicationResult) RenderHuman() ([]byte, error) {
	return renderPublication(r.PublicPublicationResult, true, r.SourceFailure, r.sourceStage)
}

func validPublicationSourceFailure(r core.PublicPublicationResult, f *ConfigurationSourceFailure, stage string) bool {
	if f == nil {
		return true
	}
	return validConfigurationSourceFailure(f) && (f.SourceID == "source" || f.SourceID == "source.generated") &&
		(stage == "capture" || stage == "parse" || stage == "declaration" || stage == "public-basis") &&
		r.Output == nil && r.OperationID.IsZero() && r.RequestIdentity.IsZero() &&
		validUnadmittedSourceResult(r.Result)
}
