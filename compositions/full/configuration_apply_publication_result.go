package compositionfull

import (
	"enkv.sh/core"
	"io"
)

type ConfigurationApplyPublicationResult struct {
	core.PublicApplyPublicationResult
	SourceFailure *ConfigurationSourceFailure
	storeLocation *resultStoreLocation
}

func (r ConfigurationApplyPublicationResult) WriteJSON(out io.Writer) error {
	if r.SourceFailure != nil && (r.Publication.Stage != "unstarted" || r.Publication.Reason != "apply-incomplete") {
		return ErrApplyPublicationResult
	}
	return writeApplyPublicationResult(out, r.PublicApplyPublicationResult, false, r.SourceFailure, r.storeLocation)
}
func (r ConfigurationApplyPublicationResult) WriteHuman(out io.Writer) error {
	if r.SourceFailure != nil && (r.Publication.Stage != "unstarted" || r.Publication.Reason != "apply-incomplete") {
		return ErrApplyPublicationResult
	}
	return writeApplyPublicationResult(out, r.PublicApplyPublicationResult, true, r.SourceFailure, r.storeLocation)
}
