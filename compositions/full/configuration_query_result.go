package compositionfull

import (
	"context"
	"io"

	"enkv.sh/core"
)

// These composition results retain native source admission separately from the
// unchanged authenticated Core query facts.
type ConfigurationInspectionResult struct {
	core.PublicDomainInspectionResult
	SourceFailure *ConfigurationSourceFailure
	storeLocation *resultStoreLocation
}

func (r ConfigurationInspectionResult) WriteJSON(ctx context.Context, out io.Writer) error {
	return writeInspection(ctx, out, r.PublicDomainInspectionResult, false, r.SourceFailure, r.storeLocation)
}
func (r ConfigurationInspectionResult) WriteHuman(ctx context.Context, out io.Writer) error {
	return writeInspection(ctx, out, r.PublicDomainInspectionResult, true, r.SourceFailure, r.storeLocation)
}

type ConfigurationRecipientInspectionResult struct {
	core.PublicRecipientInspectionResult
	SourceFailure *ConfigurationSourceFailure
}

func (r ConfigurationRecipientInspectionResult) WriteJSON(ctx context.Context, out io.Writer) error {
	return writeRecipientInspection(ctx, out, r.PublicRecipientInspectionResult, false, r.SourceFailure)
}
func (r ConfigurationRecipientInspectionResult) WriteHuman(ctx context.Context, out io.Writer) error {
	return writeRecipientInspection(ctx, out, r.PublicRecipientInspectionResult, true, r.SourceFailure)
}

type ConfigurationReceiptListResult struct {
	core.PublicReceiptListResult
	SourceFailure *ConfigurationSourceFailure
}

func (r ConfigurationReceiptListResult) WriteJSON(ctx context.Context, out io.Writer) error {
	return writeReceiptList(ctx, out, r.PublicReceiptListResult, false, r.SourceFailure)
}
func (r ConfigurationReceiptListResult) WriteHuman(ctx context.Context, out io.Writer) error {
	return writeReceiptList(ctx, out, r.PublicReceiptListResult, true, r.SourceFailure)
}

type ConfigurationReceiptDetailResult struct {
	core.PublicReceiptDetailResult
	SourceFailure *ConfigurationSourceFailure
}

func (r ConfigurationReceiptDetailResult) WriteJSON(ctx context.Context, out io.Writer) error {
	return writeReceiptDetail(ctx, out, r.PublicReceiptDetailResult, false, r.SourceFailure)
}
func (r ConfigurationReceiptDetailResult) WriteHuman(ctx context.Context, out io.Writer) error {
	return writeReceiptDetail(ctx, out, r.PublicReceiptDetailResult, true, r.SourceFailure)
}

type ConfigurationCapacityResult struct {
	core.PublicCapacityInspectionResult
	SourceFailure *ConfigurationSourceFailure
}

func (r ConfigurationCapacityResult) WriteJSON(ctx context.Context, out io.Writer) error {
	return writeCapacityInspection(ctx, out, r.PublicCapacityInspectionResult, false, r.SourceFailure)
}
func (r ConfigurationCapacityResult) WriteHuman(ctx context.Context, out io.Writer) error {
	return writeCapacityInspection(ctx, out, r.PublicCapacityInspectionResult, true, r.SourceFailure)
}

func validQuerySourceFailure(base core.PublicQueryResult, failure *ConfigurationSourceFailure) bool {
	if failure == nil {
		return true
	}
	if !validConfigurationSourceFailure(failure) || !validConfigurationAdmissionSourceFailure(failure, base.PreAdmission, base.RequestIdentity, base.Result) {
		return false
	}
	if failure.SourceID != "source" && failure.SourceID != "source.generated" {
		return false
	}
	switch base.PreAdmission.Stage {
	case "capture", "parse", "declaration":
	default:
		return false
	}
	switch base.StateResult {
	case core.PublicQueryRefused, core.PublicQueryProfileBlocked:
		return base.Result.Outcome == core.AdmissionRefused
	case core.PublicQueryUnavailable:
		return base.Result.Outcome == core.EvidenceUnavailable
	}
	return false
}
