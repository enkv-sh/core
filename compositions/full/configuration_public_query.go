package compositionfull

import (
	"context"
	"errors"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type ReceiptReaderConfig struct {
	ReaderConfig
	SourcePins  core.AdministrativeSourcePins
	CheckSource func(context.Context) error
}

type InspectionReaderConfig struct {
	ReaderConfig
	SourcePins  core.AdministrativeSourcePins
	CheckSource func(context.Context) error
}

func NewReceiptReader(ctx context.Context, c ReceiptReaderConfig) (*core.InstalledReceiptReader, error) {
	if !validReaderConfig(c.ReaderConfig) {
		return nil, ErrCell
	}
	return newProviderReceiptReader(ctx, c, false)
}

func NewDefaultReceiptReader(ctx context.Context, c ReceiptReaderConfig) (*core.InstalledReceiptReader, error) {
	if !validReaderConfig(c.ReaderConfig) {
		return nil, ErrCell
	}
	return newProviderReceiptReader(ctx, c, true)
}

func NewInspectionReader(ctx context.Context, c InspectionReaderConfig) (*core.InstalledInspectionReader, error) {
	installed, err := readerConfigWithValidator(c.ReaderConfig)
	if err != nil {
		return nil, err
	}
	c.ReaderConfig = installed
	return newProviderInspectionReader(ctx, c, false)
}

func NewDefaultInspectionReader(ctx context.Context, c InspectionReaderConfig) (*core.InstalledInspectionReader, error) {
	installed, err := readerConfigWithValidator(c.ReaderConfig)
	if err != nil {
		return nil, err
	}
	c.ReaderConfig = installed
	return newProviderInspectionReader(ctx, c, true)
}

func configurationSourcePins(pair *configuration.Pair, m *configuration.Model) (core.AdministrativeSourcePins, error) {
	if pair == nil || pair.Editable == nil || pair.Generated == nil || m == nil || !m.Resolved || m.FileID.IsZero() {
		return core.AdministrativeSourcePins{}, contract.ErrRecord
	}
	pins := core.AdministrativeSourcePins{FileID: m.FileID, Format: uint8(pair.Format), EditableDigest: contract.ID(pair.Editable.Digest()), EditableLength: uint64(pair.Editable.Size()), GeneratedDigest: contract.ID(pair.Generated.Digest()), GeneratedLength: uint64(pair.Generated.Size()), HasGenerated: true}
	if !pins.Valid() {
		return core.AdministrativeSourcePins{}, contract.ErrRecord
	}
	return pins, nil
}

func configurationPublicQueryInput(ctx context.Context, nonce contract.ID, pair *configuration.Pair) (ReaderConfig, core.AdministrativeSourcePins, error) {
	config, pins, _, err := configurationPublicQueryModel(ctx, nonce, pair)
	return config, pins, err
}
func configurationPublicQueryModel(ctx context.Context, nonce contract.ID, pair *configuration.Pair) (ReaderConfig, core.AdministrativeSourcePins, *configuration.Model, error) {
	if ctx == nil || ctx.Err() != nil || nonce.IsZero() {
		return ReaderConfig{}, core.AdministrativeSourcePins{}, nil, &configurationQueryInputError{"context", contract.ErrRecord}
	}
	if deadline, finite := ctx.Deadline(); !finite || !time.Now().Before(deadline) {
		return ReaderConfig{}, core.AdministrativeSourcePins{}, nil, &configurationQueryInputError{"context", context.DeadlineExceeded}
	}
	m, err := configuration.Parse(ctx, pair)
	if err != nil {
		return ReaderConfig{}, core.AdministrativeSourcePins{}, nil, &configurationQueryInputError{"parse", err}
	}
	pins, err := configurationSourcePins(pair, m)
	if err != nil {
		return ReaderConfig{}, pins, nil, &configurationQueryInputError{"declaration", err}
	}
	c, err := configurationReaderConfig(m)
	if err != nil {
		return ReaderConfig{}, pins, nil, &configurationQueryInputError{"declaration", err}
	}
	if err := pair.CheckUnchanged(ctx); err != nil {
		return ReaderConfig{}, pins, nil, &configurationQueryInputError{"capture", err}
	}
	return c, pins, m, nil
}

func newConfigurationQueryRefusal(operation string, nonce contract.ID, format configuration.Format) (core.PublicQueryResult, error) {
	id, q, err := configurationPreAdmission(format, nonce)
	return core.PublicQueryResult{Operation: operation, RequestID: nonce, OperationID: id, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}, StateResult: core.PublicQueryRefused, FailureReason: contract.ReasonInvalidInput, PreAdmission: q}, err
}

type configurationQueryInputError struct {
	stage string
	cause error
}

func (e *configurationQueryInputError) Error() string { return "public query input refused" }
func (e *configurationQueryInputError) Unwrap() error { return e.cause }

func configurationQueryFailure(ctx context.Context, out *core.PublicQueryResult, sourceFailure **ConfigurationSourceFailure, stage string, err error, unavailable bool) {
	var input *configurationQueryInputError
	if errors.As(err, &input) {
		stage = input.stage
	}
	out.FailureReason = contract.DiagnosticReason(configurationFailureCode(ctx, err))
	switch out.FailureReason {
	case contract.ReasonExpired, contract.ReasonCancelled, contract.ReasonTrustBasisInvalid, contract.ReasonUnsupportedSchema, contract.ReasonUnsupportedProfile, contract.ReasonLimitExceeded:
	default:
		out.FailureReason = contract.ReasonInvalidInput
	}
	out.Result = core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}
	out.StateResult = core.PublicQueryRefused
	if out.FailureReason == contract.ReasonUnsupportedSchema || out.FailureReason == contract.ReasonUnsupportedProfile {
		out.StateResult = core.PublicQueryProfileBlocked
	}
	if unavailable && (ctx == nil || ctx.Err() == nil) {
		out.FailureReason = contract.ReasonEvidenceUnavailable
		out.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
		out.StateResult = core.PublicQueryUnavailable
	}
	if out.PreAdmission != nil && out.RequestIdentity.IsZero() {
		out.PreAdmission.Stage, out.PreAdmission.Code = stage, string(out.FailureReason)
	}
	if sourceFailure != nil {
		if failure := configurationSourceFailure("source", err); failure != nil && validQuerySourceFailure(*out, failure) {
			*sourceFailure = failure
		}
	}
}

func finishConfigurationQuery(out *core.PublicQueryResult, initial core.PublicQueryResult) {
	if !out.RequestIdentity.IsZero() {
		out.PreAdmission = nil
		return
	}
	if out.OperationID.IsZero() {
		out.OperationID = initial.OperationID
	}
	out.PreAdmission = initial.PreAdmission
	if out.PreAdmission != nil {
		out.PreAdmission.Stage, out.PreAdmission.Code = "observation", string(out.FailureReason)
	}
}

func capturedPublicQuery(ctx context.Context, path string, format configuration.Format, invoke func(*configuration.Pair)) (err error) {
	pair, err := configuration.Capture(ctx, path, format)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, pair.Close()) }()
	invoke(pair)
	return nil
}
