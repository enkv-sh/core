package gcp

import (
	"context"
	"net/url"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
	"google.golang.org/api/storage/v1"
)

// CandidateReadConfig contains only an independently supplied public location.
// The regional REP endpoint is derived, not selected by a candidate object.
type CandidateReadConfig struct {
	Client                                  *Client
	Region, Bucket, Prefix, CredentialRoute string
}

// CandidateReader has only the three GET operations needed before selection.
type CandidateReader struct {
	config  CandidateReadConfig
	service *storage.Service
	host    string
}

func (c CandidateReadConfig) location() contract.StoreLocation {
	return contract.StoreLocation{Provider: contract.GCP, Region: c.Region, Bucket: c.Bucket, PrefixBeforeHEAD: c.Prefix}
}

func validCandidateReadConfig(c CandidateReadConfig) bool {
	if c.Client == nil || c.Client.http == nil || c.Client.credentials == nil ||
		!CredentialRouteValid(c.CredentialRoute) || !contract.StoreLocationValid(c.location()) {
		return false
	}
	return true
}

func NewCandidateReader(ctx context.Context, c CandidateReadConfig) (*CandidateReader, error) {
	if ctx == nil || ctx.Err() != nil || !sdkEnvironmentAdmitted() || !validCandidateReadConfig(c) {
		return nil, ErrConstruction
	}
	endpoint := "https://storage." + c.Region + ".rep.googleapis.com/download/storage/v1/"
	service, err := storage.NewService(ctx, sdkOptions(c.Client, endpoint)...)
	if err != nil {
		return nil, ErrConstruction
	}
	host, _ := url.Parse(endpoint)
	return &CandidateReader{config: c, service: service, host: host.Host}, nil
}

// CandidateLocation reports the constructor's public location, not a claim
// that any selected candidate authenticated it.
func (r *CandidateReader) CandidateLocation() contract.StoreLocation {
	if r == nil {
		return contract.StoreLocation{}
	}
	return r.config.location()
}

func (r *CandidateReader) read(ctx context.Context, key, pathKind string, limit uint32) (result contract.ReadResult) {
	if ctx == nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	ctx, call := startTelemetryDetails(ctx, telemetry.OpStoreRead, (telemetry.DiagnosticDetails{}).WithPathKind(pathKind))
	defer func() { finishReadTelemetry(call, result) }()
	if r == nil || r.service == nil || limit == 0 || ctx.Err() != nil {
		if ctx.Err() != nil {
			return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
		}
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	result = readGCSObject(ctx, r.config.Client, r.service, r.host, r.config.Bucket, key, limit)
	if ctx.Err() != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
	return result
}

func (r *CandidateReader) ReadHEAD(ctx context.Context) contract.ReadResult {
	if r == nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return r.read(ctx, r.config.Prefix+"/HEAD", "state_head", contract.MaxHeadLength)
}

func (r *CandidateReader) ReadConfiguration(ctx context.Context, domain, storeID contract.ID) contract.ReadResult {
	if r == nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	key, err := contract.StoreConfigurationKeyForID(contract.GCP, r.config.Prefix, domain, storeID)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return r.read(ctx, key, "state_object", contract.MaxStoreConfigurationLength)
}

func (r *CandidateReader) ReadRoot(ctx context.Context, ref contract.Ref) contract.ReadResult {
	if r == nil || ref.Kind != contract.RootKind || ref.Index != 0 || !ref.ValidFor(contract.CanonicalSchema) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	key, err := format.Key(r.config.Prefix, ref)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	result := r.read(ctx, key, "state_object", ref.Length)
	if result.Status == contract.ReadOK && len(result.Body) != int(ref.Length) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
	}
	return result
}
