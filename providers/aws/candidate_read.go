package awsprovider

import (
	"context"
	"net/http"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// CandidateReadConfig is an independently supplied public location. An empty
// ExpectedBucketOwner is admitted only for these three candidate reads.
type CandidateReadConfig struct {
	Region, Bucket, Prefix, ExpectedBucketOwner string
	CredentialRoute                             contract.ID
	Credentials                                 aws.CredentialsProvider
	Transport                                   *http.Transport
	Timeout                                     time.Duration
}

// CandidateReader has no Store, signing, listing or mutation authority.
type CandidateReader struct {
	config CandidateReadConfig
	client *http.Client
}

func (c CandidateReadConfig) location() contract.StoreLocation {
	return contract.StoreLocation{Provider: contract.AWS, Region: c.Region, Bucket: c.Bucket,
		PrefixBeforeHEAD: c.Prefix, ExpectedOwner: c.ExpectedBucketOwner}
}

func validCandidateReadConfig(c CandidateReadConfig) bool {
	if !validCommon(c.Region, c.CredentialRoute, c.Credentials, c.Timeout) ||
		!contract.StoreLocationValid(c.location()) {
		return false
	}
	return true
}

func NewCandidateReader(c CandidateReadConfig) (*CandidateReader, error) {
	if !validCandidateReadConfig(c) {
		return nil, ErrConstruction
	}
	rt, err := privateTransport(c.Transport)
	if err != nil {
		return nil, err
	}
	return newCandidateReader(c, rt)
}

func newCandidateReader(c CandidateReadConfig, rt http.RoundTripper) (*CandidateReader, error) {
	if !validCandidateReadConfig(c) || rt == nil {
		return nil, ErrConstruction
	}
	host := "s3." + c.Region + ".amazonaws.com"
	return &CandidateReader{config: c, client: ownedClient(rt, host, c.Timeout)}, nil
}

// CandidateLocation reports the constructor's public location, not a claim
// that any selected candidate authenticated it.
func (r *CandidateReader) CandidateLocation() contract.StoreLocation {
	if r == nil {
		return contract.StoreLocation{}
	}
	return r.config.location()
}

func (r *CandidateReader) read(ctx context.Context, key, owner, pathKind string, limit uint32) (result contract.ReadResult) {
	if ctx == nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	ctx, call := startTelemetryDetails(ctx, telemetry.OpStoreRead, (telemetry.DiagnosticDetails{}).WithPathKind(pathKind))
	defer func() { finishReadTelemetry(call, result) }()
	if r == nil || r.client == nil || len(key) > maximumObjectKeyLength || limit == 0 || ctx.Err() != nil {
		if ctx.Err() != nil {
			return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
		}
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	result = readS3Object(ctx, r.client, r.config.Region, r.config.Bucket, owner, r.config.Credentials, key, limit)
	if ctx.Err() != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
	return result
}

func (r *CandidateReader) ReadHEAD(ctx context.Context) contract.ReadResult {
	if r == nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return r.read(ctx, r.config.Prefix+"/HEAD", r.config.ExpectedBucketOwner, "state_head", contract.MaxHeadLength)
}

func (r *CandidateReader) ReadHEADGuarded(ctx context.Context, owner string) contract.ReadResult {
	if r == nil || !accountPattern.MatchString(owner) || r.config.ExpectedBucketOwner != "" && r.config.ExpectedBucketOwner != owner {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return r.read(ctx, r.config.Prefix+"/HEAD", owner, "state_head", contract.MaxHeadLength)
}

func (r *CandidateReader) ReadConfiguration(ctx context.Context, domain, storeID contract.ID) contract.ReadResult {
	if r == nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	key, err := contract.StoreConfigurationKeyForID(contract.AWS, r.config.Prefix, domain, storeID)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return r.read(ctx, key, r.config.ExpectedBucketOwner, "state_object", contract.MaxStoreConfigurationLength)
}

func (r *CandidateReader) ReadRoot(ctx context.Context, ref contract.Ref) contract.ReadResult {
	if r == nil || ref.Kind != contract.RootKind || ref.Index != 0 || !ref.ValidFor(contract.CanonicalSchema) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	key, err := format.Key(r.config.Prefix, ref)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	result := r.read(ctx, key, r.config.ExpectedBucketOwner, "state_object", ref.Length)
	if result.Status == contract.ReadOK && len(result.Body) != int(ref.Length) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
	}
	return result
}
