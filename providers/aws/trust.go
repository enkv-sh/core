package awsprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const TrustClass = "aws-kms-p256-v1"
const VerifierClass = "aws-kms-p256-spki-v1"

// TrustConfig pins one SIGN_VERIFY, ECC_NIST_P256 key by exact ARN and public
// verifier. Provisioning evidence belongs to admission; this client has no key
// discovery operation and verifies each returned signature locally.
type TrustConfig struct {
	Role            uint8
	Region, KeyARN  string
	PublicKeyDER    []byte
	CredentialRoute contract.ID
	Credentials     aws.CredentialsProvider
	Transport       *http.Transport
	Timeout         time.Duration
}
type Trust struct {
	config   TrustConfig
	identity contract.ID
	public   *ecdsa.PublicKey
	client   *http.Client
}

// PublicSigningAnchor is a public-only qualification route. Its key ARN and
// role come from independent local input, before any selected binding is read.
// It does not expose Sign or obtain private signing permission.
type PublicSigningAnchorConfig struct {
	Role            uint8
	Region, KeyARN  string
	CredentialRoute contract.ID
	Credentials     aws.CredentialsProvider
	Transport       *http.Transport
	Timeout         time.Duration
}
type PublicSigningAnchor struct {
	config   PublicSigningAnchorConfig
	identity contract.ID
	client   *http.Client
}

func validPublicSigningAnchor(c PublicSigningAnchorConfig) bool {
	return (c.Role == contract.NormalSigningRole || c.Role == contract.RecoverySigningRole) &&
		validTrust(TrustConfig{Role: c.Role, Region: c.Region, KeyARN: c.KeyARN, CredentialRoute: c.CredentialRoute, Credentials: c.Credentials, Timeout: c.Timeout})
}

func NewPublicSigningAnchor(c PublicSigningAnchorConfig) (*PublicSigningAnchor, error) {
	if !validPublicSigningAnchor(c) {
		return nil, ErrConstruction
	}
	rt, err := privateTransport(c.Transport)
	if err != nil {
		return nil, err
	}
	return newPublicSigningAnchor(c, rt)
}

func newPublicSigningAnchor(c PublicSigningAnchorConfig, rt http.RoundTripper) (*PublicSigningAnchor, error) {
	if !validPublicSigningAnchor(c) || rt == nil {
		return nil, ErrConstruction
	}
	host := "kms." + c.Region + ".amazonaws.com"
	id := identity(TrustClass, host, "ECC_NIST_P256", "SIGN_VERIFY", "ECDSA_SHA_256", "DIGEST", fmt.Sprint(c.Role))
	return &PublicSigningAnchor{config: c, identity: id, client: ownedClient(rt, host, c.Timeout)}, nil
}

var _ contract.Trust = (*Trust)(nil)

func ParseVerifier(der []byte) (*ecdsa.PublicKey, error) {
	key, err := contract.ParseSigningPublicKey(der)
	if err != nil {
		return nil, ErrConstruction
	}
	if _, err := key.ECDH(); err != nil {
		return nil, ErrConstruction
	}
	return key, nil
}

func validTrust(c TrustConfig) bool {
	selector, ok := contract.ParseAWSKeySelector(c.KeyARN, true)
	return (c.Role == 0 || c.Role == contract.NormalSigningRole || c.Role == contract.RecoverySigningRole) && validCommon(c.Region, c.CredentialRoute, c.Credentials, c.Timeout) && ok && selector.Region == c.Region
}
func NewTrust(c TrustConfig) (*Trust, error) {
	if !validTrust(c) {
		return nil, ErrConstruction
	}
	t, err := privateTransport(c.Transport)
	if err != nil {
		return nil, err
	}
	return newTrust(c, t)
}
func newTrust(c TrustConfig, rt http.RoundTripper) (*Trust, error) {
	if !validTrust(c) || rt == nil {
		return nil, ErrConstruction
	}
	if c.Role == 0 {
		c.Role = contract.NormalSigningRole
	}
	pub, err := ParseVerifier(c.PublicKeyDER)
	if err != nil {
		return nil, err
	}
	c.PublicKeyDER = bytes.Clone(c.PublicKeyDER)
	host := "kms." + c.Region + ".amazonaws.com"
	// The public construction survives key and credential replacement. Exact
	// resources and verifiers remain pinned by this instance and its binding.
	id := identity(TrustClass, host, "ECC_NIST_P256", "SIGN_VERIFY", "ECDSA_SHA_256", "DIGEST", fmt.Sprint(c.Role))
	t := &Trust{config: c, identity: id, public: pub}
	t.client = ownedClient(rt, host, c.Timeout)
	return t, nil
}
func (a *PublicSigningAnchor) Identity() contract.ID {
	if a == nil {
		return contract.ID{}
	}
	return a.identity
}

func (t *Trust) Identity() contract.ID   { return t.identity }
func (t *Trust) Family() contract.Family { return contract.AWS }
func (t *Trust) Sign(ctx context.Context, req contract.SignRequest) (result contract.SignResult) {
	ctx, call := startTelemetry(ctx, telemetry.OpTrustSign)
	defer func() { finishSignTelemetry(call, result) }()
	if t == nil || t.identity.IsZero() || t.public == nil || !req.Valid() || !contract.SigningPurposeAllowed(t.config.Role, req.Purpose()) {
		return contract.SignResult{Reason: contract.ReasonProof}
	}
	call.InputBytes(32)
	ctx = operationContext(ctx, maximumPublicResponseBytes)
	creds, ok := retrieve(ctx, t.config.Credentials)
	if !ok {
		return contract.SignResult{Reason: contract.ReasonAccess}
	}
	client := kms.New(kms.Options{Region: t.config.Region, BaseEndpoint: aws.String("https://kms." + t.config.Region + ".amazonaws.com"), Credentials: creds, HTTPClient: t.client, Retryer: aws.NopRetryer{}})
	digest := req.Digest()
	out, err := client.Sign(ctx, &kms.SignInput{KeyId: aws.String(t.config.KeyARN), Message: digest[:], MessageType: types.MessageTypeDigest, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
	if err != nil {
		status, _ := serviceError(err)
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			return contract.SignResult{Reason: contract.ReasonAccess}
		}
		return contract.SignResult{Reason: contract.ReasonTransport}
	}
	if aws.ToString(out.KeyId) != t.config.KeyARN || out.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 || len(out.Signature) == 0 || len(out.Signature) > contract.MaxSignature || !ecdsa.VerifyASN1(t.public, digest[:], out.Signature) {
		return contract.SignResult{Reason: contract.ReasonProof}
	}
	return contract.SignResult{Signature: bytes.Clone(out.Signature)}
}

func (t *Trust) QualifySigningBinding(ctx context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	ctx, call := startTelemetry(ctx, telemetry.OpTrustQualify)
	result := t.qualifySigningBinding(ctx, binding)
	finishQualificationTelemetry(ctx, call, result)
	return result
}

func (t *Trust) qualifySigningBinding(ctx context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	if t == nil {
		return contract.SigningQualificationResult{Reason: contract.ReasonConstruction}
	}
	return qualifySigningBinding(ctx, signingQualification{
		role: t.config.Role, region: t.config.Region, keyARN: t.config.KeyARN,
		credentials: t.config.Credentials, client: t.client, identity: t.identity,
		pinnedDER: t.config.PublicKeyDER,
	}, binding)
}

func (a *PublicSigningAnchor) QualifySigningBinding(ctx context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	ctx, call := startTelemetry(ctx, telemetry.OpTrustQualify)
	result := a.qualifySigningBinding(ctx, binding)
	finishQualificationTelemetry(ctx, call, result)
	return result
}

func (a *PublicSigningAnchor) qualifySigningBinding(ctx context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	if a == nil {
		return contract.SigningQualificationResult{Reason: contract.ReasonConstruction}
	}
	return qualifySigningBinding(ctx, signingQualification{
		role: a.config.Role, region: a.config.Region, keyARN: a.config.KeyARN,
		credentials: a.config.Credentials, client: a.client, identity: a.identity,
	}, binding)
}

type signingQualification struct {
	role        uint8
	region      string
	keyARN      string
	credentials aws.CredentialsProvider
	client      *http.Client
	identity    contract.ID
	pinnedDER   []byte
}

func qualifySigningBinding(ctx context.Context, q signingQualification, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	refused := contract.SigningQualificationResult{Reason: contract.ReasonConstruction}
	if q.client == nil || q.identity.IsZero() || binding.Role != q.role || binding.Provider != contract.AWS || binding.KeySelector != q.keyARN || binding.Binding.Trust != q.identity || (q.pinnedDER != nil && !bytes.Equal(binding.SPKI, q.pinnedDER)) {
		return refused
	}
	digest, err := contract.SigningBindingDigest(binding)
	if err != nil {
		return refused
	}
	_, reason := resolveSigningKey(ctx, q, binding.SPKI)
	if reason != contract.ReasonNone {
		return contract.SigningQualificationResult{Reason: reason}
	}
	role := contract.NormalSignerTarget
	if binding.Role == contract.RecoverySigningRole {
		role = contract.RecoverySignerTarget
	}
	return contract.SigningQualificationResult{TargetRole: role, SigningBindingDigest: digest, Provider: contract.AWS, Qualified: 1}
}
