package gcp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"time"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/telemetry"
	"google.golang.org/api/cloudkms/v1"
)

const maximumECDSASigningPublicKeyPEMLength = 1024

const (
	TrustClass    = "gcp-cloudkms-p256-v1"
	VerifierClass = "gcp-p256-spki-v1"
)

// TrustConfig binds a pre-provisioned asymmetric signing key version and its
// independently pinned verifier. No key lookup is used during construction.
type TrustConfig struct {
	Role                                                              uint8
	Client                                                            *Client
	Region, Endpoint, CredentialRoute, KeyVersion, Algorithm, Purpose string
	PublicKey                                                         []byte
}
type Trust struct {
	role             uint8
	client           *Client
	service          *cloudkms.Service
	identity         contract.ID
	keyVersion, host string
	verifier         *ecdsa.PublicKey
}

// PublicSigningAnchor fixes one independently supplied KMS version and role
// before a selected binding is read. It has public qualification only.
type PublicSigningAnchorConfig struct {
	Role               uint8
	Client             *Client
	Region, KeyVersion string
	CredentialRoute    string
}
type PublicSigningAnchor struct {
	role             uint8
	client           *Client
	service          *cloudkms.Service
	identity         contract.ID
	keyVersion, host string
}

func validSigningLocation(client *Client, region, keyVersion, route string) bool {
	selector, ok := contract.ParseGCPKeySelector(keyVersion, true)
	return sdkEnvironmentAdmitted() && client != nil && client.http != nil && client.credentials != nil &&
		regionPattern.MatchString(region) && CredentialRouteValid(route) && ok && selector.Region == region
}

func NewPublicSigningAnchor(ctx context.Context, c PublicSigningAnchorConfig) (*PublicSigningAnchor, error) {
	if (c.Role != contract.NormalSigningRole && c.Role != contract.RecoverySigningRole) || !validSigningLocation(c.Client, c.Region, c.KeyVersion, c.CredentialRoute) {
		return nil, ErrConstruction
	}
	endpoint := KMSEndpoint(c.Region)
	service, err := cloudkms.NewService(ctx, sdkOptions(c.Client, endpoint)...)
	if err != nil {
		return nil, ErrConstruction
	}
	id := binding(TrustClass, c.Region, endpoint, SigningAlgorithm, SigningPurpose, strconv.Itoa(int(c.Role)))
	return &PublicSigningAnchor{role: c.Role, client: c.Client, service: service, identity: id, keyVersion: c.KeyVersion, host: c.Region + "-cloudkms.googleapis.com"}, nil
}

func NewTrust(ctx context.Context, c TrustConfig) (*Trust, error) {
	if (c.Role != 0 && c.Role != contract.NormalSigningRole && c.Role != contract.RecoverySigningRole) || !validSigningLocation(c.Client, c.Region, c.KeyVersion, c.CredentialRoute) || c.Endpoint != KMSEndpoint(c.Region) || c.Algorithm != SigningAlgorithm || c.Purpose != SigningPurpose {
		return nil, ErrConstruction
	}
	if c.Role == 0 {
		c.Role = contract.NormalSigningRole
	}
	pub, err := ParseVerifier(bytes.Clone(c.PublicKey))
	if err != nil {
		return nil, ErrConstruction
	}
	service, err := cloudkms.NewService(ctx, sdkOptions(c.Client, c.Endpoint)...)
	if err != nil {
		return nil, ErrConstruction
	}
	endpoint, _ := url.Parse(c.Endpoint)
	// The public construction survives key and credential replacement. Exact
	// resources and verifiers remain pinned by this instance and its binding.
	id := binding(TrustClass, c.Region, c.Endpoint, c.Algorithm, c.Purpose, strconv.Itoa(int(c.Role)))
	return &Trust{role: c.Role, client: c.Client, service: service, identity: id, keyVersion: c.KeyVersion, host: endpoint.Host, verifier: pub}, nil
}

func (a *PublicSigningAnchor) Identity() contract.ID {
	if a == nil {
		return contract.ID{}
	}
	return a.identity
}

func (t *Trust) Identity() contract.ID   { return t.identity }
func (t *Trust) Family() contract.Family { return contract.GCP }
func (t *Trust) Sign(ctx context.Context, request contract.SignRequest) (result contract.SignResult) {
	ctx, call := startTelemetry(ctx, telemetry.OpTrustSign)
	defer func() { finishSignTelemetry(call, result) }()
	if t == nil || !request.Valid() || !contract.SigningPurposeAllowed(t.role, request.Purpose()) {
		return contract.SignResult{Reason: contract.ReasonProof}
	}
	digest := request.Digest()
	call.InputBytes(int64(len(digest)))
	ctx, ok := t.client.begin(ctx, t.host, maxJSON)
	if !ok {
		return contract.SignResult{Reason: contract.ReasonAccess}
	}
	input := &cloudkms.AsymmetricSignRequest{Digest: &cloudkms.Digest{Sha256: base64.StdEncoding.EncodeToString(digest[:])}, DigestCrc32c: int64(crc(digest[:])), ForceSendFields: []string{"DigestCrc32c"}}
	reply, err := t.service.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.AsymmetricSign(t.keyVersion, input).Context(ctx).Do()
	if err != nil {
		return contract.SignResult{Reason: contract.ReasonTransport}
	}
	if reply == nil || reply.Name != t.keyVersion || !reply.VerifiedDigestCrc32c {
		return contract.SignResult{Reason: contract.ReasonProof}
	}
	rawCRC, present := responseString(ctx, "signatureCrc32c")
	if !present || rawCRC != strconv.FormatInt(reply.SignatureCrc32c, 10) {
		return contract.SignResult{Reason: contract.ReasonProof}
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(reply.Signature)
	if err != nil || len(signature) == 0 || len(signature) > contract.MaxSignature || reply.SignatureCrc32c != int64(crc(signature)) || !ecdsa.VerifyASN1(t.verifier, digest[:], signature) {
		return contract.SignResult{Reason: contract.ReasonProof}
	}
	return contract.SignResult{Signature: signature}
}

func (t *Trust) QualifySigningBinding(ctx context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	ctx, call := startTelemetry(ctx, telemetry.OpTrustQualify)
	result := t.qualifySigningBinding(ctx, binding)
	finishQualificationTelemetry(ctx, call, result)
	return result
}

func (t *Trust) qualifySigningBinding(ctx context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	if t == nil || t.verifier == nil {
		return contract.SigningQualificationResult{Reason: contract.ReasonConstruction}
	}
	pinned, err := x509.MarshalPKIXPublicKey(t.verifier)
	if err != nil {
		return contract.SigningQualificationResult{Reason: contract.ReasonConstruction}
	}
	return qualifySigningBinding(ctx, signingQualification{
		role: t.role, client: t.client, service: t.service, identity: t.identity,
		keyVersion: t.keyVersion, host: t.host, pinnedDER: pinned,
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
		role: a.role, client: a.client, service: a.service, identity: a.identity,
		keyVersion: a.keyVersion, host: a.host,
	}, binding)
}

type signingQualification struct {
	role             uint8
	client           *Client
	service          *cloudkms.Service
	identity         contract.ID
	keyVersion, host string
	pinnedDER        []byte
}

func qualifySigningBinding(ctx context.Context, q signingQualification, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	refused := contract.SigningQualificationResult{Reason: contract.ReasonConstruction}
	if q.client == nil || q.service == nil || q.identity.IsZero() || binding.Role != q.role || binding.Provider != contract.GCP || binding.KeySelector != q.keyVersion || binding.Binding.Trust != q.identity || (q.pinnedDER != nil && !bytes.Equal(binding.SPKI, q.pinnedDER)) {
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
	return contract.SigningQualificationResult{TargetRole: role, SigningBindingDigest: digest, Provider: contract.GCP, Qualified: 1}
}

// KMS lookup absence does not have Store's read-missing meaning. Classify
// access only from a complete error consistent with the physical response.
func signingQualificationFailure(ctx context.Context, err error) contract.Reason {
	if ctx.Err() != nil {
		return contract.ReasonLimit
	}
	if errors.Is(err, errMalformedResponse) {
		return contract.ReasonMalformed
	}
	op, _ := ctx.Value(operationKey{}).(*operation)
	if publicKeyStatus(op, err) == enkvcrypto.KeyDenied {
		return contract.ReasonAccess
	}
	return contract.ReasonTransport
}

func generatedRecoverySigningVersion(ctx context.Context, key *cloudkms.CryptoKeyVersion) bool {
	if key.GenerateTime == "" || key.ImportTime != "" || key.ImportJob != "" || key.ReimportEligible || key.ExternalProtectionLevelOptions != nil {
		return false
	}
	op, ok := ctx.Value(operationKey{}).(*operation)
	if !ok {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(op.response, &fields) != nil {
		return false
	}
	if _, present := fields["externalProtectionLevelOptions"]; present {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, key.GenerateTime)
	return err == nil
}

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
