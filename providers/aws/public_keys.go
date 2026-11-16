package awsprovider

import (
	"bytes"
	"context"
	"net/http"
	"slices"
	"strings"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type publicEncryptionLookup struct {
	config KeyAccessConfig
	client *http.Client
}

func newPublicEncryptionLookup(c KeyAccessConfig, rt http.RoundTripper) (*publicEncryptionLookup, error) {
	if !validKeyAccess(c) || rt == nil {
		return nil, ErrConstruction
	}
	return &publicEncryptionLookup{config: c, client: ownedClient(rt, "kms."+c.Region+".amazonaws.com", c.Timeout)}, nil
}

func encryptionSDK(ctx context.Context, c KeyAccessConfig, client *http.Client) (*kms.Client, enkvcrypto.KeyStatus) {
	if ctx.Err() != nil {
		return nil, enkvcrypto.KeyCancelled
	}
	creds, ok := retrieve(ctx, c.Credentials)
	if ctx.Err() != nil {
		return nil, enkvcrypto.KeyCancelled
	}
	if !ok {
		return nil, enkvcrypto.KeyDenied
	}
	return kms.New(kms.Options{Region: c.Region, BaseEndpoint: aws.String("https://kms." + c.Region + ".amazonaws.com"), Credentials: creds, HTTPClient: client, Retryer: aws.NopRetryer{}}), enkvcrypto.KeyOK
}

func (k *publicEncryptionLookup) validBinding(b contract.KMSBinding) bool {
	if k == nil || k.client == nil || b.Provider != contract.AWS || b.ProtectionClass != contract.HardwareProtection {
		return false
	}
	if _, err := contract.KMSBindingLength(b); err != nil {
		return false
	}
	selector, ok := contract.ParseAWSKeySelector(b.KeySelector, false)
	return ok && selector.Region == k.config.Region && selector.Account == k.config.Account
}

// PublicEncryptionQualifier owns public qualification for one exact binding.
// It has no private decryption method.
type PublicEncryptionQualifier struct {
	lookup  *publicEncryptionLookup
	binding contract.KMSBinding
	encoded []byte
}

func NewPublicEncryptionQualifier(c KeyAccessConfig, binding contract.KMSBinding) (*PublicEncryptionQualifier, error) {
	if !validKeyAccess(c) {
		return nil, ErrConstruction
	}
	rt, err := privateTransport(c.Transport)
	if err != nil {
		return nil, err
	}
	return newPublicEncryptionQualifier(c, binding, rt)
}

func newPublicEncryptionQualifier(c KeyAccessConfig, binding contract.KMSBinding, rt http.RoundTripper) (*PublicEncryptionQualifier, error) {
	lookup, err := newPublicEncryptionLookup(c, rt)
	if err != nil || !lookup.validBinding(binding) {
		return nil, ErrConstruction
	}
	encoded, err := contract.EncodeKMSBinding(binding)
	if err != nil {
		return nil, ErrConstruction
	}
	owned, err := contract.DecodeKMSBinding(encoded)
	if err != nil {
		return nil, ErrConstruction
	}
	return &PublicEncryptionQualifier{lookup: lookup, binding: owned, encoded: encoded}, nil
}

func (q *PublicEncryptionQualifier) Family() contract.Family { return contract.AWS }
func (q *PublicEncryptionQualifier) CredentialRoute() contract.ID {
	if q == nil || q.lookup == nil {
		return contract.ID{}
	}
	return q.lookup.config.CredentialRoute
}
func (q *PublicEncryptionQualifier) Qualify(ctx context.Context, binding contract.KMSBinding) (result enkvcrypto.KeyResult) {
	ctx, call := startTelemetry(ctx, telemetry.OpKeyQualify)
	defer func() { finishKeyTelemetry(call, result.Status) }()
	result.Status = enkvcrypto.KeyInvalid
	if q == nil || q.lookup == nil {
		return
	}
	encoded, err := contract.EncodeKMSBinding(binding)
	if err != nil || !bytes.Equal(encoded, q.encoded) {
		return
	}
	_, _, result = q.lookup.resolveEncryptionKey(ctx, q.binding.KeySelector, q.binding.ProtectionClass, q.binding.SPKI)
	return
}

func resolveSigningKey(ctx context.Context, q signingQualification, pinned []byte) ([]byte, contract.Reason) {
	ctx = operationContext(ctx, maximumPublicResponseBytes)
	creds, ok := retrieve(ctx, q.credentials)
	if !ok {
		return nil, contract.ReasonAccess
	}
	client := kms.New(kms.Options{Region: q.region, BaseEndpoint: aws.String("https://kms." + q.region + ".amazonaws.com"), Credentials: creds, HTTPClient: q.client, Retryer: aws.NopRetryer{}})
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(q.keyARN)})
	if err != nil {
		status, code := serviceError(err)
		if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusBadRequest && code == "AccessDeniedException" {
			return nil, contract.ReasonAccess
		}
		return nil, contract.ReasonTransport
	}
	if ctx.Err() != nil {
		return nil, contract.ReasonLimit
	}
	if out == nil || aws.ToString(out.KeyId) != q.keyARN || out.KeySpec != types.KeySpecEccNistP256 || out.KeyUsage != types.KeyUsageTypeSignVerify || (pinned != nil && !bytes.Equal(out.PublicKey, pinned)) || contract.ValidateSigningPublicKey(out.PublicKey) != nil || len(out.SigningAlgorithms) != 1 || out.SigningAlgorithms[0] != types.SigningAlgorithmSpecEcdsaSha256 {
		return nil, contract.ReasonProof
	}
	if q.role == contract.RecoverySigningRole {
		// The recovery profile additionally requires provider-generated material.
		metadataCtx := operationContext(ctx, maximumPublicResponseBytes)
		metadata, err := client.DescribeKey(metadataCtx, &kms.DescribeKeyInput{KeyId: aws.String(q.keyARN)})
		if err != nil {
			status, code := serviceError(err)
			if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusBadRequest && code == "AccessDeniedException" {
				return nil, contract.ReasonAccess
			}
			return nil, contract.ReasonTransport
		}
		if metadata == nil || metadata.KeyMetadata == nil {
			return nil, contract.ReasonProof
		}
		key := metadata.KeyMetadata
		if aws.ToString(key.Arn) != q.keyARN || !key.Enabled || key.KeyState != types.KeyStateEnabled || key.Origin != types.OriginTypeAwsKms || key.KeySpec != types.KeySpecEccNistP256 || key.KeyUsage != types.KeyUsageTypeSignVerify {
			return nil, contract.ReasonProof
		}
	}
	if ctx.Err() != nil {
		return nil, contract.ReasonLimit
	}
	return bytes.Clone(out.PublicKey), contract.ReasonNone
}

func (k *publicEncryptionLookup) resolveEncryptionKey(ctx context.Context, selectorName string, protection uint8, pinned []byte) (der []byte, protectionClass uint8, result enkvcrypto.KeyResult) {
	result.Status = enkvcrypto.KeyInvalid
	defer func() {
		if ctx.Err() != nil {
			result.Status = enkvcrypto.KeyCancelled
			der = nil
			protectionClass = 0
		}
	}()
	client, status := encryptionSDK(ctx, k.config, k.client)
	if status != enkvcrypto.KeyOK {
		result.Status = status
		return
	}
	publicCtx := operationContext(ctx, maximumPublicResponseBytes)
	a := publicCtx.Value(attemptKey{}).(*attempt)
	public, err := client.GetPublicKey(publicCtx, &kms.GetPublicKeyInput{KeyId: aws.String(selectorName)})
	if err != nil {
		result.Status = publicKeyStatus(err)
		result.Uses.Record(a.sent.Load(), result.Status)
		return
	}
	if public == nil || aws.ToString(public.KeyId) != selectorName || public.KeySpec != types.KeySpecRsa3072 || public.KeyUsage != types.KeyUsageTypeEncryptDecrypt || !slices.Contains(public.EncryptionAlgorithms, types.EncryptionAlgorithmSpecRsaesOaepSha256) || (pinned != nil && !bytes.Equal(public.PublicKey, pinned)) || contract.ValidateEncryptionPublicKey(public.PublicKey) != nil {
		result.Uses.Record(a.sent.Load(), result.Status)
		return
	}
	result.Uses.Record(a.sent.Load(), enkvcrypto.KeyOK)
	if ctx.Err() != nil {
		result.Status = enkvcrypto.KeyCancelled
		return
	}
	metadataCtx := operationContext(ctx, maximumPublicResponseBytes)
	a = metadataCtx.Value(attemptKey{}).(*attempt)
	metadata, err := client.DescribeKey(metadataCtx, &kms.DescribeKeyInput{KeyId: aws.String(selectorName)})
	if err != nil {
		result.Status = publicKeyStatus(err)
		result.Uses.Record(a.sent.Load(), result.Status)
		return
	}
	if metadata == nil || metadata.KeyMetadata == nil {
		result.Uses.Record(a.sent.Load(), result.Status)
		return
	}
	m := metadata.KeyMetadata
	if aws.ToString(m.Arn) != selectorName || aws.ToString(m.KeyId) != strings.Split(selectorName, "key/")[1] || aws.ToString(m.AWSAccountId) != k.config.Account || m.KeySpec != types.KeySpecRsa3072 || m.KeyUsage != types.KeyUsageTypeEncryptDecrypt || !m.Enabled || m.KeyState != types.KeyStateEnabled || !slices.Contains(m.EncryptionAlgorithms, types.EncryptionAlgorithmSpecRsaesOaepSha256) || (m.Origin != types.OriginTypeAwsKms && m.Origin != types.OriginTypeExternal) || m.CustomKeyStoreId != nil || m.CloudHsmClusterId != nil || m.XksKeyConfiguration != nil {
		result.Uses.Record(a.sent.Load(), result.Status)
		return
	}
	result.Uses.Record(a.sent.Load(), enkvcrypto.KeyOK)
	der = bytes.Clone(public.PublicKey)
	protectionClass = contract.HardwareProtection
	result.Status = enkvcrypto.KeyOK
	if ctx.Err() != nil {
		result.Status = enkvcrypto.KeyCancelled
	}
	return
}

// ResolveSigningKey retrieves validated public material from the anchor's exact
// resource. It does not create a signing binding or establish private access.
func (a *PublicSigningAnchor) ResolveSigningKey(ctx context.Context) (der []byte, fingerprint contract.ID, reason contract.Reason) {
	ctx, call := startTelemetry(ctx, telemetry.OpSetupPublicKey)
	defer func() { finishPublicKeyTelemetry(ctx, call, reason, len(der)) }()
	if a == nil || a.client == nil || a.identity.IsZero() {
		return nil, contract.ID{}, contract.ReasonConstruction
	}
	der, reason = resolveSigningKey(ctx, signingQualification{role: a.config.Role, region: a.config.Region, keyARN: a.config.KeyARN, credentials: a.config.Credentials, client: a.client, identity: a.identity}, nil)
	if reason != contract.ReasonNone {
		return nil, contract.ID{}, reason
	}
	return der, contract.Hash(der), contract.ReasonNone
}

// ResolveEncryptionKey retrieves public material for one exact
// resource. It derives the protection class and returns no private key route
// or binding identities.
func ResolveEncryptionKey(ctx context.Context, c KeyAccessConfig, selector string) (der []byte, fingerprint contract.ID, protection uint8, result enkvcrypto.KeyResult) {
	ctx, call := startTelemetry(ctx, telemetry.OpSetupPublicKey)
	defer func() { finishKeyTelemetry(call, result.Status) }()
	result.Status = enkvcrypto.KeyInvalid
	if !validKeyAccess(c) {
		return
	}
	rt, err := privateTransport(c.Transport)
	if err != nil {
		return
	}
	k, err := newPublicEncryptionLookup(c, rt)
	if err != nil {
		return
	}
	der, protection, result = resolvePublicEncryptionKey(ctx, k, selector)
	if result.Status == enkvcrypto.KeyOK {
		fingerprint = contract.Hash(der)
	}
	return
}

func resolvePublicEncryptionKey(ctx context.Context, k *publicEncryptionLookup, selectorName string) ([]byte, uint8, enkvcrypto.KeyResult) {
	selector, ok := contract.ParseAWSKeySelector(selectorName, false)
	if k == nil || k.client == nil || !ok || selector.Account != k.config.Account || selector.Region != k.config.Region {
		return nil, 0, enkvcrypto.KeyResult{Status: enkvcrypto.KeyInvalid}
	}
	return k.resolveEncryptionKey(ctx, selectorName, contract.HardwareProtection, nil)
}

func finishPublicKeyTelemetry(ctx context.Context, call *telemetry.Call, reason contract.Reason, length int) {
	if call == nil {
		return
	}
	call.OutputBytes(int64(length))
	if ctx.Err() != nil {
		call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(telemetry.DiagnosticReasonCancelled, 0))
		call.Finish(telemetry.ResultCancelled)
		return
	}
	status := telemetry.ResultSuccess
	if reason != contract.ReasonNone {
		call.ReturnDetails(providerReasonDetails(reason))
		status = telemetry.ResultInvalid
		if reason == contract.ReasonAccess || reason == contract.ReasonTransport || reason == contract.ReasonLimit {
			status = telemetry.ResultEvidenceUnavailable
		}
	}
	call.Finish(status)
}
