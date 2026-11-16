package gcp

import (
	"bytes"
	"context"
	"encoding/pem"
	"strconv"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/telemetry"
	"google.golang.org/api/cloudkms/v1"
)

type publicEncryptionLookup struct {
	client                *Client
	service               *cloudkms.Service
	project, region, host string
	route                 contract.ID
}

func newPublicEncryptionLookup(ctx context.Context, c KeyAccessConfig) (*publicEncryptionLookup, error) {
	if !sdkEnvironmentAdmitted() || c.Client == nil || c.Client.http == nil || c.Client.credentials == nil || c.CredentialRoute.IsZero() || !contract.GCPEncryptionProjectValid(c.Project) || !regionPattern.MatchString(c.Region) || c.Endpoint != KMSEndpoint(c.Region) {
		return nil, ErrConstruction
	}
	service, err := cloudkms.NewService(ctx, sdkOptions(c.Client, c.Endpoint)...)
	if err != nil {
		return nil, ErrConstruction
	}
	return &publicEncryptionLookup{client: c.Client, service: service, project: c.Project, region: c.Region, host: c.Region + "-cloudkms.googleapis.com", route: c.CredentialRoute}, nil
}

func (k *publicEncryptionLookup) validBinding(b contract.KMSBinding) bool {
	if k == nil || k.client == nil || k.service == nil || b.Provider != contract.GCP {
		return false
	}
	if _, err := contract.KMSBindingLength(b); err != nil {
		return false
	}
	selector, ok := contract.ParseGCPKeySelector(b.KeySelector, false)
	return ok && selector.Project == k.project && selector.Region == k.region
}

// PublicEncryptionQualifier owns public qualification for one exact binding.
// It has no private decryption method.
type PublicEncryptionQualifier struct {
	lookup  *publicEncryptionLookup
	binding contract.KMSBinding
	encoded []byte
}

func NewPublicEncryptionQualifier(ctx context.Context, c KeyAccessConfig, binding contract.KMSBinding) (*PublicEncryptionQualifier, error) {
	lookup, err := newPublicEncryptionLookup(ctx, c)
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

func (q *PublicEncryptionQualifier) Family() contract.Family { return contract.GCP }
func (q *PublicEncryptionQualifier) CredentialRoute() contract.ID {
	if q == nil || q.lookup == nil {
		return contract.ID{}
	}
	return q.lookup.route
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
	ctx, ok := q.client.begin(ctx, q.host, maxJSON)
	if !ok {
		return nil, contract.ReasonAccess
	}
	out, err := q.service.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.GetPublicKey(q.keyVersion).Context(ctx).Do()
	if err != nil {
		return nil, signingQualificationFailure(ctx, err)
	}
	if ctx.Err() != nil {
		return nil, contract.ReasonLimit
	}
	if out == nil || out.Name != q.keyVersion || out.Algorithm != SigningAlgorithm || (out.ProtectionLevel != "SOFTWARE" && out.ProtectionLevel != "HSM") || len(out.Pem) > maximumECDSASigningPublicKeyPEMLength {
		return nil, contract.ReasonProof
	}
	checksum, present := responseString(ctx, "pemCrc32c")
	if !present || checksum != strconv.FormatInt(out.PemCrc32c, 10) || out.PemCrc32c < 0 || out.PemCrc32c > 1<<32-1 || out.PemCrc32c != int64(crc([]byte(out.Pem))) {
		return nil, contract.ReasonProof
	}
	block, rest := pem.Decode([]byte(out.Pem))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(rest) != 0 || (pinned != nil && !bytes.Equal(block.Bytes, pinned)) || contract.ValidateSigningPublicKey(block.Bytes) != nil {
		return nil, contract.ReasonProof
	}
	if q.role == contract.RecoverySigningRole {
		ctx, ok = q.client.begin(ctx, q.host, maxJSON)
		if !ok {
			return nil, contract.ReasonAccess
		}
		key, err := q.service.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.Get(q.keyVersion).Context(ctx).Do()
		if err != nil {
			return nil, signingQualificationFailure(ctx, err)
		}
		if key == nil || key.Name != q.keyVersion || key.Algorithm != SigningAlgorithm || key.State != "ENABLED" ||
			!generatedRecoverySigningVersion(ctx, key) || key.ProtectionLevel != out.ProtectionLevel {
			return nil, contract.ReasonProof
		}
	}
	if ctx.Err() != nil {
		return nil, contract.ReasonLimit
	}
	return bytes.Clone(block.Bytes), contract.ReasonNone
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
	if ctx.Err() != nil {
		result.Status = enkvcrypto.KeyCancelled
		return
	}
	selector, _ := contract.ParseGCPKeySelector(selectorName, false)
	parent := "projects/" + selector.Project + "/locations/" + selector.Region + "/keyRings/" + selector.KeyRing + "/cryptoKeys/" + selector.Key
	callCtx, ok := k.client.begin(ctx, k.host, maxJSON)
	if !ok {
		result.Status = keyBeginStatus(ctx)
		return
	}
	op := callCtx.Value(operationKey{}).(*operation)
	key, err := k.service.Projects.Locations.KeyRings.CryptoKeys.Get(parent).Context(callCtx).Do()
	if err != nil {
		result.Status = publicKeyStatus(op, err)
		result.Uses.Record(op.sent.Load(), result.Status)
		return
	}
	if key == nil || key.Name != parent || key.Purpose != "ASYMMETRIC_DECRYPT" {
		result.Uses.Record(op.sent.Load(), result.Status)
		return
	}
	importOnly := key.ImportOnly
	result.Uses.Record(op.sent.Load(), enkvcrypto.KeyOK)
	if ctx.Err() != nil {
		result.Status = enkvcrypto.KeyCancelled
		return
	}
	callCtx, ok = k.client.begin(ctx, k.host, maxJSON)
	if !ok {
		result.Status = keyBeginStatus(ctx)
		return
	}
	op = callCtx.Value(operationKey{}).(*operation)
	version, err := k.service.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.Get(selectorName).Context(callCtx).Do()
	if err != nil {
		result.Status = publicKeyStatus(op, err)
		result.Uses.Record(op.sent.Load(), result.Status)
		return
	}
	if version == nil || version.Name != selectorName || version.Algorithm != "RSA_DECRYPT_OAEP_3072_SHA256" || version.State != "ENABLED" || (version.ProtectionLevel != "HSM" && version.ProtectionLevel != "SOFTWARE") || (protection != 0 && version.ProtectionLevel != protectionName(contract.KMSBinding{ProtectionClass: protection})) || version.ExternalProtectionLevelOptions != nil || !hostedVersion(version, importOnly) {
		result.Uses.Record(op.sent.Load(), result.Status)
		return
	}
	protection = contract.SoftwareProtection
	if version.ProtectionLevel == "HSM" {
		protection = contract.HardwareProtection
	}
	result.Uses.Record(op.sent.Load(), enkvcrypto.KeyOK)
	if ctx.Err() != nil {
		result.Status = enkvcrypto.KeyCancelled
		return
	}
	callCtx, ok = k.client.begin(ctx, k.host, maxJSON)
	if !ok {
		result.Status = keyBeginStatus(ctx)
		return
	}
	op = callCtx.Value(operationKey{}).(*operation)
	public, err := k.service.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.GetPublicKey(selectorName).Context(callCtx).Do()
	if err != nil {
		result.Status = publicKeyStatus(op, err)
		result.Uses.Record(op.sent.Load(), result.Status)
		return
	}
	if public == nil || public.Name != selectorName || public.Algorithm != "RSA_DECRYPT_OAEP_3072_SHA256" || public.ProtectionLevel != protectionName(contract.KMSBinding{ProtectionClass: protection}) || len(public.Pem) > maximumRSAWrappingPublicKeyPEMLength {
		result.Uses.Record(op.sent.Load(), result.Status)
		return
	}
	rawCRC, present := responseString(callCtx, "pemCrc32c")
	if !present || rawCRC != strconv.FormatInt(public.PemCrc32c, 10) || public.PemCrc32c != int64(crc([]byte(public.Pem))) {
		result.Uses.Record(op.sent.Load(), result.Status)
		return
	}
	block, rest := pem.Decode([]byte(public.Pem))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || (pinned != nil && !bytes.Equal(block.Bytes, pinned)) || contract.ValidateEncryptionPublicKey(block.Bytes) != nil {
		result.Uses.Record(op.sent.Load(), result.Status)
		return
	}
	result.Uses.Record(op.sent.Load(), enkvcrypto.KeyOK)
	der = bytes.Clone(block.Bytes)
	protectionClass = protection
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
	if a == nil || a.client == nil || a.identity.IsZero() || a.service == nil {
		return nil, contract.ID{}, contract.ReasonConstruction
	}
	der, reason = resolveSigningKey(ctx, signingQualification{role: a.role, client: a.client, service: a.service, identity: a.identity, keyVersion: a.keyVersion, host: a.host}, nil)
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
	k, err := newPublicEncryptionLookup(ctx, c)
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
	selector, ok := contract.ParseGCPKeySelector(selectorName, false)
	if k == nil || k.client == nil || !ok || k.service == nil || selector.Project != k.project || selector.Region != k.region {
		return nil, 0, enkvcrypto.KeyResult{Status: enkvcrypto.KeyInvalid}
	}
	return k.resolveEncryptionKey(ctx, selectorName, 0, nil)
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
