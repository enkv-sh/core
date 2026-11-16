package awsprovider

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KeyAccessConfig admits one commercial AWS account, region and credential
// route. The private parent admits each operation and its exact public binding.
type KeyAccessConfig struct {
	Region, Account string
	CredentialRoute contract.ID
	Credentials     aws.CredentialsProvider
	Transport       *http.Transport
	Timeout         time.Duration
}
type KeyAccess struct {
	config KeyAccessConfig
	client *http.Client
}

var _ enkvcrypto.KeyAccess = (*KeyAccess)(nil)

func validKeyAccess(c KeyAccessConfig) bool {
	return validCommon(c.Region, c.CredentialRoute, c.Credentials, c.Timeout) && accountPattern.MatchString(c.Account)
}
func NewKeyAccess(c KeyAccessConfig) (*KeyAccess, error) {
	if !validKeyAccess(c) {
		return nil, ErrConstruction
	}
	t, err := privateTransport(c.Transport)
	if err != nil {
		return nil, err
	}
	return newKeyAccess(c, t)
}
func newKeyAccess(c KeyAccessConfig, rt http.RoundTripper) (*KeyAccess, error) {
	lookup, err := newPublicEncryptionLookup(c, rt)
	if err != nil {
		return nil, err
	}
	return &KeyAccess{config: lookup.config, client: lookup.client}, nil
}
func (k *KeyAccess) Family() contract.Family { return contract.AWS }
func (k *KeyAccess) CredentialRoute() contract.ID {
	if k == nil {
		return contract.ID{}
	}
	return k.config.CredentialRoute
}

func (k *KeyAccess) validBinding(b contract.KMSBinding) bool {
	return k != nil && (&publicEncryptionLookup{config: k.config, client: k.client}).validBinding(b)
}
func (k *KeyAccess) sdk(ctx context.Context) (*kms.Client, enkvcrypto.KeyStatus) {
	return encryptionSDK(ctx, k.config, k.client)
}
func publicKeyStatus(err error) enkvcrypto.KeyStatus {
	status, code := serviceError(err)
	if outcome := privateCode(code).outcome(status); outcome != enkvcrypto.KeyUnknown {
		return outcome
	}
	return enkvcrypto.KeyUnavailable
}

func (k *KeyAccess) Qualify(ctx context.Context, b contract.KMSBinding) (result enkvcrypto.KeyResult) {
	ctx, call := startTelemetry(ctx, telemetry.OpKeyQualify)
	defer func() { finishKeyTelemetry(call, result.Status) }()
	result.Status = enkvcrypto.KeyInvalid
	if !k.validBinding(b) {
		return
	}
	lookup := publicEncryptionLookup{config: k.config, client: k.client}
	_, _, result = lookup.resolveEncryptionKey(ctx, b.KeySelector, b.ProtectionClass, b.SPKI)
	return
}

func (k *KeyAccess) Decrypt(ctx context.Context, b contract.KMSBinding, ciphertext []byte, packetLength uint16) (result enkvcrypto.PrivateResult) {
	ctx, call := startTelemetry(ctx, telemetry.OpKeyDecrypt)
	defer func() { finishKeyTelemetry(call, result.Status) }()
	result.Status = enkvcrypto.KeyInvalid
	if !k.validBinding(b) || len(ciphertext) != contract.RSACiphertextLength || (packetLength != contract.SingleKeyMaterialPacketLength && packetLength != contract.ValueMaterialPacketLength) {
		return
	}
	client, status := k.sdk(ctx)
	if status != enkvcrypto.KeyOK {
		result.Status = status
		return
	}
	p := &privateDecrypt{selector: b.KeySelector, packetLength: packetLength}
	defer p.clear()
	ctx = operationContext(ctx, maximumPrivateSuccessResponseBytes)
	a := ctx.Value(attemptKey{}).(*attempt)
	a.private = p
	result.Status = enkvcrypto.KeyUnknown
	input := bytes.Clone(ciphertext)
	output, err := client.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String(b.KeySelector), EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256, CiphertextBlob: input})
	if output != nil {
		defer func() {
			clear(output.Plaintext[:cap(output.Plaintext)])
			clear(output.CiphertextForRecipient[:cap(output.CiphertextForRecipient)])
			*output = kms.DecryptOutput{}
		}()
	}
	if err != nil {
		result.Status = privateStatus(err)
		if ctx.Err() != nil {
			result.Status = enkvcrypto.KeyCancelled
		}
		if p.observed != (enkvcrypto.KeyUses{}) && a.sent.Load() != 0 {
			result.Uses = p.observed
		} else {
			result.Uses.Record(a.sent.Load(), result.Status)
		}
		return
	}
	if output == nil || aws.ToString(output.KeyId) != b.KeySelector || output.EncryptionAlgorithm != types.EncryptionAlgorithmSpecRsaesOaepSha256 || len(output.Plaintext) != int(packetLength) || len(output.CiphertextForRecipient) != 0 || output.KeyMaterialId != nil {
		result.Uses.Record(a.sent.Load(), result.Status)
		return
	}
	result.Uses.Record(a.sent.Load(), enkvcrypto.KeyOK)
	if ctx.Err() != nil {
		result.Status = enkvcrypto.KeyCancelled
		return
	}
	result.Packet = make([]byte, packetLength)
	copy(result.Packet, output.Plaintext)
	result.Status = enkvcrypto.KeyOK
	return
}
