package gcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/telemetry"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/googleapi"
)

const maximumRSAWrappingPublicKeyPEMLength = 2048

type KeyAccessConfig struct {
	Client                    *Client
	Project, Region, Endpoint string
	CredentialRoute           contract.ID
}
type KeyAccess struct {
	client                *Client
	service               *cloudkms.Service
	project, region, host string
	route                 contract.ID
}

var _ enkvcrypto.KeyAccess = (*KeyAccess)(nil)

func NewKeyAccess(ctx context.Context, c KeyAccessConfig) (*KeyAccess, error) {
	lookup, err := newPublicEncryptionLookup(ctx, c)
	if err != nil {
		return nil, err
	}
	return &KeyAccess{client: lookup.client, service: lookup.service, project: lookup.project, region: lookup.region, host: lookup.host, route: lookup.route}, nil
}
func (k *KeyAccess) Family() contract.Family { return contract.GCP }
func (k *KeyAccess) CredentialRoute() contract.ID {
	if k == nil {
		return contract.ID{}
	}
	return k.route
}
func (k *KeyAccess) validBinding(b contract.KMSBinding) bool {
	return k != nil && (&publicEncryptionLookup{client: k.client, service: k.service, project: k.project, region: k.region, host: k.host, route: k.route}).validBinding(b)
}
func protectionName(b contract.KMSBinding) string {
	if b.ProtectionClass == contract.HardwareProtection {
		return "HSM"
	}
	return "SOFTWARE"
}
func publicKeyStatus(op *operation, err error) enkvcrypto.KeyStatus {
	var response *googleapi.Error
	if op == nil || (op.status != http.StatusUnauthorized && op.status != http.StatusForbidden) || !errors.As(err, &response) || response.Code != op.status {
		return enkvcrypto.KeyUnavailable
	}
	code, present, ok := publicErrorCode(op.response)
	if !ok || present && code != op.status {
		return enkvcrypto.KeyUnavailable
	}
	return enkvcrypto.KeyDenied
}

func publicErrorCode(body []byte) (code int, present, ok bool) {
	errorBody, seen, valid := publicErrorField(body, "error")
	if !valid || !seen || bytes.Equal(bytes.TrimSpace(errorBody), []byte("null")) {
		return 0, false, false
	}
	raw, present, valid := publicErrorField(errorBody, "code")
	if !valid || present && (bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &code) != nil) {
		return 0, false, false
	}
	return code, present, true
}

func publicErrorField(body []byte, name string) (value json.RawMessage, present, ok bool) {
	if len(body) == 0 || len(body) > maxJSON || !utf8.Valid(body) {
		return nil, false, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false, false
	}
	for decoder.More() {
		token, err := decoder.Token()
		field, isString := token.(string)
		if err != nil || !isString {
			return nil, false, false
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return nil, false, false
		}
		if strings.EqualFold(field, name) {
			if field != name || present {
				return nil, false, false
			}
			value, present = raw, true
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, false, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false, false
	}
	return value, present, true
}

func keyBeginStatus(ctx context.Context) enkvcrypto.KeyStatus {
	if ctx.Err() != nil {
		return enkvcrypto.KeyCancelled
	}
	return enkvcrypto.KeyDenied
}

func (k *KeyAccess) Qualify(ctx context.Context, b contract.KMSBinding) (result enkvcrypto.KeyResult) {
	ctx, call := startTelemetry(ctx, telemetry.OpKeyQualify)
	defer func() { finishKeyTelemetry(call, result.Status) }()
	result.Status = enkvcrypto.KeyInvalid
	if !k.validBinding(b) {
		return
	}
	lookup := publicEncryptionLookup{client: k.client, service: k.service, project: k.project, region: k.region, host: k.host, route: k.route}
	_, _, result = lookup.resolveEncryptionKey(ctx, b.KeySelector, b.ProtectionClass, b.SPKI)
	return
}

// ImportOnly is a parent policy, not an origin proof. Check the selected
// version's generated/imported facts; both provider-hosted forms are allowed.
func hostedVersion(v *cloudkms.CryptoKeyVersion, importOnly bool) bool {
	if v.GenerateTime != "" {
		_, err := time.Parse(time.RFC3339Nano, v.GenerateTime)
		return err == nil && !importOnly && v.ImportTime == "" && v.ImportJob == ""
	}
	if v.ImportTime == "" || v.ImportJob == "" {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, v.ImportTime)
	return err == nil
}

func (k *KeyAccess) Decrypt(ctx context.Context, b contract.KMSBinding, ciphertext []byte, packetLength uint16) (result enkvcrypto.PrivateResult) {
	ctx, call := startTelemetry(ctx, telemetry.OpKeyDecrypt)
	defer func() { finishKeyTelemetry(call, result.Status) }()
	result.Status = enkvcrypto.KeyInvalid
	if !k.validBinding(b) || len(ciphertext) != contract.RSACiphertextLength || (packetLength != contract.SingleKeyMaterialPacketLength && packetLength != contract.ValueMaterialPacketLength) {
		return
	}
	if ctx.Err() != nil {
		result.Status = enkvcrypto.KeyCancelled
		return
	}
	ctx, ok := k.client.begin(ctx, k.host, maximumPrivateSuccessResponseBytes)
	if !ok {
		result.Status = keyBeginStatus(ctx)
		return
	}
	op := ctx.Value(operationKey{}).(*operation)
	p := &privateDecrypt{packetLength: packetLength, protection: protectionName(b)}
	op.private = p
	defer p.clear()
	result.Status = enkvcrypto.KeyUnknown
	input := bytes.Clone(ciphertext)
	request := &cloudkms.AsymmetricDecryptRequest{Ciphertext: base64.StdEncoding.EncodeToString(input), CiphertextCrc32c: int64(crc(input)), ForceSendFields: []string{"CiphertextCrc32c"}}
	output, err := k.service.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.AsymmetricDecrypt(b.KeySelector, request).Context(ctx).Do()
	if output != nil {
		defer func() { *output = cloudkms.AsymmetricDecryptResponse{} }()
	}
	if err != nil {
		result.Status = privateStatus(err)
		if ctx.Err() != nil {
			result.Status = enkvcrypto.KeyCancelled
		}
		if p.observed != (enkvcrypto.KeyUses{}) && op.sent.Load() != 0 {
			result.Uses = p.observed
		} else {
			result.Uses.Record(op.sent.Load(), result.Status)
		}
		return
	}
	if output == nil || output.ProtectionLevel != p.protection || !output.VerifiedCiphertextCrc32c || len(output.Plaintext) != base64.StdEncoding.EncodedLen(int(packetLength)) {
		result.Uses.Record(op.sent.Load(), result.Status)
		return
	}
	var scratch [102]byte
	var encoded [136]byte
	defer clear(encoded[:])
	defer clear(scratch[:])
	n, err := base64.StdEncoding.Strict().Decode(scratch[:], encoded[:copy(encoded[:], output.Plaintext)])
	if err != nil || n != int(packetLength) || output.PlaintextCrc32c != int64(crc(scratch[:n])) {
		result.Uses.Record(op.sent.Load(), result.Status)
		return
	}
	result.Uses.Record(op.sent.Load(), enkvcrypto.KeyOK)
	if ctx.Err() != nil {
		result.Status = enkvcrypto.KeyCancelled
		return
	}
	result.Packet = make([]byte, packetLength)
	copy(result.Packet, scratch[:n])
	result.Status = enkvcrypto.KeyOK
	return
}
