package contract

import (
	"errors"

	protocol "enkv.sh/sdk/protocols/generator"
)

type GeneratorIntent struct {
	Schema             uint16
	ConfigContractID   ID
	LifecycleMode      GeneratorLifecycleMode
	ResourceContractID ID
	Settings           []byte
}

func (v GeneratorIntent) valid() bool {
	return v.Schema == 1 && !v.ConfigContractID.IsZero() && v.LifecycleMode.resourceValid(v.ResourceContractID) && protocol.ValidCanonicalSettings(v.Settings)
}
func EncodeGeneratorIntent(v GeneratorIntent) ([]byte, error) {
	if len(v.Settings) > GeneratorIntentMaxLength-71 {
		return nil, ErrRecordCapacity
	}
	if !v.valid() {
		return nil, ErrRecord
	}
	body, err := protocol.EncodeIntent(protocol.Intent{Schema: v.Schema, ConfigContractID: protocol.ID(v.ConfigContractID),
		LifecycleMode: uint8(v.LifecycleMode), ResourceContractID: protocol.ID(v.ResourceContractID), Settings: v.Settings})
	if errors.Is(err, protocol.ErrCapacity) {
		return nil, ErrRecordCapacity
	}
	if err != nil {
		return nil, ErrRecord
	}
	return body, nil
}
func InspectGeneratorIntent(body []byte) (GeneratorIntent, error) {
	if len(body) > GeneratorIntentMaxLength {
		return GeneratorIntent{}, ErrRecordCapacity
	}
	decoded, err := protocol.DecodeIntent(body)
	if err != nil {
		if errors.Is(err, protocol.ErrCapacity) {
			return GeneratorIntent{}, ErrRecordCapacity
		}
		return GeneratorIntent{}, ErrRecord
	}
	v := GeneratorIntent{Schema: decoded.Schema, ConfigContractID: ID(decoded.ConfigContractID), LifecycleMode: GeneratorLifecycleMode(decoded.LifecycleMode),
		ResourceContractID: ID(decoded.ResourceContractID), Settings: decoded.Settings}
	if !v.valid() {
		return GeneratorIntent{}, ErrRecord
	}
	return v, nil
}

// Native facts carry the public protocol schema. Durable facts use their own revision.
func EncodeNativeGeneratorSafeFacts(v GeneratorSafeFacts) ([]byte, error) {
	if v.Schema != GeneratorSafeFactsSchema || v.Disposition >= GeneratorDispositionScopedUnusability {
		return nil, ErrRecord
	}
	if _, err := GeneratorSafeFactsLength(v); err != nil {
		return nil, err
	}
	return protocol.EncodeSafeFacts(protocol.SafeFacts{Schema: protocol.Schema, Action: v.Action, LifecycleMode: uint8(v.LifecycleMode), Disposition: v.Disposition, Reason: v.Reason, RequestDigest: protocol.ID(v.RequestDigest), IntentDigest: protocol.ID(v.IntentDigest), ResourceContractID: protocol.ID(v.ResourceContractID), Target: v.Target, ResourceData: v.ResourceData, ProviderFacts: v.ProviderFacts})
}
func InspectNativeGeneratorSafeFacts(body []byte) (GeneratorSafeFacts, error) {
	v, err := protocol.DecodeSafeFacts(body)
	if err != nil {
		return GeneratorSafeFacts{}, ErrRecord
	}
	return GeneratorSafeFacts{Schema: GeneratorSafeFactsSchema, Action: v.Action, LifecycleMode: GeneratorLifecycleMode(v.LifecycleMode), Disposition: v.Disposition, Reason: v.Reason, RequestDigest: ID(v.RequestDigest), IntentDigest: ID(v.IntentDigest), ResourceContractID: ID(v.ResourceContractID), Target: v.Target, ResourceData: v.ResourceData, ProviderFacts: v.ProviderFacts}, nil
}
