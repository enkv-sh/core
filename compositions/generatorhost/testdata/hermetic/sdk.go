package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"os"

	"enkv.sh/sdk/generator"
	protocol "enkv.sh/sdk/protocols/generator"
)

//go:embed plugin.json
var descriptorBytes []byte

func runSDK() int {
	config := protocol.ID(sha256.Sum256([]byte{13}))
	binding, err := generator.Bind(descriptorBytes, config)
	if err != nil {
		return 20
	}
	resource := protocol.ID(sha256.Sum256([]byte{22}))
	validate := func(_ context.Context, intent protocol.Intent) error {
		if intent.ConfigContractID != config || intent.LifecycleMode != protocol.LifecycleManaged || intent.ResourceContractID != resource {
			return protocol.ErrProtocol
		}
		return nil
	}
	implementation := generator.Implementation{Binding: binding,
		Normalize: func(_ context.Context, r protocol.NormalizeRequest) (protocol.Intent, error) {
			return protocol.Intent{Schema: 1, ConfigContractID: r.ConfigContractID, LifecycleMode: protocol.LifecycleManaged, ResourceContractID: resource, Settings: bytes.Clone(r.Settings)}, nil
		}, ValidateCanonical: validate,
		CheckRetirementCompatibility: func(_ context.Context, r protocol.RetirementCompatibilityRequest) (bool, error) {
			intent, err := protocol.DecodeIntent(r.Intent)
			return err == nil && validate(context.Background(), intent) == nil, nil
		},
		Create: func(_ context.Context, i generator.Invocation) (protocol.SafeFacts, []byte, error) {
			if os.Getenv("ENKV_GENERATOR_TEST_TOKEN") == "" {
				return protocol.SafeFacts{}, nil, protocol.ErrProtocol
			}
			facts := i.Command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone)
			facts.Target = []byte("hermetic-account")
			facts.ResourceData = []byte("resource")
			return facts, []byte("different-size-value"), nil
		},
		Retire: func(_ context.Context, i generator.Invocation) (protocol.SafeFacts, error) {
			original, err := protocol.DecodeSafeFacts(i.Command.OriginalFacts)
			facts := i.Command.NewFacts(protocol.DispositionRetirementAcknowledged, protocol.ReasonNone)
			facts.Target = bytes.Clone(original.Target)
			facts.ResourceData = bytes.Clone(original.ResourceData)
			return facts, err
		},
	}
	return generator.Main(implementation)
}
