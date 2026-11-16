package outputhost

import (
	"bytes"
	"context"
	"testing"

	protocol "enkv.sh/sdk/protocols/output"
)

// full_only: false
func TestPublicationActionFactsComeFromSelectedPlugin(t *testing.T) {
	config := testArtifactAndConfig(t)
	validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := validator.Normalize(t.Context(), protocol.NormalizeRequest{Schema: 1, DeadlineUnixMillis: testDeadline(), Settings: []byte(`{"prefix":"private"}`)})
	if err != nil || !normalized.Accepted || normalized.Destination.ConfigContractID != "test-output/config/v1" || normalized.Destination.ServiceContractID != "test-output/service/v1" || !bytes.Equal(normalized.Destination.CanonicalSettings, []byte(`{"prefix":"private"}`)) {
		t.Fatal("plugin normalization differs", err)
	}
	if _, err := validator.ValidateCanonical(t.Context(), protocol.CanonicalRequest{Schema: 1, DeadlineUnixMillis: testDeadline(), Destination: normalized.Destination}); err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []uint8{protocol.EncodingRaw, protocol.EncodingBase64} {
		interpreted, err := validator.InterpretTarget(t.Context(), protocol.InterpretRequest{Schema: 1, DeadlineUnixMillis: testDeadline(), Destination: normalized.Destination, EntryName: "key", PayloadEncoding: encoding})
		target := interpreted.Target
		if err != nil || target.CanonicalTarget != "private/key" || target.ConsumerLocator != "private/key" || target.PayloadEncoding != encoding || target.Capabilities != 255 || target.CreateValueBounds != (protocol.PayloadBounds{Maximum: 65536}) || target.WriteValueBounds != (protocol.PayloadBounds{Maximum: 65536}) {
			t.Fatal("typed target differs", err, target)
		}
	}
	assertNoStagedChild(t, config.ArtifactPath)
}

// full_only: false
func TestPublicationActionCheckRejectsUnsupportedPolicyBytes(t *testing.T) {
	config := testArtifactAndConfig(t)
	validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
	if err != nil {
		t.Fatal(err)
	}
	request, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
	for _, data := range [][]byte{[]byte("unsupported"), []byte("1,1"), nil} {
		policy.Data = data
		request.PolicyDigest, err = protocol.PolicyDigest(request.DomainID, policy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validator.CheckAction(context.Background(), request, policy); err == nil {
			t.Fatal("plugin policy refusal was lost")
		}
	}
	assertNoStagedChild(t, config.ArtifactPath)
}

// full_only: false
func TestPublicationActionCheckRetiredTargetNeedsNoPolicy(t *testing.T) {
	config := testArtifactAndConfig(t)
	validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := testPublicRequest(t, config.Installation.Artifact(), "fixture")
	request.Action = protocol.ActionDeleteReservedSlot
	request.Target.Capabilities = protocol.CapabilityDeleteReservedSlot
	request.Target.CreateValueBounds, request.Target.WriteValueBounds = protocol.PayloadBounds{}, protocol.PayloadBounds{}
	request.PolicyDigest = protocol.ID{}
	request.PolicyContractID = ""
	request.PayloadLengthMode, request.PayloadLength = protocol.LengthAbsent, 0
	request.OwnershipMode = protocol.OwnershipUncertain
	request.UncertainCreateAttemptID, request.ExclusiveNamespaceDigest = protocol.ID{1}, protocol.ID{2}
	result, err := validator.CheckAction(t.Context(), request, protocol.Policy{})
	if err != nil || !result.Accepted || result.PayloadBounds != (protocol.PayloadBounds{}) {
		t.Fatal("deletion-only interpretation refused", err)
	}
	assertNoStagedChild(t, config.ArtifactPath)
}

// full_only: false
func TestPublicationPluginConsumerPolicyRemoval(t *testing.T) {
	config := testArtifactAndConfig(t)
	validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
	if err != nil {
		t.Fatal(err)
	}
	request, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
	for _, data := range []string{"1,9", "1"} {
		policy.Data = []byte(data)
		request.PolicyDigest, err = protocol.PolicyDigest(request.DomainID, policy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validator.CheckAction(t.Context(), request, policy); err != nil {
			t.Fatal("qualified consumer policy refused", data, err)
		}
	}
	for _, data := range []string{"", "1,9,12"} {
		policy.Data = []byte(data)
		request.PolicyDigest, err = protocol.PolicyDigest(request.DomainID, policy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validator.CheckAction(t.Context(), request, policy); err == nil {
			t.Fatal("unqualified consumer set admitted", data)
		}
	}
}
