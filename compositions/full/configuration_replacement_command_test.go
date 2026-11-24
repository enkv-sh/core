package compositionfull

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/installedarchive"
)

// full_only: false
func TestReplaceKeysOutputTargetIsFixedBeforeSourceRefusal(t *testing.T) {
	fixture, _ := installedarchive.LoadReader(t, "aws")
	parts, err := fixture.Archive.SelectedParts()
	if err != nil {
		t.Fatal(err)
	}
	var candidate []byte
	for _, part := range parts {
		if part.Kind == "HEAD" {
			candidate = part.Body
		}
	}
	head, err := format.DecodeHead(candidate)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := contract.MatchHeadCondition(head.Core.PreviousToken)
	if err != nil {
		t.Fatal(err)
	}
	conditional, err := format.EncodeConditionalPlan(format.ConditionalPlan{Family: head.Core.PreviousToken.Family, Store: head.Core.Store, Coordinate: head.Core.Coordinate, NonBody: head.Core.NonBody, Condition: condition, HeadCore: contract.Hash(encoded), HeadCoreLength: uint32(len(encoded))})
	if err != nil {
		t.Fatal(err)
	}
	id := func(n byte) contract.ID { return contract.ID{n} }
	subject := contract.LifecycleSubject{OperationKind: contract.OperationApplyDeclaration, Operation: id(25), Request: id(26), Recipient: id(1), KeyBinding: id(2), Fingerprint: id(3), BindingVersion: 1, IdentityPlan: contract.DigestLength{Digest: id(27), Length: 337}, HeadCore: contract.Hash(encoded), HeadCoreLength: uint32(len(encoded)), ConditionalPlan: contract.Hash(conditional), BeforeValueEntryCount: 1, AfterValueEntryCount: 1, BeforeRawBytes: 5, AfterRawBytes: 5, BeforeAccessRoot: id(28), AfterAccessRoot: id(29), BeforeMembershipCount: 1, AfterMembershipCount: 1, Normal: contract.NormalSection{Intent: contract.DigestLength{Digest: id(30), Length: 888}, PublicState: contract.DigestLength{Digest: id(31), Length: 187}, Union: contract.DescriptorVector{Digest: id(32), Length: 282, Count: 1}, Changed: 1}, Grant: contract.GrantSection{Grants: contract.DescriptorVector{Digest: id(33), Length: 61}}, Exclusion: contract.ExclusionSection{Exclusions: contract.DescriptorVector{Digest: id(34), Length: 65}, Retirements: contract.DescriptorVector{Digest: id(35), Length: 66}}}
	signature := []byte{0x30, 6, 2, 1, 1, 2, 1, 1}
	candidate, err = format.EncodeHead(format.Head{Core: head.Core, AuthKind: format.LifecycleAuth, Subject: subject, K1: signature, AuthorizationSignature: signature})
	if err != nil {
		t.Fatal(err)
	}
	// This metadata exercises local target selection only. The absent or changed
	// source prevents remote admission; it is not a replacement authority proof.
	output := configurationReaderPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
		generated["replacement"] = map[string]any{"kind": "key-replacement/v1", "source": map[string]any{"format": "json", "editable_digest": readerID(contract.ID{1}), "editable_length": 1, "generated_digest": readerID(contract.ID{2}), "generated_length": 1}, "target": "recipient", "recipient": "member", "recipient_id": readerID(contract.ID{3}), "encryption": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", "authorizer": "authority", "material_source": "authority", "request_identity": readerID(contract.ID{4}), "candidate": candidate}
	})
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"secret-sentinel":"private-parser-error"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(t.TempDir(), "missing.json"), bad, source.path} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		result := ReplaceKeysConfiguration(ctx, contract.ID{5}, path, configuration.JSON, configuration.ReplacementRequest{Target: configuration.ReplaceAuthority, Authorizer: contract.NormalSigningRole, SigningSelector: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"}, output.path)
		cancel()
		if result.Authority != nil || result.Recovery != nil || result.Recipient != nil || result.Observation == nil || result.Observation.Operation != core.ReplacementReceipt || result.Observation.Target != core.ReplacementTargetRecipient || result.Observation.UnderlyingOperation != contract.OperationRotateRecipientKeyBinding || result.Observation.StateResult != contract.ReaderRefused || result.Delivery.Status != "existing" {
			t.Fatal("source refusal changed protected read target", result)
		}
		var rendered bytes.Buffer
		if err := WriteReplacementJSON(context.Background(), &rendered, result); err != nil || bytes.Contains(rendered.Bytes(), []byte("secret-sentinel")) || bytes.Contains(rendered.Bytes(), []byte("private-parser-error")) {
			t.Fatal("unsafe protected-target refusal", err, rendered.String())
		}
		for _, file := range []struct {
			path string
			want []byte
		}{{output.path, output.editableBytes}, {output.generated, output.generatedBytes}, {source.path, source.editableBytes}, {source.generated, source.generatedBytes}} {
			got, err := os.ReadFile(file.path)
			if err != nil || !bytes.Equal(got, file.want) {
				t.Fatal("refusal changed captured pair", err)
			}
		}
	}
}
