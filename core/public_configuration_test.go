package core

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

func publicPresent[T any](v T) contract.PublicField[T] {
	return contract.PublicField[T]{State: contract.PublicPresent, Value: v}
}

func publicRecoveryFixture(t *testing.T, input *contract.PublicConfiguration) {
	t.Helper()
	signing := input.Authority.Signing
	spki, err := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d030107034200047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1")
	if err != nil {
		t.Fatal(err)
	}
	signing.PublicKey = publicPresent(spki)
	signing.Fingerprint = publicPresent(contract.ID(sha256.Sum256(spki)))
	signing.Role = publicPresent(contract.RecoverySigningRole)
	signing.Selector = publicPresent("projects/fixture/locations/us-central1/keyRings/ring/cryptoKeys/recovery-signing/cryptoKeyVersions/1")
	encryption := input.Recipients.Value[0].Encryption
	n := new(big.Int).Lsh(big.NewInt(1), 3071)
	n.Add(n, big.NewInt(12347))
	spki, err = x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	encryption.PublicKey = publicPresent(spki)
	encryption.Fingerprint = publicPresent(contract.ID(sha256.Sum256(spki)))
	encryption.Selector = publicPresent("projects/fixture/locations/us-central1/keyRings/ring/cryptoKeys/recovery-key/cryptoKeyVersions/1")
	input.Recovery = contract.PublicRecoverySettings{Enabled: publicPresent(true), Signing: &signing, Encryption: &encryption}
}

// full_only: false
func TestPublicConfigurationKnownInvalidDiagnosticSurvivesEitherArrivalOrder(t *testing.T) {
	subject := contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}
	for _, reasons := range [][]contract.DiagnosticReason{
		{contract.ReasonPublicFactUnavailable, contract.ReasonInvalidInput},
		{contract.ReasonInvalidInput, contract.ReasonPublicFactUnavailable},
	} {
		t.Run(string(reasons[0]), func(t *testing.T) {
			check := publicConfigurationCheck{result: PublicConfigurationValidation{Valid: true, Complete: true, DiagnosticsComplete: true}}
			for _, reason := range reasons {
				check.add(subject, contract.FieldPresence, reason, nil)
			}
			want := []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput}}
			if check.result.Valid || check.result.Complete || !check.result.DiagnosticsComplete || !reflect.DeepEqual(check.result.Diagnostics, want) {
				t.Fatalf("diagnostic arrival order: valid=%t complete=%t diagnostics_complete=%t diagnostics=%+v want=%+v", check.result.Valid, check.result.Complete, check.result.DiagnosticsComplete, check.result.Diagnostics, want)
			}
		})
	}
	for _, tc := range []struct {
		name, destination string
		want              []contract.Diagnostic
	}{
		{"empty-destination", "", []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput}}},
		{"nul-identifier-with-missing-fields", "\x00", []contract.Diagnostic{
			{Subject: subject, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable},
			{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "\x00"}, Path: []contract.DiagnosticField{contract.FieldDestination}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonMissingRequiredField},
			{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "\x00"}, Path: []contract.DiagnosticField{contract.FieldTargets}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonMissingRequiredField},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := publicConfigurationFixture(t)
			input.Entries = contract.PublicField[[]contract.PublicEntry]{State: contract.PublicUnavailable}
			input.OutputBindings = publicPresent([]contract.PublicOutputBinding{{DestinationID: tc.destination}})
			got := NewPublicConfigurationValidator(nil).Validate(t.Context(), input)
			if got.Valid || got.Complete || !got.DiagnosticsComplete || !reflect.DeepEqual(got.Diagnostics, tc.want) {
				t.Fatalf("unavailable entries and destination: valid=%t complete=%t diagnostics_complete=%t diagnostics=%+v want=%+v", got.Valid, got.Complete, got.DiagnosticsComplete, got.Diagnostics, tc.want)
			}
		})
	}
}

// full_only: false
func TestPublicConfigurationEqualKeySelectorsRefuseWithoutPublicFacts(t *testing.T) {
	for _, kind := range []string{"signing", "encryption"} {
		for _, relation := range []string{"different", "equal", "unresolved-project"} {
			equal := relation == "equal"
			t.Run(fmt.Sprintf("%s/%s", kind, relation), func(t *testing.T) {
				input := publicConfigurationFixture(t)
				publicRecoveryFixture(t, &input)
				field := contract.FieldSigningSelector
				if kind == "signing" {
					if equal {
						input.Recovery.Signing.Selector = input.Authority.Signing.Selector
					} else if relation == "unresolved-project" {
						input.Recovery.Signing.Selector = publicPresent(strings.Replace(input.Authority.Signing.Selector.Value, "projects/fixture/", "projects/123456/", 1))
					}
					input.Authority.Signing.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
					input.Authority.Signing.Fingerprint = contract.PublicField[contract.ID]{State: contract.PublicUnavailable}
					input.Recovery.Signing.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
					input.Recovery.Signing.Fingerprint = contract.PublicField[contract.ID]{State: contract.PublicUnavailable}
				} else {
					field = contract.FieldEncryptionSelector
					if equal {
						input.Recovery.Encryption.Selector = input.Recipients.Value[0].Encryption.Selector
					} else if relation == "unresolved-project" {
						input.Recovery.Encryption.Selector = publicPresent(strings.Replace(input.Recipients.Value[0].Encryption.Selector.Value, "projects/fixture/", "projects/123456/", 1))
					}
					input.Recipients.Value[0].Encryption.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
					input.Recipients.Value[0].Encryption.Fingerprint = contract.PublicField[contract.ID]{State: contract.PublicUnavailable}
					input.Recovery.Encryption.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
					input.Recovery.Encryption.Fingerprint = contract.PublicField[contract.ID]{State: contract.PublicUnavailable}
				}
				got := NewPublicConfigurationValidator(nil).Validate(t.Context(), input)
				var invalid []contract.Diagnostic
				for _, row := range got.Diagnostics {
					if row.Reason != contract.ReasonPublicFactUnavailable {
						invalid = append(invalid, row)
					}
				}
				var want []contract.Diagnostic
				if equal {
					want = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectRecovery}, Path: []contract.DiagnosticField{field}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidFieldCombination}}
				}
				if got.Valid == equal || got.Complete || !got.DiagnosticsComplete || !reflect.DeepEqual(invalid, want) || len(got.Diagnostics) != 4+len(want) {
					t.Fatal("literal key relation depended on unavailable public facts", got)
				}
			})
		}
	}
}

// full_only: false
func TestPublicConfigurationKeepsIndependentFaults(t *testing.T) {
	for _, owner := range []string{"recipient", "authority", "recovery-signing", "recovery-encryption"} {
		t.Run(owner, func(t *testing.T) {
			input := publicConfigurationFixture(t)
			subject := contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}
			keyField, fingerprintField := contract.FieldEncryptionPublicKey, contract.FieldEncryptionFingerprint
			switch owner {
			case "recipient":
				input.Recipients.Value[0].Encryption.PublicKey = publicPresent([]byte{1})
				input.Recipients.Value[0].Encryption.Fingerprint = contract.PublicField[contract.ID]{State: contract.PublicUnavailable}
			case "authority":
				subject = contract.DiagnosticSubject{Kind: contract.SubjectAuthority}
				keyField, fingerprintField = contract.FieldSigningPublicKey, contract.FieldSigningFingerprint
				input.Authority.Signing.PublicKey = publicPresent([]byte{1})
				input.Authority.Signing.Fingerprint = contract.PublicField[contract.ID]{State: contract.PublicUnavailable}
			case "recovery-signing":
				publicRecoveryFixture(t, &input)
				subject = contract.DiagnosticSubject{Kind: contract.SubjectRecovery}
				keyField, fingerprintField = contract.FieldSigningPublicKey, contract.FieldSigningFingerprint
				input.Recovery.Signing.PublicKey = publicPresent([]byte{1})
				input.Recovery.Signing.Fingerprint = contract.PublicField[contract.ID]{State: contract.PublicUnavailable}
			case "recovery-encryption":
				publicRecoveryFixture(t, &input)
				subject = contract.DiagnosticSubject{Kind: contract.SubjectRecovery}
				input.Recovery.Encryption.PublicKey = publicPresent([]byte{1})
				input.Recovery.Encryption.Fingerprint = contract.PublicField[contract.ID]{State: contract.PublicUnavailable}
			}
			v := NewPublicConfigurationValidator(nil)
			got := v.Validate(context.Background(), input)
			want := []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{fingerprintField}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable}, {Subject: subject, Path: []contract.DiagnosticField{keyField}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput}}
			if got.Valid || got.Complete || !reflect.DeepEqual(got.Diagnostics, want) {
				t.Fatalf("independent key faults=%+v want=%+v", got.Diagnostics, want)
			}
		})
	}
	t.Run("unavailable-contract-and-locator", func(t *testing.T) {
		input := publicConfigurationFixture(t)
		input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "e")})
		target := publicFixtureTarget("e", "slot")
		target.TargetContractID = contract.PublicField[string]{State: contract.PublicUnavailable}
		target.ConsumerLocator = contract.PublicField[string]{State: contract.PublicUnavailable}
		input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", target)})
		calls, generatorCalls := 0, 0
		v := publicFixtureValidator(t, &calls, &generatorCalls)
		publicFixtureInstallSources(v, input.OutputBindings.Value...)
		publicFixtureRouteTargets(&input)
		got := v.Validate(context.Background(), input)
		subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "d", Name: "e"}
		want := []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{contract.FieldConsumerLocator}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable}, {Subject: subject, Path: []contract.DiagnosticField{contract.FieldTargetContract}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable}}
		if !got.Valid || got.Complete || calls != 0 || !reflect.DeepEqual(got.Diagnostics, want) {
			t.Fatalf("independent interpretation faults=%+v want=%+v", got.Diagnostics, want)
		}
	})
	t.Run("generated-intent-independent-of-epoch", func(t *testing.T) {
		input := publicConfigurationFixture(t)
		entry := publicFixtureEntry(input, "e")
		entry.Source = publicPresent(contract.Generated)
		entry.Generated = publicFixtureGenerated(t, contract.GeneratorLifecycleManaged)
		entry.Generated.Epoch = contract.PublicField[uint64]{State: contract.PublicUnavailable}
		entry.Generated.ContentIntent = publicPresent([]byte{9})
		input.Entries = publicPresent([]contract.PublicEntry{entry})
		calls, generatorCalls := 0, 0
		v := publicFixtureValidator(t, &calls, &generatorCalls)
		publicFixtureInstallSources(v, input.OutputBindings.Value...)
		publicFixtureRouteTargets(&input)
		got := v.Validate(context.Background(), input)
		subject := contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "e"}
		want := []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{contract.FieldGenerated, contract.FieldContentIntent}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput}, {Subject: subject, Path: []contract.DiagnosticField{contract.FieldGenerated, contract.FieldEpoch}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable}}
		if got.Valid || got.Complete || generatorCalls != 0 || !reflect.DeepEqual(got.Diagnostics, want) {
			t.Fatalf("independent intent faults=%+v want=%+v", got.Diagnostics, want)
		}
	})
	t.Run("recovery-key-independent-of-mode", func(t *testing.T) {
		input := publicConfigurationFixture(t)
		publicRecoveryFixture(t, &input)
		input.Recovery.Enabled = contract.PublicField[bool]{State: contract.PublicUnavailable}
		input.Recovery.Encryption.PublicKey = publicPresent([]byte{1})
		v := NewPublicConfigurationValidator(nil)
		got := v.Validate(context.Background(), input)
		subject := contract.DiagnosticSubject{Kind: contract.SubjectRecovery}
		want := []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{contract.FieldEnabled}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable}, {Subject: subject, Path: []contract.DiagnosticField{contract.FieldEncryptionPublicKey}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput}}
		if got.Valid || got.Complete || !reflect.DeepEqual(got.Diagnostics, want) {
			t.Fatalf("independent recovery faults=%+v want=%+v", got.Diagnostics, want)
		}
	})
}

// full_only: false
func TestPublicConfigurationRetainsIndependentPublicFields(t *testing.T) {
	for _, name := range []string{"invalid-class", "unavailable-class", "secret-payload"} {
		t.Run(name, func(t *testing.T) {
			input := publicConfigurationFixture(t)
			entry := publicFixtureEntry(input, "e")
			entry.PlainValue = publicPresent([]byte{9})
			valid := false
			switch name {
			case "invalid-class":
				entry.Class = publicPresent(uint8(90))
			case "unavailable-class":
				entry.Class = contract.PublicField[uint8]{State: contract.PublicUnavailable}
				valid = true
			}
			input.Entries = publicPresent([]contract.PublicEntry{entry})
			input.Store.Region = publicPresent("us-east1")
			v := NewPublicConfigurationValidator(nil)
			got := v.Validate(context.Background(), input)
			if got.Valid != valid || got.Complete || got.Configuration.Store.Region.State != contract.PublicPresent || got.Configuration.Store.Region.Value != "us-east1" || len(got.Configuration.Entries.Value) != 1 {
				t.Fatal("field-local fault erased independent public settings")
			}
			if got.Configuration.Entries.Value[0].PlainValue.State == contract.PublicPresent || got.Configuration.Entries.Value[0].PlainValue.Value != nil {
				t.Fatal("unknown/secret class retains plaintext equality input")
			}
		})
	}
}

// full_only: false
func TestPublicConfigurationInvalidServiceContractDoesNotAllocatePhysicalKey(t *testing.T) {
	input := publicConfigurationFixture(t)
	input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "e")})
	target := publicFixtureTarget("e", "slot")
	input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", target)})
	calls, generatorCalls := 0, 0
	v := publicFixtureValidator(t, &calls, &generatorCalls)
	publicFixtureInstallSources(v, input.OutputBindings.Value...)
	publicFixtureRouteTargets(&input)
	v.Validate(context.Background(), input)
	input.OutputBindings.Value[0].Targets.Value[0].ServiceContractID = publicPresent(strings.Repeat("p", 1<<20))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got := v.Validate(context.Background(), input)
	runtime.ReadMemStats(&after)
	if got.Valid || got.Complete || after.TotalAlloc-before.TotalAlloc >= 512<<10 {
		t.Fatal("invalid service contract created unbounded indexing backing")
	}
}

// full_only: false
func TestPublicConfigurationOwnsEarlyFailureSubjects(t *testing.T) {
	input := publicConfigurationFixture(t)
	backing := strings.Repeat("n", 1024)
	name := backing[100:101]
	entry := publicFixtureEntry(input, name)
	entry.Class = publicPresent(contract.Plain)
	entry.PlainValue = publicPresent(make([]byte, contract.CryptoMaxRetainedValue+1))
	input.Entries = publicPresent([]contract.PublicEntry{entry})
	v := NewPublicConfigurationValidator(nil)
	got := v.Validate(context.Background(), input)
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].Subject.Name != name || unsafe.StringData(got.Diagnostics[0].Subject.Name) == unsafe.StringData(name) {
		t.Fatal("early failure retains caller subject backing")
	}
}

func publicConfigurationFixture(t *testing.T) contract.PublicConfiguration {
	t.Helper()
	id := func(b byte) contract.ID { var id contract.ID; id[0] = b; return id }
	// Structural 3072-bit odd modulus and the standard P-256 base point SPKI.
	n := new(big.Int).Lsh(big.NewInt(1), 3071)
	n.Add(n, big.NewInt(12345))
	spki, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	signing, err := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	if err != nil {
		t.Fatal(err)
	}
	encryption := contract.PublicEncryptionSettings{Provider: publicPresent(contract.GCP), Selector: publicPresent("projects/fixture/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"), PublicKey: publicPresent(spki), Fingerprint: publicPresent(contract.ID(sha256.Sum256(spki))), WrapProfile: publicPresent(contract.RSAOAEPWrapProfile), ProtectionClass: publicPresent(contract.SoftwareProtection)}
	return contract.PublicConfiguration{
		Entries:        publicPresent([]contract.PublicEntry{}),
		Recipients:     publicPresent([]contract.PublicRecipient{{RecipientID: id(2), DisplayName: publicPresent("authority"), Encryption: encryption}, {RecipientID: id(3), DisplayName: publicPresent("unassigned"), Encryption: encryption}}),
		OutputBindings: publicPresent([]contract.PublicOutputBinding{}), Routing: publicPresent([]contract.PublicRoutingRule{}),
		Groups:    publicPresent([][]string{}),
		Store:     contract.PublicStoreSettings{DomainID: publicPresent(id(1)), Provider: publicPresent(contract.GCP), ConstructionProfile: publicPresent(contract.StoreConstructionProfile), Region: publicPresent("us-central1"), Bucket: publicPresent("enkv-example-bucket"), Prefix: publicPresent("team/prod"), ExpectedOwner: publicPresent("")},
		Authority: contract.PublicAuthoritySettings{RecipientID: publicPresent(id(2)), Signing: contract.PublicSigningSettings{Provider: publicPresent(contract.GCP), Selector: publicPresent("projects/fixture/locations/us-central1/keyRings/ring/cryptoKeys/signing/cryptoKeyVersions/1"), PublicKey: publicPresent(signing), Fingerprint: publicPresent(contract.ID(sha256.Sum256(signing))), Role: publicPresent(contract.NormalSigningRole), Profile: publicPresent(contract.P256SigningProfile)}},
		Recovery:  contract.PublicRecoverySettings{Enabled: publicPresent(false)},
	}
}

// full_only: false
func TestPublicConfigurationAcceptsEmptyAndOwnsExactBytes(t *testing.T) {
	validator := NewPublicConfigurationValidator(nil)
	input := publicConfigurationFixture(t)
	got := validator.Validate(context.Background(), input)
	if !got.Valid || !got.Complete || len(got.Diagnostics) != 0 {
		t.Fatalf("validation=%+v", got)
	}
	input.Entries = publicPresent([]contract.PublicEntry{{Name: "", Class: publicPresent(contract.Plain), Source: publicPresent(contract.Supplied), PlainValue: publicPresent([]byte{0, '\n'}), Memberships: publicPresent([]contract.ID{input.Authority.RecipientID.Value})}, {Name: "A", Class: publicPresent(contract.Secret), Source: publicPresent(contract.Supplied), Memberships: publicPresent([]contract.ID{input.Authority.RecipientID.Value})}, {Name: "a", Class: publicPresent(contract.Plain), Source: publicPresent(contract.Supplied), PlainValue: publicPresent([]byte{}), Memberships: publicPresent([]contract.ID{input.Authority.RecipientID.Value})}})
	got = validator.Validate(context.Background(), input)
	want := slices.Clone(input.Entries.Value)
	for i := range want {
		want[i].InputEncoding = publicPresent(uint8(contract.InputEncodingRaw))
		want[i].OutputEncoding = publicPresent(uint8(contract.OutputEncodingRaw))
	}
	if !got.Valid || !got.Complete || !reflect.DeepEqual(got.Configuration.Entries.Value, want) {
		t.Fatalf("exact input refused: %+v", got.Diagnostics)
	}
	input.Entries.Value[0].PlainValue.Value[0] = 9
	if got.Configuration.Entries.Value[0].PlainValue.Value[0] != 0 {
		t.Fatal("normalized configuration borrows application bytes")
	}
}

// full_only: false
func TestPublicConfigurationCollectsSafeInputFailures(t *testing.T) {
	validator := NewPublicConfigurationValidator(nil)
	input := publicConfigurationFixture(t)
	input.Store.Region = contract.PublicField[string]{State: contract.PublicUnavailable}
	input.Authority.Signing.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
	input.Entries = contract.PublicField[[]contract.PublicEntry]{}
	got := validator.Validate(context.Background(), input)
	if got.Valid || got.Complete || len(got.Diagnostics) != 3 {
		t.Fatalf("independent failures=%+v", got)
	}
	for _, diagnostic := range got.Diagnostics {
		if len(diagnostic.Path) != 1 || diagnostic.Outcome != contract.DiagnosticUnable {
			t.Fatalf("unsafe diagnostic=%+v", diagnostic)
		}
	}
}

func publicFixtureEntry(input contract.PublicConfiguration, name string) contract.PublicEntry {
	return contract.PublicEntry{Name: name, Class: publicPresent(contract.Secret), Source: publicPresent(contract.Supplied), Memberships: publicPresent([]contract.ID{input.Authority.RecipientID.Value})}
}

func publicFixtureIntent(mode contract.GeneratorLifecycleMode, settings []byte) []byte {
	// Schema1, configID, lifecycle, resourceID, settings length and JSON bytes.
	body := make([]byte, 71+len(settings))
	body[1], body[2], body[34] = 1, 9, byte(mode)
	if mode == contract.GeneratorLifecycleManaged {
		body[35] = 7
	}
	binary.BigEndian.PutUint32(body[67:71], uint32(len(settings)))
	copy(body[71:], settings)
	return body
}
func publicFixtureGenerated(t *testing.T, mode contract.GeneratorLifecycleMode) *contract.PublicGeneratedSettings {
	t.Helper()
	resource := contract.ID{}
	if mode == contract.GeneratorLifecycleManaged {
		resource[0] = 7
	}
	g := &contract.PublicGeneratedSettings{Epoch: publicPresent(uint64(0)), ConfigContractID: publicPresent(contract.ID{9}), ResourceContractID: publicPresent(resource), LifecycleMode: publicPresent(mode), ContentIntent: publicPresent(publicFixtureIntent(mode, []byte("{}")))}
	if mode == contract.GeneratorLifecycleManaged {
		g.Retirement = publicPresent(contract.GeneratedRetirementManual)
		g.Completion = publicPresent(contract.GeneratedCompletionAcknowledged)
	}
	return g
}
func publicFixtureTarget(name, slot string) contract.PublicOutputTarget {
	return contract.PublicOutputTarget{EntryName: name, ServiceContractID: publicPresent("test-output/service/v1"), CanonicalTarget: publicPresent(slot), ConsumerLocator: publicPresent(slot + "/latest"), TargetContractID: publicPresent("test-output/target/v1"), TargetData: publicPresent([]byte("single")), PayloadEncoding: publicPresent(contract.OutputEncodingRaw), LocatorRequiresCreation: publicPresent(false), Capabilities: publicPresent((contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot)), CreateValueBounds: publicPresent(contract.OutputPayloadBounds{}), WriteValueBounds: publicPresent(contract.OutputPayloadBounds{Maximum: 65536}), ConsumerPolicy: publicPresent(contract.OutputPolicy{ContractID: "test-policy", Data: []byte{3, 7}})}
}
func publicFixtureBinding(id string, targets ...contract.PublicOutputTarget) contract.PublicOutputBinding {
	policy := publicFixtureTarget("", "").ConsumerPolicy.Value
	if len(targets) != 0 {
		policy = targets[0].ConsumerPolicy.Value
	}
	policy.Data = slices.Clone(policy.Data)
	settings, _ := json.Marshal(struct {
		Fixture string `json:"fixture"`
	}{id})
	return contract.PublicOutputBinding{DestinationID: id, Destination: publicPresent(contract.OutputDestination{ConfigContractID: "test-output/config/v1", ServiceContractID: "test-output/service/v1", CanonicalSettings: settings, Policy: policy, Capabilities: publicFixtureTarget("", "").Capabilities.Value}), Targets: publicPresent(targets)}
}

// The table is authored before input damage. Derivation uses this fixed table.
func publicFixtureInstallSources(v *PublicConfigurationValidator, bindings ...contract.PublicOutputBinding) {
	coordinates := make(map[string]map[string]contract.OutputTarget)
	for _, binding := range bindings {
		rows := make(map[string]contract.OutputTarget)
		for _, target := range binding.Targets.Value {
			rows[target.EntryName] = contract.OutputTarget{ServiceContractID: target.ServiceContractID.Value, TargetContractID: target.TargetContractID.Value, CanonicalTarget: target.CanonicalTarget.Value, ConsumerLocator: target.ConsumerLocator.Value, TargetData: slices.Clone(target.TargetData.Value), PayloadEncoding: target.PayloadEncoding.Value, LocatorRequiresCreation: target.LocatorRequiresCreation.Value, Capabilities: target.Capabilities.Value, CreateValueBounds: target.CreateValueBounds.Value, WriteValueBounds: target.WriteValueBounds.Value}
		}
		coordinates[binding.DestinationID] = rows
	}
	before := v.interpret
	v.interpret = func(ctx context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
		if before != nil {
			if _, err := before(ctx, id, destination, name, encoding); err != nil {
				return contract.OutputTarget{}, err
			}
		}
		target, ok := coordinates[id][name]
		if !ok {
			return contract.OutputTarget{}, contract.ErrRecord
		}
		target.PayloadEncoding = encoding
		target.Policy = destination.Policy
		return target, nil
	}
}

func publicFixtureRouteTargets(input *contract.PublicConfiguration) {
	routes := make(map[string][]string)
	for _, binding := range input.OutputBindings.Value {
		for _, target := range binding.Targets.Value {
			routes[target.EntryName] = append(routes[target.EntryName], binding.DestinationID)
		}
	}
	input.Routing = publicPresent([]contract.PublicRoutingRule{})
	for name, destinations := range routes {
		slices.Sort(destinations)
		input.Routing.Value = append(input.Routing.Value, contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: name}, Destinations: publicPresent(destinations)})
	}
	slices.SortFunc(input.Routing.Value, func(a, b contract.PublicRoutingRule) int { return strings.Compare(a.Key.EntryName, b.Key.EntryName) })
}

func publicFixtureValidator(t *testing.T, outputCalls, generatorCalls *int) *PublicConfigurationValidator {
	t.Helper()
	return NewPublicConfigurationValidator(func(context.Context, string, contract.OutputDestination, string, uint8) (contract.OutputTarget, error) {
		*outputCalls++
		return contract.OutputTarget{}, nil
	})
}

// full_only: false
func TestPublicConfigurationNormalizesCompleteSetsAndCanonicalFacts(t *testing.T) {
	outputCalls, generatorCalls := 0, 0
	v := publicFixtureValidator(t, &outputCalls, &generatorCalls)
	input := publicConfigurationFixture(t)
	authority, other := input.Authority.RecipientID.Value, input.Recipients.Value[1].RecipientID
	entry := publicFixtureEntry(input, "")
	entry.Source = publicPresent(contract.Generated)
	entry.Memberships = publicPresent([]contract.ID{other, authority})
	entry.Generated = publicFixtureGenerated(t, contract.GeneratorLifecycleManaged)
	input.Entries = publicPresent([]contract.PublicEntry{entry, publicFixtureEntry(input, "second")})
	input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("z", publicFixtureTarget("second", "slot-z-second")), publicFixtureBinding("a", publicFixtureTarget("second", "slot-a-second"), publicFixtureTarget("", "slot-a"))})
	input.Routing = publicPresent([]contract.PublicRoutingRule{{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: publicPresent([]string{"z", "a"})}, {Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: ""}, Destinations: publicPresent([]string{"a"})}})
	publicFixtureInstallSources(v, input.OutputBindings.Value...)
	got := v.Validate(context.Background(), input)
	if !got.Valid || !got.Complete || len(got.Diagnostics) != 0 || outputCalls != 0 || generatorCalls != 0 {
		t.Fatalf("validation=%+v calls=%d,%d", got.Diagnostics, outputCalls, generatorCalls)
	}
	if got.Configuration.OutputBindings.Value[0].DestinationID != "a" || !slices.Equal(got.Configuration.Entries.Value[0].Memberships.Value, []contract.ID{authority, other}) || !slices.Equal(got.Configuration.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.Value.Data, []byte{3, 7}) {
		t.Fatal("complete sets not normalized")
	}
	if got.Configuration.Entries.Value[0].Generated.ResourceContractID.Value != (contract.ID{7}) {
		t.Fatal("canonical generated resource changed")
	}
	slices.Reverse(input.Entries.Value)
	slices.Reverse(input.Recipients.Value)
	for i := range input.Entries.Value {
		slices.Reverse(input.Entries.Value[i].Memberships.Value)
	}
	slices.Reverse(input.OutputBindings.Value)
	for i := range input.OutputBindings.Value {
		slices.Reverse(input.OutputBindings.Value[i].Targets.Value)
	}
	slices.Reverse(input.Routing.Value)
	for i := range input.Routing.Value {
		slices.Reverse(input.Routing.Value[i].Destinations.Value)
	}
	second := v.Validate(context.Background(), input)
	if !second.Complete || !reflect.DeepEqual(got.Configuration, second.Configuration) {
		t.Fatal("permuted true sets differ")
	}
	for i := range input.Entries.Value {
		if input.Entries.Value[i].Generated != nil {
			input.Entries.Value[i].Generated.ContentIntent.Value[71] = 9
		}
	}
	input.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.Value.Data[0] = 99
	if got.Configuration.Entries.Value[0].Generated.ContentIntent.Value[71] != '{' || got.Configuration.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.Value.Data[1] != 7 {
		t.Fatal("returned fields borrow input backing")
	}
}

// full_only: false
func TestPublicConfigurationRefusesMalformedCombinationsAndReferences(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*contract.PublicConfiguration)
		field  contract.DiagnosticField
		reason contract.DiagnosticReason
	}{
		{"duplicate-entry", func(v *contract.PublicConfiguration) { v.Entries.Value = append(v.Entries.Value, v.Entries.Value[0]) }, contract.FieldPresence, contract.ReasonDuplicateKey},
		{"duplicate-recipient", func(v *contract.PublicConfiguration) {
			v.Recipients.Value = append(v.Recipients.Value, v.Recipients.Value[0])
		}, contract.FieldPresence, contract.ReasonDuplicateKey},
		{"duplicate-member", func(v *contract.PublicConfiguration) {
			e := &v.Entries.Value[0]
			e.Memberships.Value = append(e.Memberships.Value, e.Memberships.Value[0])
		}, contract.FieldMemberships, contract.ReasonDuplicateMember},
		{"unresolved-member", func(v *contract.PublicConfiguration) {
			var id contract.ID
			id[0] = 99
			v.Entries.Value[0].Memberships.Value = append(v.Entries.Value[0].Memberships.Value, id)
		}, contract.FieldMemberships, contract.ReasonUnresolvedReference},
		{"absent-authority-membership", func(v *contract.PublicConfiguration) { v.Entries.Value[0].Memberships = publicPresent([]contract.ID{}) }, contract.FieldMemberships, contract.ReasonUnresolvedReference},
		{"generated-plain", func(v *contract.PublicConfiguration) {
			v.Entries.Value[0].Class = publicPresent(contract.Plain)
			v.Entries.Value[0].Source = publicPresent(contract.Generated)
			v.Entries.Value[0].PlainValue = publicPresent([]byte{})
		}, contract.FieldSource, contract.ReasonInvalidFieldCombination},
		{"secret-payload", func(v *contract.PublicConfiguration) {
			v.Entries.Value[0].PlainValue = publicPresent([]byte("must-not-be-reported"))
		}, contract.FieldPlainValue, contract.ReasonInvalidFieldCombination},
		{"dormant-payload", func(v *contract.PublicConfiguration) {
			v.Entries.Value[0].Memberships = contract.PublicField[[]contract.ID]{Value: []contract.ID{v.Authority.RecipientID.Value}}
		}, contract.FieldMemberships, contract.ReasonInvalidFieldCombination},
		{"invalid-class", func(v *contract.PublicConfiguration) { v.Entries.Value[0].Class = publicPresent(uint8(90)) }, contract.FieldClass, contract.ReasonInvalidInput},
		{"disabled-recovery-fields", func(v *contract.PublicConfiguration) { v.Recovery.Signing = &v.Authority.Signing }, contract.FieldEnabled, contract.ReasonInvalidFieldCombination},
		{"selector-alias", func(v *contract.PublicConfiguration) { v.Authority.Signing.Selector = publicPresent("alias/current") }, contract.FieldSigningSelector, contract.ReasonInvalidInput},
		{"selector-latest", func(v *contract.PublicConfiguration) {
			v.Recipients.Value[0].Encryption.Selector = publicPresent("projects/fixture/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/latest")
		}, contract.FieldEncryptionSelector, contract.ReasonInvalidInput},
		{"invalid-utf8", func(v *contract.PublicConfiguration) { v.Entries.Value[0].Name = string([]byte{0xff}) }, contract.FieldPresence, contract.ReasonInvalidUTF8},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := publicConfigurationFixture(t)
			input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "entry")})
			test.change(&input)
			v := NewPublicConfigurationValidator(nil)
			got := v.Validate(context.Background(), input)
			if got.Valid || got.Complete {
				t.Fatal("malformed input accepted")
			}
			subject := contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "entry"}
			switch test.name {
			case "duplicate-recipient", "selector-latest":
				subject = contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Authority.RecipientID.Value}
			case "disabled-recovery-fields":
				subject = contract.DiagnosticSubject{Kind: contract.SubjectRecovery}
			case "selector-alias":
				subject = contract.DiagnosticSubject{Kind: contract.SubjectAuthority}
			case "invalid-utf8":
				subject = contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}
			}
			want := []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{test.field}, Outcome: contract.DiagnosticUnable, Reason: test.reason}}
			if test.name == "generated-plain" {
				want = append([]contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{contract.FieldGenerated, contract.FieldContentIntent}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonMissingRequiredField}}, want...)
			}
			if !reflect.DeepEqual(got.Diagnostics, want) {
				t.Fatalf("diagnostics=%+v want=%+v", got.Diagnostics, want)
			}

		})
	}
}

// full_only: false
func TestPublicConfigurationReportsIndependentUnavailableFields(t *testing.T) {
	outputCalls, generatorCalls := 0, 0
	v := publicFixtureValidator(t, &outputCalls, &generatorCalls)
	input := publicConfigurationFixture(t)
	input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "e")})
	target := publicFixtureTarget("e", "slot")
	target.TargetContractID = contract.PublicField[string]{State: contract.PublicUnavailable}
	input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", target)})
	location := &contract.SourceLocation{SourceID: "source-1", Line: 4, Column: 2}
	input.Recipients.Value[1].Encryption.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable, SourceLocation: location}
	publicFixtureInstallSources(v, input.OutputBindings.Value...)
	publicFixtureRouteTargets(&input)
	got := v.Validate(context.Background(), input)
	if !got.Valid || got.Complete || len(got.Diagnostics) != 2 || outputCalls != 0 || generatorCalls != 0 {
		t.Fatalf("validation=%+v", got.Diagnostics)
	}
	want := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, Name: "e", DestinationID: "d"}, Path: []contract.DiagnosticField{contract.FieldTargetContract}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable}, {Subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[1].RecipientID}, Path: []contract.DiagnosticField{contract.FieldEncryptionPublicKey}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable, SourceLocation: &contract.SourceLocation{SourceID: "source-1", Line: 4, Column: 2}}}
	if !reflect.DeepEqual(got.Diagnostics, want) {
		t.Fatalf("whole diagnostics=%+v want=%+v", got.Diagnostics, want)
	}
	location.Line = 99
	if got.Diagnostics[1].SourceLocation.Line != 4 {
		t.Fatal("diagnostic borrows source location")
	}
}

// full_only: false
func TestPublicConfigurationExactSmallBoundaries(t *testing.T) {
	v := NewPublicConfigurationValidator(nil)
	for _, name := range []string{"", strings.Repeat("n", contract.CryptoMaxName), "A", "a", "é", "e\u0301", "\x00\n"} {
		input := publicConfigurationFixture(t)
		input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, name)})
		if got := v.Validate(context.Background(), input); !got.Complete {
			t.Fatalf("exact name refused: %+v", got.Diagnostics)
		}
	}
	input := publicConfigurationFixture(t)
	entry := publicFixtureEntry(input, "e")
	entry.Class = publicPresent(contract.Plain)
	entry.PlainValue = publicPresent(make([]byte, contract.CryptoMaxRawValue))
	input.Entries = publicPresent([]contract.PublicEntry{entry})
	if got := v.Validate(context.Background(), input); !got.Complete {
		t.Fatal("exact raw limit refused", got.Diagnostics)
	}
	input.Entries.Value[0].PlainValue.Value = make([]byte, contract.CryptoMaxRetainedValue+1)
	got := v.Validate(context.Background(), input)
	if got.Valid || got.Complete || len(got.Diagnostics) != 1 || got.Diagnostics[0].Reason != contract.ReasonLimitExceeded {
		t.Fatal("raw one-over accepted", got.Diagnostics)
	}
	input = publicConfigurationFixture(t)
	input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, strings.Repeat("n", contract.CryptoMaxName+1))})
	if got := v.Validate(context.Background(), input); got.Valid || got.Complete {
		t.Fatal("name one-over accepted")
	}
}

// full_only: false
func TestPublicConfigurationChecksStaticFamilyAndRecoveryRelations(t *testing.T) {
	v := NewPublicConfigurationValidator(nil)
	input := publicConfigurationFixture(t)
	publicRecoveryFixture(t, &input)
	if got := v.Validate(context.Background(), input); !got.Complete {
		t.Fatal("complete independent Recovery refused", got.Diagnostics)
	}
	for _, name := range []string{"recipient-family", "signing-independence", "encryption-independence"} {
		t.Run(name, func(t *testing.T) {
			input := publicConfigurationFixture(t)
			publicRecoveryFixture(t, &input)
			subject := contract.DiagnosticSubject{Kind: contract.SubjectRecovery}
			field := contract.FieldSigningFingerprint
			switch name {
			case "recipient-family":
				input.Recipients.Value[1].Encryption.Provider = publicPresent(contract.AWS)
				input.Recipients.Value[1].Encryption.Selector = publicPresent("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")
				subject = contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[1].RecipientID}
				field = contract.FieldEncryptionProvider
			case "signing-independence":
				input.Recovery.Signing.PublicKey = input.Authority.Signing.PublicKey
				input.Recovery.Signing.Fingerprint = input.Authority.Signing.Fingerprint
			case "encryption-independence":
				input.Recovery.Encryption.Selector = input.Recipients.Value[0].Encryption.Selector
				field = contract.FieldEncryptionSelector
			}
			got := v.Validate(context.Background(), input)
			want := []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{field}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidFieldCombination}}
			if got.Valid || got.Complete || !reflect.DeepEqual(got.Diagnostics, want) {
				t.Fatalf("relations=%+v want=%+v", got.Diagnostics, want)
			}
		})
	}
	input = publicConfigurationFixture(t)
	input.Store.Provider = publicPresent(contract.AWS)
	input.Store.Region = publicPresent("us-east-1")
	input.Store.ExpectedOwner = publicPresent("123456789012")
	input.Authority.Signing.Provider = publicPresent(contract.AWS)
	input.Authority.Signing.Selector = publicPresent("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")
	for i := range input.Recipients.Value {
		input.Recipients.Value[i].Encryption.Provider = publicPresent(contract.AWS)
		input.Recipients.Value[i].Encryption.Selector = publicPresent("arn:aws:kms:us-east-1:123456789012:key/22345678-1234-1234-1234-123456789012")
	}
	if got := v.Validate(context.Background(), input); !got.Complete {
		t.Fatal("globally valid proposed family change refused", got.Diagnostics)
	}
}

// full_only: false
func TestPublicConfigurationCollectsJoinedOutputFields(t *testing.T) {
	input := publicConfigurationFixture(t)
	input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "e")})
	binding := publicFixtureBinding("d", publicFixtureTarget("e", "slot"))
	input.OutputBindings = publicPresent([]contract.PublicOutputBinding{binding})
	publicFixtureRouteTargets(&input)
	input.OutputBindings.Value[0].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
	v := NewPublicConfigurationValidator(func(context.Context, string, contract.OutputDestination, string, uint8) (contract.OutputTarget, error) {
		return contract.OutputTarget{}, errors.Join(PublicOutputError{Field: contract.FieldTargetData}, PublicOutputError{Field: contract.FieldConsumerPolicy})
	})
	got := v.Validate(context.Background(), input)
	subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, Name: "e", DestinationID: "d"}
	want := []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{contract.FieldConsumerPolicy}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput}, {Subject: subject, Path: []contract.DiagnosticField{contract.FieldTargetData}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput}}
	if got.Valid || got.Complete || !reflect.DeepEqual(got.Diagnostics, want) {
		t.Fatalf("joined output faults=%+v want=%+v", got.Diagnostics, want)
	}
	for _, field := range []contract.DiagnosticField{contract.FieldResourceContract, contract.FieldContentIntent} {
		t.Run("generated-"+string(field)+"-source-location", func(t *testing.T) {
			input := publicConfigurationFixture(t)
			entry := publicFixtureEntry(input, "e")
			entry.Source = publicPresent(contract.Generated)
			entry.Generated = publicFixtureGenerated(t, contract.GeneratorLifecycleManaged)
			location := &contract.SourceLocation{SourceID: "input", Line: 4, Column: 3}
			reason := contract.ReasonInvalidInput
			if field == contract.FieldResourceContract {
				entry.Generated.ResourceContractID = contract.PublicField[contract.ID]{State: contract.PublicPresent, SourceLocation: location}
				reason = contract.ReasonInvalidFieldCombination
			} else {
				entry.Generated.ContentIntent = contract.PublicField[[]byte]{State: contract.PublicPresent, Value: []byte{1}, SourceLocation: location}
			}
			input.Entries = publicPresent([]contract.PublicEntry{entry})
			got := NewPublicConfigurationValidator(nil).Validate(context.Background(), input)
			want := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "e"}, Path: []contract.DiagnosticField{contract.FieldGenerated, field}, Outcome: contract.DiagnosticUnable, Reason: reason, SourceLocation: location}}
			if got.Valid || got.Complete || !reflect.DeepEqual(got.Diagnostics, want) {
				t.Fatalf("source location=%+v want=%+v", got.Diagnostics, want)
			}
			location.Line = 99
			if got.Diagnostics[0].SourceLocation.Line != 4 {
				t.Fatal("diagnostic borrows source location")
			}
		})
	}
}

// full_only: false
func TestPublicConfigurationRefusesOversizedStoreFieldsIndependently(t *testing.T) {
	for _, field := range []contract.DiagnosticField{contract.FieldRegion, contract.FieldBucket, contract.FieldPrefix, contract.FieldExpectedOwner} {
		t.Run(string(field), func(t *testing.T) {
			input := publicConfigurationFixture(t)
			input.Store.Provider = publicPresent(contract.Family(99))
			huge := publicPresent(strings.Repeat("x", 1<<20))
			switch field {
			case contract.FieldRegion:
				input.Store.Region = huge
			case contract.FieldBucket:
				input.Store.Bucket = huge
			case contract.FieldPrefix:
				input.Store.Prefix = huge
			case contract.FieldExpectedOwner:
				input.Store.ExpectedOwner = huge
			}
			v := NewPublicConfigurationValidator(nil)
			got := v.Validate(context.Background(), input)
			wanted := false
			for _, d := range got.Diagnostics {
				if d.Subject.Kind == contract.SubjectStore && d.Path[0] == field && d.Reason == contract.ReasonLimitExceeded {
					wanted = true
				}
			}
			if got.Valid || got.Complete || !wanted {
				t.Fatal("oversized field hidden by invalid provider", got.Diagnostics)
			}
			for _, value := range []string{got.Configuration.Store.Region.Value, got.Configuration.Store.Bucket.Value, got.Configuration.Store.Prefix.Value, got.Configuration.Store.ExpectedOwner.Value} {
				if len(value) > 1024 {
					t.Fatal("refusal retains borrowed oversized Store field")
				}
			}
		})
	}
}

// full_only: false
func TestPublicConfigurationUnavailableEntriesDoNotMutateCallerRows(t *testing.T) {
	input := publicConfigurationFixture(t)
	entry := publicFixtureEntry(input, "e")
	input.Entries = contract.PublicField[[]contract.PublicEntry]{State: contract.PublicUnavailable, Value: []contract.PublicEntry{entry}}
	v := NewPublicConfigurationValidator(nil)
	got := v.Validate(context.Background(), input)
	if got.Valid || got.Complete || len(got.Configuration.Entries.Value) != 0 || !reflect.DeepEqual(input.Entries.Value, []contract.PublicEntry{entry}) {
		t.Fatal("dormant collection mutated or retained caller rows")
	}
}

// full_only: false
func TestPublicConfigurationChecksStoreGrammarWithUnavailableProvider(t *testing.T) {
	for _, test := range []struct {
		name            string
		field           contract.DiagnosticField
		value           string
		invalidProvider bool
	}{
		{"region-empty", contract.FieldRegion, "", false},
		{"region-malformed", contract.FieldRegion, "///", true},
		{"bucket-empty", contract.FieldBucket, "", false},
		{"bucket-malformed", contract.FieldBucket, "!", true},
		{"prefix-empty", contract.FieldPrefix, "", false},
		{"prefix-root", contract.FieldPrefix, "/", true},
		{"expected-owner-malformed", contract.FieldExpectedOwner, "abc", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := publicConfigurationFixture(t)
			input.Store.Provider = contract.PublicField[contract.Family]{State: contract.PublicUnavailable}
			providerReason := contract.ReasonPublicFactUnavailable
			if test.invalidProvider {
				input.Store.Provider = publicPresent(contract.Family(99))
				providerReason = contract.ReasonInvalidInput
			}
			switch test.field {
			case contract.FieldRegion:
				input.Store.Region = publicPresent(test.value)
			case contract.FieldBucket:
				input.Store.Bucket = publicPresent(test.value)
			case contract.FieldPrefix:
				input.Store.Prefix = publicPresent(test.value)
			case contract.FieldExpectedOwner:
				input.Store.ExpectedOwner = publicPresent(test.value)
			}
			v := NewPublicConfigurationValidator(nil)
			got := v.Validate(context.Background(), input)
			subject := contract.DiagnosticSubject{Kind: contract.SubjectStore}
			first := contract.Diagnostic{Subject: subject, Path: []contract.DiagnosticField{test.field}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput}
			second := contract.Diagnostic{Subject: subject, Path: []contract.DiagnosticField{contract.FieldProvider}, Outcome: contract.DiagnosticUnable, Reason: providerReason}
			want := []contract.Diagnostic{first, second}
			if test.field == contract.FieldRegion {
				want = []contract.Diagnostic{second, first}
			}
			if got.Valid || got.Complete || !reflect.DeepEqual(got.Diagnostics, want) {
				t.Fatalf("Store faults=%+v want=%+v", got.Diagnostics, want)
			}
		})
	}
	input := publicConfigurationFixture(t)
	input.Store.Provider = contract.PublicField[contract.Family]{State: contract.PublicUnavailable}
	input.Store.Region = publicPresent("us-east-1")
	v := NewPublicConfigurationValidator(nil)
	got := v.Validate(context.Background(), input)
	if !got.Valid || got.Complete || got.Configuration.Store.Region.Value != "us-east-1" || len(got.Diagnostics) != 1 {
		t.Fatal("one-family valid setting was erased", got.Diagnostics)
	}
}
