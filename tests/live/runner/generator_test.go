package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/custody"
)

func fixtureTokenID(id contract.ID) string { return string(id[:]) }

func liveGeneratedProcessFixture(t testing.TB, input liveRunInput, budget *runBudget) *generatedProcessFixture {
	t.Helper()
	g := input.Generator
	if g == nil || g.Account == "" || g.PermissionGroup == "" || input.GeneratorCleanupLedger == "" {
		t.Fatal("live generator inputs missing")
	}
	config, err := liveGeneratedInstallation(g.Artifact)
	row := config.Artifact
	if err != nil || g.CredentialsFile != "" || row.Validate() != nil || row.NativeTuple == "" || row.ArtifactLength > 512<<20 {
		t.Fatal("Cloudflare installed implementation unavailable", err)
	}
	artifact, err := os.Open(g.Artifact)
	if err != nil {
		t.Fatal("Cloudflare artifact unavailable")
	}
	hash := sha256.New()
	length, readErr := io.Copy(hash, io.LimitReader(artifact, int64(row.ArtifactLength)+1))
	closeErr := artifact.Close()
	if readErr != nil || closeErr != nil || length != int64(row.ArtifactLength) || hex.EncodeToString(hash.Sum(nil)) != hex.EncodeToString(row.ArtifactSHA256[:]) {
		t.Fatal("Cloudflare artifact differs from captured installation")
	}
	intent, _ := cloudflareIntent(g.Account, g.PermissionGroup, "enkv-test-"+input.RunID)
	canonical, err := contract.InspectGeneratorIntent(intent)
	if err != nil || canonical.LifecycleMode != contract.GeneratorLifecycleManaged || canonical.ConfigContractID != row.ConfigContractID {
		t.Fatal("Cloudflare canonical intent differs from installed implementation")
	}
	intentDigest, err := contract.GeneratorIntentDigest(intent)
	if err != nil {
		t.Fatal("Cloudflare canonical intent unavailable")
	}
	preimage := append([]byte("ENKV/GENERATOR-REQUEST/v1\x00"), byte(contract.GeneratorActionCreate))
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(intent)))
	preimage = append(preimage, intent...)
	requestDigest := sha256.Sum256(binary.BigEndian.AppendUint32(preimage, 0))
	expectations := make(map[contract.ID]contract.GeneratorResultExpectation)
	path := input.GeneratorCleanupLedger
	if _, err := records.ReadGeneratorFixtureLedger(path, input.RunID, g.Account); err != nil {
		t.Fatal("Cloudflare fixture ledger unavailable")
	}
	update := func(change func(*records.GeneratorFixtureLedger) error) error {
		return records.UpdateGeneratorFixtureLedger(path, input.RunID, g.Account, change)
	}
	return &generatedProcessFixture{
		Artifact: g.Artifact, Implementation: row, Intent: intent, RequestDigest: requestDigest,
		Configure: func(t testing.TB, artifact string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
			t.Helper()
			if artifact != g.Artifact || expected.Template.DescriptorID != row.DescriptorID || expected.Template.ConfigContractID != canonical.ConfigContractID ||
				expected.Template.ExecutorID != row.ExecutorID || expected.Template.CredentialRouteID != row.CredentialRouteID ||
				expected.Template.LifecycleMode != canonical.LifecycleMode || expected.Template.ResourceContractID != canonical.ResourceContractID || expected.Template.IntentDigest != intentDigest {
				t.Fatal("Cloudflare selected attempt differs from installed implementation")
			}
			expectations[expected.Template.AttemptID] = expected
			out := config
			out.Metadata, out.Dependency = slices.Clone(config.Metadata), slices.Clone(config.Dependency)
			return out
		},
		BeforeCreate: func(attempt contract.ID) error {
			if !budget.reserveGenerator(true) {
				return errRunLimit
			}
			return update(func(ledger *records.GeneratorFixtureLedger) error {
				return ledger.BeginCreate(fmt.Sprintf("%x", attempt))
			})
		},
		AfterCreate: func(attempt contract.ID, facts contract.GeneratorSafeFacts) error {
			expected, ok := expectations[attempt]
			if !ok || expected.Template.Action != contract.GeneratorActionCreate ||
				(facts.Disposition != contract.GeneratorDispositionCompleteCreate && facts.Disposition != contract.GeneratorDispositionOwnedUnusableCreate) ||
				facts.Action != contract.GeneratorActionCreate || !bytes.Equal(facts.Target, []byte(g.Account)) || !validCloudflareFixtureID(string(facts.ResourceData)) ||
				facts.IntentDigest != intentDigest || facts.ResourceContractID != canonical.ResourceContractID || facts.LifecycleMode != canonical.LifecycleMode ||
				facts.RequestDigest != requestDigest || facts.RequestDigest != expected.RequestDigest || !validLiveGeneratorFacts(facts) {
				return errInventory
			}
			return update(func(ledger *records.GeneratorFixtureLedger) error {
				return ledger.RecordCreate(fmt.Sprintf("%x", attempt), string(facts.ResourceData))
			})
		},
		BeforeDelete: func(attempt, target contract.ID) error {
			if !budget.reserveGenerator(false) {
				return errRunLimit
			}
			return update(func(ledger *records.GeneratorFixtureLedger) error {
				return ledger.BeginDelete(fmt.Sprintf("%x", attempt), fixtureTokenID(target))
			})
		},
		AfterDelete: func(attempt, target contract.ID, facts contract.GeneratorSafeFacts) error {
			expected, ok := expectations[attempt]
			if !ok || expected.Template.Action != contract.GeneratorActionDelete || facts.Action != contract.GeneratorActionDelete ||
				facts.Disposition != contract.GeneratorDispositionRetirementAcknowledged || !bytes.Equal(facts.ResourceData, target[:]) || !bytes.Equal(facts.Target, []byte(g.Account)) ||
				facts.IntentDigest != intentDigest || facts.ResourceContractID != canonical.ResourceContractID || facts.LifecycleMode != canonical.LifecycleMode ||
				generatedFactsResourceDigest(facts) != expected.TargetResourceDigest || facts.RequestDigest != expected.RequestDigest || !validLiveGeneratorFacts(facts) {
				return errInventory
			}
			return update(func(ledger *records.GeneratorFixtureLedger) error {
				return ledger.RecordDelete(fmt.Sprintf("%x", attempt), fixtureTokenID(target))
			})
		},
	}
}

func validLiveGeneratorFacts(facts contract.GeneratorSafeFacts) bool {
	_, err := contract.GeneratorSafeFactsLength(facts)
	return err == nil
}

var generatorFixtureExpectations string

func liveGeneratedInstallation(path string) (custody.GeneratedProcessConfig, error) {
	var want [2]string
	refused := errors.New("Cloudflare installation fixture refused")
	if len(generatorFixtureExpectations) == 0 || len(generatorFixtureExpectations) > 1024 || json.Unmarshal([]byte(generatorFixtureExpectations), &want) != nil || len(want[0]) != 64 || len(want[1]) != 64 {
		return custody.GeneratedProcessConfig{}, refused
	}
	executable, err := os.Executable()
	if err != nil {
		return custody.GeneratedProcessConfig{}, err
	}
	read := func(name, expected string) ([]byte, error) {
		file, err := os.Open(filepath.Join(filepath.Dir(executable), name))
		if err != nil {
			return nil, err
		}
		info, statErr := file.Stat()
		body, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		closeErr := file.Close()
		digest := sha256.Sum256(body)
		if statErr != nil || readErr != nil || closeErr != nil || !info.Mode().IsRegular() || len(body) == 0 || len(body) > 1<<20 || hex.EncodeToString(digest[:]) != expected {
			return nil, refused
		}
		return body, nil
	}
	body, err := read("cloudflare.installation.json", want[0])
	if err != nil {
		return custody.GeneratedProcessConfig{}, err
	}
	var envelope struct {
		Artifact contract.GeneratorImplementation `json:"artifact"`
		Metadata json.RawMessage                  `json:"metadata"`
	}
	if json.Unmarshal(body, &envelope) != nil || len(envelope.Metadata) == 0 {
		return custody.GeneratedProcessConfig{}, refused
	}
	dependency, err := read("cloudflare.dependency", want[1])
	if err != nil {
		return custody.GeneratedProcessConfig{}, err
	}
	return custody.GeneratedProcessConfig{ArtifactPath: path, Artifact: envelope.Artifact, Metadata: slices.Clone(envelope.Metadata), Dependency: dependency}, nil
}
