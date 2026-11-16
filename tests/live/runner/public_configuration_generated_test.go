package core

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

type publicGeneratedResult struct {
	Schema    string
	State     string `json:"state_result"`
	Operation string `json:"operation_id"`
	Effects   []struct {
		Facts struct {
			Attempt string `json:"attempt_id"`
		}
	}
	Duties []struct {
		Facts struct {
			Duty string `json:"duty_id"`
		}
		Target struct {
			publicGeneratedTarget
			OriginalOperation string `json:"original_operation_id"`
			OriginalAttempt   string `json:"original_attempt_id"`
		}
	}
	Current []struct {
		publicGeneratedTarget
		Generation      string `json:"generation_id"`
		OriginOperation string `json:"origin_operation_id"`
		OriginAttempt   string `json:"origin_attempt_id"`
	} `json:"current_generations"`
}

func publicGeneratedOutcome(t testing.TB, result publicChildResult, state string, code int) publicGeneratedResult {
	t.Helper()
	defer clear(result.Body)
	var out publicGeneratedResult
	if json.Unmarshal(result.Body, &out) != nil || out.Schema != "ProductResult/v1" || out.State != state || result.Code != code {
		t.Fatalf("public generated result differs: expected %s/%d, got %s/%d", state, code, out.State, result.Code)
	}
	return out
}

type publicGeneratedTarget struct {
	Name        string `json:"name"`
	Incarnation string `json:"entry_incarnation_id"`
	Resource    string `json:"resource_incarnation_id"`
	Digest      string `json:"resource_digest"`
	Config      string `json:"config_contract_id"`
	Contract    string `json:"resource_contract_id"`
	Lifecycle   string `json:"lifecycle_mode"`
	Epoch       uint64 `json:"epoch"`
}

func (target publicGeneratedTarget) valid() bool {
	return target.Name == "generated" && publicIdentityHex(target.Incarnation) && publicIdentityHex(target.Resource) && publicIdentityHex(target.Digest) && publicIdentityHex(target.Config) && publicIdentityHex(target.Contract) && target.Lifecycle == "managed"
}

func publicGeneratedSameResource(target, current publicGeneratedTarget) bool {
	return target.valid() && target == current
}

func publicGeneratedDeclaration(t testing.TB, source, account, permission, name, policy string, epoch uint64, present bool) {
	t.Helper()
	document := publicSourceDocument(t, source)
	entries := map[string]any{}
	if present {
		entries["generated"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "cloudflare-account-token", "epoch": epoch, "retirement": policy, "settings": map[string]any{"account": account, "name": name, "policies": []any{map[string]any{"effect": "allow", "permission_groups": []string{permission}, "resources": []any{map[string]string{"kind": "account", "id": account}}}}}}}
	}
	document["entries"] = entries
	publicWriteSource(t, source, document)
}

// All effects use installed public commands and the environment credential
// producer. Ownership comes only from the pre/post custody observer ledger.
func runPublicGeneratedLifecycle(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, row catalog.PublicConfigurationCase, source string) {
	t.Helper()
	if input.Generator == nil || !row.Generated {
		t.Fatal("public generator capability unavailable")
	}
	g := input.Generator
	policy := "manual"
	if row.Condition == "generated-auto-rotation" {
		policy = "auto"
	}
	declare := func(account string, epoch uint64, present bool) {
		publicGeneratedDeclaration(t, source, account, g.PermissionGroup, "enkv-test-"+input.RunID, policy, epoch, present)
	}
	invoke := func(creates, retires uint64, action string, selectors ...string) publicChildResult {
		image := publicSourceImage(t, source)
		reservation := publicCommandReservation(input, false, nativeprocess.Policy{}, strings.Fields(action))
		effects := creates + retires
		reservation.Requests += effects
		reservation.BodyBytes += effects * operationBodyAllowance
		reservation.GeneratorCreates, reservation.GeneratorRetires = creates, retires
		args := append(strings.Fields(action), "--source", source, "--source-format", "json", "--json")
		args = append(args, selectors...)
		result := publicCLIReserved(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, reservation, nil, args...)
		publicImageUnchanged(t, image)
		return result
	}
	list := func() publicGeneratedResult {
		result := publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, nil, "generated", "list", "--source", source, "--source-format", "json", "--json")
		for _, e := range result.Capture.Events {
			if e.Kind == "generator-entry" {
				t.Fatal("read-only generated list entered producer")
			}
		}
		return publicGeneratedOutcome(t, result, "success", 0)
	}
	declare(g.Account, 0, true)
	// Planning cannot demand a bearer and has no producer allowance.
	image := publicSourceImage(t, source)
	plan := publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, nil, "plan", "--trusted", source, "--trusted-format", "json", "--json")
	if plan.Code != 1 {
		clear(plan.Body)
		t.Fatal("unapplied generated declaration did not produce a read-only mismatch")
	}
	clear(plan.Body)
	publicImageUnchanged(t, image)
	// A lineage has five reserved templates. Only original, conditional retry,
	// and successor can enter create; the other templates are dormant branches.
	publicGeneratedOutcome(t, invoke(3, 0, "apply"), "success", 0)
	first := list()
	config := sha256.Sum256([]byte("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/CONFIG/v1\x00https://api.cloudflare.com/client/v4"))
	resource := sha256.Sum256([]byte("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/RESOURCE/v1\x00https://api.cloudflare.com/client/v4"))
	if len(first.Current) != 1 || first.Current[0].Config != fmt.Sprintf("%x", config) || first.Current[0].Contract != fmt.Sprintf("%x", resource) || first.Current[0].Epoch != 0 || !publicIdentityHex(first.Current[0].Generation) || !publicIdentityHex(first.Current[0].OriginOperation) || !publicIdentityHex(first.Current[0].OriginAttempt) || !first.Current[0].valid() {
		t.Fatal("public generated initial current differs")
	}
	publicGeneratedOutcome(t, invoke(0, 0, "apply"), "no-op", 0)
	declare(g.Account, 1, true)
	state, code, retires := "retirement-pending", 3, uint64(0)
	if policy == "auto" {
		state, code, retires = "success", 0, 8
	}
	publicGeneratedOutcome(t, invoke(3, retires, "apply"), state, code)
	rotated := list()
	if len(rotated.Current) != 1 || rotated.Current[0].Epoch != 1 || !publicIdentityHex(rotated.Current[0].Generation) || !publicIdentityHex(rotated.Current[0].OriginOperation) || !publicIdentityHex(rotated.Current[0].OriginAttempt) || rotated.Current[0].Generation == first.Current[0].Generation || rotated.Current[0].Resource == first.Current[0].Resource || rotated.Current[0].Digest == first.Current[0].Digest || !rotated.Current[0].valid() {
		t.Fatal("public generated successor was not selected")
	}
	if policy == "manual" {
		if len(rotated.Duties) != 1 || !publicGeneratedSameResource(rotated.Duties[0].Target.publicGeneratedTarget, first.Current[0].publicGeneratedTarget) || rotated.Duties[0].Target.OriginalOperation != first.Current[0].OriginOperation || rotated.Duties[0].Target.OriginalAttempt != first.Current[0].OriginAttempt {
			t.Fatal("public manual retirement lost exact old target")
		}
		// An unrelated current proposal cannot rebind an authenticated old duty.
		other := strings.Repeat("f", 32)
		if other == g.Account {
			other = strings.Repeat("e", 32)
		}
		declare(other, 2, true)
		publicGeneratedOutcome(t, invoke(0, 8, "generated retire", "--duty", rotated.Duties[0].Facts.Duty), "success", 0)
	} else if len(rotated.Duties) != 0 {
		t.Fatal("public automatic retirement left old duty")
	}
	observed := list()
	if len(observed.Duties) != 0 || len(observed.Current) != 1 || observed.Current[0].Generation != rotated.Current[0].Generation {
		t.Fatal("public retirement changed selected successor")
	}
	declare(g.Account, 1, false)
	publicGeneratedOutcome(t, invoke(0, 0, "apply", "--retire-generator", "generated=cloudflare-account-token"), "retirement-pending", 3)
	removed := list()
	if len(removed.Current) != 0 || len(removed.Duties) != 1 || !publicGeneratedSameResource(removed.Duties[0].Target.publicGeneratedTarget, rotated.Current[0].publicGeneratedTarget) || removed.Duties[0].Target.OriginalOperation != rotated.Current[0].OriginOperation || removed.Duties[0].Target.OriginalAttempt != rotated.Current[0].OriginAttempt {
		t.Fatal("public removal lost exact retained retirement")
	}
	publicGeneratedOutcome(t, invoke(0, 8, "generated retire", "--duty", removed.Duties[0].Facts.Duty), "success", 0)
	publicGeneratedOutcome(t, invoke(0, 0, "generated cleanup"), "no-op", 0)
	final := list()
	if len(final.Current) != 0 || len(final.Duties) != 0 {
		t.Fatal("public generated terminal current or work remains")
	}
	ledger, err := records.ReadGeneratorFixtureLedger(input.GeneratorCleanupLedger, input.RunID, g.Account)
	if err != nil || !ledger.Clean() {
		t.Fatal("public generated qualified producer ledger remains unsettled")
	}
}

// full_only: false
func TestPublicGeneratedEnvironmentRouteIsEffectBoundAndExact(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", strings.Repeat("a", 40))
	inherited := []string{"PATH=/bin", "CLOUDFLARE_API_TOKEN=wrong"}
	readonly := publicGeneratorEnvironment(inherited, false)
	if len(readonly) != 1 || readonly[0] != "PATH=/bin" {
		t.Fatal("read-only child inherited producer bearer")
	}
	effect := publicGeneratorEnvironment(inherited, true)
	if len(effect) != 2 || effect[1] != "CLOUDFLARE_API_TOKEN="+strings.Repeat("a", 40) {
		t.Fatal("effect child did not use exact environment route")
	}
	if !validPublicGeneratorBearer(strings.Repeat("a", 40)) || validPublicGeneratorBearer(strings.Repeat("a", 40)+"\n") || validPublicGeneratorBearer(" "+strings.Repeat("a", 40)) {
		t.Fatal("public environment bearer was normalized or misqualified")
	}
}

type publicGeneratedCleanupStop struct{}
type publicGeneratedCleanupTB struct {
	testing.TB
	stopped bool
	message string
}

func (t *publicGeneratedCleanupTB) Fatal(args ...any) {
	t.stopped = true
	t.message = fmt.Sprint(args...)
	panic(publicGeneratedCleanupStop{})
}
func (t *publicGeneratedCleanupTB) Failed() bool { return t.stopped || t.TB.Failed() }

// full_only: false
func TestPublicGeneratedCleanupBlocksBeforePrefixContext(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runID, account := strings.Repeat("a", 32), strings.Repeat("b", 32)
	state := filepath.Join(root, "tests", "live", "runs", runID, "private", "0000-public-generated")
	output := filepath.Join(state, "workers", "cleanup")
	if os.MkdirAll(output, 0700) != nil {
		t.Fatal("private cleanup fixture unavailable")
	}
	inputPath := filepath.Join(state, "input.json")
	if records.WriteJSON(inputPath, struct{}{}, 0400) != nil {
		t.Fatal("private invocation fixture unavailable")
	}
	scenario := "public-configuration.generated-manual-lifecycle/generated_manual_lifecycle"
	inv := records.Invocation{SchemaVersion: records.SchemaVersion, RunID: runID, Worker: "public-generated-cleanup", Nonce: strings.Repeat("c", 32), Role: "cleanup", Scenario: scenario, Input: inputPath, StateDir: state, OutputDir: output}
	if inv.Validate() != nil {
		t.Fatal("cleanup fixture invocation refused")
	}
	input := liveRunInput{RunID: runID, Scenarios: []string{scenario}, Prefix: "enkv-test/" + runID + "/order", Participants: map[string]string{"cleanup": "cleanup"}, Settings: liveSettings{Provider: liveProvider()}, Generator: &liveGeneratorSettings{Account: account}, GeneratorCleanupLedger: filepath.Join(state, "generator-cleanup.json"), PublicConfiguration: &publicConfigurationInput{}, Limits: liveLimits{Requests: 32, BodyBytes: 32 << 20, GeneratorCreates: 6, GeneratorRetires: 22, CleanupRequests: 32, CleanupBytes: 32 << 20, CleanupSeconds: 10}}
	ownership := publicOwnership{Version: 1, RunID: runID, Prefix: input.Prefix, Binding: settingsBinding(input.Settings), Source: filepath.Join(state, "public-source", "configuration.json"), PreflightEmpty: true}
	if records.WriteJSON(publicLedgerPath(inv), ownership, 0600) != nil || records.NewGeneratorFixtureLedger(input.GeneratorCleanupLedger, runID, account) != nil || records.WriteGeneratorFixtureJoined(filepath.Join(state, "generator-writer-joined.json"), runID, scenario) != nil {
		t.Fatal("cleanup ownership fixture unavailable")
	}
	if err := records.UpdateGeneratorFixtureLedger(input.GeneratorCleanupLedger, runID, account, func(l *records.GeneratorFixtureLedger) error { return l.BeginCreate(strings.Repeat("d", 64)) }); err != nil {
		t.Fatal(err)
	}
	// The prefix context is deliberately absent. The generator gate must refuse
	// before the code can construct that context, list or delete any prefix key.
	stopped := &publicGeneratedCleanupTB{TB: t}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				if _, expected := recovered.(publicGeneratedCleanupStop); !expected {
					panic(recovered)
				}
			}
		}()
		runPublicConfigurationCleanup(stopped, inv, input, nil)
	}()
	if !stopped.stopped || stopped.message != "public generator cleanup unresolved; domain prefix retained" {
		t.Fatal("prefix context preceded generator settlement", stopped.message)
	}
	if _, err := os.Stat(filepath.Join(state, "public-cleanup-inventory.json")); !os.IsNotExist(err) {
		t.Fatal("blocked generator cleanup acquired prefix inventory authority", err)
	}
	ledger, err := records.ReadGeneratorFixtureLedger(input.GeneratorCleanupLedger, runID, account)
	if err != nil || len(ledger.PendingCreates) != 1 || ledger.Clean() {
		t.Fatal("blocked prefix cleanup lost entered create intent", err)
	}
}

// full_only: false
func TestPublicGeneratedCommandBudgetsSeparateReadsAndWrites(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		requests uint64
	}{
		{"public-configuration.generated-manual-lifecycle/generated_manual_lifecycle", 512},
		{"public-configuration.generated-auto-rotation/generated_auto_rotation", 1024},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			input := liveRunInput{Scenarios: []string{scenario.name}}
			for _, command := range []struct {
				args          []string
				writes, bytes uint64
			}{
				{[]string{"init"}, 16, 8 << 20},
				{[]string{"apply"}, 256, 32 << 20},
				{[]string{"generated", "retire"}, 256, 32 << 20},
				{[]string{"generated", "cleanup"}, 256, 32 << 20},
				{[]string{"generated", "list"}, 0, 0},
				{[]string{"plan", "--trusted", "source"}, 0, 0},
			} {
				got := publicCommandReservation(input, false, nativeprocess.Policy{}, command.args)
				want := budgetReservation{Requests: scenario.requests, BodyBytes: 64 << 20, Objects: command.writes, ObjectBytes: command.bytes}
				if got != want {
					t.Fatalf("generated command budget differs for %v: got %+v want %+v", command.args, got, want)
				}
				limited := publicCommandReservation(input, false, nativeprocess.Policy{MaxRequests: 1, MaxBytes: 1}, command.args)
				if limited.Requests != 1 || limited.BodyBytes != 1 || limited.Objects != min(command.writes, 1) || limited.ObjectBytes != min(command.bytes, 1) {
					t.Fatal("negative policy widened", limited)
				}
			}
		})
	}
}

// full_only: false
func TestPublicGeneratedCommandPolicyGuardsExactLifecycleOnly(t *testing.T) {
	for _, scenario := range []string{
		"public-configuration.generated-manual-lifecycle/generated_manual_lifecycle",
		"public-configuration.generated-auto-rotation/generated_auto_rotation",
	} {
		input := liveRunInput{Scenarios: []string{scenario}}
		for _, args := range [][]string{{"plan", "--trusted", "writer"}, {"plan", "--trusted", "fresh"}, {"generated", "list"}} {
			policy := publicGeneratedCommandPolicy(input, false, nativeprocess.Policy{}, args)
			if !policy.StoreReadOnly || !policy.NoKMS || policy.MaxStoreWrites != 0 || policy.MaxStoreWriteBytes != 0 {
				t.Fatal("generated reader acquired mutation or KMS allowance")
			}
		}
		for _, args := range [][]string{{"init"}, {"apply"}, {"generated", "retire"}, {"generated", "cleanup"}} {
			policy := publicGeneratedCommandPolicy(input, false, nativeprocess.Policy{}, args)
			reservation := publicCommandReservation(input, false, policy, args)
			if policy.MaxStoreWrites == 0 || policy.MaxStoreWrites != reservation.Objects || policy.MaxStoreWriteBytes != reservation.ObjectBytes || policy.StoreReadOnly {
				t.Fatal("write guards differ from reservations")
			}
			narrow := nativeprocess.Policy{MaxRequests: 32, MaxBytes: 1024, MaxStoreWrites: 3, MaxStoreWriteBytes: 17}
			if got := publicGeneratedCommandPolicy(input, false, narrow, args); got.MaxRequests != narrow.MaxRequests || got.MaxBytes != narrow.MaxBytes || got.MaxStoreWrites != narrow.MaxStoreWrites || got.MaxStoreWriteBytes != narrow.MaxStoreWriteBytes {
				t.Fatal("explicit guard widened")
			}
		}
	}
	for _, scenario := range []string{"public-configuration.plugin-contracts/plugin_contracts", "public-configuration.inspection-receipts/inspection_receipts"} {
		input := liveRunInput{Scenarios: []string{scenario}}
		policy := nativeprocess.Policy{MaxRequests: 3, MaxBytes: 5}
		if got := publicGeneratedCommandPolicy(input, false, policy, []string{"apply"}); got.MaxRequests != policy.MaxRequests || got.MaxBytes != policy.MaxBytes || got.MaxStoreWrites != 0 || got.MaxStoreWriteBytes != 0 || got.StoreReadOnly || got.NoKMS {
			t.Fatal("unrelated scenario changed")
		}
	}
}
