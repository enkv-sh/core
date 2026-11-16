package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

type publicConfigurationInput struct {
	Artifact publicProcessArtifact               `json:"artifact"`
	Stock    *records.StockPluginAcceptanceInput `json:"stock,omitempty"`
	Actors   map[string]liveSettings             `json:"actors"`
	Outputs  *records.PublicOutputScopes         `json:"outputs,omitempty"`
}
type publicProcessArtifact struct {
	records.PublicProcessArtifact
}
type publicProcessFacts struct {
	RunID, Prefix, Source string
	Domain                string
	ExpectReady           bool
	CapturePaths          []string
	Operator              *publicOperatorFacts        `json:",omitempty"`
	Replacement           *publicReplacementFacts     `json:",omitempty"`
	Inspection            *publicInspectionFacts      `json:",omitempty"`
	Materialization       *publicMaterializationFacts `json:",omitempty"`
	Manifest              *publicManifestFacts        `json:",omitempty"`
	CapacityGC            *publicCapacityGCFacts      `json:",omitempty"`
	Outputs               []publicOutputCoordinate    `json:",omitempty"`
}

func publicContext(s liveSettings) nativeprocess.StandardContext {
	return nativeprocess.StandardContext{Mode: s.SDKMode, Home: s.SDKHome, Profile: s.SDKProfile, CredentialsFile: s.SDKCredentialsFile, QuotaProject: s.SDKQuotaProject}
}
func livePublicConfigurationAdmitted(input liveRunInput) bool {
	if input.PublicConfiguration == nil || len(input.Scenarios) != 1 || input.RecoveryMode != input.Settings.RecoveryMode || input.Settings.CredentialsFile != "" || input.Settings.PublicKeyPEM != "" {
		return false
	}
	definition, ok := catalog.DefinitionFor(input.Scenarios[0])
	if !ok || !catalog.HasFixtureCapability(input.Scenarios[0], catalog.FixturePublicConfiguration) {
		return false
	}
	roles := definition.RolesForRecovery(input.RecoveryMode)
	if len(roles) == 0 || len(roles) != len(input.PublicConfiguration.Actors) {
		return false
	}
	row, _ := catalog.PublicConfiguration(input.Scenarios[0])
	if !input.PublicConfiguration.Outputs.ValidForScopes(row.OutputScopes(input.Settings.Provider)) {
		return false
	}
	stock := stockPluginCase(input)
	if stock {
		selected := input.PublicConfiguration.Stock
		if selected == nil || !reflect.DeepEqual(input.PublicConfiguration.Artifact, publicProcessArtifact{}) || selected.Fixture.Validate() != nil || selected.Artifact.Validate(input.Settings.Provider) != nil || selected.Fixture.Provider != input.Settings.Provider || selected.Fixture.Region != input.Settings.Region || selected.Fixture.Bucket != input.Settings.Bucket || selected.Fixture.Account != input.Settings.Account || selected.Fixture.Project != input.Settings.Project || selected.Fixture.ProjectNumber != input.Settings.ProjectNumber || input.Generator != nil || input.GeneratorCleanupLedger != "" || input.RecoveryMode != "enabled" || !validCloudflareFixtureID(selected.CloudflareAccount) || !validCloudflareFixtureID(selected.CloudflarePermissionGroup) {
			return false
		}
	} else if input.PublicConfiguration.Stock != nil {
		return false
	}
	generated := catalog.HasFixtureCapability(input.Scenarios[0], catalog.FixtureGeneratedProcess)
	if !generated && input.Generator != nil || input.Generator == nil && input.GeneratorCleanupLedger != "" {
		return false
	}
	if generated && input.Generator != nil && (input.Generator.CredentialsFile != "" || !validCloudflareFixtureID(input.Generator.Account) || !validCloudflareFixtureID(input.Generator.PermissionGroup) || input.GeneratorCleanupLedger == "" || input.PublicConfiguration.Artifact.GeneratorArtifact == "") {
		return false
	}
	for _, role := range roles {
		actor, ok := input.PublicConfiguration.Actors[role]
		if stock && (input.Settings.Provider == "aws" && actor.SDKMode != "aws-assume-role" || input.Settings.Provider == "gcp" && actor.SDKMode != "gcp-impersonated-adc") {
			return false
		}
		if row.UsesOperatorSDKContext() && (!publicContext(actor).OperatorDiscovery(input.Settings.Provider) || input.Participants[role] != input.Participants["authority"] || publicContext(actor) != publicContext(input.PublicConfiguration.Actors["authority"])) {
			return false
		}
		if (actor.SDKMode == "gcp-service-account-adc" || actor.SDKMode == "gcp-impersonated-adc") && (actor.SDKQuotaProject == "" || actor.SDKQuotaProject != actor.QuotaProject) {
			return false
		}
		if !ok || input.Participants[role] == "" || actor.Provider != input.Settings.Provider || actor.Region != input.Settings.Region || actor.Bucket != input.Settings.Bucket || actor.Account != input.Settings.Account || actor.Project != input.Settings.Project || actor.ProjectNumber != input.Settings.ProjectNumber || actor.QuotaProject != input.Settings.QuotaProject || actor.NormalSuccessorKeyID != input.Settings.NormalSuccessorKeyID || actor.AuthoritySuccessor1KEKID != input.Settings.AuthoritySuccessor1KEKID || actor.RecoverySuccessorKeyID != input.Settings.RecoverySuccessorKeyID || actor.RecoverySuccessor1KEKID != input.Settings.RecoverySuccessor1KEKID || actor.ReaderSuccessorKEKID != input.Settings.ReaderSuccessorKEKID || actor.KeyID != input.Settings.KeyID || actor.AuthorityKEKID != input.Settings.AuthorityKEKID || actor.ReaderKEKID != input.Settings.ReaderKEKID || actor.RecoveryMode != input.RecoveryMode || actor.RecoveryKeyID != input.Settings.RecoveryKeyID || actor.RecoveryKEKID != input.Settings.RecoveryKEKID || actor.CredentialsFile != "" || actor.PublicKeyPEM != "" || publicContext(actor).Validate(input.Settings.Provider) != nil || row.Condition == "standard-discovery" && !publicContext(actor).StandardDiscovery(input.Settings.Provider) {
			return false
		}
	}
	execution, known := catalog.ExecutionFor(input.Scenarios[0], "live")
	if !known || execution.Family != catalog.FamilyAuthorityOperator && execution.Family != catalog.FamilyPublicConfiguration ||
		(row.Condition == "portable-validation" || execution.Family == catalog.FamilyAuthorityOperator && input.Scenarios[0] == publicOperatorReplacementScenario) && input.RecoveryMode == "enabled" && input.Settings.NormalSuccessorKeyID == "" {
		return false
	}
	if row.Replacement != nil && !publicReplacementAdmitted(input, *row.Replacement) {
		return false
	}
	return true
}
func publicInvocationOwner(inv records.Invocation) (string, string, bool) {
	if inv.ValidateEvidence() != nil {
		return "", "", false
	}
	owner, _, runID, err := records.PrivateOwner(inv.StateDir)
	return owner, runID, err == nil
}

func publicProcessAdmitted(inv records.Invocation, input liveRunInput) bool {
	if input.OutputRecovery != nil {
		if !publicOutputRecoveryIdentity(inv, input) || !livePublicConfigurationAdmitted(input) {
			return false
		}
		original := inv
		original.StateDir = input.OutputRecovery.OriginalState
		return publicArtifactValid(original, input.PublicConfiguration.Artifact)
	}
	_, original, valid := publicInvocationOwner(inv)
	return valid && original == input.RunID && livePublicConfigurationAdmitted(input) && publicArtifactValid(inv, input.PublicConfiguration.Artifact)
}

func publicOutputRecoveryIdentity(inv records.Invocation, input liveRunInput) bool {
	r := input.OutputRecovery
	if r == nil || input.PublicConfiguration == nil || r.Validate() != nil || inv.ValidateEvidence() != nil || inv.Role != "cleanup" || inv.RunID != r.RecoveryRunID ||
		input.RunID != r.OriginalRunID || inv.StateDir != r.StateDir || inv.Scenario != r.OriginalEntry.Scenario ||
		input.Prefix != r.Prefix || input.Settings.Provider != r.Provider || input.RecoveryMode != r.RecoveryMode ||
		input.CleanupRetry != nil || input.CleanupGrant != nil || input.StockRecovery != nil || input.Generator != nil {
		return false
	}
	if inv.StateDir != filepath.Join(filepath.Dir(inv.OutputDir), "state") || r.Region != input.Settings.Region || r.Account != input.Settings.Account ||
		r.ProjectNumber != input.Settings.ProjectNumber || !reflect.DeepEqual(r.Outputs, input.PublicConfiguration.Outputs) {
		return false
	}
	_, runs, owner, err := records.PrivateOwner(inv.StateDir)
	_, originalRuns, originalOwner, originalErr := records.PrivateOwner(r.OriginalState)
	if err != nil || originalErr != nil || runs != originalRuns || owner != inv.RunID || originalOwner != input.RunID || r.VerifyFiles() != nil {
		return false
	}
	body, err := json.Marshal(input.Limits)
	if err != nil || bodyDigest(body) != r.LimitsSHA256 {
		return false
	}
	var original liveRunInput
	if readPrivateJSON(filepath.Join(r.OriginalState, "input.json"), &original) != nil || original.OutputRecovery != nil {
		return false
	}
	if !r.MutationAllowance(original.Limits.Objects, original.Limits.ObjectBytes) || r.Binding != settingsBinding(input.Settings) {
		return false
	}
	original.Limits, original.OutputRecovery = input.Limits, r
	return reflect.DeepEqual(original, input)
}

func publicArtifactValid(inv records.Invocation, a publicProcessArtifact) bool {
	owner, _, valid := publicInvocationOwner(inv)
	if !valid {
		return false
	}
	build := filepath.Join(owner, "build")
	if !a.PublicProcessArtifact.ValidatePlugins(context.Background(), build) {
		return false
	}
	if a.GeneratorArtifact != "" {
		if a.GeneratorArtifact != filepath.Join(build, "enkv-generator-cloudflare") || len(a.GeneratorSHA256) != 64 || a.GeneratorLength <= 0 || len(a.GeneratorManifest) != 64 {
			return false
		}
		info, err := os.Lstat(a.GeneratorArtifact)
		if err != nil || !info.Mode().IsRegular() || info.Size() != a.GeneratorLength || info.Size() > 512<<20 || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}

	} else if a.GeneratorSHA256 != "" || a.GeneratorLength != 0 || a.GeneratorManifest != "" {
		return false
	}
	items := []struct {
		path, want, sha string
		executable      bool
	}{{a.CLI, filepath.Join(build, "enkv-public"), a.CLISHA256, true}, {a.Consumer, filepath.Join(build, "enkv-public-reconstruct"), a.ConsumerSHA256, true}, {a.Overlay.Path, filepath.Join(build, "public-configuration-overlay", "overlay.json"), a.Overlay.SHA256, false}, {a.Overlay.Manifest, filepath.Join(build, "public-configuration-overlay", "sources.json"), a.Overlay.ManifestSHA256, false}}
	if a.GeneratorArtifact != "" {
		items = append(items, struct {
			path, want, sha string
			executable      bool
		}{a.GeneratorArtifact, filepath.Join(build, "enkv-generator-cloudflare"), a.GeneratorSHA256, true})
	}
	for _, item := range items {
		if item.path != item.want || len(item.sha) != 64 {
			return false
		}
		info, err := os.Lstat(item.path)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 512<<20 || item.executable && info.Mode().Perm()&0111 == 0 {
			return false
		}
		file, err := os.Open(item.path)
		if err != nil {
			return false
		}
		opened, statErr := file.Stat()
		sum := sha256.New()
		count, copyErr := io.Copy(sum, io.LimitReader(file, info.Size()+1))
		closeErr := file.Close()
		if statErr != nil || !records.SameLocalFile(info, opened) || copyErr != nil || closeErr != nil || count != info.Size() || hex.EncodeToString(sum.Sum(nil)) != item.sha {
			return false
		}
	}
	return true
}

type publicChildResult struct {
	Code            int
	DiagnosticBytes int
	Body            []byte
	Capture         nativeprocess.Capture
	CapturePath     string
}

func publicCommandMutationAllowance(consumer bool, args []string) (uint64, uint64) {
	mutating := false
	if !consumer && len(args) > 0 {
		mutating = args[0] == "init" || args[0] == "apply" || args[0] == "publish" || args[0] == "rekey" ||
			len(args) > 1 && args[0] == "generated" && args[1] != "list" ||
			len(args) > 1 && (args[0] == "abandon" && args[1] == "apply" || args[0] == "keys" && args[1] == "replace" || args[0] == "recipients" && args[1] == "retire")
	}
	if consumer {
		for _, arg := range args {
			if arg == "--successor-signing-selector" || strings.HasPrefix(arg, "--successor-signing-selector=") {
				mutating = true
			}
		}
	}
	if mutating {
		return 16, 8 << 20
	}
	return 0, 0
}

// The two public lifecycle fixtures have independent HTTP and Store-write bounds.
// Stock plugin scenarios have their own command and service reservations.
func publicGeneratedRequestLimit(input liveRunInput) uint64 {
	if len(input.Scenarios) != 1 {
		return 0
	}
	switch input.Scenarios[0] {
	case "public-configuration.generated-manual-lifecycle/generated_manual_lifecycle":
		return 512
	case "public-configuration.generated-auto-rotation/generated_auto_rotation":
		return 1024
	}
	return 0
}

func publicGeneratedCommandPolicy(input liveRunInput, consumer bool, policy nativeprocess.Policy, args []string) nativeprocess.Policy {
	limit := publicGeneratedRequestLimit(input)
	if limit == 0 || consumer {
		return policy
	}
	if policy.MaxRequests == 0 {
		policy.MaxRequests = limit
	}
	if policy.MaxBytes == 0 {
		policy.MaxBytes = 64 << 20
	}
	writes, writeBytes := publicCommandMutationAllowance(false, args)
	if writes == 0 {
		policy.StoreReadOnly, policy.NoKMS = true, true
		return policy
	}
	if len(args) > 0 && args[0] != "init" {
		writes, writeBytes = 256, 32<<20
	}
	writes, writeBytes = min(writes, policy.MaxRequests), min(writeBytes, policy.MaxBytes)
	if policy.MaxStoreWrites == 0 && policy.MaxStoreWriteBytes == 0 {
		policy.MaxStoreWrites, policy.MaxStoreWriteBytes = writes, writeBytes
	} else {
		policy.MaxStoreWrites, policy.MaxStoreWriteBytes = min(policy.MaxStoreWrites, writes), min(policy.MaxStoreWriteBytes, writeBytes)
	}
	return policy
}

func publicCommandReservation(input liveRunInput, consumer bool, policy nativeprocess.Policy, args []string) budgetReservation {
	policy = publicGeneratedCommandPolicy(input, consumer, policy, args)
	objects, objectBytes := publicCommandMutationAllowance(consumer, args)
	publication := !consumer && rowOutputCommand(input, args)
	if policy.MaxRequests == 0 {
		policy.MaxRequests = 128
		if publication {
			policy.MaxRequests = 2048
		}
	}
	if policy.MaxBytes == 0 {
		policy.MaxBytes = 16 << 20
		if publication {
			policy.MaxBytes = 64 << 20
		}
	}
	row, _ := catalog.PublicConfiguration(input.Scenarios[0])
	if objects != 0 && publicGeneratedRequestLimit(input) != 0 && !consumer {
		objects, objectBytes = policy.MaxStoreWrites, policy.MaxStoreWriteBytes
	} else if objects != 0 && len(input.Scenarios) == 1 && (catalog.HasFixtureCapability(input.Scenarios[0], catalog.FixtureGeneratedProcess) || row.Output) {
		// Each physical SDK write consumes at least one request and its body.
		// Generated graphs have more checkpoints than ordinary supplied apply.
		objects, objectBytes = policy.MaxRequests, policy.MaxBytes
	}
	return budgetReservation{Requests: policy.MaxRequests, BodyBytes: policy.MaxBytes, Objects: objects, ObjectBytes: objectBytes}
}

// One original child invocation is joined. Failure never restarts an init or
// apply command. The caller owns the exact source and verifies it after return.
func publicCLI(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, role string, consumer bool, policy nativeprocess.Policy, stdin []byte, args ...string) publicChildResult {
	t.Helper()
	return publicCLIReserved(t, ctx, inv, input, budget, role, consumer, policy,
		publicCommandReservation(input, consumer, policy, args), stdin, args...)
}

func publicCLIReserved(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, role string, consumer bool, policy nativeprocess.Policy, reservation budgetReservation, stdin []byte, args ...string) publicChildResult {
	t.Helper()
	if !publicProcessAdmitted(inv, input) {
		t.Fatal("public process admission refused")
	}
	actor, ok := input.PublicConfiguration.Actors[role]
	if !ok {
		t.Fatal("public process exact role unavailable")
	}
	if input.Generator != nil && input.GeneratorCleanupLedger != filepath.Join(inv.StateDir, "generator-cleanup.json") {
		t.Fatal("public generator ledger owner differs")
	}
	effects := reservation.GeneratorCreates + reservation.GeneratorRetires
	if effects > 11 || reservation.GeneratorCreates > 3 || reservation.GeneratorRetires > 8 || reservation.Requests <= effects || reservation.BodyBytes <= effects*operationBodyAllowance {
		t.Fatal("public generator reservation refused")
	}
	policy.MaxRequests, policy.MaxBytes = reservation.Requests-effects, reservation.BodyBytes-effects*operationBodyAllowance
	policy = publicGeneratedCommandPolicy(input, consumer, policy, args)
	if publicGeneratedRequestLimit(input) != 0 && !consumer {
		writes, _ := publicCommandMutationAllowance(false, args)
		if writes != 0 && (reservation.Objects != policy.MaxStoreWrites || reservation.ObjectBytes != policy.MaxStoreWriteBytes) || writes == 0 && (reservation.Objects != 0 || reservation.ObjectBytes != 0) {
			t.Fatal("public generated Store reservation differs from executable policy")
		}
	}
	if input.Generator != nil {
		policy.GeneratorLedgerPath, policy.GeneratorRunID, policy.GeneratorAccount = input.GeneratorCleanupLedger, input.RunID, input.Generator.Account
		policy.GeneratorCreates, policy.GeneratorRetires = reservation.GeneratorCreates, reservation.GeneratorRetires
	} else if effects != 0 {
		t.Fatal("public generator capability unavailable")
	}
	if !budget.absorbChild(reservation) {
		t.Fatal("public process finite reservation refused")
	}
	if !consumer && rowOutputCommand(input, args) && !budget.absorbChild(budgetReservation{Requests: 128, BodyBytes: 16 << 20, Objects: 8, ObjectBytes: 1 << 20}) {
		t.Fatal("public output service finite reservation refused")
	}
	directory, err := os.MkdirTemp(inv.StateDir, "public-command-")
	if err != nil {
		t.Fatal("public command directory unavailable")
	}
	record := filepath.Join(directory, "capture.jsonl")
	if err := os.WriteFile(record, nil, 0600); err != nil {
		t.Fatal("public capture owner unavailable")
	}
	policy.Version, policy.RecordPath, policy.Bucket, policy.Prefix = 1, record, input.Settings.Bucket, input.Prefix
	policy.RequireStandardSource = true
	policy.ExpectedSourceKind = actor.SDKMode
	policy.NormalSigner, policy.AuthorityKEK, policy.RecoverySigner = input.Settings.KeyID, input.Settings.AuthorityKEKID, input.Settings.RecoveryKeyID
	if policy.RecoveryKEK == "" {
		policy.RecoveryKEK = input.Settings.RecoveryKEKID
	}
	if policy.SuccessorSigner == "" {
		policy.SuccessorSigner = input.Settings.NormalSuccessorKeyID
	}
	policy.QuotaProject = input.Settings.QuotaProject
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal("public capture policy unavailable")
	}
	path := filepath.Join(directory, "policy.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal("public policy owner unavailable")
	}
	environment, err := publicContext(actor).Environment(input.Settings.Provider, os.Environ(), filepath.Join(directory, "absent-static-credentials"))
	if err != nil {
		t.Fatal("public context isolation refused")
	}
	environment = publicGeneratorEnvironment(environment, effects != 0)
	environment = publicOutputEnvironment(environment, !consumer && rowOutputCommand(input, args), publicOutputScopes(input))
	if effects != 0 && !validPublicGeneratorBearer(os.Getenv("CLOUDFLARE_API_TOKEN")) {
		t.Fatal("public Cloudflare environment credential unavailable")
	}
	environment = append(environment, "ENKV_NATIVE_PROCESS_POLICY="+path)
	environment, releasePlugins := publicPluginEnvironment(t, inv, input, role, environment, args)
	defer releasePlugins()
	selected := input.PublicConfiguration.Artifact.CLI
	if consumer {
		selected = input.PublicConfiguration.Artifact.Consumer
	}
	childContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(childContext, selected, args...)
	cmd.Dir = directory
	cmd.Env = environment
	cmd.WaitDelay = 10 * time.Second
	cmd.Stdin = bytes.NewReader(stdin)
	var out, diagnostic operatorCLIOutput
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	nativeKind := "cli"
	if consumer {
		nativeKind = "consumer"
	}
	registration := publicCaptureReceipt{Path: record, ParentWorker: inv.Worker, ParentNonce: inv.Nonce, ParentRole: inv.Role, Actor: input.Participants[role], NativeKind: nativeKind}
	var recoveryCommand *records.PublicOutputRecoveryCommand
	if input.OutputRecovery != nil {
		r := input.OutputRecovery
		var proof records.PublicOutputRecoveryProof
		if consumer || records.ReadJSON(filepath.Join(inv.StateDir, "public-output-recovery.json"), &proof) != nil || !proof.BeforeStore(*r) || proof.Stages[len(proof.Stages)-1].Outcome != "entered" {
			t.Fatal("output recovery command has no durable entered stage")
		}
		stage := proof.Stages[len(proof.Stages)-1].Name
		command := records.PublicOutputRecoveryCommand{Version: 1, InputSHA256: proof.InputSHA256, StageSHA256: records.PublicOutputRecoveryStageBinding(proof.InputSHA256, stage), Stage: stage, Role: role, Args: append([]string(nil), args...), Reservation: records.BudgetReservation{Requests: reservation.Requests, BodyBytes: reservation.BodyBytes, Objects: reservation.Objects, ObjectBytes: reservation.ObjectBytes, GeneratorCreates: reservation.GeneratorCreates, GeneratorRetires: reservation.GeneratorRetires}}
		if stage == "prepare-pair" {
			if _, err := os.Lstat(filepath.Join(inv.StateDir, "public-source/configuration.json")); !os.IsNotExist(err) {
				t.Fatal("recovery prepare would replace an existing source")
			}
		} else {
			pair := publicOutputRecoveryPairImage(t, *r)
			var prepared records.PublicOutputRecoveryPreparedPair
			if records.ReadJSON(filepath.Join(inv.StateDir, "public-output-recovery-prepared-pair.json"), &prepared) != nil || prepared.InputSHA256 != proof.InputSHA256 || prepared.Pair.Validate(*r) != nil || !pair.OutputsRemovedFrom(prepared.Pair) {
				t.Fatal("recovery command changed the prepared pair beyond output retirement")
			}
			command.Pair = &pair
		}
		if command.Validate(*r, proof) != nil || records.WriteJSON(filepath.Join(directory, "command.json"), command, 0400) != nil {
			t.Fatal("output recovery command input unavailable")
		}
		recoveryCommand = &command
	}
	if publicCaptureReceiptUpdate(inv, registration, false) != nil {
		t.Fatal("public original child intent unavailable")
	}
	err = cmd.Run()
	body, overflow := out.result()
	errorBody, errorOverflow := diagnostic.result()
	diagnosticBytes := len(errorBody)
	clear(errorBody)
	if overflow || errorOverflow {
		clear(body)
		t.Fatal("public child output exceeded finite intake")
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || childContext.Err() != nil {
			clear(body)
			t.Fatal("public child did not join normal return")
		}
		code = exit.ExitCode()
	}
	capture, captureErr := nativeprocess.ReadCapture(record)
	if captureErr != nil || len(capture.Events) == 0 || capture.Events[len(capture.Events)-1].Code != code {
		clear(body)
		t.Fatal("public child native observation incomplete")
	}
	registration.ExitCode = code
	if publicCaptureReceiptUpdate(inv, registration, true) != nil {
		clear(body)
		t.Fatal("public joined child evidence unavailable")
	}
	if recoveryCommand != nil && recoveryCommand.Pair != nil && !reflect.DeepEqual(*recoveryCommand.Pair, publicOutputRecoveryPairImage(t, *input.OutputRecovery)) {
		clear(body)
		t.Fatal("recovery child changed its exact consumed source or dependency image")
	}
	used, matched := false, false
	wantKind := actor.SDKMode
	for _, event := range capture.Events {
		if event.Kind == "generator-refused" || event.Kind == "generator-return" && !event.GeneratorQualified {
			clear(body)
			t.Fatal("public producer result ledger unavailable; native ledger evidence is incomplete")
		}
		if event.Kind == "http-start" && event.Sent {
			used = true
		}
		if event.Kind == "source-kind" {
			if event.SourceKind != wantKind || !event.Matched || event.Count != 1 {
				clear(body)
				t.Fatal("public child selected another credential source kind")
			}
			matched = true
		}
		if input.Settings.Provider == "gcp" && event.Kind == "http-return" && event.Sent && event.Status != 0 && !event.QuotaMatched {
			clear(body)
			t.Fatal("public child quota project differs from selected ADC metadata")
		}
	}
	if used && !matched {
		clear(body)
		t.Fatal("public child standard credential source witness unavailable")
	}
	if input.RecoveryMode == "disabled" {
		publicAssertNoRecovery(t, capture)
	}
	return publicChildResult{Code: code, DiagnosticBytes: diagnosticBytes, Body: body, Capture: capture, CapturePath: record}
}

// No read-only, no-op, initialization or risk command inherits the generator
// bearer. Only a child with a reserved producer allowance receives this route.
func publicGeneratorEnvironment(environment []string, effects bool) []string {
	out := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, "CLOUDFLARE_API_TOKEN=") {
			out = append(out, entry)
		}
	}
	if effects {
		out = append(out, "CLOUDFLARE_API_TOKEN="+os.Getenv("CLOUDFLARE_API_TOKEN"))
	}
	return out
}
func validPublicGeneratorBearer(value string) bool {
	return validCloudflareFixtureBearer([]byte(value))
}

// full_only: false
func TestPublicConfigurationAdmissionUsesSelectedOutputScopes(t *testing.T) {
	valid := &records.PublicOutputScopes{
		Repository:   records.PublicOutputScope{Owner: "owner", Repository: "repository"},
		Organization: records.PublicOutputScope{Owner: "organization", Visibility: "selected", Repositories: []uint64{101, 202}},
		Environment:  records.PublicOutputScope{Owner: "owner", Repository: "repository", Environment: "prod"},
	}
	for _, provider := range []string{"aws", "gcp"} {
		for _, cell := range []struct {
			name                          string
			scenario                      string
			nilAccepted, suppliedAccepted bool
		}{
			{"cloud-only", "public-configuration.manifest/atomic_public_file", true, true},
			{"github", "public-configuration.output-standalone/output_standalone", false, true},
			{"no-output", "public-configuration.empty-initialization/empty_initialization", true, false},
		} {
			for _, supplied := range []string{"absent", "valid", "malformed"} {
				t.Run(provider+"/"+cell.name+"/"+supplied, func(t *testing.T) {
					settings := liveSettings{Provider: provider, RecoveryMode: "disabled", SDKMode: "aws-assume-role", SDKHome: "/isolated/functional", SDKProfile: "selected"}
					if provider == "gcp" {
						settings.SDKMode, settings.SDKProfile = "gcp-impersonated-adc", ""
						settings.SDKQuotaProject, settings.QuotaProject = "selected-project", "selected-project"
					}
					definition, known := catalog.DefinitionFor(cell.scenario)
					if !known {
						t.Fatal("selected public case unavailable")
					}
					input := liveRunInput{Settings: settings, RecoveryMode: "disabled", Scenarios: []string{cell.scenario}, Participants: map[string]string{}, PublicConfiguration: &publicConfigurationInput{Actors: map[string]liveSettings{}}}
					for _, role := range definition.RolesForRecovery("disabled") {
						input.Participants[role], input.PublicConfiguration.Actors[role] = role, settings
					}
					want := cell.nilAccepted
					switch supplied {
					case "valid":
						input.PublicConfiguration.Outputs, want = valid, cell.suppliedAccepted
					case "malformed":
						input.PublicConfiguration.Outputs, want = &records.PublicOutputScopes{}, false
					}
					if livePublicConfigurationAdmitted(input) != want {
						t.Fatal("public admission changed the selected destination credential requirements")
					}
				})
			}
		}
	}
}
