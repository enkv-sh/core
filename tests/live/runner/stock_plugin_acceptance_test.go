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
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
)

const stockMaximumCommands = records.MaximumStockPluginCommands
const stockMaximumVerifications = records.MaximumStockPluginVerifications

type stockPluginRun struct {
	t            testing.TB
	inv          records.Invocation
	input        liveRunInput
	budget       *runBudget
	evidence     records.StockPluginEvidence
	homes        map[string]string
	saveRecovery func() error
}

func (r *stockPluginRun) retainCommandIntent() error {
	if err := records.WriteStockPluginEvidence(stockEvidencePath(r.evidenceInvocation()), r.evidence); err != nil {
		return err
	}
	if r.saveRecovery != nil {
		return r.saveRecovery()
	}
	return nil
}

func stockPluginCase(input liveRunInput) bool {
	return len(input.Scenarios) == 1 && input.Scenarios[0] == records.StockPluginScenario
}

func stockEvidencePath(inv records.Invocation) string {
	return filepath.Join(inv.StateDir, "stock-plugin-evidence.json")
}
func stockGrantPath(inv records.Invocation) string {
	return filepath.Join(inv.StateDir, "stock-plugin-grant.json")
}

func (r *stockPluginRun) save() {
	r.t.Helper()
	if records.WriteStockPluginEvidence(stockEvidencePath(r.evidenceInvocation()), r.evidence) != nil {
		r.t.Fatal("stock plugin evidence could not be retained")
	}
}

func (r *stockPluginRun) evidenceInvocation() records.Invocation {
	inv := r.inv
	if r.input.StockRecovery != nil {
		inv.StateDir = inv.OutputDir
	}
	return inv
}
func (r *stockPluginRun) assert(name string) {
	if slices.Contains(r.evidence.Assertions, name) {
		r.t.Fatal("stock assertion was repeated")
	}
	r.evidence.Assertions = append(r.evidence.Assertions, name)
	r.save()
}

func stockFileMatches(file records.StockPluginFile) bool {
	return stockFileIdentityMatches(file, artifact.MaxExecutableBytes, true)
}

func stockFileIdentityMatches(file records.StockPluginFile, maximum uint64, executable bool) bool {
	info, err := os.Lstat(file.Path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || uint64(info.Size()) != file.Length || executable && info.Mode().Perm()&0111 == 0 || file.Length > maximum {
		return false
	}
	opened, err := os.Open(file.Path)
	if err != nil {
		return false
	}
	stat, statErr := opened.Stat()
	sum := sha256.New()
	n, readErr := io.Copy(sum, io.LimitReader(opened, int64(file.Length)+1))
	closeErr := opened.Close()
	return statErr == nil && records.SameLocalFile(info, stat) && readErr == nil && closeErr == nil && uint64(n) == file.Length && hex.EncodeToString(sum.Sum(nil)) == file.SHA256
}

func stockConfigDirectory(home string) string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support")
	}
	return filepath.Join(home, ".config")
}

func stockCreateSDKHome(root, role string, actor liveSettings) (string, error) {
	home := filepath.Join(root, role)
	if err := os.MkdirAll(home, 0700); err != nil {
		return "", errInventory
	}
	link := func(source, target string) error {
		if _, err := os.Lstat(source); err != nil {
			return errInventory
		}
		if info, err := os.Lstat(target); err == nil {
			if info.Mode()&os.ModeSymlink == 0 {
				return errInventory
			}
			got, err := os.Readlink(target)
			if err != nil || got != source {
				return errInventory
			}
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return errInventory
		}
		return os.Symlink(source, target)
	}
	if actor.Provider == "aws" {
		if err := os.MkdirAll(filepath.Join(home, ".aws"), 0700); err != nil {
			return "", errInventory
		}
		for _, name := range []string{"config", "credentials", "sso"} {
			source := filepath.Join(actor.SDKHome, ".aws", name)
			_, err := os.Lstat(source)
			required := name == "config" && actor.SDKMode != "aws-shared-credentials" || name == "credentials" && actor.SDKMode == "aws-shared-credentials" || name == "sso" && actor.SDKMode == "aws-sso"
			if errors.Is(err, os.ErrNotExist) && !required {
				continue
			}
			if err != nil || link(source, filepath.Join(home, ".aws", name)) != nil {
				return "", errInventory
			}
		}
	} else {
		if err := os.MkdirAll(filepath.Join(home, ".config"), 0700); err != nil {
			return "", errInventory
		}
		if actor.SDKMode != "gcp-service-account-adc" && link(filepath.Join(actor.SDKHome, ".config", "gcloud"), filepath.Join(home, ".config", "gcloud")) != nil {
			return "", errInventory
		}
	}
	return home, nil
}

func (r *stockPluginRun) home(role string) string {
	if home := r.homes[role]; home != "" {
		return home
	}
	actor, ok := r.input.PublicConfiguration.Actors[role]
	if !ok || validateStockSDKContext(r.input, role) != nil {
		r.t.Fatal("stock standard credential context refused")
	}
	home, err := stockCreateSDKHome(filepath.Join(r.evidenceInvocation().StateDir, "stock-homes", r.inv.Worker), role, actor)
	if err != nil {
		r.t.Fatal("stock test-owned SDK home unavailable")
	}
	r.homes[role] = home
	return home
}

func (r *stockPluginRun) selectPlugins(source string, b bool) {
	r.t.Helper()
	a := r.input.PublicConfiguration.Stock.Artifact
	g := a.GeneratorA
	if b {
		g = a.GeneratorB
	}
	plugins := []artifact.LocalPlugin{{Name: g.Metadata.Name, Directory: g.Directory}, {Name: a.Renderer.Metadata.Name, Directory: a.Renderer.Directory}}
	for _, output := range a.Outputs {
		plugins = append(plugins, artifact.LocalPlugin{Name: output.Metadata.Name, Directory: output.Directory})
	}
	slices.SortFunc(plugins, func(a, b artifact.LocalPlugin) int { return strings.Compare(a.Name, b.Name) })
	application, err := filepath.EvalSymlinks(filepath.Dir(source))
	if err != nil {
		r.t.Fatal("stock application scope unavailable")
	}
	body, err := artifact.EncodeSettings(artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{{Directory: application, Plugins: plugins}}})
	if err != nil {
		r.t.Fatal("stock local trust settings refused")
	}
	for _, role := range []string{"authority", "apply", "reader", "consumer"} {
		directory := filepath.Join(stockConfigDirectory(r.home(role)), "enkv")
		if os.MkdirAll(directory, 0700) != nil || os.WriteFile(filepath.Join(directory, "plugins.json"), body, 0600) != nil {
			r.t.Fatal("stock test-owned local trust selection failed")
		}
	}
}

func stockReplaceEnvironment(environment []string, key, value string) []string {
	out := make([]string, 0, len(environment)+1)
	for _, item := range environment {
		if !strings.HasPrefix(item, key+"=") {
			out = append(out, item)
		}
	}
	return append(out, key+"="+value)
}

func (r *stockPluginRun) diagnosticAdmission(role, phase string) bool {
	if r.input.PublicConfiguration == nil || r.input.Settings.Provider == "aws" && r.input.PublicConfiguration.Outputs == nil || !records.ValidRunID(r.input.RunID) || !stockDiagnosticLabel(r.inv.Worker) || !stockDiagnosticHex(r.inv.Nonce, 16) || !stockDiagnosticLabel(role) || !stockDiagnosticLabel(r.input.Participants[role]) || !stockDiagnosticLabel(phase) || len(r.evidence.Commands) >= stockMaximumCommands {
		return false
	}
	_, _, ownerID, err := records.PrivateOwner(r.inv.StateDir)
	if err != nil || ownerID != r.input.RunID {
		return false
	}
	evidenceInv := r.evidenceInvocation()
	if recovery := r.input.StockRecovery; recovery != nil {
		_, _, recoveryID, err := records.PrivateOwner(evidenceInv.StateDir)
		if err != nil || recoveryID != r.inv.RunID || recovery.Validate(r.input.RunID, r.inv.RunID) != nil ||
			uint32(len(r.evidence.Commands)) < recovery.OriginalCommands || recovery.PriorCommands+uint32(len(r.evidence.Commands))-recovery.OriginalCommands >= stockMaximumCommands {
			return false
		}
	}
	info, err := os.Lstat(evidenceInv.StateDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return false
	}
	path := stockDiagnosticPath(evidenceInv, uint32(len(r.evidence.Commands)))
	if safe, err := records.SafePath(evidenceInv.StateDir, filepath.Base(path)); err != nil || safe != path {
		return false
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return false
	}
	_, fits := records.StockPluginEvidenceReservationBytes(r.evidence, publicExpectedOutputCoordinates(r.input))
	return fits
}

func (r *stockPluginRun) command(ctx context.Context, phase, role, credential string, stdin []byte, args ...string) publicChildResult {
	r.t.Helper()
	if r.input.StockRecovery != nil && !stockRecoveryCommandAllowed(r.input, phase, role, credential, stdin, args) {
		r.t.Fatal("stock failed-writer recovery command refused")
	}
	if !r.diagnosticAdmission(role, phase) {
		r.t.Fatal("stock command diagnostic admission refused")
	}
	stock := r.input.PublicConfiguration.Stock
	if !livePublicConfigurationAdmitted(r.input) || stock == nil || !stockFileMatches(stock.Artifact.CLI) || len(r.evidence.Commands) >= stockMaximumCommands {
		r.t.Fatal("stock command admission refused")
	}
	actorLabel := r.input.Participants[role]
	reservation, reserved := stockCommandReservation(r.input, phase, args, uint64(len(r.evidence.Retirements)))
	if !reserved {
		r.t.Fatal("stock command reservation shape refused")
	}
	if !r.budget.absorbChild(reservation) {
		r.t.Fatal("stock command finite reservation exhausted")
	}
	directory, err := os.MkdirTemp(r.evidenceInvocation().StateDir, "stock-command-")
	if err != nil {
		r.t.Fatal("stock command owner unavailable")
	}
	actor := r.input.PublicConfiguration.Actors[role]
	actor.SDKHome = r.home(role)
	environment, err := publicContext(actor).Environment(r.input.Settings.Provider, os.Environ(), filepath.Join(directory, "absent-credentials"))
	if err != nil {
		r.t.Fatal("stock standard child environment refused")
	}
	if actor.Provider == "aws" {
		environment = stockReplaceEnvironment(environment, "AWS_SHARED_CREDENTIALS_FILE", filepath.Join(directory, "absent-credentials"))
	}
	for _, key := range []string{"CLOUDFLARE_API_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"} {
		environment = stockReplaceEnvironment(environment, key, "")
	}
	for _, build := range []records.StockPluginBuild{stock.Artifact.GeneratorA, stock.Artifact.GeneratorB} {
		facts, factErr := build.Metadata.GeneratorFacts()
		if factErr != nil {
			r.t.Fatal("stock generator descriptor refused")
		}
		route, routeErr := credentialroute.Decode(facts.Descriptor.Generator.CredentialRoute)
		if routeErr != nil || len(route.Names) != 1 {
			r.t.Fatal("stock generator credential recipe refused")
		}
		environment = stockReplaceEnvironment(environment, route.Names[0], "")
	}
	if credential != "" {
		build := stock.Artifact.GeneratorA
		if credential == "b" {
			build = stock.Artifact.GeneratorB
		} else if credential != "a" {
			r.t.Fatal("stock credential selection refused")
		}
		facts, _ := build.Metadata.GeneratorFacts()
		route, _ := credentialroute.Decode(facts.Descriptor.Generator.CredentialRoute)
		token := os.Getenv("CLOUDFLARE_API_TOKEN")
		if !validPublicGeneratorBearer(token) {
			r.t.Fatal("stock Cloudflare environment bearer unavailable")
		}
		environment = stockReplaceEnvironment(environment, route.Names[0], token)
	}
	if (phase == "publish" || phase == "output-delete") && r.input.Settings.Provider == "aws" {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			r.t.Fatal("stock GitHub environment bearer unavailable")
		}
		environment = stockReplaceEnvironment(environment, "GITHUB_TOKEN", token)
	}
	entry := records.StockPluginCommand{Ordinal: uint32(len(r.evidence.Commands)), Worker: r.inv.Worker, Nonce: r.inv.Nonce, Role: role, Actor: actorLabel, Phase: phase, ExitCode: -1}
	r.evidence.Commands = append(r.evidence.Commands, entry)
	if err := r.retainCommandIntent(); err != nil {
		r.t.Fatal("stock command intent or reservation could not be retained")
	}
	childContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(childContext, stock.Artifact.CLI.Path, args...)
	cmd.Dir = directory
	cmd.Env = environment
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.WaitDelay = 10 * time.Second
	var stdout, stderr operatorCLIOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if r.input.StockRecovery != nil && (!stockRecoveryInputsUnchanged(r.inv, r.input) || r.input.StockRecovery.PreAdmission != nil && !stockRecoverySupportUnchanged(childContext, r.input)) {
		r.t.Fatal("stock recovery admission or retained support changed before command start")
	}
	startErr := cmd.Start()
	at := len(r.evidence.Commands) - 1
	if startErr != nil {
		if r.recordStartFailure(!stockFileMatches(stock.Artifact.CLI)) != nil {
			r.t.Fatal("stock child start failure evidence could not be retained")
		}
		r.t.Fatal("stock child could not start")
	}
	r.evidence.Commands[at].Started = true
	// Once a child starts, a failure to record that fact must not bypass Wait.
	// Cancel it on a failed write, then retain whatever completion facts remain
	// available before reporting the failure to the caller.
	startSaveErr := records.WriteStockPluginEvidence(stockEvidencePath(r.evidenceInvocation()), r.evidence)
	return r.completeCommand(childContext, cancel, cmd, &stdout, &stderr, startSaveErr)
}

func (r *stockPluginRun) recordStartFailure(cliChanged bool) error {
	at := len(r.evidence.Commands) - 1
	entry := r.evidence.Commands[at]
	value := stockDiagnostic{RunID: r.input.RunID, Ordinal: entry.Ordinal, Worker: entry.Worker, Nonce: entry.Nonce, Phase: entry.Phase, CLISHA256: r.input.PublicConfiguration.Stock.Artifact.CLI.SHA256, CLIChanged: cliChanged}
	digest, length, status, diagnosticErr := retainStockDiagnostic(r.evidenceInvocation(), value, nil)
	r.evidence.Commands[at].DiagnosticSHA256, r.evidence.Commands[at].DiagnosticBytes, r.evidence.Commands[at].DiagnosticStatus = digest, length, status
	indexErr := records.WriteStockPluginEvidence(stockEvidencePath(r.evidenceInvocation()), r.evidence)
	return errors.Join(diagnosticErr, indexErr)
}

func (r *stockPluginRun) completeCommand(childContext context.Context, cancel context.CancelFunc, cmd *exec.Cmd, stdout, stderr *operatorCLIOutput, startSaveErr error) publicChildResult {
	r.t.Helper()
	at := len(r.evidence.Commands) - 1
	stock := r.input.PublicConfiguration.Stock
	waitErr := stockWaitAfterStart(cmd, startSaveErr, cancel)
	body, overflow := stdout.result()
	diagnostic, diagnosticOverflow := stderr.result()
	diagnosticBytes := len(diagnostic)
	clear(diagnostic)
	code, joined := stockChildExit(waitErr, childContext.Err(), cmd.ProcessState != nil)
	r.evidence.Commands[at].Joined = joined
	r.evidence.Commands[at].ExitCode = code
	r.evidence.Commands[at].ResultSHA256 = bodyDigest(body)
	cliChanged := !stockFileMatches(stock.Artifact.CLI)
	entry := r.evidence.Commands[at]
	value := stockDiagnostic{RunID: r.input.RunID, Ordinal: entry.Ordinal, Worker: entry.Worker, Nonce: entry.Nonce, Phase: entry.Phase, CLISHA256: stock.Artifact.CLI.SHA256, StdoutOverflow: overflow, StderrOverflow: diagnosticOverflow, StderrCapturedBytes: uint32(diagnosticBytes), Started: true, WaitReturned: true, WaitHasProcessState: cmd.ProcessState != nil, ProductJoined: joined, TimedOut: errors.Is(childContext.Err(), context.DeadlineExceeded), StartSaveFailed: startSaveErr != nil, CLIChanged: cliChanged}
	digest, length, status, diagnosticErr := retainStockDiagnostic(r.evidenceInvocation(), value, body)
	r.evidence.Commands[at].DiagnosticSHA256, r.evidence.Commands[at].DiagnosticBytes, r.evidence.Commands[at].DiagnosticStatus = digest, length, status
	completionSaveErr := records.WriteStockPluginEvidence(stockEvidencePath(r.evidenceInvocation()), r.evidence)
	if startSaveErr != nil || diagnosticErr != nil || completionSaveErr != nil {
		clear(body)
		if startSaveErr != nil {
			r.t.Fatal("stock child start could not be retained")
		}
		if diagnosticErr != nil {
			r.t.Fatal("stock child diagnostic could not be retained")
		}
		r.t.Fatal("stock plugin evidence could not be retained")
	}
	if !joined || overflow || diagnosticOverflow || cliChanged || status != "observed" {
		clear(body)
		r.t.Fatal("stock child did not return a bounded joined result")
	}
	return publicChildResult{Code: code, DiagnosticBytes: diagnosticBytes, Body: body}
}

func stockWaitAfterStart(cmd *exec.Cmd, startSaveErr error, cancel context.CancelFunc) error {
	if startSaveErr != nil {
		cancel()
	}
	return cmd.Wait()
}

func stockChildExit(waitErr, contextErr error, waited bool) (int, bool) {
	if !waited || contextErr != nil {
		return -1, false
	}
	if waitErr == nil {
		return 0, true
	}
	var exit *exec.ExitError
	if !errors.As(waitErr, &exit) || exit.ExitCode() < 0 {
		return -1, false
	}
	return exit.ExitCode(), true
}

func (r *stockPluginRun) generated(ctx context.Context, phase, credential, source, state string, args ...string) stockGeneratedResult {
	image := publicSourceImage(r.t, source)
	args = append(args, "--source", source, "--source-format", "json", "--json")
	child := r.command(ctx, phase, "apply", credential, nil, args...)
	defer clear(child.Body)
	result, err := stockGeneratedDecode(child.Body, child.Code, state)
	wantOperation := "apply-declaration"
	if len(args) > 1 && args[0] == "generated" && args[1] == "retire" {
		wantOperation = "retire-generated-generation"
	}
	if err != nil || result.Operation != wantOperation {
		r.t.Fatal("stock generated Product result differs")
	}
	publicImageUnchanged(r.t, image)
	return result
}

func (r *stockPluginRun) list(ctx context.Context, source string) stockGeneratedResult {
	image := publicSourceImage(r.t, source)
	child := r.command(ctx, "generated-list", "reader", "", nil, "generated", "list", "--source", source, "--source-format", "json", "--json")
	defer clear(child.Body)
	result, err := stockGeneratedDecode(child.Body, child.Code, "success")
	if err != nil || result.Operation != "generated-list" {
		r.t.Fatal("stock generated current observation differs")
	}
	publicImageUnchanged(r.t, image)
	return result
}

func (r *stockPluginRun) verify(ctx context.Context) {
	if r.evidence.ServiceVerifications >= stockMaximumVerifications || !r.budget.reserve(1, stockVerificationBytes, "", 0) {
		r.t.Fatal("stock independent verification allowance exhausted")
	}
	r.evidence.ServiceVerifications++
	r.save()
}

func stockDeclareGenerated(t testing.TB, source string, stock records.StockPluginAcceptanceInput, prefix, expires string, epoch uint64, present bool) {
	document := publicSourceDocument(t, source)
	entries, ok := document["entries"].(map[string]any)
	if !ok {
		t.Fatal("stock entry declaration unavailable")
	}
	delete(entries, "generated")
	if present {
		entries["generated"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "cloudflare-account-token", "epoch": epoch, "retirement": "manual", "settings": map[string]any{"account": stock.CloudflareAccount, "name": "enkv-test-" + prefix, "expires_on": expires, "policies": []any{map[string]any{"effect": "allow", "permission_groups": []string{stock.CloudflarePermissionGroup}, "resources": []any{map[string]string{"kind": "account", "id": stock.CloudflareAccount}}}}}}}
	}
	publicWriteSource(t, source, document)
}

func runStockPluginAcceptance(t testing.TB, inv records.Invocation, input liveRunInput, failure *records.FailureRecorder) {
	worker, err := records.NewWorker(inv, liveProvider(), input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("stock writer owner unavailable")
	}
	worker.Result.Actor = input.Participants["authority"]
	budget := &runBudget{limits: input.Limits, keys: map[string]bool{}}
	defer finishLiveWorker(t, worker, budget)
	lease, err := lockInventory(inv.StateDir)
	if err != nil {
		t.Fatal("stock private owner unavailable")
	}
	defer lease.Close()
	ctx, cancel := context.WithTimeout(worker.Context(context.Background()), time.Duration(input.Limits.ElapsedSeconds)*time.Second)
	defer cancel()
	execution, known := catalog.ExecutionForRecovery(input.Scenarios[0], "live", input.RecoveryMode)
	if !known || len(execution.Writer) != 3 || !livePublicConfigurationAdmitted(input) {
		t.Fatal("stock live contract refused")
	}
	if input.PublicConfiguration.Stock.Fixture.ValidateNewStockRun() != nil {
		t.Fatal("stock AWS retirement requires an admitted historical Reader before effects")
	}
	begin := func(index int) uint64 {
		sequence, err := worker.BeginStep(execution.Writer[index].Step, input.Participants[execution.Writer[index].Step.Role])
		if err != nil {
			t.Fatal("stock step unavailable")
		}
		return sequence
	}
	r := &stockPluginRun{t: t, inv: inv, input: input, budget: budget, homes: map[string]string{}, evidence: records.StockPluginEvidence{Schema: 1, RunID: input.RunID, Scenario: input.Scenarios[0], Provider: input.Settings.Provider, Prefix: input.Prefix, FixtureID: input.PublicConfiguration.Stock.Fixture.FixtureID, CLISHA256: input.PublicConfiguration.Stock.Artifact.CLI.SHA256}}
	sequence := begin(0)
	for _, role := range []string{"authority", "apply", "reader", "consumer", "cleanup"} {
		if validateStockSDKContext(input, role) != nil {
			t.Fatal("stock configured credential route refused")
		}
	}
	stock := input.PublicConfiguration.Stock
	if !stockFileMatches(stock.Artifact.CLI) {
		t.Fatal("stock CLI changed before fixture admission")
	}
	for _, build := range append([]records.StockPluginBuild{stock.Artifact.GeneratorA, stock.Artifact.GeneratorB, stock.Artifact.Renderer}, stock.Artifact.Outputs...) {
		got, err := artifact.VerifyBuild(ctx, build.Directory)
		if err != nil || !reflect.DeepEqual(got, build.Metadata) {
			t.Fatal("stock exact plugin build changed")
		}
	}
	store, err := openStockStorePrefix(ctx, input, inv.StateDir, nil)
	if err != nil {
		t.Fatal("stock reusable Store capability unavailable")
	}
	inspection, err := store.Inspect(ctx, budget)
	if err != nil || !inspection.Empty || inspection.Identity == "" || inspection.Prefix != input.Prefix {
		t.Fatal("stock fresh Store prefix preflight refused")
	}
	limitsBody, err := json.Marshal(input.Limits)
	if err != nil {
		t.Fatal("stock limit identity unavailable")
	}
	grant := records.StockPluginGrant{
		Schema: 1, Fixture: stock.Fixture, RunID: input.RunID, Scenario: input.Scenarios[0], Prefix: input.Prefix,
		LimitsSHA256: bodyDigest(limitsBody), PreflightEmpty: true, BucketIdentity: inspection.Identity,
	}
	if grant.Validate() != nil || writeNewLiveJSON(stockGrantPath(inv), grant) != nil {
		t.Fatal("stock original prefix grant unavailable")
	}
	r.save()
	directory := filepath.Join(inv.StateDir, "stock-source")
	if os.Mkdir(directory, 0700) != nil {
		t.Fatal("stock application source unavailable")
	}
	source := filepath.Join(directory, "configuration.json")
	publicSetupSource(t, input, source)
	r.selectPlugins(source, false)
	liveEndPhase(t, worker, sequence, true)
	sequence = begin(1)
	initialized := r.command(ctx, "init", "authority", "", nil, "init", "--source", source, "--source-format", "json", "--json")
	product := publicProduct(t, initialized, "initialize-empty-domain")
	clear(initialized.Body)
	if initialized.Code != 0 || product.State != "success" || !publicIdentityHex(product.Payload.Domain) {
		t.Fatal("stock initialization did not select an empty domain")
	}
	expires := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	stockDeclareGenerated(t, source, *stock, input.RunID, expires, 0, true)
	a0Result := r.generated(ctx, "a0-created", "a", source, "success", "apply")
	a0 := r.list(ctx, source)
	if len(a0.Current) != 1 || len(a0.Duties) != 0 || !stockCurrentValid(a0.Current[0], 0) {
		t.Fatal("stock A0 current generation differs")
	}
	a0Create, valid := stockCreateForBuild(a0Result, a0.Current[0], stock.Artifact.GeneratorA.Metadata)
	if !valid {
		t.Fatal("stock A0 was not created by exact A support")
	}
	r.evidence.Creates = append(r.evidence.Creates, stockCreateEvidence("a0-created", a0Create))
	r.evidence.Generations = append(r.evidence.Generations, stockGenerationEvidence("a0-created", a0.Current[0]))
	r.save()
	r.verifySelectedToken(ctx, source)
	r.assert("a0-created")
	stockDeclareGenerated(t, source, *stock, input.RunID, expires, 1, true)
	a1Result := r.generated(ctx, "a1-pending-a", "a", source, "retirement-pending", "apply")
	a1 := r.list(ctx, source)
	if len(a1.Current) != 1 || len(a1.Duties) != 1 || !stockCurrentValid(a1.Current[0], 1) || a1.Current[0].Generation == a0.Current[0].Generation || !stockDutyMatches(a1.Duties[0], a0.Current[0], a0Create, stock.Artifact.GeneratorA.Metadata) {
		t.Fatal("stock A1 did not retain exact A retirement")
	}
	a1Create, valid := stockCreateForBuild(a1Result, a1.Current[0], stock.Artifact.GeneratorA.Metadata)
	if !valid {
		t.Fatal("stock A1 was not created by exact A support")
	}
	r.evidence.Creates = append(r.evidence.Creates, stockCreateEvidence("a1-pending-a", a1Create))
	r.evidence.Generations = append(r.evidence.Generations, stockGenerationEvidence("a1-pending-a", a1.Current[0]))
	r.evidence.Duties = append(r.evidence.Duties, stockDutyEvidence("a1-pending-a", a1.Duties[0]))
	r.save()
	r.verifySelectedToken(ctx, source)
	r.assert("a1-pending-a")
	r.selectPlugins(source, true)
	r.generated(ctx, "b-same-epoch-reused", "", source, "no-op", "apply")
	if !stockSameGeneratedSelection(a1, r.list(ctx, source)) {
		t.Fatal("stock B changed same-epoch intent or accepted A Duty")
	}
	r.assert("b-same-epoch-reused")
	r.missingA(ctx, source, a1)
	r.retire(ctx, "exact-a-retired", "a", source, a1.Duties[0])
	r.assert("exact-a-retired")
	stockDeclareGenerated(t, source, *stock, input.RunID, expires, 2, true)
	b2Result := r.generated(ctx, "b2-created", "b", source, "retirement-pending", "apply")
	b2 := r.list(ctx, source)
	if len(b2.Current) != 1 || len(b2.Duties) != 1 || !stockCurrentValid(b2.Current[0], 2) || b2.Current[0].Generation == a1.Current[0].Generation || !stockDutyMatches(b2.Duties[0], a1.Current[0], a1Create, stock.Artifact.GeneratorB.Metadata) {
		t.Fatal("stock B2 did not bind new B work to exact A1 resource")
	}
	b2Create, valid := stockCreateForBuild(b2Result, b2.Current[0], stock.Artifact.GeneratorB.Metadata)
	if !valid {
		t.Fatal("stock B2 was not created by exact B support")
	}
	r.evidence.Creates = append(r.evidence.Creates, stockCreateEvidence("b2-created", b2Create))
	r.evidence.Generations = append(r.evidence.Generations, stockGenerationEvidence("b2-created", b2.Current[0]))
	r.evidence.Duties = append(r.evidence.Duties, stockDutyEvidence("b2-created", b2.Duties[0]))
	r.save()
	r.verifySelectedToken(ctx, source)
	r.assert("b2-created")
	r.retire(ctx, "b-retired-a1", "b", source, b2.Duties[0])
	r.assert("b-retired-a1")
	r.publishOutputs(ctx, source)
	r.manifest(ctx, source)
	source = r.reconstruct(ctx, source, expires)
	r.removeOutputs(ctx, source)
	stockDeclareGenerated(t, source, *stock, input.RunID, expires, 2, false)
	r.generated(ctx, "remove-generated", "", source, "retirement-pending", "apply", "--retire-generator", "generated=cloudflare-account-token")
	final := r.list(ctx, source)
	if len(final.Current) != 0 || len(final.Duties) != 1 || !stockDutyMatches(final.Duties[0], b2.Current[0], b2Create, stock.Artifact.GeneratorB.Metadata) {
		t.Fatal("stock canonical absence did not accept exact final B Duty")
	}
	r.evidence.Duties = append(r.evidence.Duties, stockDutyEvidence("final-generation-retired", final.Duties[0]))
	r.save()
	r.retire(ctx, "final-generation-retired", "b", source, final.Duties[0])
	closed := r.list(ctx, source)
	if len(closed.Current) != 0 || len(closed.Duties) != 0 || len(closed.Hazards) != 0 {
		t.Fatal("stock final generated work remains")
	}
	r.assert("final-generation-retired")
	liveEndPhase(t, worker, sequence, true)
	sequence = begin(2)
	portable := publicPortablePair(t, source, filepath.Join(inv.StateDir, "fresh-pair"))
	facts := publicProcessFacts{RunID: input.RunID, Prefix: input.Prefix, Source: portable, Domain: product.Payload.Domain, ExpectReady: true}
	if writeNewLiveJSON(filepath.Join(inv.StateDir, "after.json"), facts) != nil {
		t.Fatal("stock final Reader handoff unavailable")
	}
	worker.Result.FreshChecks = []records.FreshCheck{{Facts: "after.json"}}
	r.save()
	liveEndPhase(t, worker, sequence, true)
}

func (r *stockPluginRun) missingA(ctx context.Context, source string, before stockGeneratedResult) {
	id, err := r.input.PublicConfiguration.Stock.Artifact.GeneratorA.Metadata.Identity()
	if err != nil {
		r.t.Fatal("stock original A identity unavailable")
	}
	build := filepath.Join(stockConfigDirectory(r.home("apply")), "enkv", "installation", "builds", id.String())
	plugin := filepath.Join(build, "plugin")
	info, err := os.Stat(build)
	if err != nil {
		r.t.Fatal("stock retained A directory unavailable")
	}
	backup := filepath.Join(r.inv.StateDir, "retained-a-original")
	if os.Chmod(build, 0700) != nil || os.Rename(plugin, backup) != nil {
		r.t.Fatal("stock retained A support fault could not be prepared")
	}
	defer func() {
		if os.Rename(backup, plugin) != nil || os.Chmod(build, info.Mode().Perm()) != nil {
			r.t.Error("stock exact original A restoration failed")
		}
	}()
	r.generated(ctx, "missing-a-refused", "b", source, "refused", "generated", "retire", "--duty", before.Duties[0].Facts.Duty)
	if !stockSameGeneratedSelection(before, r.list(ctx, source)) {
		r.t.Fatal("stock unavailable A changed accepted work or selected generation")
	}
	r.assert("missing-a-refused")
}

func (r *stockPluginRun) verifySelectedToken(ctx context.Context, source string) {
	directory, err := os.MkdirTemp("", "enkv-stock-token-")
	if err != nil {
		r.t.Fatal("stock private token sink unavailable")
	}
	path := filepath.Join(directory, "selected.env")
	defer func() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			r.t.Error("stock private token sink removal failed")
		}
		if os.Remove(directory) != nil {
			r.t.Error("stock private token directory removal failed")
		}
	}()
	child := r.command(ctx, "materialize", "consumer", "", nil, "materialize", "--source", source, "--source-format", "json", "--name", "generated", "--out", path, "--json")
	defer clear(child.Body)
	var result publicMaterializationResult
	if child.Code != 0 || json.Unmarshal(child.Body, &result) != nil || result.Schema != "ProductResult/v1" || result.State != "success" || len(result.Payload.Entries) != 1 || result.Payload.Entries[0].Name != "generated" || result.Payload.Target.Path != path {
		r.t.Fatal("stock selected token private materialization differs")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 512 {
		r.t.Fatal("stock private token sink facts differ")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		r.t.Fatal("stock private selected token unavailable")
	}
	defer clear(body)
	token, err := stockTokenBytes(body)
	if err != nil {
		r.t.Fatal("stock selected token projection differs")
	}
	defer clear(token)
	r.verify(ctx)
	client, closeClient := stockVerificationClient()
	defer closeClient()
	id, err := stockVerifyCloudflare(ctx, client, r.input.PublicConfiguration.Stock.CloudflareAccount, token)
	if err != nil || slices.Contains(r.evidence.ProviderTokenIDs, id) {
		r.t.Fatal("stock independent selected-token observation differs")
	}
	r.evidence.ProviderTokenIDs = append(r.evidence.ProviderTokenIDs, id)
	r.save()
}
