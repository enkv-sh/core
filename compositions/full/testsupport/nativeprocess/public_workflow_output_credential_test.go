package nativeprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/core"
	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
)

// full_only: false
func TestPublicNativeOutputCredentialCaptureJoinsIsolatedChild(t *testing.T) {
	output := newNativePublicationServer(t)
	binaries := buildNativeOutputExecutables(t, output.server.URL)
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			s := newWorkflowServer(t, family, false)
			source := filepath.Join(t.TempDir(), "configuration.json")
			plugins := binaries.nativePluginFixture
			var declaredNames []string
			if err := os.WriteFile(source, workflowSetup(t, s, false), 0600); err != nil {
				t.Fatal(err)
			}
			run := func(phase string, environment []string, args ...string) workflowChild {
				return workflowRunDeclaredEnvironment(t, s, binaries.cli, phase, observer.Policy{}, nil, append(plugins.Environment(t, source), environment...), declaredNames, args...)
			}
			children := []workflowChild{run("init", nil, "init", "--source", source, "--source-format", "json", "--json")}
			workflowResult(t, children[0], "success")
			plugin, settings := "gcp-secret-manager", map[string]any{"project_number": "123456789012"}
			service, physical := "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", "projects/123456789012/secrets/VALUE"
			if family == "gcp" {
				plugin, settings = "aws-secrets-manager", map[string]any{"account": "123456789012", "region": "us-east-1"}
				service, physical = "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", "arn:aws:secretsmanager:us-east-1:123456789012:secret:VALUE"
			}
			for _, facts := range binaries.artifacts {
				if facts.Descriptor.Name == plugin {
					route, err := credentialroute.Decode(facts.Descriptor.Output.CredentialRoute)
					if err != nil {
						t.Fatal(err)
					}
					declaredNames = route.Names
				}
			}
			if len(declaredNames) == 0 {
				t.Fatal("selected output descriptor route absent")
			}
			nativePublicationSource(t, source, func(value map[string]any) {
				value["entries"] = map[string]any{"VALUE": map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "value": "never send this value"}}}
				value["outputs"] = map[string]any{"destinations": map[string]any{"selected": map[string]any{"plugin": plugin, "settings": settings}}, "routing": map[string]any{"default": []string{"selected"}}}
			})
			applied := run("apply", nil, "apply", "--source", source, "--source-format", "json", "--json")
			workflowResult(t, applied, "success")
			children = append(children, applied)
			pair := workflowReadPair(t, source)
			images := nativePublicationImages(t, source, filepath.Join(filepath.Dir(source), pair.reference))
			head, _ := workflowHead(t, s)
			selected := workflowRoot(t, s, head)
			before := nativePublicationCounters(t, binaries)
			effects := output.effectCount()
			initialLedger, err := os.ReadFile(binaries.ledger)
			if err != nil {
				t.Fatal(err)
			}
			refusedBefore := bytes.Count(initialLedger, []byte{'R'})
			emptyHome := t.TempDir()
			// Standard discovery receives only its declared native inputs. Invalid local
			// sources must fail before payload readiness and before any output mutation.
			environment := []string{"GOOGLE_APPLICATION_CREDENTIALS=" + filepath.Join(emptyHome, "missing-adc.json"), "GCE_METADATA_HOST=127.0.0.1:1"}
			if family == "gcp" {
				environment = []string{"AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=", "AWS_SESSION_TOKEN=", "AWS_PROFILE=", "AWS_DEFAULT_PROFILE=", "AWS_CONFIG_FILE=" + filepath.Join(emptyHome, "missing-config"), "AWS_SHARED_CREDENTIALS_FILE=" + filepath.Join(emptyHome, "missing-credentials"), "AWS_EC2_METADATA_DISABLED=true"}
			}

			failed := run("apply", environment, "publish", "--source", source, "--source-format", "json", "--name", "VALUE", "--json")
			children = append(children, failed)
			domain := hex.EncodeToString(pair.descriptor.DomainID[:])
			var result nativePublicationOutput
			if err := json.Unmarshal(failed.out, &result); err != nil {
				t.Fatal("complete credential refusal result did not decode", err)
			}
			if failed.code != 2 || result.Schema != "ProductResult/v1" || result.Operation != "publish" || result.Domain != domain || result.State != "effect-terminal-failure" || result.Summary != "output-failed" || result.Replay != "none" || result.Effect != "not-applicable" || result.Payload.Schema != "OutputPayload/v3" || result.Payload.Domain != domain || result.Payload.Operation != result.OperationID || result.Payload.Warning || len(result.Payload.Entries) != 1 {
				t.Fatal("complete credential refusal lost its admitted failed publication envelope")
			}
			entry := result.Payload.Entries[0]
			if entry.Coordinate != nativePublicationCoordinate(t, domain, service, physical) || len(entry.Actions) != 2 {
				t.Fatal("credential refusal changed the exact coordinate or action vector")
			}
			first, next := entry.Actions[0], entry.Actions[1]
			if first.Action == nil || *first.Action != "create-empty" || first.Attempt == nil || first.Projection == nil || first.Disposition != "rejected" || first.Reason != 0 || first.Remote || first.Late || len(first.Blockers) != 0 || first.Evidence == nil || first.Evidence.Schema != "PublicationEvidence/v3" || first.Evidence.Entry != "not-entered" || first.Evidence.Class != "qualified-no-effect" || first.Evidence.Status != 0 || first.Evidence.Resource != "" || first.Evidence.Locator == nil || *first.Evidence.Locator != "" {
				t.Fatal("checked preparation refusal lost its exact no-effect evidence")
			}
			if next.Action == nil || *next.Action != "write-value" || next.Projection == nil || next.Attempt != nil || next.Evidence != nil || next.Disposition != "not-sent" || next.Reason != uint16(core.AdmissionInvalid) || next.Remote || next.Late || len(next.Blockers) != 0 {
				t.Fatal("credential refusal admitted its later value write")
			}
			for _, text := range []string{result.Request, result.OperationID, result.Identity, result.Payload.Snapshot, result.Payload.Selection, *first.Attempt, *first.Projection, *next.Projection, first.Evidence.Response} {
				if nativePublicationID(t, text).IsZero() {
					t.Fatal("credential refusal lost exact nonzero operation or action correlation")
				}
			}
			if *first.Projection == *next.Projection {
				t.Fatal("separate fixed actions reused one projection")
			}

			after := nativePublicationCounters(t, binaries)
			if after.captures-before.captures != 1 || after.dispatches-before.dispatches != 1 || after.checks <= before.checks || after.joins-before.joins != after.checks-before.checks+1 || output.effectCount() != effects {
				t.Fatal("failed discovery lost capture, actual native dispatch, or joined child", before, after)
			}
			for _, body := range [][]byte{failed.out, failed.diagnostic} {
				for _, forbidden := range []string{"never send this value", emptyHome, "missing-adc.json", "missing-credentials"} {
					if bytes.Contains(body, []byte(forbidden)) {
						t.Fatal("native refusal disclosed private value or credential source")
					}
				}
			}
			nativePublicationUnchanged(t, images)
			current, _ := workflowHead(t, s)
			retained := workflowRoot(t, s, current)
			if !reflect.DeepEqual(selected.ValueEntryPages, retained.ValueEntryPages) || !reflect.DeepEqual(selected.CurrentAccess, retained.CurrentAccess) || selected.OutputConfiguration != retained.OutputConfiguration {
				t.Fatal("failed discovery changed selected values, access or output declaration")
			}
			ledger, err := os.ReadFile(binaries.ledger)
			if err != nil || bytes.Count(ledger, []byte{'R'})-refusedBefore != 1 {
				t.Fatal("native failure did not reach its preparation-refused gate", err)
			}

			nativeMaterializationJoined(t, children, 3)
		})
	}
}

type nativeOutputExecutables struct {
	nativePluginFixture
	cli, helper, ledger string
	artifacts           []artifact.OutputFacts
}

// The fixed loopback origin is compiled into these controlled output artifacts.
// The installed CLI and every plugin keep the same bytes across runtime targets.
func buildNativeOutputExecutables(t *testing.T, origin string) nativeOutputExecutables {
	t.Helper()
	address, err := url.Parse(origin)
	if err != nil || address.Scheme != "http" || address.User != nil || address.Path != "" || address.RawQuery != "" || address.Fragment != "" {
		t.Fatal("controlled output origin is not a plain loopback origin")
	}
	host := net.ParseIP(address.Hostname())
	if host == nil || !host.IsLoopback() || address.Port() == "" {
		t.Fatal("controlled output origin is not loopback")
	}
	root, private := nativeRepository(t), nativeGeneratedPrivateDirectory(t)
	overlay, err := observer.BuildOverlay(root, filepath.Join(private, "overlay"))
	if err != nil {
		t.Fatal("public output observer unavailable", err)
	}
	var mapping struct{ Replace map[string]string }
	var sources []observer.Source
	nativeGeneratedReadJSON(t, overlay.Path, &mapping)
	nativeGeneratedReadJSON(t, overlay.Manifest, &sources)
	result := nativeOutputExecutables{cli: filepath.Join(private, "enkv"), helper: filepath.Join(private, "reconstruct"), ledger: filepath.Join(private, "output-ledger")}
	add := func(relative, anchor, replacement, suffix string) {
		t.Helper()
		target := nativeGeneratedSourcePath(root, relative)
		original, err := os.ReadFile(target)
		selected := original
		if previous, present := mapping.Replace[target]; present {
			selected, err = os.ReadFile(previous)
		}
		if err != nil || strings.Count(string(selected), anchor) != 1 {
			t.Fatal("output observer source anchor differs", relative)
		}
		body := []byte(strings.Replace(string(selected), anchor, replacement, 1) + suffix)
		path := filepath.Join(private, "overlay", strings.ReplaceAll(relative, "/", "_"))
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal("output observer source unavailable", err)
		}
		mapping.Replace[target] = path
		found := false
		for i := range sources {
			if sources[i].Target == target {
				sources[i].Replacement, sources[i].ReplacementSHA256 = path, workflowDigest(body)
				found = true
			}
		}
		if !found {
			sources = append(sources, observer.Source{Target: target, OriginalSHA256: workflowDigest(original), Replacement: path, ReplacementSHA256: workflowDigest(body)})
		}
	}
	quote := strconv.Quote
	ledger := `
func nativeOutputRecord(kind byte) error {
 file, err := os.OpenFile(` + quote(result.ledger) + `, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
 if err != nil { return err }
 n, writeErr := file.Write([]byte{kind})
 closeErr := file.Close()
 if writeErr != nil { return writeErr }
 if closeErr != nil { return closeErr }
 if n != 1 { return os.ErrInvalid }
 return nil
}
`
	captureAnchor := "func captureEnvironment(ctx context.Context, route credentialroute.Route) ([]byte, error) {"
	add("compositions/outputhost/host.go", captureAnchor, captureAnchor+"\n if err := nativeOutputRecord('C'); err != nil { return nil, err }", ledger)
	wireAnchor := "func (n *Native) run(ctx context.Context, stage *artifactStage, command protocol.Command, commandBody, policyBody, credentialBody, payload []byte) (result protocol.Result, proof dispatchProof, err error) {"
	add("compositions/outputhost/host.go", wireAnchor, wireAnchor+"\n if recordErr := nativeOutputRecord('W'); recordErr != nil { return protocol.Result{}, dispatchUnqualified, recordErr }", "")
	refusalAnchor := "if gate.Kind == protocol.KindPreparationRefused {"
	add("compositions/outputhost/host.go", refusalAnchor, refusalAnchor+"\n if recordErr := nativeOutputRecord('R'); recordErr != nil {return protocol.Result{},dispatchUnqualified,recordErr}", "")
	profileAnchor := "func (v *PublicValidator) runPublic(ctx context.Context, checkID protocol.ID, kind, resultKind uint8, requestBody, policyBody []byte, maximum uint32) (result []byte, err error) {"
	add("compositions/outputhost/public.go", profileAnchor, profileAnchor+"\n if recordErr := nativeOutputRecord('P'); recordErr != nil { return nil, recordErr }", "")
	add("compositions/internal/nativeprocess/process_unix.go", "package nativeprocess", "package nativeprocess", ledger)
	childAnchor := "type Child struct {"
	add("compositions/internal/nativeprocess/process_unix.go", childAnchor, childAnchor+"\n nativeOutputObserved bool", "")
	startAnchor := "child = &Child{Process: process}"
	add("compositions/internal/nativeprocess/process_unix.go", startAnchor, startAnchor+`
 child.nativeOutputObserved = entrypoint == "output-public-v3" || entrypoint == "output-wire-v6"`, "")
	joinAnchor := "\treturn nil\n}\n\n// Start launches"
	add("compositions/internal/nativeprocess/process_unix.go", joinAnchor, "\tif child.nativeOutputObserved { return nativeOutputRecord('J') }\n"+joinAnchor, "")
	stageAnchor := "func (s *artifactStage) closeOutcome() (removalErr, resourceErr error) {"
	add("compositions/outputhost/artifact_stage.go", stageAnchor, stageAnchor+`
 owned := ""
 if s != nil { owned = s.ownedRoot }
 defer func() {
  if owned == "" || removalErr != nil || resourceErr != nil { return }
  if _, err := os.Lstat(owned); !os.IsNotExist(err) {
   resourceErr = errors.Join(ErrProcess, errStagingCleanup, err, nativeOutputRecord('F'))
   return
  }
  resourceErr = nativeOutputRecord('S')
 }()`, "")
	for _, edit := range []struct{ path, anchor, replacement string }{
		{"plugins/aws-output/internal/awssm/client.go", "return Implementation{transport:", "return Implementation{endpoint: " + quote(origin) + ", transport:"},
		{"plugins/gcp-output/internal/gcpsm/client.go", "return Implementation{transport:", "return Implementation{endpoint: " + quote(origin) + ", transport:"},
		{"plugins/github-output/internal/github/client.go", "endpoint: apiHost", "endpoint: " + quote(origin)},
	} {
		add(edit.path, edit.anchor, edit.replacement, "")
	}
	slices.SortFunc(sources, func(a, b observer.Source) int { return strings.Compare(a.Target, b.Target) })
	nativeGeneratedWriteJSON(t, overlay.Path, mapping)
	nativeGeneratedWriteJSON(t, overlay.Manifest, sources)
	var localBuilds []artifact.LocalPlugin
	for _, row := range []struct{ module, command, name string }{
		{"aws-output", "enkv-output-aws-secrets-manager", "aws-secrets-manager"},
		{"gcp-output", "enkv-output-gcp-secret-manager", "gcp-secret-manager"},
		{"github-output", "enkv-output-github-repository", "github-actions-repository"},
		{"github-output", "enkv-output-github-organization", "github-actions-organization"},
		{"github-output", "enkv-output-github-environment", "github-actions-environment"},
	} {
		module := "plugins/" + row.module
		modulePath := nativeGeneratedModulePath(t, module)
		command := modulePath + "/cmd/" + row.command
		path := filepath.Join(private, row.command)
		build := []string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-overlay=" + overlay.Path, "-o", path, "./cmd/" + row.command}
		nativeOutputGo(t, root, module, path+".mod", build...)
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("controlled output artifact unavailable", err)
		}
		digest, length := sha256.Sum256(body), uint64(len(body))
		clear(body)
		descriptor, _, err := artifact.ReadDescriptor(t.Context(), filepath.Join(nativeGeneratedSourcePath(root, module), "cmd", row.command, "plugin.json"))
		if err != nil || descriptor.Name != row.name {
			t.Fatal("controlled output descriptor refused", err)
		}
		facts, manifest := nativeOutputDependencyManifest(t, root, module, path, overlay.Path, mapping.Replace, descriptor)
		dependency, err := artifact.DependencyID("output", manifest)
		if err != nil {
			t.Fatal("controlled output dependency identity refused", err)
		}
		family, err := artifact.BindOutputFacts(artifact.OutputFacts{Schema: artifact.FamilySchema, Descriptor: descriptor,
			ExecutionFacts: artifact.ExecutionFacts{Module: modulePath, Command: command, GoVersion: facts.Toolchain, NativeTuple: facts.Platform}}, artifact.Digest(digest), length, dependency)
		if err != nil {
			t.Fatal("controlled output family binding failed", err)
		}
		raw, err := json.Marshal(family)
		if err != nil {
			t.Fatal(err)
		}
		metadata := artifact.Metadata{Schema: "enkv/plugin-artifact/v2", Purpose: "plugin-executable", Name: row.name, Role: facts.Role, Version: descriptor.Version, MainModule: facts.MainModule, Command: facts.Command, Platform: facts.Platform, Toolchain: facts.Toolchain, BuildOptions: facts.BuildOptions, Contracts: facts.Contracts, Sources: facts.Sources, Resolved: facts.Resolved, Compiled: facts.Compiled, Executable: artifact.DigestLength{SHA256: artifact.Digest(digest), Length: length}, Family: &artifact.Family{Schema: artifact.FamilySchema, Facts: raw, Dependency: artifact.DigestLength{SHA256: artifact.Hash(manifest), Length: uint64(len(manifest))}}}
		localBuild := filepath.Join(private, "local-"+row.name)
		marker, err := artifact.PublishBuild(t.Context(), localBuild, metadata, path, manifest)
		if err != nil {
			t.Fatal("publish controlled output build", err)
		}
		result.artifacts = append(result.artifacts, family)
		localBuilds = append(localBuilds, artifact.LocalPlugin{Name: row.name, Directory: localBuild})
		t.Logf("controlled output command=%s sha256=%x length=%d dependency_id=%s dependency_sha256=%s metadata_id=%s source_overlay=%s source_manifest=%s local_build=%s", command, digest, length, dependency.String(), artifact.Hash(manifest).String(), marker.Artifact.String(), overlay.Path, overlay.Manifest, localBuild)
	}
	result.nativePluginFixture = newNativePluginFixture(t, localBuilds...)
	build := func(path string, files ...string) {
		args := nativeGoArguments("build", "-mod=readonly", "-tags=netgo", "-trimpath", "-buildvcs=false", "-overlay="+overlay.Path, "-ldflags="+nativePluginLinkerFlags(), "-o", path)
		nativeGeneratedGo(t, root, "compositions/full", append(args, files...)...)
		nativeRequireRaceMode(t, path)
	}
	build(result.cli, "./cmd/enkv")
	files, err := filepath.Glob(filepath.Join(root, "tests", "live", "publicprocess", "*.go"))
	if err != nil {
		t.Fatal("public output helper sources unavailable", err)
	}
	selected := []string{}
	for _, file := range files {
		if !strings.HasSuffix(file, "_test.go") {
			selected = append(selected, file)
		}
	}
	selected = append(selected, filepath.Join(root, "tests", "live", "publicprocess", "nativeprocess_observer.go"))
	build(result.helper, selected...)
	t.Logf("controlled public output builds=%d overlay=%s sources=%s ledger=%s", len(result.builds), overlay.Path, overlay.Manifest, result.ledger)
	return result
}

func nativeOutputLedger(t *testing.T, binaries nativeOutputExecutables) (captures, checks, dispatches int) {
	t.Helper()
	body, err := os.ReadFile(binaries.ledger)
	if os.IsNotExist(err) {
		return 0, 0, 0
	}
	if err != nil || len(body) > 1<<20 {
		t.Fatal("controlled output ledger unavailable or over capacity")
	}
	for _, event := range body {
		switch event {
		case 'C':
			captures++
		case 'P':
			checks++
		case 'W':
			dispatches++
		case 'R':
		// Preparation refused before payload readiness or plugin Send.
		case 'S':
			// The actual owned staging root was absent after successful close.
		case 'J':
			// A successful actual Wait is counted separately by native callers.
		default:
			t.Fatal("controlled output ledger has an unknown event")
		}
	}
	return captures, checks, dispatches
}

func nativeOutputGo(t *testing.T, root, module, modfile string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir = nativeGeneratedSourcePath(root, module)
	fixed := map[string]string{
		"GOENV": "off", "GO111MODULE": "on", "GOTOOLCHAIN": "local", "GOWORK": "off",
		"GOFLAGS": "-trimpath -p=1", "GOEXPERIMENT": "", "CGO_ENABLED": "0",
		"GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "GOAMD64": "v1", "GOARM64": "v8.0",
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := fixed[key]; !replaced {
			command.Env = append(command.Env, entry)
		}
	}
	for key, value := range fixed {
		command.Env = append(command.Env, key+"="+value)
	}
	if args[0] == "build" {
		prepareNativeModule(t, root, command, modfile)
	} else {
		command.Args = append([]string{"go", args[0], "-modfile=" + modfile}, args[1:]...)
	}
	body, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("installed output fixture build facts failed: %v\n%s", err, body)
	}
	return body
}

func nativeOutputDependencyManifest(t *testing.T, root, module, path, overlay string, replacements map[string]string, descriptor artifact.Descriptor) (artifact.BuildFacts, []byte) {
	t.Helper()
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		return nativeOutputGo(t, root, module, path+".mod", args...)
	}
	type listedModule = artifact.SourceModule
	var modules []listedModule
	decoder := json.NewDecoder(bytes.NewReader(run("list", "-mod=readonly", "-m", "-json", "all")))
	for {
		var row listedModule
		err := decoder.Decode(&row)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		modules = append(modules, row)
	}
	args := []string{"list", "-mod=readonly", "-deps", "-json", "-overlay=" + overlay}
	args = append(args, "./cmd/"+filepath.Base(info.Path))
	type pkg = artifact.SourcePackage
	var packages []pkg
	decoder = json.NewDecoder(bytes.NewReader(run(args...)))
	for {
		var row pkg
		err := decoder.Decode(&row)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		packages = append(packages, row)
	}
	sources := nativeOutputCapturedSources(t, modules, packages, replacements)
	options, err := artifact.BuildOptions(info)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := artifact.CompiledDependencies(info, sources)
	if err != nil {
		t.Fatal(err)
	}
	sourceMap := map[string]artifact.Digest{}
	for _, row := range sources {
		sourceMap[row.Module] = row.Digest
	}
	resolved := make([]artifact.Dependency, 0, len(modules))
	for _, row := range modules {
		r := artifact.Dependency{Path: row.Path, Version: row.Version, Sum: row.Sum}
		if row.Replace != nil {
			r.Replacement = &artifact.Replacement{Path: row.Replace.Path, Version: row.Replace.Version, Sum: row.Replace.Sum}
			if row.Replace.Version == "" && row.Replace.Sum == "" {
				r.Replacement.SourceDigest = sourceMap[row.Path]
			}
		}
		resolved = append(resolved, r)
	}
	slices.SortFunc(resolved, func(a, b artifact.Dependency) int { return strings.Compare(a.Path, b.Path) })
	facts := artifact.BuildFacts{Role: "output", MainModule: info.Main.Path, Command: info.Path, Platform: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: info.GoVersion, BuildOptions: options, Contracts: []artifact.Contract{descriptor.Wire}, Sources: sources, Resolved: resolved, Compiled: compiled}
	body, err := artifact.EncodeDependency(facts)
	if err != nil {
		t.Fatal("output build manifest refused", err)
	}
	if err := artifact.VerifyBuildInfo(info, facts); err != nil {
		t.Fatal("controlled output closure refused", err)
	}
	return facts, body
}

// Stage the controlled overlay's selected bytes under their original relative
// names so the public source collector checks the same compiler inputs.
func nativeOutputCapturedSources(t *testing.T, modules []artifact.SourceModule, packages []artifact.SourcePackage, replacements map[string]string) []artifact.Source {
	t.Helper()
	owners := map[string]*artifact.SourceModule{}
	originalRoots := map[string]string{}
	stageOwner := func(module artifact.SourceModule) *artifact.SourceModule {
		t.Helper()
		if owner := owners[module.Path]; owner != nil {
			return owner
		}
		original := module
		actual := &original
		if original.Replace != nil {
			actual = original.Replace
		}
		root, err := filepath.EvalSymlinks(actual.Dir)
		if err != nil {
			t.Fatal(err)
		}
		staged := module
		stagedRoot := t.TempDir()
		if module.Replace != nil {
			replacement := *module.Replace
			replacement.Dir = stagedRoot
			staged.Replace = &replacement
		} else {
			staged.Dir = stagedRoot
		}
		owners[module.Path] = &staged
		originalRoots[module.Path] = root
		for _, name := range artifact.SourceMetadataFiles() {
			path := filepath.Join(root, name)
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				continue
			} else if err != nil {
				t.Fatal(err)
			}
			nativeOutputCopySelected(t, root, path, stagedRoot, name, replacements)
		}
		return &staged
	}
	selected := make([]artifact.SourcePackage, 0, len(packages))
	for _, pkg := range packages {
		if pkg.Standard {
			continue
		}
		if pkg.Module == nil {
			t.Fatal("controlled selected package has no module")
		}
		owner := stageOwner(*pkg.Module)
		original := originalRoots[pkg.Module.Path]
		stagedRoot := owner.Dir
		if owner.Replace != nil {
			stagedRoot = owner.Replace.Dir
		}
		relative, err := filepath.Rel(original, pkg.Dir)
		if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			t.Fatal("controlled source package escaped module")
		}
		originalDirectory := pkg.Dir
		pkg.Dir = filepath.Join(stagedRoot, relative)
		pkg.Module = owner
		for _, files := range [][]string{pkg.GoFiles, pkg.CgoFiles, pkg.CFiles, pkg.CXXFiles, pkg.MFiles, pkg.HFiles, pkg.FFiles, pkg.SFiles, pkg.SwigFiles, pkg.SwigCXXFiles, pkg.SysoFiles, pkg.EmbedFiles} {
			for _, name := range files {
				nativeOutputCopySelected(t, original, filepath.Join(originalDirectory, name), stagedRoot, filepath.Join(relative, name), replacements)
			}
		}
		if len(pkg.SFiles)+len(pkg.HFiles) > 0 {
			path := filepath.Join(originalDirectory, "textflag.h")
			if _, err := os.Lstat(path); err == nil {
				nativeOutputCopySelected(t, original, path, stagedRoot, filepath.Join(relative, "textflag.h"), replacements)
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
		selected = append(selected, pkg)
	}
	stagedModules := make([]artifact.SourceModule, 0, len(modules))
	for _, module := range modules {
		actual := &module
		if module.Replace != nil {
			actual = module.Replace
		}
		if owners[module.Path] != nil || actual.Version == "" && actual.Sum == "" {
			stagedModules = append(stagedModules, *stageOwner(module))
		} else {
			stagedModules = append(stagedModules, module)
		}
	}
	sources, err := artifact.CaptureSourcesForModules(t.Context(), "output", selected, stagedModules)
	if err != nil {
		t.Fatal("controlled selected sources refused", err)
	}
	return sources
}

func nativeOutputCopySelected(t *testing.T, root, source, directory, relative string, replacements map[string]string) {
	t.Helper()
	clean := filepath.Clean(relative)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		t.Fatal("controlled source path escaped module")
	}
	var target string
	if replacement, ok := replacements[source]; ok {
		target = replacement
	} else {
		resolved, err := filepath.EvalSymlinks(source)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(root, resolved)
		if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatal("controlled source symlink escaped module")
		}
		target = resolved
	}
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("controlled source is not a regular file", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, clean)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestNativeOutputSourcesBindSelectedOverlayBytes(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "main.go")
	replacement := filepath.Join(t.TempDir(), "replacement.go")
	legal := map[string]string{"LICENSE.txt": "text license\n", "LICENSE.md": "markdown license\n", "NOTICE.txt": "text notice\n"}
	for path, body := range map[string]string{filepath.Join(root, "go.mod"): "module example.invalid/overlay\n", source: "package main\n", replacement: "package main\nconst Controlled=true\n"} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range legal {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	module := artifact.SourceModule{Path: "example.invalid/overlay", Dir: root, Main: true}
	packages := []artifact.SourcePackage{{ImportPath: module.Path, Dir: root, Module: &module, GoFiles: []string{"main.go"}}}
	plain := nativeOutputCapturedSources(t, []artifact.SourceModule{module}, packages, nil)
	overlaid := nativeOutputCapturedSources(t, []artifact.SourceModule{module}, packages, map[string]string{source: replacement})
	if len(plain) != 1 || len(overlaid) != 1 || plain[0].Digest == overlaid[0].Digest {
		t.Fatal("controlled overlay bytes were not bound")
	}
	// Independent Python struct/hashlib derivation binds the exact five inputs.
	if got := plain[0].Digest.String(); got != "d7aceab19e20feda8648ad9e94a05554151927a306bb17b18d36ff01d568e0e8" {
		t.Errorf("plain source whole set differs: %s", got)
	}
	if got := overlaid[0].Digest.String(); got != "eb23d808b8568747b2856e9e0c500ef8f31bb8ef3d9da6c3f518f1d1f418048f" {
		t.Errorf("overlaid source whole set differs: %s", got)
	}
	if err := os.WriteFile(source, []byte("package main\nconst Unselected=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	same := nativeOutputCapturedSources(t, []artifact.SourceModule{module}, packages, map[string]string{source: replacement})
	if same[0].Digest != overlaid[0].Digest {
		t.Fatal("unselected original bytes entered overlay source identity")
	}
	for _, name := range []string{"LICENSE.txt", "LICENSE.md", "NOTICE.txt"} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(root, name), []byte(legal[name]+"changed\n"), 0600); err != nil {
				t.Fatal(err)
			}
			changed := nativeOutputCapturedSources(t, []artifact.SourceModule{module}, packages, map[string]string{source: replacement})
			if changed[0].Digest == overlaid[0].Digest {
				t.Error("controlled staging omitted present legal file bytes", name)
			}
			if err := os.WriteFile(filepath.Join(root, name), []byte(legal[name]), 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}
