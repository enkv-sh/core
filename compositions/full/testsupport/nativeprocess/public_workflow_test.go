package nativeprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/telemetry"
)

// full_only: false
func TestPublicNativeInitializationSetApplyAndPortableReader(t *testing.T) {
	cli, helper := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recovery-%t", family, recovery), func(t *testing.T) { workflowPublicProcess(t, cli, helper, family, recovery) })
		}
	}
}

func workflowExecutables(t *testing.T) (cli, helper string) {
	t.Helper()
	return workflowBuildExecutables(t, true)
}

func workflowBuildExecutables(t *testing.T, reconstruct bool) (cli, helper string) {
	t.Helper()
	root := nativeRepository(t)
	private := t.TempDir()
	overlay, err := observer.BuildOverlay(root, filepath.Join(private, "overlay"))
	if err != nil {
		t.Fatal(err)
	}
	cli, helper = filepath.Join(private, "enkv"), filepath.Join(private, "reconstruct")
	build := func(binary string, sources []string) {
		t.Helper()
		args := nativeGoArguments("build", "-mod=readonly", "-tags=netgo", "-trimpath", "-buildvcs=false", "-overlay="+overlay.Path, "-ldflags="+nativePluginLinkerFlags(), "-o", binary)
		args = append(args, sources...)
		nativeGeneratedGo(t, root, "compositions/full", args...)
		nativeRequireRaceMode(t, binary)
	}
	build(cli, []string{"./cmd/enkv"})
	if !reconstruct {
		return cli, ""
	}
	sources, err := filepath.Glob(filepath.Join(root, "tests", "live", "publicprocess", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	selected := []string{}
	for _, source := range sources {
		if !strings.HasSuffix(source, "_test.go") {
			selected = append(selected, source)
		}
	}
	selected = append(selected, filepath.Join(root, "tests", "live", "publicprocess", "nativeprocess_observer.go"))
	build(helper, selected)
	return cli, helper
}

type workflowPair struct {
	editable, generated []byte
	reference           string
	descriptor          contract.GenesisDescriptorCore // Present only for a genesis basis.
	control             contract.ControlCore
	fileID              contract.ID
	sealed              []byte
}

func workflowReadPair(t *testing.T, path string) workflowPair {
	t.Helper()
	return workflowReadNamedPair(t, path, "prod")
}

func workflowReadNamedPair(t *testing.T, path, name string) workflowPair {
	t.Helper()
	var p workflowPair
	var err error
	p.editable, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var editable struct {
		Generated string
		Domain    struct {
			Name, Provider string
			Store          struct {
				Region, Bucket, Prefix string
				ExpectedOwner          string `json:"expected_owner"`
			}
		}
	}
	if json.Unmarshal(p.editable, &editable) != nil || !strings.HasPrefix(editable.Generated, ".enkv/") || strings.Contains(editable.Generated, "..") {
		t.Fatal("public writer did not deliver one generated dependency")
	}
	p.reference = editable.Generated
	p.generated, err = os.ReadFile(filepath.Join(filepath.Dir(path), p.reference))
	if err != nil {
		t.Fatal(err)
	}
	if editable.Domain.Name != name || p.reference != ".enkv/"+name+".generated.json" {
		t.Fatal("generated dependency does not match the local domain name")
	}
	var generated struct {
		FileID      string `json:"file_id"`
		Domain      struct{ ID string }
		PublicBasis json.RawMessage `json:"public_basis"`
		Secrets     map[string]struct{ Sealed []byte }
	}
	if json.Unmarshal(p.generated, &generated) != nil {
		t.Fatal("generated dependency is not JSON")
	}
	var image workflowSuccessorBasis
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(generated.PublicBasis))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&image) != nil || decoder.Decode(new(any)) != io.EOF || json.Unmarshal(generated.PublicBasis, &fields) != nil {
		t.Fatal("delivered public basis has invalid fields")
	}
	basis := core.PublicBasis{Descriptor: image.Descriptor, Control: image.Control, Selection: image.Selection,
		SigningAnchor: image.SigningAnchor, StoreConfiguration: image.StoreConfiguration, HEAD: image.HEAD, Root: image.Root, RecipientPages: image.RecipientPages}
	observationEmpty := len(image.SigningAnchor) == 0 && len(image.StoreConfiguration) == 0 && len(image.HEAD) == 0 && len(image.Root) == 0 && len(image.RecipientPages) == 0
	var coordinate, nonBody contract.ID
	switch image.Kind {
	case "genesis":
		if !observationEmpty || len(fields) != 2 || len(image.Descriptor) == 0 || len(image.Control) != 0 || len(image.Selection) != 0 || len(image.Enrollment) != 0 {
			t.Fatal("delivered genesis basis is not complete and exclusive")
		}
		p.descriptor, err = contract.DecodeGenesisDescriptorCore(image.Descriptor)
		if err != nil {
			t.Fatal("delivered public basis is invalid", err)
		}
		coordinate, nonBody = p.descriptor.CoordinateID, p.descriptor.NonBodyID
	case "successor":
		if !observationEmpty || len(fields) != 4 || len(image.Descriptor) != 0 || len(image.Control) == 0 || len(image.Selection) == 0 || len(image.Enrollment) == 0 {
			t.Fatal("delivered successor basis is not complete and exclusive")
		}
		control, err := contract.DecodeControlCore(image.Control)
		if err != nil {
			t.Fatal("delivered successor control is invalid", err)
		}
		coordinate, nonBody = control.CoordinateID, control.NonBodyID
		for _, row := range image.Enrollment {
			id, err := hex.DecodeString(row.ID)
			if err != nil || len(id) != 32 {
				t.Fatal("delivered successor enrollment identity is invalid")
			}
			enrollment := core.PublicEnrollment{RecipientID: contract.ID(id), DisplayName: row.DisplayName}
			switch row.Status {
			case "current":
				enrollment.Status = contract.CurrentRecipient
			case "retired":
				enrollment.Status = contract.RetiredRecipient
			default:
				t.Fatal("delivered successor enrollment status is invalid")
			}
			basis.Enrollment = append(basis.Enrollment, enrollment)
		}
	case "observation":
		if len(fields) != 6 || len(image.Descriptor) != 0 || len(image.Control) != 0 || len(image.Selection) != 0 || len(image.Enrollment) != 0 || len(image.SigningAnchor) == 0 || len(image.StoreConfiguration) == 0 || len(image.HEAD) == 0 || len(image.Root) == 0 || len(image.RecipientPages) == 0 {
			t.Fatal("delivered observation basis is not complete and exclusive")
		}
		head, err := stateformat.DecodeHead(image.HEAD)
		if err != nil {
			t.Fatal("delivered observation HEAD is invalid", err)
		}
		coordinate, nonBody = head.Core.Coordinate, head.Core.NonBody
	default:
		t.Fatal("delivered public basis kind is invalid")
	}
	domainID, err := hex.DecodeString(generated.Domain.ID)
	if err != nil || len(domainID) != 32 {
		t.Fatal("delivered domain identity is invalid")
	}
	family := contract.AWS
	switch editable.Domain.Provider {
	case "aws":
	case "gcp":
		family = contract.GCP
	default:
		t.Fatal("delivered provider is invalid")
	}
	store := editable.Domain.Store
	storeID, err := contract.StoreConfigurationID(contract.StoreConfiguration{Provider: family, ConstructionProfile: contract.StoreConstructionProfile,
		DomainID: contract.ID(domainID), Region: store.Region, Bucket: store.Bucket, PrefixBeforeHEAD: store.Prefix, ExpectedOwner: store.ExpectedOwner})
	if err != nil {
		t.Fatal("delivered store configuration is invalid", err)
	}
	p.control, err = basis.ControlCore(contract.ID(domainID), contract.Descriptor{Family: family, Identity: storeID, Coordinate: coordinate, NonBody: nonBody, Prefix: store.Prefix, HeadKey: store.Prefix + "/HEAD"})
	if err != nil {
		t.Fatal("delivered public basis failed verification against its source", err)
	}
	id, err := hex.DecodeString(generated.FileID)
	if err != nil || len(id) != 32 {
		t.Fatal("delivered file identity is invalid")
	}
	copy(p.fileID[:], id)
	p.sealed = generated.Secrets["binary"].Sealed
	return p
}
func workflowSetup(t *testing.T, s *workflowServer, recovery bool) []byte {
	t.Helper()
	recoveryRole := map[string]any{"enabled": recovery}
	if recovery {
		recoveryRole["signing_key"], recoveryRole["encryption_key"] = s.selector(3), s.selector(4)
	}
	source := map[string]any{"schema": "enkv/configuration/v3", "domain": map[string]any{"name": "prod", "provider": "aws", "store": map[string]any{"region": "us-east-1", "bucket": "fixture-bucket", "prefix": s.prefix, "expected_owner": "123456789012"}, "authority": map[string]any{"display_name": "Authority", "signing_key": s.selector(1), "encryption_key": s.selector(2)}, "recovery": recoveryRole}, "recipients": map[string]any{"reader": map[string]any{"display_name": "Reader", "encryption_key": s.selector(5)}}, "entries": map[string]any{}, "outputs": map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}}
	if s.family == "gcp" {
		domain := source["domain"].(map[string]any)
		domain["provider"] = "gcp"
		domain["store"] = map[string]any{"region": "us-central1", "bucket": "fixture-bucket", "prefix": s.prefix}
	}
	body, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type workflowOutput struct {
	Schema           string
	State            string `json:"state_result"`
	Receipt          string `json:"receipt_hex"`
	OperationPayload string `json:"operation_payload"`
	Payload          struct {
		Schema, Verdict     string
		DiagnosticsComplete bool                              `json:"diagnostics_complete"`
		EvidenceLimit       string                            `json:"evidence_limit"`
		Scope               []struct{ Family, Status string } `json:"checked_scope"`
	}
	Observation struct {
		Revision string `json:"head_revision_id"`
	}
}
type workflowChild struct {
	summary            string
	code               int
	out, diagnostic    []byte
	capture            observer.Capture
	cancellation       *workflowCancelGate
	generatedResources map[string]contract.GeneratorSafeFacts
}

func workflowEnvironment(home, phase string) []string {
	result := []string{}
	for _, entry := range os.Environ() {
		name := strings.SplitN(entry, "=", 2)[0]
		if name == "HOME" || name == "XDG_CONFIG_HOME" || strings.HasPrefix(name, "AWS_") || strings.HasPrefix(name, "GOOGLE_") || strings.HasPrefix(name, "GCLOUD_") || strings.HasPrefix(name, "CLOUDSDK_") || strings.HasPrefix(name, "ENKV_") || strings.HasPrefix(name, "EXPERIMENTAL_GOOGLE_") {
			continue
		}
		result = append(result, entry)
	}
	// These are synthetic local signing labels. They do not prove SSO or any
	// standard user login; the real SDK source constructor still owns selection.
	return append(result, "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"), "AWS_ACCESS_KEY_ID="+workflowAccess(phase), "AWS_SECRET_ACCESS_KEY=offline-local-not-a-cloud-secret", "AWS_EC2_METADATA_DISABLED=true", "AWS_CONFIG_FILE="+filepath.Join(home, "absent-config"), "AWS_SHARED_CREDENTIALS_FILE="+filepath.Join(home, "absent-credentials"))
}

type workflowLimitedOutput struct {
	bytes.Buffer
	overflow bool
}

func (w *workflowLimitedOutput) Write(body []byte) (int, error) {
	if len(body) > 1<<20-w.Len() {
		w.overflow = true
		return 0, io.ErrShortWrite
	}
	return w.Buffer.Write(body)
}
func workflowRun(t *testing.T, s *workflowServer, binary, phase string, policy observer.Policy, input []byte, args ...string) workflowChild {
	return workflowRunEnvironment(t, s, binary, phase, policy, input, nil, args...)
}

func workflowRunEnvironment(t *testing.T, s *workflowServer, binary, phase string, policy observer.Policy, input []byte, extraEnvironment []string, args ...string) workflowChild {
	t.Helper()
	return workflowRunDeclaredEnvironment(t, s, binary, phase, policy, input, extraEnvironment, nil, args...)
}

func workflowRunDeclaredEnvironment(t *testing.T, s *workflowServer, binary, phase string, policy observer.Policy, input []byte, extraEnvironment, declaredNames []string, args ...string) workflowChild {
	t.Helper()
	requestLimit, admitted := s.admitChild()
	if !admitted {
		t.Fatal("offline workflow finite child admission refused")
	}
	private := t.TempDir()
	record := filepath.Join(private, "capture.jsonl")
	if os.WriteFile(record, nil, 0600) != nil {
		t.Fatal("capture unavailable")
	}
	policy.Version, policy.RecordPath, policy.Bucket, policy.Prefix = 1, record, "fixture-bucket", s.prefix
	policy.MaxRequests, policy.MaxBytes = uint64(requestLimit), 64<<20
	if s.childBytesLimit != 0 {
		policy.MaxBytes = s.childBytesLimit
	}
	policy.LocalAddress = strings.TrimPrefix(s.server.URL, "https://")
	policy.RootCAPEM = s.rootPEM
	if policy.NormalSigner == "" {
		policy.NormalSigner = s.selector(1)
	}
	policy.SuccessorSigner = s.selector(6)
	if policy.AuthorityKEK == "" {
		policy.AuthorityKEK = s.selector(2)
	}
	if _, ok := s.keys[s.selector(3)]; ok {
		if policy.RecoverySigner == "" {
			policy.RecoverySigner = s.selector(3)
		}
		if policy.RecoveryKEK == "" {
			policy.RecoveryKEK = s.selector(4)
		}
	}
	if s.family == "gcp" {
		policy.QuotaProject = "fixture-quota"
	}
	body, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(private, "policy.json")
	if os.WriteFile(policyPath, body, 0600) != nil {
		t.Fatal("policy unavailable")
	}
	timeout := 2 * time.Minute
	if s.childTimeout != 0 {
		timeout = s.childTimeout
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = private
	environment := s.environment(t, private, phase)
	seen := map[string]bool{}
	for _, setting := range extraEnvironment {
		name, value, found := strings.Cut(setting, "=")
		if !found || seen[name] {
			t.Fatal("ambiguous additional native environment")
		}
		switch name {
		case "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_EC2_METADATA_DISABLED", "GOOGLE_APPLICATION_CREDENTIALS", "GCE_METADATA_HOST", "GITHUB_TOKEN":
		case "HOME", "XDG_CONFIG_HOME":
			info, err := os.Lstat(value)
			if err != nil || !filepath.IsAbs(value) || filepath.Clean(value) != value || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
				t.Fatal("additional native application directory is not private")
			}
		default:
			if !slices.Contains(declaredNames, name) || name == "ENKV_NATIVE_PROCESS_POLICY" {
				t.Fatal("unsupported additional native environment")
			}
		}
		seen[name] = true
	}
	environment = slices.DeleteFunc(environment, func(setting string) bool { name, _, _ := strings.Cut(setting, "="); return seen[name] })
	environment = append(environment, extraEnvironment...)
	command.Env = append(environment, "ENKV_NATIVE_PROCESS_POLICY="+policyPath)
	command.Stdin = bytes.NewReader(input)
	var stdout, stderr workflowLimitedOutput
	var gate *workflowCancelGate
	command.Stdout, command.Stderr = &stdout, &stderr
	if policy.Fault == "cancel-private-return" {
		gate = &workflowCancelGate{ready: make(chan *os.Process, 1)}
		s.mu.Lock()
		if s.cancelGate != nil {
			s.mu.Unlock()
			t.Fatal("cancellation gate reused")
		}
		s.cancelGate = gate
		s.mu.Unlock()
		if err = command.Start(); err == nil {
			gate.ready <- command.Process
			err = command.Wait()
		}
	} else {
		err = command.Run()
	}
	code := 0
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal("public process did not join", err)
		}
		code = exit.ExitCode()
	}
	if ctx.Err() != nil || stdout.overflow || stderr.overflow {
		t.Fatal("public process exceeded finite bounds")
	}
	capture, err := observer.ReadCapture(record)
	if err != nil {
		commandName := "unknown"
		if len(args) != 0 {
			switch args[0] {
			case "init", "set", "apply", "publish", "materialize", "plan", "prepare", "inspect", "receipt", "manifest", "keys", "abandon", "gc":
				commandName = args[0]
			}
		}
		t.Logf("native observation failure: command=%s %s", commandName, s.summary(phase))
		captureBytes := int64(-1)
		if info, statErr := os.Stat(record); statErr == nil {
			captureBytes = info.Size()
		}
		progress, progressErr := observer.ReadProgress(record)
		footer, entries, returns, plaintext, matched := false, 0, 0, 0, 0
		identities := make(map[string]bool)
		lastKind := "none"
		lastOperation, lastStatus := "none", 0
		if progressErr == nil {
			for _, event := range progress.Events {
				lastKind = event.Kind
				lastOperation, lastStatus = event.Operation, event.Status
				switch event.Kind {
				case "footer":
					footer = true
				case "generator-entry":
					entries++
				case "generator-return":
					returns++
				case "plaintext":
					plaintext++
					identities[event.EntrySHA256] = true
					if event.Matched {
						matched++
					}
				}
			}
		}
		encodedFooter, footerErr := json.Marshal(observer.Event{Kind: "footer", Code: code})
		footerRoom := captureBytes >= 0 && footerErr == nil && captureBytes+int64(len(encodedFooter))+1 <= observer.MaxCaptureBytes
		panicPrefix := bytes.HasPrefix(stderr.Bytes(), []byte("panic:")) || bytes.Contains(stderr.Bytes(), []byte("\npanic:"))
		fatalPrefix := bytes.HasPrefix(stderr.Bytes(), []byte("fatal error:")) || bytes.Contains(stderr.Bytes(), []byte("\nfatal error:"))
		t.Logf("native observation failure facts: exit=%d stdout_bytes=%d stderr_bytes=%d capture_bytes=%d panic_prefix=%t fatal_prefix=%t progress_valid=%t progress_events=%d footer_observed=%t footer_room=%t generator_entries=%d generator_returns=%d", code, stdout.Len(), stderr.Len(), captureBytes, panicPrefix, fatalPrefix, progressErr == nil, len(progress.Events), footer, footerRoom, entries, returns)
		sanitizer := bytes.Contains(stderr.Bytes(), []byte("ThreadSanitizer"))
		t.Logf("native runtime failure facts: sanitizer=%t out_of_memory=%t mapping_failure=%t race_warning=%t goroutine_limit=%t plaintext_events=%d plaintext_matched=%d distinct_entries=%d last_event=%s", sanitizer, sanitizer && bytes.Contains(stderr.Bytes(), []byte("out of memory")), sanitizer && bytes.Contains(stderr.Bytes(), []byte("mmap")), bytes.Contains(stderr.Bytes(), []byte("WARNING: DATA RACE")), bytes.Contains(stderr.Bytes(), []byte("simultaneously alive goroutines")), plaintext, matched, len(identities), lastKind)
		if sanitizer {
			var allocation, decimal uint64
			var action string
			known, internal := false, false
			if _, suffix, found := strings.Cut(stderr.String(), "FATAL: ThreadSanitizer: internal allocator is out of memory trying to allocate "); found {
				n, _ := fmt.Sscanf(suffix, "0x%x bytes", &allocation)
				known, internal = n == 1, true
			} else if _, suffix, found := strings.Cut(stderr.String(), "ERROR: ThreadSanitizer: out of memory: failed to "); found {
				n, _ := fmt.Sscanf(suffix, "%s 0x%x (%d) bytes", &action, &allocation, &decimal)
				known = n == 3 && allocation == decimal
			}
			t.Logf("native sanitizer allocation facts: parsed=%t internal_allocator=%t allocation_bytes=%d", known, internal, allocation)
		}
		t.Logf("native final transport facts: operation=%s status=%d", lastOperation, lastStatus)
		for i := 0; i+1 < len(args); i++ {
			if args[i] != "--source" {
				continue
			}
			parent := filepath.Dir(args[i+1])
			for class, pattern := range []string{".enkv-editable-*", ".enkv/.enkv-generated-*", ".enkv/*.generated.json"} {
				paths, listErr := filepath.Glob(filepath.Join(parent, pattern))
				valid := listErr == nil && len(paths) <= 4
				var size int64
				for _, path := range paths[:min(4, len(paths))] {
					info, statErr := os.Lstat(path)
					if statErr != nil || !info.Mode().IsRegular() {
						valid = false
						continue
					}
					size += info.Size()
				}
				t.Logf("native local image facts: class=%d count=%d bytes=%d metadata_complete=%t", class, len(paths), size, valid)
			}
			break
		}
		t.Fatal("public process lost complete native observation", err)
	}
	footer := capture.Events[len(capture.Events)-1]
	if footer.Kind != "footer" || footer.Code != code {
		t.Fatal("normal footer did not agree with actual process exit")
	}
	s.clean(t)
	if gate != nil {
		s.mu.Lock()
		if s.cancelGate != gate {
			s.mu.Unlock()
			t.Fatal("joined child lost its cancellation barrier")
		}
		s.cancelGate = nil
		s.mu.Unlock()
	}
	return workflowChild{cancellation: gate, code: code, out: bytes.Clone(stdout.Bytes()), diagnostic: bytes.Clone(stderr.Bytes()), capture: capture, summary: s.summary(phase)}
}
func workflowResult(t *testing.T, child workflowChild, state string) workflowOutput {
	t.Helper()
	var result workflowOutput
	decodeErr := json.Unmarshal(child.out, &result)
	if child.code != 0 || decodeErr != nil || result.Schema != "ProductResult/v1" || result.State != state {
		workflowCoreFailureTelemetry(t, child.diagnostic)
		var failure struct {
			Identity struct{ Schema, Stage, Code string } `json:"request_identity"`
			Commit   bool                                 `json:"commit_may_have_occurred"`
		}
		failureDecoded := json.Unmarshal(child.out, &failure) == nil
		stage, code := "other", "other"
		switch failure.Identity.Stage {
		case "dispatch", "input", "context", "capture", "parse", "declaration", "construction", "resolution", "observation", "installation", "initialize", "apply", "compare", "rekey", "retire", "output", "local-cleanup", "public-configuration":
			stage = failure.Identity.Stage
		}
		switch failure.Identity.Code {
		case "invalid-input", "unsupported-schema", "missing-required-field", "duplicate-key", "duplicate-member", "invalid-field-combination", "limit-exceeded", "unresolved-reference", "source-unavailable", "evidence-unavailable", "cancelled", "expired", "unsupported-apply-change", "trust-basis-invalid", "domain-basis-invalid", "store-basis-invalid", "refused":
			code = failure.Identity.Code
		}
		t.Logf("public failure boundary: decoded=%t pre_admission=%t stage=%s code=%s commit_possible=%t", failureDecoded, failure.Identity.Schema == "PreAdmissionRequestIdentity/v1", stage, code, failure.Commit)
		facts := []string{}
		events := child.capture.Events
		if len(events) > 32 {
			events = events[len(events)-32:]
		}
		for _, event := range events {
			if event.Kind == "http-start" || event.Kind == "http-return" || event.Kind == "footer" {
				facts = append(facts, fmt.Sprintf("%s:%s:%s:sent=%t:status=%d:code=%d", event.Kind, event.Operation, event.Role, event.Sent, event.Status, event.Code))
			}
		}
		t.Fatalf("public operation expected=%s actual=%s valid_schema=%t has_init_payload=%t exit=%d decoded=%t %s last_events=%v", state, workflowSafeState(result.State), result.Schema == "ProductResult/v1", result.OperationPayload == "InitPayload/v1", child.code, decodeErr == nil, child.summary, facts)
	}
	return result
}
func workflowReceipt(t *testing.T, encoded string, kind uint16) contract.CompactMutationReceipt {
	t.Helper()
	body, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal("receipt encoding invalid")
	}
	receipt, err := contract.InspectCompactMutationReceipt(body)
	if err != nil || receipt.OperationKind != kind || receipt.StateResult != contract.ReceiptStateSuccess || receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected {
		t.Fatal("public success did not carry its exact selected compact receipt", err)
	}
	return receipt
}
func workflowGETOnly(t *testing.T, child workflowChild) {
	t.Helper()
	requests := 0
	for _, event := range child.capture.Events {
		if event.Kind == "http-start" {
			requests++
			if !event.Sent || (event.Operation != "head-read" && event.Operation != "store-read") {
				t.Fatal("public GET-only process attempted another capability")
			}
		}
		if event.Kind == "plaintext" || event.Kind == "recovery-plaintext" {
			t.Fatal("public Reader borrowed private material")
		}
	}
	if requests == 0 {
		t.Fatal("public Reader did not read current state")
	}
}
func workflowPlaintext(t *testing.T, child workflowChild, kind string) {
	t.Helper()
	count := 0
	for _, event := range child.capture.Events {
		switch event.Kind {
		case kind:
			if event.Count != 1 || !event.Matched {
				t.Fatal("actual borrowed plaintext differed from independent bytes")
			}
			count++
		case "plaintext", "recovery-plaintext":
			t.Fatal("another plaintext route was borrowed")
		}
	}
	if count != 1 {
		t.Fatal("exact plaintext observation missing")
	}
}
func workflowNoRecovery(t *testing.T, child workflowChild) {
	t.Helper()
	for _, event := range child.capture.Events {
		if event.Kind == "http-start" && (event.Operation == "kms-decrypt" && event.Role == "recovery-private" || event.Operation == "kms-sign" && event.Role == "recovery-signing") {
			t.Fatal("normal operation attempted a Recovery route")
		}
	}
}
func workflowHead(t *testing.T, s *workflowServer) (stateformat.Head, workflowObject) {
	t.Helper()
	object := s.object(t, s.prefix+"/HEAD")
	head, err := stateformat.DecodeHead(object.body)
	if err != nil {
		t.Fatal("actual selected HEAD is invalid", err)
	}
	return head, object
}
func workflowRoot(t *testing.T, s *workflowServer, head stateformat.Head) stateformat.Root {
	t.Helper()
	key, err := stateformat.Key(s.prefix, head.Core.Root)
	if err != nil {
		t.Fatal(err)
	}
	object := s.object(t, key)
	if contract.Hash(object.body) != head.Core.Root.Digest {
		t.Fatal("ROOT digest differs")
	}
	root, err := stateformat.DecodeRoot(object.body)
	if err != nil {
		t.Fatal(err)
	}
	return root
}
func workflowUnchanged(t *testing.T, path string, pair workflowPair) {
	t.Helper()
	editable, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("portable editable readback failed", err)
	}
	generated, err := os.ReadFile(filepath.Join(filepath.Dir(path), pair.reference))
	if err != nil {
		t.Fatal("portable generated readback failed", err)
	}
	if !bytes.Equal(editable, pair.editable) || !bytes.Equal(generated, pair.generated) {
		t.Fatal("read or remote apply changed portable pair")
	}
}
func workflowPublicProcess(t *testing.T, cli, helper, family string, recovery bool) {
	s := newWorkflowServer(t, family, recovery)
	machine := t.TempDir()
	path := filepath.Join(machine, "configuration.json")
	setup := workflowSetup(t, s, recovery)
	if err := os.WriteFile(path, setup, 0600); err != nil {
		t.Fatal(err)
	}
	initialized := workflowRun(t, s, cli, "init", observer.Policy{}, nil, "init", "--source", path, "--source-format", "json", "--json")
	initResult := workflowResult(t, initialized, "success")
	initReceipt := workflowReceipt(t, initResult.Receipt, contract.OperationInitializeDomain)
	if initResult.OperationPayload != "InitPayload/v1" || initResult.Payload.Schema != "InitPayload/v1" {
		t.Fatal("ready initialization payload missing")
	}
	pair := workflowReadPair(t, path)
	d := pair.descriptor
	head, originalHead := workflowHead(t, s)
	root := workflowRoot(t, s, head)
	if head.Core.Form != stateformat.GenesisHead || head.Genesis == nil || head.Genesis.Request.SetupDigest != contract.Hash(setup) || head.Genesis.Request.Expiry == 0 || head.Genesis.Request.RecoveryMode != d.RecoveryMode() || d.RecoveryMode() != uint8(boolInt(recovery)) || root.ValueEntryCount != 0 || root.SecretCount != 0 || initReceipt.DomainID != d.DomainID || initReceipt.ObservedRevisionID != head.Core.Revision {
		t.Fatal("empty genesis did not bind original setup, mode and selected receipt")
	}
	if !bytes.Equal(d.NormalSigning.SPKI, s.keys[s.selector(1)].der) {
		t.Fatal("descriptor signing public material differs from local exact resource")
	}
	for _, recipient := range d.Recipients {
		if recipient.CurrentBinding == nil || !bytes.Equal(recipient.CurrentBinding.SPKI, s.keys[recipient.CurrentBinding.KeySelector].der) {
			t.Fatal("descriptor recipient binding differs from resolved public material")
		}
	}
	if recovery && (d.Recovery == nil || !bytes.Equal(d.Recovery.Signing.SPKI, s.keys[s.selector(3)].der) || !bytes.Equal(d.Recovery.KMS.SPKI, s.keys[s.selector(4)].der)) {
		t.Fatal("Recovery descriptor differs from exact resource")
	}
	manifestPath := filepath.Join(machine, ".enkv", hex.EncodeToString(d.ManifestArtifactID[:])+".init")
	manifest, err := os.ReadFile(manifestPath)
	if err != nil || contract.Hash(manifest) != head.Genesis.Closure.ManifestDigest {
		t.Fatal("selected closure did not bind delivered manifest", err)
	}
	counts := s.snapshot("init")
	if counts.headCreates != 1 || counts.headUpdates != 0 || counts.creates != 6 || counts.conditions != 0 || counts.calls["Sign/normal"] != 2 || counts.calls["Decrypt/authority"] != 1 || counts.calls["Decrypt/ordinary"] != 0 || counts.calls["Decrypt/recovery-private"] != boolInt(recovery) || counts.calls["Sign/recovery-signing"] != 2*boolInt(recovery) {
		t.Fatal("initialization effects or exact role qualification counts differ", counts)
	}
	retry := workflowRun(t, s, cli, "retry", observer.Policy{NoKMS: true}, nil, "init", "--source", path, "--source-format", "json", "--json")
	retryResult := workflowResult(t, retry, "exact-resume")
	workflowGETOnly(t, retry)
	_, afterRetry := workflowHead(t, s)
	if retryResult.Receipt != initResult.Receipt || afterRetry.etag != originalHead.etag || !bytes.Equal(afterRetry.body, originalHead.body) {
		t.Fatal("same-init observation changed the original selected receipt or HEAD")
	}
	workflowUnchanged(t, path, pair)
	workflowPlainSet(t, s, cli, path, pair)
	plaintext := append([]byte("independent offline supplied binary value: "), []byte{0, 255, 1, 2, 3, 4, 5, 0, 250, 128, 99, 88, 77, 66, 55, 44}...)
	defer clear(plaintext)
	afterSet := workflowPrepare(t, s, cli, path, "set", pair, plaintext)
	applied := workflowRun(t, s, cli, "apply", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--json")
	applyResult := workflowResult(t, applied, "success")
	applyReceipt := workflowReceipt(t, applyResult.Receipt, contract.OperationApplyDeclaration)
	workflowNoRecovery(t, applied)
	workflowUnchanged(t, path, afterSet)
	selected, selectedObject := workflowHead(t, s)
	selectedRoot := workflowRoot(t, s, selected)
	if selected.Core.Form != stateformat.SuccessorHead || selected.Core.PreviousRevision != head.Core.Revision || selected.Core.PreviousDigest != contract.Hash(originalHead.body) || selected.Core.PreviousToken != (contract.Token{Family: d.Provider, Value: originalHead.etag}) || selected.Core.Revision == head.Core.Revision || selectedObject.etag == originalHead.etag || selectedRoot.ValueEntryCount != 1 || selectedRoot.SecretCount != 1 || applyReceipt.PredecessorRevisionID != head.Core.Revision || applyReceipt.ObservedRevisionID != selected.Core.Revision {
		t.Fatal("fresh apply did not select one exact conditional successor")
	}
	counts = s.snapshot("apply")
	if counts.headCreates != 0 || counts.headUpdates != 1 || counts.creates != 7 || counts.conditions != 0 || counts.calls["Sign/normal"] != 1 || counts.calls["Decrypt/authority"] != 2 || counts.calls["Decrypt/recovery-private"] != 0 || counts.calls["Sign/recovery-signing"] != 0 || counts.calls["Decrypt/ordinary"] != 0 {
		t.Fatal("fresh normal apply used unexpected authority or effect counts", counts)
	}
	if (selectedRoot.CurrentAccess.Core.Recovery != nil) != recovery {
		t.Fatal("apply changed fixed Recovery mode")
	}
	workflowRecoveryWraps(t, s, selectedRoot, recovery)
	workflowSupportIndexes(t, root, []uint16{0, 1})
	workflowSupportIndexes(t, selectedRoot, []uint16{0, 1, 2})
	firstEntry := workflowEntry(t, s, selectedRoot)
	firstSelected, firstSelectedObject := selected, selectedObject
	retainedOutput := selectedRoot.RequiredSupport[0]
	changedPlaintext := append([]byte("different independent replacement for the existing secret: "), []byte{255, 0, 12, 34, 56, 78, 90, 0, 128, 254, 253, 252, 251, 250, 249, 248, 247}...)
	defer clear(changedPlaintext)
	if bytes.Equal(plaintext, changedPlaintext) {
		t.Fatal("changed-value fixture repeated the birth bytes")
	}
	afterChangeSet := workflowPrepare(t, s, cli, path, "set-change", afterSet, changedPlaintext)
	changed := workflowRun(t, s, cli, "change", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--json")
	changedResult := workflowResult(t, changed, "success")
	changedReceipt := workflowReceipt(t, changedResult.Receipt, contract.OperationApplyDeclaration)
	workflowNoRecovery(t, changed)
	workflowUnchanged(t, path, afterChangeSet)
	selected, selectedObject = workflowHead(t, s)
	selectedRoot = workflowRoot(t, s, selected)
	changedEntry := workflowEntry(t, s, selectedRoot)
	if selected.Core.PreviousRevision != firstSelected.Core.Revision || selected.Core.PreviousDigest != contract.Hash(firstSelectedObject.body) || selected.Core.PreviousToken != (contract.Token{Family: d.Provider, Value: firstSelectedObject.etag}) || selected.Core.Revision == firstSelected.Core.Revision || selectedObject.etag == firstSelectedObject.etag || changedReceipt.PredecessorRevisionID != firstSelected.Core.Revision || changedReceipt.ObservedRevisionID != selected.Core.Revision || changedReceipt.OperationID == applyReceipt.OperationID || changedResult.Receipt == applyResult.Receipt || selectedRoot.ValueEntryCount != 1 || selectedRoot.SecretCount != 1 || changedEntry.Incarnation != firstEntry.Incarnation || changedEntry.ValueState == firstEntry.ValueState {
		t.Fatal("changed existing secret did not select a fresh value under the same entry identity")
	}
	workflowSupportIndexes(t, selectedRoot, []uint16{0, 1, 2})
	if selectedRoot.RequiredSupport[0] != retainedOutput {
		t.Fatal("changed apply rewrote the unchanged output support page")
	}
	if selectedRoot.RequiredSupport[1] == workflowRoot(t, s, firstSelected).RequiredSupport[1] || selectedRoot.RequiredSupport[2] == workflowRoot(t, s, firstSelected).RequiredSupport[2] {
		t.Fatal("changed apply retained its old receipt window or index")
	}
	counts = s.snapshot("change")
	if counts.headCreates != 0 || counts.headUpdates != 1 || counts.creates != 6 || counts.conditions != 0 || counts.calls["Sign/normal"] != 1 || counts.calls["Decrypt/authority"] != 3 || counts.calls["Decrypt/recovery-private"] != 0 || counts.calls["Sign/recovery-signing"] != 0 || counts.calls["Decrypt/ordinary"] != 0 {
		t.Fatal("changed existing secret used unexpected capabilities or effect counts", counts)
	}
	workflowRecoveryWraps(t, s, selectedRoot, recovery)
	objectsBeforeNoop := s.objectCount()
	noop := workflowRun(t, s, cli, "noop", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--json")
	noopResult := workflowResult(t, noop, "no-op")
	var noopPayload struct{ Payload json.RawMessage }
	if json.Unmarshal(noop.out, &noopPayload) != nil || string(noopPayload.Payload) != "null" || noopResult.Receipt != "" {
		t.Fatal("unchanged repeat fabricated a transition or receipt")
	}
	workflowNoRecovery(t, noop)
	for _, event := range noop.capture.Events {
		if event.Kind == "http-start" && event.Operation != "head-read" && event.Operation != "store-read" && event.Operation != "kms-public" && (event.Operation != "kms-decrypt" || event.Role != "authority") {
			t.Fatal("true no-op attempted a write or signature")
		}
	}
	counts = s.snapshot("noop")
	if counts.headCreates != 0 || counts.headUpdates != 0 || counts.creates != 0 || counts.conditions != 0 || counts.calls["Sign/normal"] != 0 || counts.calls["Decrypt/authority"] != 2 || counts.calls["Decrypt/recovery-private"] != 0 || s.objectCount() != objectsBeforeNoop {
		t.Fatal("unchanged repeat did not remain a true no-op", counts)
	}
	_, afterNoop := workflowHead(t, s)
	if afterNoop.etag != selectedObject.etag || !bytes.Equal(afterNoop.body, selectedObject.body) {
		t.Fatal("true no-op changed HEAD or its version")
	}
	workflowUnchanged(t, path, afterChangeSet)
	afterSet, plaintext = afterChangeSet, changedPlaintext
	portable := t.TempDir()
	portablePath := filepath.Join(portable, "configuration.json")
	if os.Mkdir(filepath.Join(portable, ".enkv"), 0700) != nil || os.WriteFile(portablePath, afterSet.editable, 0600) != nil || os.WriteFile(filepath.Join(portable, afterSet.reference), afterSet.generated, 0600) != nil {
		t.Fatal("portable pair copy unavailable")
	}
	copied, err := os.ReadDir(filepath.Join(portable, ".enkv"))
	if err != nil || len(copied) != 1 {
		t.Fatal("portable machine contains more than the exact pair")
	}
	compared := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", portablePath, "--trusted-format", "json", "--json")
	comparison := workflowResult(t, compared, "success")
	workflowGETOnly(t, compared)
	workflowUnchanged(t, portablePath, afterSet)
	if comparison.Payload.Schema != "ComparisonPayload/v1" || comparison.Payload.Verdict != "match" || !comparison.Payload.DiagnosticsComplete || comparison.Payload.EvidenceLimit != contract.ComparisonEvidenceLimit || len(comparison.Payload.Scope) != 12 || comparison.Observation.Revision != hex.EncodeToString(selected.Core.Revision[:]) {
		t.Fatal("portable Reader did not report complete current public comparison")
	}
	for _, scope := range comparison.Payload.Scope {
		if scope.Status != "complete" {
			t.Fatal("portable Reader comparison scope incomplete")
		}
	}
	sum := sha256.Sum256(plaintext)
	expected := map[string]string{"binary": hex.EncodeToString(sum[:])}
	reconstructed := workflowRun(t, s, helper, "authority", observer.Policy{ExpectedSHA256: expected}, nil, "--source", portablePath, "--source-format", "json")
	if reconstructed.code != 0 {
		t.Fatal("fresh production Authority reconstruction refused")
	}
	workflowPlaintext(t, reconstructed, "plaintext")
	workflowNoRecovery(t, reconstructed)
	counts = s.snapshot("authority")
	if counts.calls["Decrypt/authority"] != 1 || counts.headCreates != 0 || counts.headUpdates != 0 || counts.creates != 0 {
		t.Fatal("Authority reconstruction capability counts differ", counts)
	}
	if recovery {
		binding, err := contract.EncodeBindingTable([]contract.BindingTableRow{{SubjectKind: contract.RecoveryWrapSubject, SubjectID: d.Recovery.RoleID, Binding: d.Recovery.KMS}})
		if err != nil {
			t.Fatal(err)
		}
		oracle := workflowRun(t, s, helper, "recovery", observer.Policy{ExpectedSHA256: expected, RecoveryOracle: true, RecoveryBinding: binding}, nil, "--source", portablePath, "--source-format", "json")
		if oracle.code != 2 {
			t.Fatal("Recovery oracle was presented as Product reconstruction success")
		}
		workflowPlaintext(t, oracle, "recovery-plaintext")
		counts = s.snapshot("recovery")
		if counts.calls["Decrypt/recovery-private"] != 1 || counts.calls["Decrypt/authority"] != 0 || counts.headCreates != 0 || counts.headUpdates != 0 || counts.creates != 0 {
			t.Fatal("independent Recovery oracle used another authority", counts)
		}
	}
	workflowUnchanged(t, portablePath, afterSet)
	_, lastHead := workflowHead(t, s)
	if lastHead.etag != selectedObject.etag || !bytes.Equal(lastHead.body, selectedObject.body) {
		t.Fatal("post-apply public/private observation changed HEAD")
	}
	s.clean(t)
	workflowFaults(t, s, cli, path, afterSet, selected, selectedObject, recovery)
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func workflowDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func workflowPrepare(t *testing.T, s *workflowServer, cli, path, phase string, pair workflowPair, plaintext []byte) workflowPair {
	t.Helper()
	d := pair.control
	prepared := workflowRun(t, s, cli, phase, observer.Policy{NoKMS: true}, plaintext, "set", "--source", path, "--source-format", "json", "--name", "binary", "--json")
	var setResult struct {
		Schema           string
		State            string `json:"state_result"`
		OperationPayload string `json:"operation_payload"`
		Payload          struct {
			Schema      string
			FileID      string `json:"input_file_id"`
			Predecessor string `json:"predecessor_digest"`
			Target      struct {
				Domain string `json:"domain_id"`
				Name   string
			}
			Artifact string `json:"sealed_artifact_digest"`
			Readback struct {
				Editable  string `json:"editable_digest"`
				Generated string `json:"generated_digest"`
			}
		}
	}
	if prepared.code != 0 || json.Unmarshal(prepared.out, &setResult) != nil || setResult.Schema != "ProductResult/v1" || setResult.State != "success" || setResult.OperationPayload != "SealedArtifactPayload/v1" || setResult.Payload.Schema != "SealedArtifactPayload/v1" || len(prepared.capture.Events) != 1 {
		t.Fatal("native set did not complete without any provider operation")
	}
	afterSet := workflowReadPair(t, path)
	envelope, err := contract.DecodeSealedInputEnvelope(afterSet.sealed)
	if err != nil || envelope.Core.Name != "binary" || envelope.Core.ContentLength != uint32(len(plaintext)) || envelope.Core.DomainID != d.DomainID || envelope.Core.FileIdentity != pair.fileID || envelope.Core.FilePredecessorDigest != contract.Hash(pair.editable) {
		t.Fatal("set did not preserve exact sealed source provenance", err)
	}
	if setResult.Payload.FileID != hex.EncodeToString(pair.fileID[:]) || setResult.Payload.Predecessor != workflowDigest(pair.editable) || setResult.Payload.Target.Domain != hex.EncodeToString(d.DomainID[:]) || setResult.Payload.Target.Name != "binary" || setResult.Payload.Artifact != workflowDigest(afterSet.sealed) || setResult.Payload.Readback.Editable != workflowDigest(afterSet.editable) || setResult.Payload.Readback.Generated != workflowDigest(afterSet.generated) {
		t.Fatal("native set result lost exact request or readback anchors")
	}
	for _, body := range [][]byte{prepared.out, prepared.diagnostic, afterSet.editable, afterSet.generated, afterSet.sealed} {
		if bytes.Contains(body, plaintext) || bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(plaintext))) {
			t.Fatal("set disclosed plaintext in native files or output")
		}
	}
	return afterSet
}

func workflowRecoveryWraps(t *testing.T, s *workflowServer, selectedRoot stateformat.Root, recovery bool) {
	t.Helper()
	recoveryWraps := 0
	for _, ref := range selectedRoot.CurrentAccess.Core.AccessPageRefs {
		key, err := stateformat.Key(s.prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		object := s.object(t, key)
		page, err := stateformat.DecodeAccessPage(object.body)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range page.Records {
			for _, wrap := range record.Wraps {
				if wrap.SubjectKind == contract.RecoveryWrapSubject {
					recoveryWraps++
				}
			}
		}
	}
	if recoveryWraps != boolInt(recovery) {
		t.Fatal("selected value did not preserve exact Recovery wrap mode")
	}
}

func workflowSupportIndexes(t *testing.T, root stateformat.Root, expected []uint16) {
	t.Helper()
	if len(root.RequiredSupport) != len(expected) {
		t.Fatal("selected support page cardinality differs")
	}
	for i, ref := range root.RequiredSupport {
		if ref.Index != expected[i] {
			t.Fatal("selected support page index differs")
		}
	}
}
func workflowEntry(t *testing.T, s *workflowServer, root stateformat.Root) contract.ValueEntry {
	t.Helper()
	if len(root.Names) != 1 || root.Names[0].Name != "binary" {
		t.Fatal("selected entry name differs")
	}
	slot := root.Names[0].Slot
	ref := root.ValueEntryPages[int(slot)/stateformat.PageSlots]
	if ref == nil {
		t.Fatal("selected value entry page absent")
	}
	key, err := stateformat.Key(s.prefix, *ref)
	if err != nil {
		t.Fatal(err)
	}
	object := s.object(t, key)
	page, err := stateformat.DecodeValueEntryPage(object.body)
	if err != nil || page.Slots[int(slot)%stateformat.PageSlots] == nil {
		t.Fatal("selected value entry invalid", err)
	}
	return *page.Slots[int(slot)%stateformat.PageSlots]
}

func workflowSafeState(state string) string {
	switch state {
	case "success", "exact-resume", "no-op", "refused", "unavailable", "contention", "commit-outcome-unknown", "positive-defect", "root-loss-unsupported", "snapshot-size-refusal", "possible-live-residue-accepted", "retirement-pending", "effect-pending", "effect-partial", "effect-unknown", "effect-terminal-failure":
		return state
	}
	return "invalid"
}

func workflowPlainSet(t *testing.T, s *workflowServer, cli, original string, pair workflowPair) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "configuration.json")
	var before map[string]any
	if json.Unmarshal(pair.editable, &before) != nil {
		t.Fatal("plain copy source unavailable")
	}
	before["entries"] = map[string]any{"kept": map[string]any{"confidentiality": "plain", "recipients": []any{}, "source": map[string]any{"kind": "supplied", "value": "unrelated value\u0000"}}}
	body, err := json.Marshal(before)
	if err != nil || os.MkdirAll(filepath.Dir(filepath.Join(directory, pair.reference)), 0700) != nil || os.WriteFile(path, body, 0600) != nil || os.WriteFile(filepath.Join(directory, pair.reference), pair.generated, 0400) != nil {
		t.Fatal("isolated plain source copy unavailable")
	}
	_, head := workflowHead(t, s)
	objects := s.objectCount()
	value := []byte{'l', 'o', 'c', 'a', 'l', 0, 255, 128}
	result := workflowRun(t, s, cli, "plain", observer.Policy{NoKMS: true}, value, "set", "--source", path, "--source-format", "json", "--name", "plain", "--confidential=false", "--json")
	var local struct {
		LocalEdit string `json:"local_edit"`
		Outcome   string `json:"outcome"`
	}
	if result.code != 0 || json.Unmarshal(result.out, &local) != nil || local.LocalEdit != "plain" || local.Outcome != "edited" || len(result.capture.Events) != 1 || result.capture.Events[0].Kind != "footer" || result.capture.Events[0].Code != 0 {
		t.Fatal("actual plain set did not join local editing without discovery or HTTP")
	}
	body, err = os.ReadFile(path)
	var after map[string]any
	if err != nil || json.Unmarshal(body, &after) != nil {
		t.Fatal("plain source readback unavailable")
	}
	entries, ok := after["entries"].(map[string]any)
	if !ok {
		t.Fatal("plain source entries unavailable")
	}
	entry, ok := entries["plain"].(map[string]any)
	if !ok {
		t.Fatal("plain local entry unavailable")
	}
	supplied, ok := entry["source"].(map[string]any)
	if !ok || entry["confidentiality"] != "plain" || supplied["kind"] != "supplied" || supplied["bytes"] != base64.StdEncoding.EncodeToString(value) {
		t.Fatal("plain local entry changed exact arbitrary bytes")
	}
	delete(entries, "plain")
	if !reflect.DeepEqual(after, before) {
		t.Fatal("plain set changed an unrelated configuration value")
	}
	generated, err := os.ReadFile(filepath.Join(directory, pair.reference))
	_, afterHead := workflowHead(t, s)
	if err != nil || !bytes.Equal(generated, pair.generated) || !bytes.Equal(afterHead.body, head.body) || afterHead.etag != head.etag || s.objectCount() != objects {
		t.Fatal("plain set changed the exact generated dependency or remote state")
	}
	workflowUnchanged(t, original, pair)
}

func workflowCoreFailureTelemetry(t *testing.T, diagnostic []byte) {
	t.Helper()
	results := []telemetry.Result{telemetry.ResultSuccess, telemetry.ResultFailure, telemetry.ResultUnknown, telemetry.ResultUnchanged, telemetry.ResultObservedCurrent, telemetry.ResultContention, telemetry.ResultUnresolvedCommit, telemetry.ResultIntegrityFailure, telemetry.ResultEvidenceUnavailable, telemetry.ResultRootLossUnsupported, telemetry.ResultAdmissionRefused, telemetry.ResultCancelled, telemetry.ResultCapacityExceeded, telemetry.ResultReadMissing}
	reasons := []telemetry.DiagnosticReason{telemetry.DiagnosticReasonNone, telemetry.DiagnosticReasonAdmissionRefused, telemetry.DiagnosticReasonIntegrityFailure, telemetry.DiagnosticReasonEvidenceUnavailable, telemetry.DiagnosticReasonInvalid, telemetry.DiagnosticReasonDenied, telemetry.DiagnosticReasonCancelled, telemetry.DiagnosticReasonUncertain, telemetry.DiagnosticReasonAdmissionInvalid, telemetry.DiagnosticReasonConstructionMismatch, telemetry.DiagnosticReasonInvalidFormat, telemetry.DiagnosticReasonInvalidProof, telemetry.DiagnosticReasonInvalidReference, telemetry.DiagnosticReasonInvalidRelation, telemetry.DiagnosticReasonMissingSelectedObject, telemetry.DiagnosticReasonReadUnavailable, telemetry.DiagnosticReasonImmutableConflict, telemetry.DiagnosticReasonCapacityExceeded, telemetry.DiagnosticReasonInvalidIntent, telemetry.DiagnosticReasonSigningUnavailable, telemetry.DiagnosticReasonWriteUncertain, telemetry.DiagnosticReasonStalePrecondition, telemetry.DiagnosticReasonDifferentSelection, telemetry.DiagnosticReasonAlreadyUsed, telemetry.DiagnosticReasonCustodyUnavailable}
	lines := strings.Split(string(diagnostic), "\n")
	for _, operation := range []telemetry.Operation{telemetry.OpCoreCompare, telemetry.OpCoreApply, telemetry.OpCoreGeneratedRetire, telemetry.OpPluginRetained} {
		observed := 0
		for _, line := range lines {
			if !strings.Contains(line, " operation="+strconv.Quote(string(operation))+" ") || !strings.Contains(line, " event="+strconv.Quote(string(telemetry.DiagnosticReturn))+" ") {
				continue
			}
			observed++
			if observed > 4 {
				continue
			}
			result, reason := "other", "other"
			for _, value := range results {
				if strings.Contains(line, " result="+strconv.Quote(string(value))+" ") {
					result = string(value)
					break
				}
			}
			for _, value := range reasons {
				if strings.Contains(line, " reason="+strconv.Quote(string(value))+" ") {
					reason = string(value)
					break
				}
			}
			t.Logf("captured operation telemetry: operation=%s result=%s reason=%s", operation, result, reason)
		}
		t.Logf("captured operation telemetry inventory: operation=%s return_records=%d", operation, observed)
	}
}
