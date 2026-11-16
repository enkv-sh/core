package nativeprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

type workflowMaterializationGate struct {
	owner              string
	method, host, path string
	entered, release   chan struct{}
	once               sync.Once
}

// Only the selected request waits. Other children can advance HEAD and perform
// GC while this handler owns neither the server mutex nor a stored body.
func (s *workflowServer) waitMaterialization(w http.ResponseWriter, r *http.Request) bool {
	s.mu.Lock()
	gate := s.materializationGate
	s.mu.Unlock()
	if gate == nil || r.Method != gate.method || r.Host != gate.host || r.URL.Path != gate.path {
		return true
	}
	owner := gate.owner
	if owner == "" {
		owner = "materialize"
	}
	authorization := r.Header.Get("Authorization")
	principal := authorization == "Bearer offline-native-"+owner || strings.Contains(authorization, "Credential="+workflowAccess(owner)+"/")
	if !principal {
		return true
	}
	selected := false
	gate.once.Do(func() { selected = true })
	if !selected {
		return true
	}
	controller := http.NewResponseController(w)
	deadline := time.Now().Add(90 * time.Second)
	if err := controller.SetReadDeadline(deadline); err != nil {
		s.mu.Lock()
		s.fail(w, "materialization-gate-read-deadline")
		s.mu.Unlock()
		return false
	}
	if err := controller.SetWriteDeadline(deadline); err != nil {
		s.mu.Lock()
		s.fail(w, "materialization-gate-write-deadline")
		s.mu.Unlock()
		return false
	}
	close(gate.entered)
	timer := time.NewTimer(90 * time.Second)
	defer timer.Stop()
	select {
	case <-gate.release:
		return true
	case <-r.Context().Done():
	case <-timer.C:
	}
	s.mu.Lock()
	s.fail(w, "materialization-gate-unjoined")
	s.mu.Unlock()
	return false
}

type nativeMaterializationFixture struct {
	source, recipient, recipientKey string
	pair                            workflowPair
	head                            stateformat.Head
	root                            stateformat.Root
	entries                         map[string]contract.ValueEntry
	children                        []workflowChild
}

func nativeMaterializationSetup(t *testing.T, s *workflowServer, cli string, generator *nativeGeneratedExecutables) nativeMaterializationFixture {
	t.Helper()
	generated := generator != nil
	source := filepath.Join(t.TempDir(), "configuration.json")
	if err := os.WriteFile(source, workflowSetup(t, s, false), 0600); err != nil {
		t.Fatal("materialization source setup failed", err)
	}
	children := []workflowChild{workflowRun(t, s, cli, "init", observer.Policy{}, nil, "init", "--source", source, "--source-format", "json", "--json")}
	workflowResult(t, children[0], "success")
	if generated {
		nativeGeneratedDeclaration(t, source, nativeGeneratedAccountA, "manual", 0, true)
	}
	nativePublicationSource(t, source, func(source map[string]any) {
		entries := source["entries"].(map[string]any)
		entries["PLAIN"] = map[string]any{"confidentiality": "plain", "recipients": []string{"reader"}, "source": map[string]any{"kind": "supplied", "value": "public #selected"}}
		entries["PRIVATE"] = map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "value": "authority-only selected"}}
		entries["SUPPLIED"] = map[string]any{"confidentiality": "secret", "recipients": []string{"reader"}, "source": map[string]any{"kind": "supplied"}}
		if generated {
			entries["generated"].(map[string]any)["recipients"] = []string{"reader"}
		}
	})
	children = append(children, workflowRun(t, s, cli, "set", observer.Policy{NoKMS: true}, []byte("selected supplied\nsecond"), "set", "--source", source, "--source-format", "json", "--name", "SUPPLIED", "--json"))
	workflowResult(t, children[1], "success")
	var environment []string
	if generator != nil {
		environment = nativeGeneratedEnvironment(t, *generator, source)
	}
	children = append(children, workflowRunEnvironment(t, s, cli, "apply", observer.Policy{}, nil, environment, "apply", "--source", source, "--source-format", "json", "--json"))
	workflowResult(t, children[2], "success")
	pair := workflowReadPair(t, source)
	head, _ := workflowHead(t, s)
	root := workflowRoot(t, s, head)
	var recipient contract.ID
	for _, row := range pair.descriptor.Recipients {
		if row.RecipientID != pair.descriptor.AuthorityRecipientID {
			recipient = row.RecipientID
		}
	}
	if recipient.IsZero() || root.ValueEntryCount != uint32(map[bool]int{false: 3, true: 4}[generated]) || root.SecretCount != uint32(map[bool]int{false: 1, true: 2}[generated]) {
		t.Fatal("materialization setup has no complete mixed current selection")
	}
	f := nativeMaterializationObservation(t, s, source, hex.EncodeToString(recipient[:]), pair)
	f.children = children
	return f
}

func nativeMaterializationObservation(t *testing.T, s *workflowServer, source, recipient string, pair workflowPair) nativeMaterializationFixture {
	t.Helper()
	head, _ := workflowHead(t, s)
	root := workflowRoot(t, s, head)
	entries := map[string]contract.ValueEntry{}
	for _, ref := range root.ValueEntryPages {
		if ref == nil {
			continue
		}
		key, err := stateformat.Key(s.prefix, *ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := stateformat.DecodeValueEntryPage(s.object(t, key).body)
		if err != nil {
			t.Fatal("selected entry page is invalid", err)
		}
		for _, entry := range page.Slots {
			if entry == nil {
				continue
			}
			row := *entry
			row.ValueBytes, row.Recipients = nil, nil
			entries[row.Name] = row
		}
	}
	return nativeMaterializationFixture{source: source, recipient: recipient, recipientKey: s.selector(5), pair: pair, head: head, root: root, entries: entries}
}

func nativeMaterializationRun(t *testing.T, s *workflowServer, cli, source, format, recipient, destination string, names ...string) workflowChild {
	t.Helper()
	args := []string{"materialize", "--source", source, "--source-format", format, "--out", destination, "--json"}
	if recipient != "" {
		args = append(args, "--recipient-id", recipient)
	}
	for _, name := range names {
		args = append(args, "--name", name)
	}
	return workflowRun(t, s, cli, "materialize", observer.Policy{RecipientKEK: s.selector(5)}, nil, args...)
}

func nativeMaterializationCapabilities(t *testing.T, child workflowChild, decrypts, constructions int) {
	t.Helper()
	nativeMaterializationRecipientCapabilities(t, child, "recipient-private", decrypts, constructions)
}

func nativeMaterializationRecipientCapabilities(t *testing.T, child workflowChild, role string, decrypts, constructions int) {
	t.Helper()
	opened, calls := 0, 0
	for _, event := range child.capture.Events {
		switch event.Kind {
		case "plaintext", "recovery-plaintext", "generator-entry", "generator-return":
			t.Fatal("materialization entered another plaintext or effect owner")
		case "construction":
			if event.Operation != "key-access" || event.Role != role {
				t.Fatal("materialization constructed another private capability", event.Operation, event.Role)
			}
			opened++
		case "http-start":
			if !event.Sent {
				t.Fatal("materialization attempted an unadmitted physical route")
			}
			switch event.Operation {
			case "head-read", "store-read":
			case "kms-decrypt":
				if event.Role != role {
					t.Fatal("materialization entered another recipient route")
				}
				calls++
			default:
				t.Fatal("materialization reached a write, metadata, signing or output operation", event.Operation)
			}
		}
	}
	if opened != constructions || calls != decrypts {
		t.Fatal("materialization private capability inventory differs", opened, calls, constructions, decrypts)
	}
}

type nativeMaterializationReply struct {
	Schema    string                          `json:"schema"`
	Operation string                          `json:"operation_kind"`
	State     string                          `json:"state_result"`
	Kind      string                          `json:"operation_payload"`
	Effect    string                          `json:"effect_summary"`
	Output    string                          `json:"output_summary"`
	Replay    string                          `json:"replay_identity"`
	Failure   *struct{ Stage, Reason string } `json:"failure"`
	Payload   *struct {
		Schema    string `json:"schema"`
		Identity  string `json:"request_identity"`
		Domain    string `json:"domain_id"`
		Revision  string `json:"head_revision_id"`
		Snapshot  string `json:"snapshot_id"`
		Recipient struct {
			ID      string `json:"recipient_id"`
			Binding struct {
				Selector string `json:"key_selector"`
			} `json:"binding"`
		} `json:"recipient"`
		Target struct {
			Path     string `json:"path"`
			Identity string `json:"surface_id"`
			Format   string `json:"format"`
			Profile  string `json:"native_profile"`
		} `json:"target"`
		Entries []struct {
			Name            string `json:"name"`
			Slot            uint16 `json:"slot"`
			Incarnation     string `json:"entry_incarnation_id"`
			Value           string `json:"value_state_id"`
			Source          uint8  `json:"value_source"`
			Confidentiality uint8  `json:"confidentiality_class"`
		} `json:"entries"`
		Facts map[string]json.RawMessage `json:"facts"`
	} `json:"payload"`
}

func nativeMaterializationResult(t *testing.T, child workflowChild, state string, payload bool) nativeMaterializationReply {
	t.Helper()
	var out nativeMaterializationReply
	var fields map[string]json.RawMessage
	if json.Unmarshal(child.out, &out) != nil || json.Unmarshal(child.out, &fields) != nil || out.Schema != "ProductResult/v1" || out.Operation != "materialize" || out.State != state || (child.code == 0) != (state == "success") || (out.Payload != nil) != payload || out.Effect != "not-applicable" || out.Output != "not-applicable" || out.Replay != "none" {
		t.Fatal("materialization did not return its closed public result", child.summary, child.code, state)
	}
	if state == "success" && out.Failure != nil || state != "success" && out.Failure == nil || fields["receipt_hex"] != nil {
		t.Fatal("materialization lost failure facts or fabricated a mutation receipt")
	}
	for _, name := range []string{"effects", "outputs", "duties", "hazards", "warning_summary"} {
		var rows []json.RawMessage
		if json.Unmarshal(fields[name], &rows) != nil || len(rows) != 0 {
			t.Fatal("materialization returned unrelated mutation or publication facts", name)
		}
	}
	if payload {
		if out.Kind != "MaterializationPayload/v1" || out.Payload.Schema != out.Kind {
			t.Fatal("materialization payload schema differs")
		}
	} else if out.Kind != "none" {
		t.Fatal("materialization fabricated a selected payload")
	}
	return out
}

func nativeMaterializationSelected(t *testing.T, s *workflowServer, child workflowChild, f nativeMaterializationFixture, destination string, names ...string) {
	t.Helper()
	out := nativeMaterializationResult(t, child, "success", true)
	p := out.Payload
	if p.Identity == "" || p.Domain != hex.EncodeToString(f.root.Domain[:]) || p.Revision != hex.EncodeToString(f.head.Core.Revision[:]) || p.Snapshot != hex.EncodeToString(f.root.Snapshot[:]) || p.Recipient.ID != f.recipient || p.Recipient.Binding.Selector != f.recipientKey || p.Target.Path != destination || p.Target.Identity == "" || p.Target.Format != contract.MaterializationDotenvFormat || p.Target.Profile != contract.MaterializationNativeFileProfile {
		t.Fatal("materialization changed its fixed selected or local surface identity")
	}
	wantNames := slices.Clone(names)
	slices.Sort(wantNames)
	if len(p.Entries) != len(wantNames) {
		t.Fatal("materialization omitted a selected result member")
	}
	for i, name := range wantNames {
		var slot uint16
		found := false
		for _, row := range f.root.Names {
			if row.Name == name {
				slot, found = row.Slot, true
			}
		}
		if !found || p.Entries[i].Name != name || p.Entries[i].Slot != slot {
			t.Fatal("materialization changed the complete ordered selected names")
		}
		entry, present := f.entries[name]
		if !present || p.Entries[i].Incarnation != hex.EncodeToString(entry.Incarnation[:]) || p.Entries[i].Value != hex.EncodeToString(entry.ValueState[:]) || p.Entries[i].Source != entry.ValueSource || p.Entries[i].Confidentiality != entry.ConfidentialityClass {
			t.Fatal("materialization changed a selected result member identity")
		}
	}
	for name, want := range map[string]string{"replacement": "replaced", "candidate_verification": "verified", "installed_verification": "verified", "native_completion": "complete", "plaintext_disk_disclosure": "occurred", "candidate_cleanup": "renamed"} {
		var got string
		if json.Unmarshal(p.Facts[name], &got) != nil || got != want {
			t.Fatal("materialization success lost a required local completion fact", name)
		}
	}
	for _, name := range []string{"failure", "cleanup_failure", "residue_path"} {
		if field := p.Facts[name]; len(field) != 0 && !bytes.Equal(field, []byte("null")) && !bytes.Equal(field, []byte(`""`)) {
			t.Fatal("materialization success retained a failure or residue", name)
		}
	}
}

func nativeMaterializationFile(t *testing.T, destination, expected string, values map[string]string) {
	t.Helper()
	body, err := os.ReadFile(destination)
	defer clear(body)
	info, statErr := os.Lstat(destination)
	if err != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !bytes.Equal(body, []byte(expected)) {
		t.Fatal("materialization did not install the complete independent expected bytes and private mode")
	}
	input, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "-e", nativeMaterializationConsumer, destination)
	command.Dir = filepath.Join(nativeRepository(t), "tests", "fixtures", "dotenv-consumer")
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil || string(output) != "complete-map\n" {
		t.Fatal("pinned application consumer did not confirm the complete installed map")
	}
}

const nativeMaterializationConsumer = `
const fs=require('node:fs'); const dotenv=require('dotenv');
if(process.version!=='v24.19.0'||require('./node_modules/dotenv/package.json').version!=='18.0.9')process.exit(2);
const expected=JSON.parse(fs.readFileSync(0,'utf8')); const actual=dotenv.parse(fs.readFileSync(process.argv[1]));
const names=Object.keys(expected).sort(), got=Object.keys(actual).sort();
if(names.length!==got.length||names.some((name,i)=>name!==got[i]||typeof actual[name]!=='string'||!Buffer.from(actual[name]).equals(Buffer.from(expected[name]))))process.exit(3);
process.stdout.write('complete-map\n');
`

func nativeMaterializationSafe(t *testing.T, child workflowChild, values map[string]string, encoded string) {
	t.Helper()
	all := []string{encoded}
	for _, value := range values {
		all = append(all, value)
	}
	for _, value := range all {
		if value == "" {
			continue
		}
		digest := sha256.Sum256([]byte(value))
		for _, body := range [][]byte{child.out, child.diagnostic} {
			for _, forbidden := range []string{value, base64.StdEncoding.EncodeToString([]byte(value)), hex.EncodeToString(digest[:])} {
				if bytes.Contains(body, []byte(forbidden)) {
					t.Fatal("materialization disclosed value bytes or a plaintext-derived digest")
				}
			}
		}
	}
}

// full_only: false
func TestPublicNativeMaterializationUsesSelectedRecipientValues(t *testing.T) {
	generated := newNativeGeneratedServer(t)
	// This existing installation admits only fixture generation. Materialize
	// itself still uses the production public constructor and native file sink.
	binaries := buildNativeGeneratedExecutables(t, generated.server.URL+"/client/v4")
	for _, family := range []string{"aws", "gcp"} {
		for _, format := range []string{"json", "yaml"} {
			t.Run(family+"/"+format, func(t *testing.T) {
				binaries := binaries
				binaries.home = nativeGeneratedPrivateDirectory(t)
				s := newWorkflowServer(t, family, false)
				s.childLimit, s.childRequestLimit, s.objectLimit = 12, 1024, 256
				t.Cleanup(func() { t.Log("materialization native inventory:", s.summary("materialize")) })
				t.Setenv("CLOUDFLARE_API_TOKEN", nativeGeneratedBearerA)
				requests, _ := generated.snapshot()
				generatedValue := nativeGeneratedSecret + "_" + fmt.Sprintf("%032x", len(requests)+1)
				f := nativeMaterializationSetup(t, s, binaries.cli, &binaries)
				created, resources := generated.snapshot()
				if len(created) != len(requests)+1 || created[len(created)-1].Method != http.MethodPost || resources != len(created) {
					t.Fatal("mixed fixture did not obtain one real generated value")
				}
				t.Setenv("CLOUDFLARE_API_TOKEN", "")
				nativePublicationSource(t, f.source, func(source map[string]any) {
					entries := source["entries"].(map[string]any)
					entries["PLAIN"].(map[string]any)["source"].(map[string]any)["value"] = "unapplied plain value"
					entries["PRIVATE"].(map[string]any)["recipients"] = []string{"reader"}
					entries["SUPPLIED"].(map[string]any)["recipients"] = []string{}
					entries["generated"].(map[string]any)["source"].(map[string]any)["epoch"] = uint64(1)
					source["outputs"] = map[string]any{
						"destinations": map[string]any{"pending": map[string]any{
							"plugin": "private-materialization-output-absent", "settings": map[string]any{"name": "unapplied-output"},
						}},
						"routing": map[string]any{"default": []string{"pending"}},
					}
				})
				workflowResult(t, workflowRun(t, s, binaries.cli, "set-change", observer.Policy{NoKMS: true}, []byte("unapplied supplied value"), "set", "--source", f.source, "--source-format", "json", "--name", "SUPPLIED", "--json"), "success")
				f.pair = workflowReadPair(t, f.source)
				source := f.source
				if format == "yaml" {
					source = nativePublicationYAML(t, f.source)
				}
				images := nativePublicationImages(t, f.source, source, filepath.Join(filepath.Dir(f.source), f.pair.reference))
				_, before := workflowHead(t, s)
				objects := s.objectCount()
				values := map[string]string{"PLAIN": "public #selected", "SUPPLIED": "selected supplied\nsecond", "generated": generatedValue}
				expected := "PLAIN='public #selected'\nSUPPLIED='selected supplied\nsecond'\ngenerated=" + generatedValue + "\n"
				out := filepath.Join(t.TempDir(), "application.env")
				if err := os.WriteFile(out, []byte("old complete file\n"), 0644); err != nil {
					t.Fatal(err)
				}
				mixed := workflowRun(t, s, binaries.cli, "materialize", observer.Policy{RecipientKEK: s.selector(5)}, nil, "materialize", "--source", source, "--source-format", format, "--out", out, "--json", "--recipient", "reader", "--name", "generated", "--name", "SUPPLIED", "--name", "PLAIN")
				nativeMaterializationCapabilities(t, mixed, 2, 1)
				nativeMaterializationSelected(t, s, mixed, f, out, "PLAIN", "SUPPLIED", "generated")
				nativeMaterializationFile(t, out, expected, values)
				nativeMaterializationSafe(t, mixed, values, expected)
				plain := filepath.Join(t.TempDir(), "plain.env")
				plainChild := nativeMaterializationRun(t, s, binaries.cli, source, format, f.recipient, plain, "PLAIN")
				nativeMaterializationCapabilities(t, plainChild, 0, 0)
				nativeMaterializationSelected(t, s, plainChild, f, plain, "PLAIN")
				nativeMaterializationFile(t, plain, "PLAIN='public #selected'\n", map[string]string{"PLAIN": "public #selected"})
				for _, selection := range []struct {
					recipient string
					names     []string
				}{{f.recipient, []string{"PLAIN", "PRIVATE"}}, {f.recipient, []string{"PLAIN", "missing"}}} {
					refused := nativeMaterializationRun(t, s, binaries.cli, source, format, selection.recipient, out, selection.names...)
					nativeMaterializationResult(t, refused, "refused", false)
					nativeMaterializationCapabilities(t, refused, 0, 0)
					nativeMaterializationSafe(t, refused, values, expected)
					nativeMaterializationFile(t, out, expected, values)
				}
				authorityPath := filepath.Join(t.TempDir(), "authority.env")
				s.mu.Lock()
				s.materializationRecipientKey = s.selector(2)
				s.mu.Unlock()
				authorityChild := workflowRun(t, s, binaries.cli, "materialize", observer.Policy{RecipientKEK: s.selector(2)}, nil, "materialize", "--source", source, "--source-format", format, "--out", authorityPath, "--json", "--name", "PLAIN", "--name", "SUPPLIED")
				s.mu.Lock()
				s.materializationRecipientKey = s.selector(5)
				s.mu.Unlock()
				authorityFixture := f
				authorityFixture.recipient = hex.EncodeToString(f.root.CurrentAccess.Core.AuthorityRecipientID[:])
				authorityFixture.recipientKey = s.selector(2)
				nativeMaterializationRecipientCapabilities(t, authorityChild, "authority", 1, 1)
				nativeMaterializationSelected(t, s, authorityChild, authorityFixture, authorityPath, "PLAIN", "SUPPLIED")
				authorityValues := map[string]string{"PLAIN": "public #selected", "SUPPLIED": "selected supplied\nsecond"}
				authorityBytes := "PLAIN='public #selected'\nSUPPLIED='selected supplied\nsecond'\n"
				nativeMaterializationFile(t, authorityPath, authorityBytes, authorityValues)
				nativeMaterializationSafe(t, authorityChild, authorityValues, authorityBytes)
				for _, alias := range []string{source, filepath.Join(filepath.Dir(f.source), f.pair.reference)} {
					refused := nativeMaterializationRun(t, s, binaries.cli, source, format, f.recipient, alias, "SUPPLIED")
					nativeMaterializationResult(t, refused, "refused", false)
					nativeMaterializationCapabilities(t, refused, 0, 0)
					for _, event := range refused.capture.Events {
						if event.Kind == "http-start" {
							t.Fatal("source alias reached provider admission")
						}
					}
				}
				s.mu.Lock()
				s.materializationDecryptDenied = true
				s.mu.Unlock()
				denied := nativeMaterializationRun(t, s, binaries.cli, source, format, f.recipient, out, "PLAIN", "SUPPLIED")
				deniedResult := nativeMaterializationResult(t, denied, "unavailable", true)
				for name, want := range map[string]string{"replacement": "not-replaced", "candidate_verification": "not-observed", "installed_verification": "not-observed", "native_completion": "not-observed", "plaintext_disk_disclosure": "none", "candidate_cleanup": "not-created"} {
					var got string
					if json.Unmarshal(deniedResult.Payload.Facts[name], &got) != nil || got != want {
						t.Fatal("denied private route lost its exact pre-staging fact", name)
					}
				}
				if deniedResult.Failure.Stage != "authentication" || deniedResult.Failure.Reason != "private-route-unavailable" {
					t.Fatal("denied private route did not retain its safe owning failure")
				}
				nativeMaterializationCapabilities(t, denied, 1, 1)
				nativeMaterializationSafe(t, denied, values, expected)
				nativeMaterializationFile(t, out, expected, values)
				nativePublicationUnchanged(t, images)
				_, after := workflowHead(t, s)
				afterRequests, afterResources := generated.snapshot()
				if !reflect.DeepEqual(before, after) || objects != s.objectCount() || !reflect.DeepEqual(created, afterRequests) || resources != afterResources || s.children != s.childLimit {
					t.Fatal("materialization changed canonical/source state, reached generation or lost a child join")
				}
			})
		}
	}
}

func nativeMaterializationGC(t *testing.T, s *workflowServer, cli, source, oldKey string) []workflowChild {
	t.Helper()
	head, _ := workflowHead(t, s)
	root := workflowRoot(t, s, head)
	original := s.object(t, oldKey)
	s.mu.Lock()
	s.gcListPrefix = s.prefix + "/" + hex.EncodeToString(root.Domain[:]) + "/"
	s.gcListKeys = []string{oldKey}
	s.mu.Unlock()
	planPath := filepath.Join(administrativeReplacementDirectory(t), "selected.GCPlan")
	preview := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true, ListPrefix: s.gcListPrefix}, nil, "gc", "plan", "--source", source, "--source-format", "json", "--out", planPath, "--json")
	var previewResult struct {
		Schema        string `json:"schema"`
		Operation     string `json:"operation_kind"`
		State         string `json:"state_result"`
		Kind          string `json:"operation_payload"`
		FailureReason string `json:"failure_reason"`
		Delivery      struct {
			Created       bool `json:"plan_created"`
			Synced        bool `json:"plan_synced"`
			Readback      bool `json:"plan_readback"`
			Failed        bool `json:"plan_failed"`
			CleanupFailed bool `json:"cleanup_failed"`
		} `json:"delivery"`
	}
	decoded := json.Unmarshal(preview.out, &previewResult) == nil
	delivery := previewResult.Delivery
	t.Logf("materialization GC preview: exit=%d decoded=%t schema_valid=%t operation_valid=%t state=%s payload_valid=%t failure_reason_present=%t plan_created=%t plan_synced=%t plan_readback=%t plan_failed=%t cleanup_failed=%t", preview.code, decoded, previewResult.Schema == "ProductResult/v1", previewResult.Operation == "gc-plan", workflowSafeState(previewResult.State), previewResult.Kind == "CleanupPayload/v1", previewResult.FailureReason != "", delivery.Created, delivery.Synced, delivery.Readback, delivery.Failed, delivery.CleanupFailed)
	workflowGCReadOnly(t, preview)
	if !decoded || preview.code != 0 || previewResult.Schema != "ProductResult/v1" || previewResult.Operation != "gc-plan" || previewResult.State != "success" || previewResult.Kind != "CleanupPayload/v1" || !delivery.Created || !delivery.Synced || !delivery.Readback || delivery.Failed || delivery.CleanupFailed {
		t.Fatal("materialization GC preview did not complete protected plan delivery")
	}
	encoded, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal("materialization GC plan was not delivered", err)
	}
	plan, err := contract.DecodeGCPlan(encoded)
	if preview.code != 0 || err != nil || len(plan.Targets) != 1 || plan.Targets[0].Token.Value != original.etag || plan.Targets[0].Digest != contract.Hash(original.body) || plan.HeadRevisionID != head.Core.Revision {
		t.Fatal("materialization GC did not retain the exact obsolete selected child")
	}
	key, err := contract.StoreObjectKey(s.prefix, root.Domain, plan.Targets[0].Object)
	if err != nil || key != oldKey {
		t.Fatal("materialization GC changed its physical target")
	}
	before := s.snapshot("apply")
	applied := workflowRun(t, s, cli, "apply", observer.Policy{ListPrefix: s.gcListPrefix}, nil, "gc", "apply", "--source", source, "--source-format", "json", "--plan", planPath, "--json")
	workflowGCResult(t, applied, "success", 0)
	workflowGCMutationCapabilities(t, applied)
	deletes := 0
	for _, event := range applied.capture.Events {
		if event.Kind == "http-start" && event.Operation == "store-delete" {
			deletes++
			if !event.Sent || event.ObjectKeySHA256 != workflowDigest([]byte(oldKey)) || event.LogicalConditionKind != "match" || string(event.LogicalConditionValue) != original.etag || string(event.WireConditionValue) != original.etag {
				t.Fatal("materialization GC did not transmit its exact original conditional delete")
			}
		}
	}
	s.mu.Lock()
	_, present := s.objects[oldKey]
	s.mu.Unlock()
	if present || deletes != 1 || s.snapshot("apply").deletes-before.deletes != 1 {
		t.Fatal("materialization interleaving did not complete one actual GC deletion")
	}
	return []workflowChild{preview, applied}
}

func nativeMaterializationJoined(t *testing.T, children []workflowChild, want int) {
	t.Helper()
	if len(children) != want {
		t.Fatal("materialization sequence lost an exact child invocation", len(children), want)
	}
	for _, child := range children {
		if len(child.capture.Events) == 0 {
			t.Fatal("materialization sequence lost a joined child's capture")
		}
		footer := child.capture.Events[len(child.capture.Events)-1]
		if footer.Kind != "footer" || footer.Code != child.code {
			t.Fatal("materialization sequence lost an exact child terminal result")
		}
	}
}

func nativeMaterializationGCRace(t *testing.T, cli, family string, loaded bool) {
	t.Helper()
	s := newWorkflowServer(t, family, false)
	t.Cleanup(func() { t.Log("materialization GC native inventory:", s.summary("materialize"), s.summary("apply")) })
	// Eight exact children retain individual request/deadline bounds. The
	// existing fixed-sequence mode avoids resetting a ceiling under a held child.
	const childrenExpected = 8
	s.requestLimit, s.objectLimit = childrenExpected*workflowChildRequestLimit, 256
	f := nativeMaterializationSetup(t, s, cli, nil)
	children := slices.Clone(f.children)
	oldKey, err := stateformat.Key(s.prefix, *f.root.ValueEntryPages[0])
	if err != nil {
		t.Fatal(err)
	}
	nativePublicationSource(t, f.source, func(source map[string]any) {
		source["entries"].(map[string]any)["PLAIN"].(map[string]any)["source"].(map[string]any)["value"] = "successor #selected"
	})
	set := workflowRun(t, s, cli, "set-change", observer.Policy{NoKMS: true}, []byte("successor supplied\nsecond"), "set", "--source", f.source, "--source-format", "json", "--name", "SUPPLIED", "--json")
	workflowResult(t, set, "success")
	children = append(children, set)
	f.pair = workflowReadPair(t, f.source)
	images := nativePublicationImages(t, f.source, filepath.Join(filepath.Dir(f.source), f.pair.reference))
	gate := &workflowMaterializationGate{method: http.MethodGet, host: "s3.us-east-1.amazonaws.com", path: "/fixture-bucket/" + oldKey, entered: make(chan struct{}), release: make(chan struct{})}
	if family == "gcp" {
		gate.host, gate.path = "storage.us-central1.rep.googleapis.com", "/download/storage/v1/b/fixture-bucket/o/"+oldKey
	}
	if loaded {
		gate.method, gate.host, gate.path = http.MethodPost, "kms.us-east-1.amazonaws.com", "/"
		if family == "gcp" {
			gate.host, gate.path = "us-central1-cloudkms.googleapis.com", "/v1/"+s.selector(5)+":asymmetricDecrypt"
		}
	}
	s.mu.Lock()
	s.materializationGate = gate
	s.mu.Unlock()
	destination := filepath.Join(t.TempDir(), "application.env")
	if err := os.WriteFile(destination, []byte("old complete file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	joined := make(chan workflowChild, 1)
	go func() {
		var child workflowChild
		defer func() { joined <- child }()
		child = nativeMaterializationRun(t, s, cli, f.source, "json", f.recipient, destination, "SUPPLIED", "PLAIN")
	}()
	var release sync.Once
	var materialized workflowChild
	collected := false
	// Release and join before testing cancels t.Context for cleanup. An earlier
	// fixture assertion must retain the child's actual result under its lifetime.
	defer func() {
		release.Do(func() { close(gate.release) })
		if !collected {
			select {
			case materialized = <-joined:
				collected = true
			case <-time.After(60 * time.Second):
				t.Error("materialization child did not join after barrier release")
			}
		}
		completeCapture := false
		if events := materialized.capture.Events; len(events) != 0 {
			footer := events[len(events)-1]
			completeCapture = footer.Kind == "footer" && footer.Code == materialized.code
		}
		var result nativeMaterializationReply
		decoded := json.Unmarshal(materialized.out, &result) == nil
		t.Logf("materialization held child: joined=%t capture_complete=%t exit=%d decoded=%t schema_valid=%t state=%s payload_present=%t failure_present=%t", collected, completeCapture, materialized.code, decoded, result.Schema == "ProductResult/v1", workflowSafeState(result.State), result.Payload != nil, result.Failure != nil)
	}()
	select {
	case <-gate.entered:
	case materialized = <-joined:
		collected = true
		t.Fatal("materialization returned before its exact selected-image cut", materialized.code)
	case <-time.After(30 * time.Second):
		t.Fatal("materialization did not reach its exact selected-image cut")
	}
	readsAtCut := s.snapshot("materialize").reads
	applied := workflowRun(t, s, cli, "apply", observer.Policy{}, nil, "apply", "--source", f.source, "--source-format", "json", "--json")
	workflowResult(t, applied, "success")
	children = append(children, applied)
	successor := nativeMaterializationObservation(t, s, f.source, f.recipient, f.pair)
	nextKey, err := stateformat.Key(s.prefix, *successor.root.ValueEntryPages[0])
	if err != nil || nextKey == oldKey || successor.head.Core.Revision == f.head.Core.Revision || successor.head.Core.PreviousRevision != f.head.Core.Revision {
		t.Fatal("materialization cut did not select a distinct authentic successor")
	}
	children = append(children, nativeMaterializationGC(t, s, cli, f.source, oldKey)...)
	current := nativeMaterializationObservation(t, s, f.source, f.recipient, f.pair)
	if !reflect.DeepEqual(current.root.ValueEntryPages, successor.root.ValueEntryPages) || current.head.Core.Revision == successor.head.Core.Revision {
		t.Fatal("GC did not preserve complete successor values under its own changed HEAD")
	}
	if loaded {
		s.mu.Lock()
		s.materializationStoreDenied = true
		s.mu.Unlock()
	}
	_, finalHEAD := workflowHead(t, s)
	objects := s.objectCount()
	release.Do(func() { close(gate.release) })
	select {
	case materialized = <-joined:
		collected = true
	case <-time.After(60 * time.Second):
		t.Fatal("materialization did not finish and join after actual GC")
	}
	children = append(children, materialized)
	nativeMaterializationCapabilities(t, materialized, 1, 1)
	missing, heads := 0, 0
	firstPrivate := uint64(0)
	for _, event := range materialized.capture.Events {
		if event.Kind == "http-start" && event.Operation == "kms-decrypt" && firstPrivate == 0 {
			firstPrivate = event.Sequence
		}
		if event.Kind == "http-start" && event.Operation == "head-read" {
			heads++
		}
		if event.Kind == "http-return" && event.ObjectKeySHA256 == workflowDigest([]byte(oldKey)) && event.Status == 404 {
			missing++
		}
		if loaded && firstPrivate != 0 && event.Kind == "http-start" && (event.Operation == "store-read" || event.Operation == "head-read") {
			t.Fatal("loaded materialization performed a later Store read")
		}
	}
	if heads > map[string]int{"aws": 6, "gcp": 5}[family] {
		t.Fatal("materialization exceeded its original public HEAD-read budget")
	}
	values := map[string]string{"PLAIN": "successor #selected", "SUPPLIED": "successor supplied\nsecond"}
	expected := "PLAIN='successor #selected'\nSUPPLIED='successor supplied\nsecond'\n"
	selected := current
	if loaded {
		selected = f
		values = map[string]string{"PLAIN": "public #selected", "SUPPLIED": "selected supplied\nsecond"}
		expected = "PLAIN='public #selected'\nSUPPLIED='selected supplied\nsecond'\n"
		if missing != 0 || s.snapshot("materialize").reads != readsAtCut {
			t.Fatal("loaded materialization read Store after its complete private handoff")
		}
	} else if missing != 1 {
		t.Fatal("materialization did not observe exactly one actual deleted unread child", missing)
	}
	nativeMaterializationSelected(t, s, materialized, selected, destination, "PLAIN", "SUPPLIED")
	nativeMaterializationFile(t, destination, expected, values)
	nativeMaterializationSafe(t, materialized, values, expected)
	nativeMaterializationJoined(t, children, childrenExpected)
	nativePublicationUnchanged(t, images)
	_, after := workflowHead(t, s)
	if !reflect.DeepEqual(finalHEAD, after) || objects != s.objectCount() || s.children != 0 {
		t.Fatal("materialization mutated state or used sequential child admission during its held process")
	}
	t.Logf("materialization GC children=%d unread_missing=%d loaded=%t store_reads_at_cut=%d store_reads_final=%d head_reads=%d", len(children), missing, loaded, readsAtCut, s.snapshot("materialize").reads, heads)
}

// full_only: false
func TestPublicNativeMaterializationRestartsAfterGCRemovesUnreadChild(t *testing.T) {
	cli, _ := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) { nativeMaterializationGCRace(t, cli, family, false) })
	}
}

// full_only: false
func TestPublicNativeMaterializationCompletesLoadedSelectionAfterGC(t *testing.T) {
	cli, _ := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) { nativeMaterializationGCRace(t, cli, family, true) })
	}
}
