package nativeprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/crypto/testsupport/installedarchive"
	"enkv.sh/crypto/testsupport/installedarchive/recovery"
)

type nativePublicationHistory struct {
	server                                       *workflowServer
	source                                       string
	pair                                         workflowPair
	domain, coordinate, physical, birth, unknown string
	remoteCalls, effects                         int
	counts                                       nativePublicationCounts
	head                                         workflowObject
	root                                         stateformat.Root
	rows                                         map[string][]byte
}

// The responder first validates and applies each exact write. Closing its
// actual connection then removes the reply, without changing admission or
// inventing provider no-effect evidence.
func nativePublicationLostReplyEndpoint(t *testing.T, output *nativePublicationServer) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	lost := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "secretsmanager.PutSecretValue" {
			output.serve(w, r)
			return
		}
		response := httptest.NewRecorder()
		output.serve(response, r)
		if response.Code != http.StatusOK {
			for key, values := range response.Header() {
				w.Header()[key] = values
			}
			w.WriteHeader(response.Code)
			_, _ = w.Write(response.Body.Bytes())
			return
		}
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error("controlled successful-write reply could not be removed")
			return
		}
		lost.Add(1)
		if err := connection.Close(); err != nil {
			t.Error("controlled lost-reply connection did not close")
		}
	}))
	t.Cleanup(server.Close)
	return server, lost
}

func nativePublicationRemoteRequests(output *nativePublicationServer) int {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.requests
}

func nativePublicationUnknown(t *testing.T, child workflowChild, coordinate string, actions []string) nativePublicationOutput {
	t.Helper()
	var result nativePublicationOutput
	if child.code != 3 || json.Unmarshal(child.out, &result) != nil || result.Schema != "ProductResult/v1" || result.Operation != "publish" || result.State != "effect-unknown" || result.Summary != "output-unknown" || result.Replay != "none" || result.Effect != "not-applicable" || result.Payload.Schema != "OutputPayload/v3" || len(result.Payload.Entries) != 1 || result.Payload.Entries[0].Coordinate != coordinate || len(result.Payload.Entries[0].Actions) != len(actions) {
		t.Fatal("lost response did not retain one complete public unknown vector")
	}
	for i, action := range result.Payload.Entries[0].Actions {
		if action.Action == nil || *action.Action != actions[i] || action.Attempt == nil || len(*action.Attempt) != 64 || action.Projection == nil || len(*action.Projection) != 64 || action.Evidence == nil || action.Evidence.Entry != "may-have-entered" || action.Reason != 0 || !action.Remote {
			t.Fatal("lost response lost exact admitted action facts")
		}
		if i == len(actions)-1 {
			if action.Disposition != "unknown" || action.Evidence.Class != "unproved" || action.Evidence.Status != 0 || action.Evidence.Resource != "" {
				t.Fatal("lost response supplied stronger remote evidence")
			}
		} else if action.Disposition != "acknowledged" || action.Evidence.Class != "acknowledged" {
			t.Fatal("later lost reply erased selected container birth")
		}
	}
	return result
}

func nativePublicationID(t *testing.T, text string) contract.ID {
	t.Helper()
	var id contract.ID
	body, err := hex.DecodeString(text)
	if err != nil || len(body) != len(id) {
		t.Fatal("public publication identity unavailable")
	}
	copy(id[:], body)
	return id
}

func nativePublicationSelectedParts(t *testing.T, s *workflowServer) []installedarchive.Part {
	t.Helper()
	head, object := workflowHead(t, s)
	family, region := contract.AWS, "us-east-1"
	if s.family == "gcp" {
		family, region = contract.GCP, "us-central1"
	}
	archive := installedarchive.Archive{Family: family, Domain: head.Core.Domain, HeadDigest: contract.Hash(object.body), Revision: head.Core.Revision, Location: contract.StoreLocation{Provider: family, Region: region, Bucket: "fixture-bucket", PrefixBeforeHEAD: s.prefix}}
	s.mu.Lock()
	for key, value := range s.objects {
		archive.Objects = append(archive.Objects, installedarchive.Object{Key: key, Body: bytes.Clone(value.body)})
	}
	s.mu.Unlock()
	parts, err := archive.SelectedParts()
	if err != nil {
		t.Fatal("independent selected-part archive", err)
	}
	return parts
}

func nativePublicationRows(parts []installedarchive.Part) map[string][]byte {
	rows := map[string][]byte{}
	for _, part := range parts {
		if part.Kind == "support row" && (part.SupportKind == contract.PublicationCoordinateSupportKind || part.SupportKind == contract.PublicationMarkerSupportKind) {
			rows[fmt.Sprintf("%d/%x", part.SupportKind, part.RecordID)] = bytes.Clone(part.Body)
		}
	}
	return rows
}

func nativePublicationRemovedHistory(t *testing.T, binaries nativeOutputExecutables, output *nativePublicationServer, family, account string) nativePublicationHistory {
	t.Helper()
	s := newWorkflowServer(t, family, false)
	s.childLimit, s.childRequestLimit, s.objectLimit = 16, 2048, 256
	path := filepath.Join(t.TempDir(), "configuration.json")
	if os.WriteFile(path, workflowSetup(t, s, false), 0600) != nil {
		t.Fatal("public continuity setup unavailable")
	}
	environment := binaries.Environment(t, path)
	if family == "gcp" {
		environment = append(environment, "AWS_ACCESS_KEY_ID=AKIANATIVEOUTPUTTEST", "AWS_SECRET_ACCESS_KEY=offline-output-only", "AWS_EC2_METADATA_DISABLED=true")
	}
	run := func(phase string, policy observer.Policy, args ...string) workflowChild {
		return workflowRunEnvironment(t, s, binaries.cli, phase, policy, nil, environment, append(args, "--source", path, "--source-format", "json", "--json")...)
	}
	workflowResult(t, run("init", observer.Policy{}, "init"), "success")
	pair := workflowReadPair(t, path)
	domain := hex.EncodeToString(pair.descriptor.DomainID[:])
	const value = "selected continuity value"
	physical := "arn:aws:secretsmanager:us-east-1:" + account + ":secret:VALUE"
	output.expect(account, map[string][]byte{"aws:" + physical + "-AbCd12": []byte(value)})
	nativePublicationSource(t, path, func(source map[string]any) {
		source["entries"] = map[string]any{"VALUE": map[string]any{"confidentiality": "plain", "recipients": []any{}, "source": map[string]any{"kind": "supplied", "value": value}}}
		source["outputs"] = map[string]any{"destinations": map[string]any{"aws": map[string]any{"plugin": "aws-secrets-manager", "settings": map[string]any{"account": account, "region": "us-east-1"}}}, "routing": map[string]any{"default": []string{"aws"}}}
	})
	before := nativePublicationCounters(t, binaries)
	workflowResult(t, run("apply", observer.Policy{}, "apply"), "success")
	nativePublicationNoEffects(t, binaries, before)
	coordinate := nativePublicationCoordinate(t, domain, "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", physical)
	first := nativePublicationUnknown(t, run("apply", observer.Policy{}, "publish", "--name", "VALUE"), coordinate, []string{"create-empty", "write-value"})
	nativePublicationEffects(t, binaries, before, 2)
	birth, old := *first.Payload.Entries[0].Actions[0].Attempt, *first.Payload.Entries[0].Actions[1].Attempt
	before = nativePublicationCounters(t, binaries)
	second := nativePublicationUnknown(t, run("apply", observer.Policy{}, "publish", "--name", "VALUE", "--republish-after-unknown", old), coordinate, []string{"write-value"})
	nativePublicationEffects(t, binaries, before, 1)
	unknown := *second.Payload.Entries[0].Actions[0].Attempt
	if unknown == old || !second.Payload.Entries[0].Actions[0].Late || !reflect.DeepEqual(second.Payload.Entries[0].Actions[0].Blockers, []string{old}) {
		t.Fatal("explicit publication lost original blocker or late-write warning")
	}
	before = nativePublicationCounters(t, binaries)
	listed := run("reader", observer.Policy{NoKMS: true}, "abandon", "list")
	var list struct {
		Payload struct {
			Targets []struct {
				Group      string `json:"group_id"`
				Kind       string `json:"kind"`
				Target     string `json:"target_id"`
				Selectable bool   `json:"selectable"`
			} `json:"targets"`
		} `json:"payload"`
	}
	if listed.code != 0 || json.Unmarshal(listed.out, &list) != nil {
		t.Fatal("public publication ending discovery unavailable")
	}
	found := false
	for _, target := range list.Payload.Targets {
		if target.Kind == "publication-marker" && target.Group == old && target.Target == coordinate && target.Selectable {
			found = true
		}
	}
	if !found {
		t.Fatal("old exact marker was not independently selectable")
	}
	plan := filepath.Join(administrativeReplacementDirectory(t), "publication-ending.json")
	if planned := run("reader", observer.Policy{NoKMS: true}, "abandon", "plan", "--target", old, "--out", plan); planned.code != 0 {
		var facts struct {
			State    string                           `json:"state_result"`
			Result   struct{ Outcome, Reason string } `json:"result"`
			Delivery struct {
				Created       bool `json:"plan_created"`
				Synced        bool `json:"plan_synced"`
				Readback      bool `json:"plan_readback"`
				Failed        bool `json:"plan_failed"`
				CleanupFailed bool `json:"cleanup_failed"`
			} `json:"delivery"`
		}
		decoded := json.Unmarshal(planned.out, &facts) == nil
		t.Fatalf("public marker ending plan refused: exit=%d decoded=%t state=%q outcome=%q reason=%q plan_created=%t plan_synced=%t plan_readback=%t plan_failed=%t cleanup_failed=%t %s", planned.code, decoded, workflowSafeState(facts.State), facts.Result.Outcome, facts.Result.Reason, facts.Delivery.Created, facts.Delivery.Synced, facts.Delivery.Readback, facts.Delivery.Failed, facts.Delivery.CleanupFailed, planned.summary)
	}
	ended := run("apply", observer.Policy{}, "abandon", "apply", "--plan", plan)
	var ending struct {
		State   string `json:"state_result"`
		Payload struct {
			Completion string `json:"original_completion"`
			Cleanup    string `json:"physical_cleanup"`
		} `json:"payload"`
	}
	if ended.code != 0 || json.Unmarshal(ended.out, &ending) != nil || ending.State != "work-ended" || ending.Payload.Completion != "not-established" || ending.Payload.Cleanup != "not-established" {
		t.Fatal("exact ending claimed remote completion or cleanup")
	}
	nativePublicationSource(t, path, func(source map[string]any) {
		source["entries"] = map[string]any{}
		source["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
	})
	workflowResult(t, run("apply", observer.Policy{}, "apply"), "success")
	nativePublicationNoEffects(t, binaries, before)
	decoded, head := workflowHead(t, s)
	root := workflowRoot(t, s, decoded)
	rows := nativePublicationRows(nativePublicationSelectedParts(t, s))
	if len(rows) != 3 || root.WarningBits&0x0c != 0x0c {
		t.Fatal("exact ending/removal lost selected publication rows or permanent warning")
	}
	coordinateBody := rows[fmt.Sprintf("%d/%s", contract.PublicationCoordinateSupportKind, coordinate)]
	c, err := contract.InspectPublicationCoordinate(coordinateBody)
	if err != nil || c.BindingState != contract.PublicationBindingRetired || !c.ActiveBindingIncarnationID.IsZero() || c.OwnedBirthAttemptID != nativePublicationID(t, birth) || c.PossibleRemoteObject != 1 || c.LateEffectRisk != 1 {
		t.Fatal("removed selected coordinate lost exact ownership or uncertainty", err)
	}
	m, err := contract.InspectPublicationMarker(rows[fmt.Sprintf("%d/%s", contract.PublicationMarkerSupportKind, unknown)])
	if err != nil || m.State != contract.PublicationUnknown || m.Projection.Action != contract.PublicationWriteValue || m.LateEffectRisk != 1 {
		t.Fatal("removed target lost its current unknown write", err)
	}
	return nativePublicationHistory{server: s, source: path, pair: workflowReadPair(t, path), domain: domain, coordinate: coordinate, physical: physical, birth: birth, unknown: unknown, remoteCalls: nativePublicationRemoteRequests(output), effects: output.effectCount(), counts: nativePublicationCounters(t, binaries), head: head, root: root, rows: rows}
}

func nativePublicationRestartPreview(t *testing.T, binaries nativeOutputExecutables, output *nativePublicationServer, history nativePublicationHistory) {
	t.Helper()
	s := history.server
	before := nativePublicationImages(t, history.source, filepath.Join(filepath.Dir(history.source), history.pair.reference))
	child := workflowRunEnvironment(t, s, binaries.cli, "reader", observer.Policy{NoKMS: true}, nil, binaries.Environment(t, history.source), "plan", "--trusted", history.source, "--trusted-format", "json", "--publish", "--json")
	workflowGETOnly(t, child)
	var result struct {
		State   string `json:"state_result"`
		Payload struct {
			Publication struct {
				Schema   string `json:"schema"`
				Complete bool   `json:"complete"`
				Warning  bool   `json:"domain_wide_warning"`
				Entries  []struct {
					Coordinate    *string `json:"coordinate_id"`
					Target        string  `json:"physical_target"`
					Locator       *string `json:"consumer_locator"`
					Origin, Basis string
					Blockers      []string `json:"blocker_ids"`
					Remote        bool     `json:"remote_value_may_remain"`
					Late          bool     `json:"late_write_risk"`
				} `json:"entries"`
			} `json:"publication"`
		} `json:"payload"`
	}
	if child.code != 0 || json.Unmarshal(child.out, &result) != nil || result.State != "success" || result.Payload.Publication.Schema != "PublicationPreview/v2" || !result.Payload.Publication.Complete || !result.Payload.Publication.Warning || len(result.Payload.Publication.Entries) != 1 {
		t.Fatal("fresh process lost complete retained publication preview")
	}
	row := result.Payload.Publication.Entries[0]
	if row.Coordinate == nil || *row.Coordinate != history.coordinate || row.Target != history.physical || row.Origin != "observed" || row.Basis != "blocked" || row.Locator == nil || *row.Locator != history.physical+"-AbCd12?stage=AWSCURRENT" || !reflect.DeepEqual(row.Blockers, []string{history.unknown}) || !row.Remote || !row.Late {
		t.Fatal("fresh preview lost retained target, birth locator, blocker or warning")
	}
	blocked := workflowRunEnvironment(t, s, binaries.cli, "apply", observer.Policy{NoKMS: true}, nil, binaries.Environment(t, history.source), "publish", "--source", history.source, "--source-format", "json", "--delete-coordinate", history.coordinate+"=aws-secrets-manager", "--json")
	var refusal struct {
		Schema  string          `json:"schema"`
		State   string          `json:"state_result"`
		Payload json.RawMessage `json:"payload"`
	}
	if blocked.code != 2 || json.Unmarshal(blocked.out, &refusal) != nil || refusal.Schema != "ProductResult/v1" || refusal.State != "refused" || string(refusal.Payload) != "null" {
		t.Fatal("fresh publication restored an old unknown deletion permission")
	}
	workflowGETOnly(t, blocked)
	prior := s.snapshot("authority")
	opened := workflowRunEnvironment(t, s, binaries.helper, "authority", observer.Policy{}, nil, binaries.Environment(t, history.source), "--source", history.source, "--source-format", "json")
	var projection struct {
		Domain, Revision string
		Parts            int
	}
	headBefore, _ := workflowHead(t, s)
	if opened.code != 0 || json.Unmarshal(opened.out, &projection) != nil || projection.Domain != history.domain || projection.Revision != hex.EncodeToString(headBefore.Core.Revision[:]) || projection.Parts != len(nativePublicationSelectedParts(t, s)) {
		t.Fatal("retained-pair public reconstruction did not complete its exact selected projection")
	}
	for _, event := range opened.capture.Events {
		if event.Kind == "http-start" && event.Operation != "head-read" && event.Operation != "store-read" && event.Operation != "kms-public" || event.Kind == "plaintext" || event.Kind == "recovery-plaintext" {
			t.Fatal("removed values restored a private or mutating reconstruction operation")
		}
	}
	afterPrivate := s.snapshot("authority")
	if afterPrivate.creates != prior.creates || afterPrivate.headCreates != prior.headCreates || afterPrivate.headUpdates != prior.headUpdates {
		t.Fatal("retained-pair reconstruction changed selected state")
	}
	nativePublicationNoEffects(t, binaries, history.counts)
	nativePublicationUnchanged(t, before)
	_, after := workflowHead(t, s)
	if !reflect.DeepEqual(after, history.head) || nativePublicationRemoteRequests(output) != history.remoteCalls || output.effectCount() != history.effects || !reflect.DeepEqual(nativePublicationRows(nativePublicationSelectedParts(t, s)), history.rows) {
		t.Fatal("fresh Reader restored send work or changed selected publication facts")
	}
}

// full_only: false
func TestPublicNativePublicationRestartPreservesRemovedTargetAndUnknown(t *testing.T) {
	output := newNativePublicationServer(t)
	endpoint, lost := nativePublicationLostReplyEndpoint(t, output)
	binaries := buildNativeOutputExecutables(t, endpoint.URL)
	for i, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			beforeLost := lost.Load()
			history := nativePublicationRemovedHistory(t, binaries, output, family, fmt.Sprintf("%012d", 800+i))
			if lost.Load()-beforeLost != 2 {
				t.Fatal("controlled history did not remove exactly two completed write replies")
			}
			nativePublicationRestartPreview(t, binaries, output, history)
		})
	}
}

func nativePublicationRecoveryWorker(t *testing.T, family string) string {
	t.Helper()
	root, directory := nativeRepository(t), t.TempDir()
	moduleName := "compositions/aws"
	if family == "gcp" {
		moduleName = "providers/gcp"
	}
	module := filepath.Join(root, filepath.FromSlash(moduleName))
	files, err := filepath.Glob(filepath.Join(module, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	selected := []string{}
	for _, file := range files {
		if !strings.HasSuffix(file, "_test.go") {
			selected = append(selected, filepath.Base(file))
		}
	}
	selected = append(selected, "reconstruction_process_test.go")
	modFlags := []string{"-mod=readonly"}
	var overlaySources map[string]string
	if family == "gcp" {
		selected = []string{"."}
		overlaySources = make(map[string]string, 2)
		for _, row := range []struct{ source, target string }{
			{"tests/gcp/admission.go", "zz_test_admission.go"},
			{"tests/gcpcredentials/admission.go", "credentials/zz_test_admission.go"},
		} {
			source := filepath.Join(root, filepath.FromSlash(row.source))
			info, err := os.Lstat(source)
			if err != nil || !info.Mode().IsRegular() {
				t.Fatal("GCP credential test source unavailable")
			}
			target := filepath.Join(module, filepath.FromSlash(row.target))
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				t.Fatal("GCP credential overlay would replace source")
			}
			overlaySources[target] = source
		}
		overlay := filepath.Join(directory, "gcp-reconstruction-overlay.json")
		nativeGeneratedWriteJSON(t, overlay, struct{ Replace map[string]string }{overlaySources})
		modFlags = append(modFlags, "-modfile="+filepath.Join(module, "telemetry_test.mod"), "-overlay="+overlay)
	}
	slices.Sort(selected)
	binary := filepath.Join(directory, family+"-reconstruction.test")
	// This existing worker uses explicit console inputs and no observer policy.
	// GCP's provider-only overlay supplies its existing credential test bridges;
	// no private Core test admission reaches the restricted worker.
	arguments := append(nativeGoArguments("test"), modFlags...)
	arguments = append(arguments, "-trimpath", "-buildvcs=false", "-c", "-o", binary)
	arguments = append(arguments, selected...)
	nativeGeneratedGo(t, root, moduleName, arguments...)
	nativeRequireRaceMode(t, binary)
	moduleArgs := append([]string{"list"}, modFlags...)
	moduleArgs = append(moduleArgs, "-m", "-json", "all")
	modules := nativeGeneratedGoCaptured(t, root, moduleName, binary+".mod", moduleArgs...)
	importArgs := append(nativeGoArguments("list"), modFlags...)
	importArgs = append(importArgs, "-deps", "-test", "-json")
	imports := nativeGeneratedGoCaptured(t, root, moduleName, binary+".mod", append(importArgs, selected...)...)
	manifest := struct {
		Arguments, Files []string
		Modules, Imports string
		Overlay          bool
		OverlaySources   map[string]string
	}{arguments, selected, string(modules), string(imports), len(overlaySources) != 0, overlaySources}
	manifestPath := filepath.Join(directory, family+"-reconstruction-dependencies.json")
	nativeGeneratedWriteJSON(t, manifestPath, manifest)
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal("restricted worker hash unavailable")
	}
	t.Logf("existing console reconstruction worker=%s sha256=%x manifest=%s", binary, hash.Sum(nil), manifestPath)
	return binary
}

// full_only: false
func TestPublicNativePublicationCompleteLocalLossPreservesSelectedFacts(t *testing.T) {
	output := newNativePublicationServer(t)
	endpoint, lost := nativePublicationLostReplyEndpoint(t, output)
	binaries := buildNativeOutputExecutables(t, endpoint.URL)
	manifest := nativeManifestProductionBuild(t)
	binaries.nativePluginFixture = newNativePluginFixture(t, append(slices.Clone(binaries.builds), manifest)...)
	for i, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			worker := nativePublicationRecoveryWorker(t, family)
			beforeLost := lost.Load()
			history := nativePublicationRemovedHistory(t, binaries, output, family, fmt.Sprintf("%012d", 900+i))
			history.server.childLimit = 24
			expectedParts := nativePublicationSelectedParts(t, history.server)
			if lost.Load()-beforeLost != 2 {
				t.Fatal("complete-loss source lacks its two lost write replies")
			}
			nativePublicationRestartPreview(t, binaries, output, history)
			beforeReceipts := nativePrepareReadFacts(t, workflowRunEnvironment(t, history.server, binaries.cli, "reader", observer.Policy{NoKMS: true}, nil, binaries.Environment(t, history.source), "receipt", "--source", history.source, "--source-format", "json", "--json"))
			beforeInspection := nativePrepareReadFacts(t, workflowRunEnvironment(t, history.server, binaries.cli, "reader", observer.Policy{NoKMS: true}, nil, binaries.Environment(t, history.source), "inspect", "--source", history.source, "--source-format", "json", "--json"))
			// Every public producer has exited and joined. Remove both local files and
			// their directory before the existing restricted worker can start.
			if err := os.RemoveAll(filepath.Dir(history.source)); err != nil {
				t.Fatal("complete local-loss removal", err)
			}
			if _, err := os.Lstat(history.source); !os.IsNotExist(err) {
				t.Fatal("complete local-loss barrier is absent")
			}
			private, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			working, home, temporary := filepath.Join(private, "working"), filepath.Join(private, "home"), filepath.Join(private, "temporary")
			for _, directory := range []string{working, home, temporary} {
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			certificate, _ := pem.Decode([]byte(history.server.rootPEM))
			if certificate == nil {
				t.Fatal("independent TLS responder certificate absent")
			}
			input := installedarchive.RecoveryInput{Provider: "aws", Bucket: "fixture-bucket", Region: "us-east-1", Prefix: history.server.prefix, Owner: "123456789012", NormalSigner: history.server.selector(1), NormalRegion: "us-east-1", ReadRoute: "new-publication-loss-read", SignRoute: "new-publication-loss-public", PrivateRoute: "new-publication-loss-private", AccessKey: workflowAccess("authority"), SecretKey: "offline-local-not-a-cloud-secret", TimeoutMillis: 60000, Output: filepath.Join(private, "observation.json"), Responder: history.server.server.Listener.Addr().String(), TLSCertificate: certificate.Bytes}
			tokenFamily := contract.AWS
			if family == "gcp" {
				tokenFamily = contract.GCP
				input.Provider, input.Region, input.NormalRegion, input.Owner = "gcp", "us-central1", "us-central1", ""
				input.AccessKey, input.SecretKey = "", ""
				input.Requests, input.BodyBytes, input.ResponseBytes = 256, 32<<20, 1<<20
				// Generate a fresh working credential through the existing fixture owner.
				// Only its standard token URI changes; signature/issuer/quota stay exact.
				history.server.environment(t, private, "authority")
				path := filepath.Join(private, "local-adc.json")
				var source map[string]any
				nativeGeneratedReadJSON(t, path, &source)
				source["token_uri"] = "https://oauth2.googleapis.com/token"
				nativeGeneratedWriteJSON(t, path, source)
				input.ServiceAccountFile = path
			}
			body, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(body)
			before := history.server.snapshot("authority")
			if _, admitted := history.server.admitChild(); !admitted {
				t.Fatal("restricted worker finite request budget refused")
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			name := "TestRestrictedAWSReconstructionFromConsoleInputs"
			if family == "gcp" {
				name = "TestRestrictedGCPReconstructionFromConsoleInputs"
			}
			command := exec.CommandContext(ctx, worker, "-test.v=test2json", "-test.count=1", "-test.timeout=60s", "-test.run=^"+name+"$")
			command.Dir, command.Env, command.Stdin = working, recovery.RecoveryEnvironment(home, temporary), bytes.NewReader(body)
			var terminal installedarchive.ChildOutput
			command.Stdout, command.Stderr = &terminal, &terminal
			joined := command.Run()
			exit, processJoined := -1, command.ProcessState != nil
			if processJoined {
				exit = command.ProcessState.ExitCode()
			}
			nativeGeneratedWriteJSON(t, filepath.Join(private, "worker-terminal-reference.json"), struct {
				Name   string
				Exit   int
				Joined bool
			}{name, exit, processJoined})
			if os.WriteFile(filepath.Join(private, "worker-terminal.txt"), terminal.Bytes(), 0600) != nil {
				t.Fatal("restricted worker terminal retention failed")
			}
			if joined != nil || ctx.Err() != nil || !processJoined || exit != 0 || terminal.Completed(name) != nil {
				t.Fatal("restricted reconstruction did not positively complete and join", joined)
			}
			var observation recovery.Observation
			nativeGeneratedReadJSON(t, input.Output, &observation)
			if observation.Result != (recovery.ObservedResult{Outcome: 2, Evidence: 1}) || observation.Provenance.Domain != history.root.Domain || observation.Provenance.Snapshot != history.root.Snapshot || observation.Provenance.HEADDigest != contract.Hash(history.head.body) || !reflect.DeepEqual(observation.Parts, expectedParts) || observation.Provenance.HEADToken != (contract.Token{Family: tokenFamily, Value: history.head.etag}) {
				t.Logf("complete local-loss facts: outcome=%d evidence=%d domain_matches=%t snapshot_matches=%t head_digest_matches=%t parts_match=%t returned_parts=%d expected_parts=%d token_matches=%t", observation.Result.Outcome, observation.Result.Evidence, observation.Provenance.Domain == history.root.Domain, observation.Provenance.Snapshot == history.root.Snapshot, observation.Provenance.HEADDigest == contract.Hash(history.head.body), reflect.DeepEqual(observation.Parts, expectedParts), len(observation.Parts), len(expectedParts), observation.Provenance.HEADToken == (contract.Token{Family: tokenFamily, Value: history.head.etag}))
				t.Fatal("complete local loss did not authenticate the exact selected closure")
			}
			returned := map[string][]byte{}
			rootSeen, headSeen := false, false
			for _, part := range observation.Parts {
				switch part.Kind {
				case "root":
					root, err := stateformat.DecodeRoot(part.Body)
					if err != nil || !reflect.DeepEqual(root, history.root) || stateformat.CheckReference(part.Ref, part.Body) != nil || rootSeen {
						t.Fatal("returned root or warning state differs", err)
					}
					rootSeen = true
				case "HEAD":
					if headSeen || !bytes.Equal(part.Body, history.head.body) {
						t.Fatal("returned HEAD differs")
					}
					headSeen = true
				case "support row":
					if part.SupportKind != contract.PublicationCoordinateSupportKind && part.SupportKind != contract.PublicationMarkerSupportKind {
						continue
					}
					key := fmt.Sprintf("%d/%x", part.SupportKind, part.RecordID)
					if returned[key] != nil {
						t.Fatal("returned publication row duplicated")
					}
					returned[key] = part.Body
				}
			}
			if !rootSeen || !headSeen || !reflect.DeepEqual(returned, history.rows) {
				t.Fatal("complete local loss omitted or recreated selected publication detail")
			}
			after := history.server.snapshot("authority")
			if after.reads <= before.reads || after.creates != before.creates || after.headCreates != before.headCreates || after.headUpdates != before.headUpdates {
				t.Fatal("restricted reconstruction did not remain read-only")
			}
			for operation, count := range after.calls {
				if strings.HasPrefix(operation, "Sign/") || strings.HasPrefix(operation, "Decrypt/") {
					if count != before.calls[operation] {
						t.Fatal("removed values caused signing or private decryption during reconstruction")
					}
				}
			}
			nativePublicationNoEffects(t, binaries, history.counts)
			_, head := workflowHead(t, history.server)
			if !reflect.DeepEqual(head, history.head) || nativePublicationRemoteRequests(output) != history.remoteCalls || output.effectCount() != history.effects {
				t.Fatal("complete local loss restored publication work or changed remote state")
			}
			const restoredName = "publication-restored"
			restored := filepath.Join(t.TempDir(), "recovered.json")
			restoredEnvironment := binaries.Environment(t, restored)
			t.Logf("local plugin settings select restored application=%s with existing installation_home=%s", filepath.Dir(restored), binaries.home)
			prepared := workflowRunEnvironment(t, history.server, binaries.cli, "authority", observer.Policy{}, nil, restoredEnvironment, nativePrepareArgs(history.server, restored, restoredName, "--normal-signing-key", history.server.selector(1))...)
			preparation := nativePrepareResult(t, prepared, "reconstruction")
			if preparation.Recovery.Domain != history.domain || preparation.Recovery.Head != workflowDigest(history.head.body) || preparation.Delivery.Outcome != "recorded" {
				t.Fatal("publication complete loss did not deliver the exact selected domain")
			}
			nativePrepareReadOnly(t, prepared)
			for _, event := range prepared.capture.Events {
				if event.Kind == "plaintext" || event.Kind == "http-start" && event.Operation == "kms-decrypt" {
					t.Fatal("removed publication values restored private decryption")
				}
			}
			history.source = restored
			history.pair = workflowReadNamedPair(t, restored, restoredName)
			nativePublicationRestartPreview(t, binaries, output, history)
			afterReceipts := nativePrepareReadFacts(t, workflowRunEnvironment(t, history.server, binaries.cli, "reader", observer.Policy{NoKMS: true}, nil, binaries.Environment(t, restored), "receipt", "--source", restored, "--source-format", "json", "--json"))
			afterInspection := nativePrepareReadFacts(t, workflowRunEnvironment(t, history.server, binaries.cli, "reader", observer.Policy{NoKMS: true}, nil, binaries.Environment(t, restored), "inspect", "--source", restored, "--source-format", "json", "--json"))
			if !reflect.DeepEqual(beforeReceipts, afterReceipts) || !reflect.DeepEqual(beforeInspection, afterInspection) {
				t.Fatal("publication recovery changed exact receipts, retained markers or warnings")
			}
			idle := workflowRunEnvironment(t, history.server, binaries.cli, "noop", observer.Policy{}, nil, binaries.Environment(t, restored), "apply", "--source", restored, "--source-format", "json", "--json")
			if workflowResult(t, idle, "no-op").Receipt != "" {
				t.Fatal("publication recovery restored a selected mutation")
			}
			nativePrepareReadOnly(t, idle)
			workflowUnchanged(t, restored, history.pair)
			nativePublicationNoEffects(t, binaries, history.counts)
			_, finalHEAD := workflowHead(t, history.server)
			if !reflect.DeepEqual(finalHEAD, history.head) || nativePublicationRemoteRequests(output) != history.remoteCalls || output.effectCount() != history.effects || !reflect.DeepEqual(nativePublicationRows(nativePublicationSelectedParts(t, history.server)), history.rows) {
				t.Fatal("prepared publication pair changed retained rows or remote effects")
			}
			history.server.clean(t)
		})
	}
}
