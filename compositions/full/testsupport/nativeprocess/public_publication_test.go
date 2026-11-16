package nativeprocess

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/compositions/configuration"
	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/artifact"
)

type nativePublicationOutput struct {
	Schema      string `json:"schema"`
	Operation   string `json:"operation_kind"`
	Request     string `json:"request_id"`
	Domain      string `json:"domain_id"`
	OperationID string `json:"operation_id"`
	Identity    string `json:"request_identity"`
	Replay      string `json:"replay_identity"`
	State       string `json:"state_result"`
	Summary     string `json:"output_summary"`
	Effect      string `json:"effect_summary"`
	Payload     struct {
		Schema    string `json:"schema"`
		Domain    string `json:"domain_id"`
		Operation string `json:"operation_id"`
		Snapshot  string `json:"snapshot_id"`
		Selection string `json:"selection_digest"`
		Warning   bool   `json:"domain_wide_warning"`
		Entries   []struct {
			Coordinate string `json:"coordinate_id"`
			Target     *struct {
				Origin      string  `json:"origin"`
				Entry       *string `json:"entry_name"`
				Destination *string `json:"destination_id"`
				Service     string  `json:"service_contract_id"`
				Canonical   string  `json:"canonical_target"`
			} `json:"target"`
			Actions []struct {
				Action      *string  `json:"action"`
				Projection  *string  `json:"projection_commitment"`
				Attempt     *string  `json:"attempt_id"`
				Disposition string   `json:"disposition"`
				Reason      uint16   `json:"reason_code"`
				Remote      bool     `json:"remote_value_may_remain"`
				Late        bool     `json:"late_write_risk"`
				Blockers    []string `json:"blocker_ids"`
				Evidence    *struct {
					Schema, Entry, Class string
					Response             string  `json:"response_contract_digest"`
					Status               uint16  `json:"normalized_status"`
					Resource             string  `json:"safe_resource_id"`
					Locator              *string `json:"consumer_locator"`
				} `json:"evidence"`
			} `json:"actions"`
		} `json:"entries"`
	} `json:"payload"`
}

type nativePublicationTarget struct{ provider, physical, key, profile, entry string }

func nativePublicationTargets(account, project, owner string) []nativePublicationTarget {
	var targets []nativePublicationTarget
	for _, entry := range []string{"BINARY", "PLAIN"} {
		aws := "arn:aws:secretsmanager:us-east-1:" + account + ":secret:" + entry
		gcp := "projects/" + project + "/secrets/" + entry
		for _, target := range []nativePublicationTarget{
			{"ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", aws, "aws:" + aws + "-AbCd12", "aws", entry},
			{"ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", gcp, "gcp:" + gcp, "gcp", entry},
			{"github-actions/service/v1", "repos/" + owner + "/repo/actions/secrets/" + entry, "", "repository", entry},
			{"github-actions/service/v1", "orgs/" + owner + "/actions/secrets/" + entry, "", "organization", entry},
			{"github-actions/service/v1", "repos/" + owner + "/repo/environments/prod/secrets/" + entry, "", "environment", entry},
		} {
			if target.key == "" {
				target.key = "github:" + target.physical
			}
			targets = append(targets, target)
		}
	}
	return targets
}

func nativePublicationDeclaration(account, project, owner string) map[string]any {
	destinations := map[string]any{}
	for _, row := range []struct {
		id, plugin string
		spec       map[string]any
	}{
		{"aws", "aws-secrets-manager", map[string]any{"account": account, "region": "us-east-1"}},
		{"gcp", "gcp-secret-manager", map[string]any{"project_number": project}},
		{"repository", "github-actions-repository", map[string]any{"owner": owner, "repository": "repo"}},
		{"organization", "github-actions-organization", map[string]any{"owner": owner, "visibility": "selected", "repositories": []uint64{7, 11}}},
		{"environment", "github-actions-environment", map[string]any{"owner": owner, "repository": "repo", "environment": "prod"}},
	} {
		destinations[row.id] = map[string]any{"plugin": row.plugin, "settings": row.spec}
	}
	return map[string]any{"destinations": destinations, "routing": map[string]any{"default": []string{"aws", "environment", "gcp", "organization", "repository"}}}
}

func nativePublicationCoordinate(t *testing.T, domain, provider, physical string) string {
	t.Helper()
	id, err := hex.DecodeString(domain)
	if err != nil || len(id) != 32 {
		t.Fatal("public domain identity unavailable")
	}
	// Independent coordinate preimage, specified by the canonical owner.
	body := append([]byte("ENKV/PUBLICATION/COORDINATE/v3\x00"), id...)
	for _, field := range []string{provider, physical} {
		body = binary.BigEndian.AppendUint32(body, uint32(len(field)))
		body = append(body, field...)
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func nativePublicationExpectedActions(t *testing.T, domain string, targets []nativePublicationTarget, mode string) map[string][]string {
	t.Helper()
	result := map[string][]string{}
	for _, target := range targets {
		actions := []string{"create-with-value"}
		if target.profile == "aws" || target.profile == "gcp" {
			actions = []string{"create-empty", "write-value"}
		}
		switch mode {
		case "noop":
			actions = []string{""}
		case "changed":
			if target.entry == "PLAIN" {
				actions = []string{"write-value"}
			} else {
				actions = []string{""}
			}
		case "delete":
			actions = []string{"delete-owned"}
		}
		result[nativePublicationCoordinate(t, domain, target.provider, target.physical)] = actions
	}
	return result
}

func nativePublicationDecode(t *testing.T, child workflowChild, expected map[string][]string, state string) nativePublicationOutput {
	t.Helper()
	var result nativePublicationOutput
	if child.code != 0 || json.Unmarshal(child.out, &result) != nil || result.Schema != "ProductResult/v1" || result.Operation != "publish" || result.State != state || result.Effect != "not-applicable" || result.Replay != "none" || len(result.Request) != 64 || len(result.OperationID) != 64 || len(result.Identity) != 64 || len(result.Domain) != 64 || result.Payload.Schema != "OutputPayload/v3" || result.Payload.Operation != result.OperationID || result.Payload.Domain != result.Domain || len(result.Payload.Snapshot) != 64 || len(result.Payload.Selection) != 64 || result.Payload.Warning || len(result.Payload.Entries) != len(expected) {
		t.Fatal("native publication lost its complete closed result", child.code)
	}
	if state == "no-op" {
		if result.Summary != "output-no-change" {
			t.Fatal("public no-op summary differs")
		}
	} else if result.Summary != "output-complete" {
		t.Fatal("public complete summary differs")
	}
	previous := ""
	attempts := map[string]bool{}
	for _, target := range result.Payload.Entries {
		want, known := expected[target.Coordinate]
		if !known || target.Coordinate <= previous || len(target.Actions) != len(want) {
			t.Fatal("native coordinate set/order/actions differ")
		}
		if target.Target == nil || target.Target.Destination == nil || target.Target.Service == "" || target.Target.Canonical == "" || nativePublicationCoordinate(t, result.Domain, target.Target.Service, target.Target.Canonical) != target.Coordinate {
			t.Fatal("native target description lost its exact coordinate relation")
		}
		deletion := len(want) == 1 && (want[0] == "delete-owned" || want[0] == "delete-reserved-slot")
		if deletion {
			if target.Target.Origin != "retained-deletion" || target.Target.Entry != nil {
				t.Fatal("native retained target acquired a current entry name")
			}
		} else if target.Target.Origin != "current" || target.Target.Entry == nil {
			t.Fatal("native current target lost its selected entry name")
		}
		previous = target.Coordinate
		for i, action := range target.Actions {
			if action.Reason != 0 || action.Late || len(action.Blockers) != 0 {
				t.Fatal("unexpected public refusal or warning")
			}
			if want[i] == "" {
				if action.Action != nil || action.Attempt != nil || action.Projection != nil || action.Evidence != nil || action.Disposition != "no-op" || action.Remote {
					t.Fatal("native no-op acquired an action")
				}
				continue
			}
			if action.Action == nil || *action.Action != want[i] || action.Attempt == nil || len(*action.Attempt) != 64 || attempts[*action.Attempt] || action.Projection == nil || len(*action.Projection) != 64 || action.Disposition != "acknowledged" || !action.Remote || action.Evidence == nil || action.Evidence.Schema != "PublicationEvidence/v3" || action.Evidence.Entry != "may-have-entered" || action.Evidence.Class != "acknowledged" || len(action.Evidence.Response) != 64 {
				t.Fatal("native exact action did not retain acknowledged evidence")
			}
			create := *action.Action == "create-empty" || *action.Action == "create-with-value"
			if action.Evidence.Locator == nil || len(*action.Evidence.Locator) > 1024 || create != (*action.Evidence.Locator != "") {
				t.Fatal("native qualified creation locator was omitted or attached to another action")
			}
			attempts[*action.Attempt] = true
		}
	}
	return result
}

func nativePublicationCombined(t *testing.T, child workflowChild, expected map[string][]string, applyState, publicationState string) nativePublicationOutput {
	t.Helper()
	var envelope struct {
		Schema      string
		Apply       json.RawMessage
		Publication struct {
			Stage  string
			Reason *string
			Result json.RawMessage
		}
	}
	if child.code != 0 || json.Unmarshal(child.out, &envelope) != nil || envelope.Schema != "ApplyPublicationResult/v1" || envelope.Publication.Stage != "evaluated" || envelope.Publication.Reason != nil {
		t.Fatal("combined native invocation did not preserve separate stages", child.code)
	}
	apply := child
	apply.out = envelope.Apply
	workflowResult(t, apply, applyState)
	publication := child
	publication.out = envelope.Publication.Result
	return nativePublicationDecode(t, publication, expected, publicationState)
}

func nativePublicationSource(t *testing.T, path string, edit func(map[string]any)) {
	t.Helper()
	var value map[string]any
	body, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(body, &value) != nil {
		t.Fatal("native output source unavailable", err)
	}
	edit(value)
	body, err = json.Marshal(value)
	if err != nil || os.WriteFile(path, body, 0600) != nil {
		t.Fatal("native output source edit failed", err)
	}
}

func nativePublicationYAML(t *testing.T, path string) string {
	t.Helper()
	pair, err := configuration.Capture(t.Context(), path, configuration.JSON)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pair.Close(); err != nil {
			t.Fatal("native YAML capture cleanup failed", err)
		}
	}()
	model, parseErr := configuration.Parse(t.Context(), pair)
	if parseErr != nil {
		t.Fatal("native YAML source capture failed", parseErr)
	}
	var body bytes.Buffer
	if configuration.EmitEditable(&body, model, configuration.YAML) != nil {
		t.Fatal("native YAML source emission failed")
	}
	if json.Valid(body.Bytes()) {
		t.Fatal("native YAML case did not produce block YAML")
	}
	yaml := filepath.Join(filepath.Dir(path), "publication.yaml")
	if os.WriteFile(yaml, body.Bytes(), 0600) != nil {
		t.Fatal("native YAML source unavailable")
	}
	return yaml
}

type nativePublicationImage struct {
	Mode   os.FileMode
	Digest [32]byte
}

func nativePublicationImages(t *testing.T, paths ...string) map[string]nativePublicationImage {
	t.Helper()
	result := map[string]nativePublicationImage{}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result[path] = nativePublicationImage{info.Mode(), sha256.Sum256(body)}
	}
	return result
}
func nativePublicationUnchanged(t *testing.T, before map[string]nativePublicationImage) {
	t.Helper()
	paths := make([]string, 0, len(before))
	for path := range before {
		paths = append(paths, path)
	}
	if !reflect.DeepEqual(before, nativePublicationImages(t, paths...)) {
		t.Fatal("remote operation changed source bytes or modes")
	}
}

type nativePublicationCounts struct{ captures, checks, dispatches, joins int }

func nativePublicationCounters(t *testing.T, binaries nativeOutputExecutables) nativePublicationCounts {
	t.Helper()
	c, p, w := nativeOutputLedger(t, binaries)
	body, err := os.ReadFile(binaries.ledger)
	if os.IsNotExist(err) {
		return nativePublicationCounts{}
	}
	if err != nil {
		t.Fatal(err)
	}
	return nativePublicationCounts{c, p, w, bytes.Count(body, []byte{'J'})}
}
func nativePublicationEffects(t *testing.T, binaries nativeOutputExecutables, before nativePublicationCounts, sends int) {
	t.Helper()
	after := nativePublicationCounters(t, binaries)
	if after.captures-before.captures != sends || after.dispatches-before.dispatches != sends || after.checks-before.checks < sends || after.joins-before.joins != (after.checks-before.checks)+(after.dispatches-before.dispatches) {
		t.Fatal("native output capture/child/positive-join counts differ", before, after, sends)
	}
	body, err := os.ReadFile(binaries.ledger)
	if err != nil || bytes.Count(body, []byte{'S'}) < after.joins {
		t.Fatal("joined native output lacks observed owned-root disposal", err)
	}
}

func nativePublicationNoEffects(t *testing.T, binaries nativeOutputExecutables, before nativePublicationCounts) {
	t.Helper()
	after := nativePublicationCounters(t, binaries)
	if after.captures != before.captures || after.dispatches != before.dispatches || after.joins-before.joins != after.checks-before.checks {
		t.Fatal("plain apply/plan/no-op acquired output credentials or unjoined child work", before, after)
	}
}

func nativePublicationADC(t *testing.T, server *nativePublicationServer) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(encoded)
	const email = "output@fixture.iam.gserviceaccount.com"
	server.mu.Lock()
	server.adcPublic = &key.PublicKey
	server.adcEmail = email
	server.mu.Unlock()
	body, err := json.Marshal(map[string]any{"type": "service_account", "client_email": email, "private_key_id": "native-output", "private_key": string(encoded), "token_uri": server.server.URL + "/token/output", "universe_domain": "googleapis.com", "quota_project_id": "fixture-quota"})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	path := filepath.Join(t.TempDir(), "output-adc.json")
	if os.WriteFile(path, body, 0600) != nil {
		t.Fatal("local output ADC unavailable")
	}
	return path
}

func nativePublicationBinaries(t *testing.T, binaries nativeOutputExecutables) map[string][32]byte {
	t.Helper()
	paths := []string{binaries.cli, binaries.helper}
	for _, artifact := range binaries.artifacts {
		paths = append(paths, filepath.Join(filepath.Dir(binaries.cli), filepath.Base(artifact.Command)))
	}
	for _, build := range binaries.builds {
		metadata, err := artifact.VerifyBuild(t.Context(), build.Directory)
		if err != nil {
			t.Fatal("published native build differs", err)
		}
		identity, err := metadata.Identity()
		if err != nil {
			t.Fatal(err)
		}
		directory := filepath.Join(build.Directory, "builds", identity.String())
		paths = append(paths, filepath.Join(build.Directory, "build.json"), filepath.Join(directory, "plugin"), filepath.Join(directory, "metadata.json"))
		if metadata.Family != nil {
			paths = append(paths, filepath.Join(directory, "dependencies.bin"))
		}
	}
	result := map[string][32]byte{}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatal("installed native binary hash failed", copyErr, closeErr)
		}
		var sum [32]byte
		copy(sum[:], hash.Sum(nil))
		result[path] = sum
	}
	return result
}

// full_only: false
func TestPublicNativePublicationAllProfilesWithoutRecovery(t *testing.T) {
	nativePublicationDomainCells(t, false)
}

// full_only: false
func TestPublicNativePublicationAllProfilesWithRecovery(t *testing.T) {
	nativePublicationDomainCells(t, true)
}

func nativePublicationDomainCells(t *testing.T, recovery bool) {
	t.Helper()
	output := newNativePublicationServer(t)
	binaries := buildNativeOutputExecutables(t, output.server.URL)
	identity := nativePublicationBinaries(t, binaries)
	for familyIndex, family := range []string{"aws", "gcp"} {
		caseIndex := 1 + 2*familyIndex
		if recovery {
			caseIndex++
		}
		t.Run(family, func(t *testing.T) {
			s := newWorkflowServer(t, family, recovery)
			s.childLimit = 12
			s.childRequestLimit = 2048
			s.objectLimit = 512
			account, project, owner := fmt.Sprintf("%012d", caseIndex), fmt.Sprint(900000000000+caseIndex), fmt.Sprintf("owner%d", caseIndex)
			targets := nativePublicationTargets(account, project, owner)
			plain := []byte("selected plain first")
			secret := []byte("native secret value\n\x00\xff\x01\x02")
			defer clear(secret)
			expected := map[string][]byte{}
			keys := []string{}
			for _, target := range targets {
				value := plain
				if target.entry == "BINARY" {
					value = []byte(base64.StdEncoding.EncodeToString(secret))
				}
				expected[target.key] = value
				keys = append(keys, target.key)
			}
			output.expect(account, expected)
			environment := []string{"GITHUB_TOKEN=github_pat_NATIVE_OUTPUT"}
			if family == "aws" {
				environment = append(environment, "GOOGLE_APPLICATION_CREDENTIALS="+nativePublicationADC(t, output), "GCE_METADATA_HOST=127.0.0.1:1")
			} else {
				environment = append(environment, "AWS_ACCESS_KEY_ID=AKIANATIVEOUTPUTTEST", "AWS_SECRET_ACCESS_KEY=offline-output-only", "AWS_EC2_METADATA_DISABLED=true")
			}
			path := filepath.Join(t.TempDir(), "configuration.json")
			run := func(phase string, policy observer.Policy, input []byte, args ...string) workflowChild {
				child := workflowRunEnvironment(t, s, binaries.cli, phase, policy, input, append(binaries.Environment(t, path), environment...), args...)
				for _, body := range [][]byte{child.out, child.diagnostic} {
					for _, forbidden := range [][]byte{secret, []byte(base64.StdEncoding.EncodeToString(secret)), []byte("github_pat_NATIVE_OUTPUT"), []byte("offline-output-only")} {
						if bytes.Contains(body, forbidden) {
							t.Fatal("credential or secret value reached ordinary native output")
						}
					}
				}
				// Existing synthetic source witnesses remain mismatched. This
				// matrix supplies no SSO/user ADC or live IAM qualification.
				for _, event := range child.capture.Events {
					if event.Kind == "source-kind" && event.Matched {
						t.Fatal("synthetic native source was labelled standard-qualified")
					}
				}
				return child
			}
			if os.WriteFile(path, workflowSetup(t, s, recovery), 0600) != nil {
				t.Fatal("native output setup unavailable")
			}
			workflowResult(t, run("init", observer.Policy{}, nil, "init", "--source", path, "--source-format", "json", "--json"), "success")
			pair := workflowReadPair(t, path)
			satellite := filepath.Join(filepath.Dir(path), pair.reference)
			workflowResult(t, run("set", observer.Policy{NoKMS: true}, secret, "set", "--source", path, "--source-format", "json", "--name", "BINARY", "--json"), "success")
			nativePublicationSource(t, path, func(value map[string]any) {
				entries := value["entries"].(map[string]any)
				entries["PLAIN"] = map[string]any{"confidentiality": "plain", "recipients": []any{}, "source": map[string]any{"kind": "supplied", "value": string(plain)}}
				entries["BINARY"].(map[string]any)["output_encoding"] = "base64"
				value["outputs"] = nativePublicationDeclaration(account, project, owner)
			})
			selectedSource, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			before := nativePublicationCounters(t, binaries)
			image := nativePublicationImages(t, path, satellite)
			workflowResult(t, run("apply", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--json"), "success")
			nativePublicationNoEffects(t, binaries, before)
			nativePublicationUnchanged(t, image)
			plan := run("reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", path, "--trusted-format", "json", "--publish", "--json")
			workflowResult(t, plan, "success")
			workflowGETOnly(t, plan)
			nativePublicationNoEffects(t, binaries, before)
			nativePublicationUnchanged(t, image)
			// Pending local value and destination edits cannot replace selected
			// content or targets in standalone publication.
			nativePublicationSource(t, path, func(value map[string]any) {
				value["entries"].(map[string]any)["PLAIN"].(map[string]any)["source"].(map[string]any)["value"] = "unapplied local value"
				value["outputs"] = nativePublicationDeclaration("999999999999", "899999999999", "pending-owner")
			})
			yaml := nativePublicationYAML(t, path)
			image = nativePublicationImages(t, path, yaml, satellite)
			domain := hex.EncodeToString(pair.descriptor.DomainID[:])
			create := nativePublicationExpectedActions(t, domain, targets, "create")
			startEffects := output.effectCount()
			published := run("apply", observer.Policy{}, nil, "publish", "--source", yaml, "--source-format", "yaml", "--name", "PLAIN", "--name", "BINARY", "--json")
			first := nativePublicationDecode(t, published, create, "success")
			nativePublicationEffects(t, binaries, before, 14)
			nativePublicationUnchanged(t, image)
			if output.effectCount()-startEffects != 14 {
				t.Fatal("native provider request total differs")
			}
			output.checkValues(t, keys, false)
			before = nativePublicationCounters(t, binaries)
			repeat := run("noop", observer.Policy{NoKMS: true}, nil, "publish", "--source", path, "--source-format", "json", "--name", "BINARY", "--name", "PLAIN", "--json")
			second := nativePublicationDecode(t, repeat, nativePublicationExpectedActions(t, domain, targets, "noop"), "no-op")
			if second.Identity == first.Identity {
				t.Fatal("new no-work observation restored an old request")
			}
			nativePublicationNoEffects(t, binaries, before)
			nativePublicationUnchanged(t, image)
			if os.WriteFile(path, selectedSource, 0600) != nil {
				t.Fatal("native selected declaration restore failed")
			}
			nativePublicationSource(t, path, func(value map[string]any) {
				value["entries"].(map[string]any)["PLAIN"].(map[string]any)["source"].(map[string]any)["value"] = "selected plain after"
			})
			for _, target := range targets {
				if target.entry == "PLAIN" {
					expected[target.key] = []byte("selected plain after")
				}
			}
			output.expect(account, expected)
			image = nativePublicationImages(t, path, yaml, satellite)
			before = nativePublicationCounters(t, binaries)
			combined := run("apply", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--publish", "--json")
			nativePublicationCombined(t, combined, nativePublicationExpectedActions(t, domain, targets, "changed"), "success", "success")
			nativePublicationEffects(t, binaries, before, 5)
			nativePublicationUnchanged(t, image)
			output.checkValues(t, keys, false)
			before = nativePublicationCounters(t, binaries)
			combinedNoop := run("noop", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--publish", "--json")
			nativePublicationCombined(t, combinedNoop, nativePublicationExpectedActions(t, domain, targets, "noop"), "no-op", "no-op")
			nativePublicationNoEffects(t, binaries, before)
			nativePublicationUnchanged(t, image)
			nativePublicationSource(t, path, func(value map[string]any) {
				value["entries"] = map[string]any{}
				value["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
			})
			image = nativePublicationImages(t, path, yaml, satellite)
			before = nativePublicationCounters(t, binaries)
			workflowResult(t, run("apply", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--json"), "success")
			nativePublicationNoEffects(t, binaries, before)
			nativePublicationUnchanged(t, image)
			deletes := nativePublicationExpectedActions(t, domain, targets, "delete")
			deletionPlugins := make(map[string]string, len(targets))
			destinations := nativePublicationDeclaration(account, project, owner)["destinations"].(map[string]any)
			for _, target := range targets {
				coordinate := nativePublicationCoordinate(t, domain, target.provider, target.physical)
				deletionPlugins[coordinate] = destinations[target.profile].(map[string]any)["plugin"].(string)
			}
			coordinates := make([]string, 0, len(deletes))
			for coordinate := range deletes {
				coordinates = append(coordinates, coordinate)
			}
			slices.Sort(coordinates)
			args := []string{"publish", "--source", path, "--source-format", "json", "--json"}
			for _, coordinate := range coordinates {
				args = append(args, "--delete-coordinate", coordinate+"="+deletionPlugins[coordinate])
			}
			deleted := run("apply", observer.Policy{}, nil, args...)
			nativePublicationDecode(t, deleted, deletes, "success")
			nativePublicationEffects(t, binaries, before, 10)
			nativePublicationUnchanged(t, image)
			output.checkValues(t, keys, true)
			for _, child := range []workflowChild{published, repeat, combined, combinedNoop, deleted} {
				workflowNoRecovery(t, child)
			}
			if !reflect.DeepEqual(identity, nativePublicationBinaries(t, binaries)) {
				t.Fatal("runtime target change rebuilt or changed installed bytes")
			}
		})
	}
}
