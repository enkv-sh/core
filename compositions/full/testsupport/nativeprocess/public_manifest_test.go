package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

type nativeManifestRow struct {
	Name   string `json:"name"`
	ID     string `json:"entry_incarnation_id"`
	Reason string `json:"reason,omitempty"`
}

type nativeManifestReply struct {
	Schema   string `json:"schema"`
	Issuance struct {
		Schema      string          `json:"schema"`
		Operation   string          `json:"operation_kind"`
		State       string          `json:"state_result"`
		Effect      string          `json:"effect_summary"`
		Output      string          `json:"output_summary"`
		Target      string          `json:"target_recipient_id"`
		Failure     string          `json:"failure_reason"`
		Observation json.RawMessage `json:"observation"`
		Scope       json.RawMessage `json:"request_scope"`
		Payload     *struct {
			Schema        string              `json:"schema"`
			RendererFacts json.RawMessage     `json:"renderer"`
			Format        string              `json:"format_contract_id"`
			Config        string              `json:"config_contract_id"`
			Settings      []byte              `json:"settings"`
			Length        uint64              `json:"artifact_length"`
			Digest        string              `json:"artifact_digest"`
			Evidence      string              `json:"evidence_limit"`
			Selection     json.RawMessage     `json:"selection"`
			Service       json.RawMessage     `json:"service_filter"`
			Included      []nativeManifestRow `json:"included_entries"`
			Excluded      []nativeManifestRow `json:"excluded_entries"`
		} `json:"payload"`
	} `json:"issuance"`
	Delivery struct {
		Target   *string `json:"target_path"`
		Artifact *struct {
			Format   string `json:"format_contract_id"`
			Renderer string `json:"renderer_artifact_id"`
			Length   uint64 `json:"length"`
			Digest   string `json:"digest"`
		} `json:"artifact"`
		Replacement string          `json:"replacement"`
		Candidate   string          `json:"candidate_verification"`
		Installed   string          `json:"installed_verification"`
		Completion  string          `json:"native_completion"`
		Cleanup     string          `json:"candidate_cleanup"`
		Residue     *string         `json:"residue_path"`
		Failure     json.RawMessage `json:"failure"`
	} `json:"delivery"`
	Source string `json:"source_cleanup"`
	Result string `json:"result_delivery"`
}

func nativeManifestRun(t *testing.T, s *workflowServer, cli string, plugins nativePluginFixture, source, format, destination string, policy observer.Policy, options ...string) workflowChild {
	t.Helper()
	policy.NoKMS = true
	args := []string{"manifest", "--source", source, "--source-format", format, "--out", destination, "--plugin", "generic-json", "--settings", "{}", "--json"}
	args = append(args, options...)
	environment := append(plugins.Environment(t, source), "GITHUB_TOKEN=")
	if s.family == "gcp" {
		environment = append(environment, "AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=", "AWS_SESSION_TOKEN=")
	}
	child := workflowRunEnvironment(t, s, cli, "reader", policy, nil, environment, args...)
	workflowGETOnly(t, child)
	for _, event := range child.capture.Events {
		switch event.Kind {
		case "construction", "generator-entry", "generator-return", "generator-refused", "recipient-plaintext":
			t.Fatal("manifest entered a private capability or effect owner")
		case "source-kind":
			if event.Matched {
				t.Fatal("synthetic manifest fixture claimed qualified cloud credentials")
			}
		}
	}
	return child
}

func nativeManifestResult(t *testing.T, child workflowChild) nativeManifestReply {
	t.Helper()
	var result nativeManifestReply
	if json.Unmarshal(child.out, &result) != nil || result.Schema != "ManifestFileResult/v2" || result.Issuance.Schema != "ProductResult/v1" || result.Issuance.Operation != "issue-consumption-manifest" || result.Issuance.Effect != "not-applicable" || result.Issuance.Output != "not-applicable" || result.Source != "complete" || result.Result != "not-observed" {
		t.Fatal("manifest lost its public issuance, native or terminal result", child.code, child.summary)
	}
	return result
}

func nativeManifestDelivered(t *testing.T, child workflowChild, destination, expected string) {
	t.Helper()
	result := nativeManifestResult(t, child)
	p, d := result.Issuance.Payload, result.Delivery
	if child.code != 0 || result.Issuance.State != "success" || result.Issuance.Failure != "" || p == nil || p.Schema != "ManifestPayload/v3" || p.Format != "ENKV/CONSUMPTION-MANIFEST/v3" || p.Config != "ENKV/CONSUMPTION-MANIFEST-CONFIG/v1" || string(p.Settings) != "{}" || p.Evidence != "authorized-input-and-exact-bytes" || d.Target == nil || *d.Target != destination || d.Artifact == nil || d.Replacement != "replaced" || d.Candidate != "verified" || d.Installed != "verified" || d.Completion != "complete" || d.Cleanup != "renamed" || d.Residue != nil || !bytes.Equal(d.Failure, []byte("null")) {
		t.Fatal("manifest did not retain complete issuance and native completion")
	}
	body, err := os.ReadFile(destination)
	info, statErr := os.Lstat(destination)
	if err != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || string(body) != expected {
		t.Fatal("manifest did not install exact independent JSON bytes and mode")
	}
	digest := sha256.Sum256([]byte(expected))
	if p.Length != uint64(len(expected)) || p.Digest != hex.EncodeToString(digest[:]) || d.Artifact.Format != p.Format || d.Artifact.Length != p.Length || d.Artifact.Digest != p.Digest {
		t.Fatal("manifest metadata differs from the complete independent artifact")
	}
	var renderer struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		Protocol   string `json:"protocol_id"`
		Descriptor string `json:"descriptor_id"`
		Executor   string `json:"executor_id"`
		Contract   string `json:"artifact_contract_id"`
		Dependency string `json:"dependency_manifest_id"`
		Artifact   string `json:"artifact_id"`
		Digest     string `json:"artifact_sha256"`
		Length     uint64 `json:"artifact_length"`
	}
	if json.Unmarshal(p.RendererFacts, &renderer) != nil || renderer.Name != "generic-json" || renderer.Version == "" || renderer.Length == 0 || d.Artifact.Renderer != renderer.Artifact {
		t.Fatal("manifest lost exact selected renderer facts")
	}
	for _, value := range []string{renderer.Protocol, renderer.Descriptor, renderer.Executor, renderer.Contract, renderer.Dependency, renderer.Artifact, renderer.Digest} {
		if nativePublicationID(t, value).IsZero() {
			t.Fatal("manifest renderer identity is zero")
		}
	}
	var scope map[string]json.RawMessage
	if json.Unmarshal(result.Issuance.Scope, &scope) != nil || len(scope) != 6 || !bytes.Equal(scope["renderer"], p.RendererFacts) || string(scope["format_contract_id"]) != `"ENKV/CONSUMPTION-MANIFEST/v3"` || string(scope["config_contract_id"]) != `"ENKV/CONSUMPTION-MANIFEST-CONFIG/v1"` || string(scope["settings"]) != `"e30="` || !bytes.Equal(scope["selection"], p.Selection) || !bytes.Equal(scope["service_filter"], p.Service) {
		t.Fatal("manifest lost its validated request scope")
	}

	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(destination), ".enkv-manifest-*")); err != nil || len(matches) != 0 {
		t.Fatal("manifest left an owned candidate after complete delivery")
	}
}

func nativeManifestInstalled(t *testing.T, child workflowChild, destination, expected string) {
	t.Helper()
	nativeManifestDelivered(t, child, destination, expected)
	result := nativeManifestResult(t, child)
	p := result.Issuance.Payload
	var artifact struct {
		Observation json.RawMessage     `json:"observation"`
		Target      string              `json:"target_recipient_id"`
		Selection   json.RawMessage     `json:"selection"`
		Service     json.RawMessage     `json:"service_filter"`
		Entries     []nativeManifestRow `json:"entries"`
		Excluded    []nativeManifestRow `json:"excluded_entries"`
	}
	jsonEqual := func(a, b json.RawMessage) bool {
		var first, second bytes.Buffer
		if json.Compact(&first, a) != nil || json.Compact(&second, b) != nil {
			return false
		}
		return bytes.Equal(first.Bytes(), second.Bytes())
	}
	if json.Unmarshal([]byte(expected), &artifact) != nil || !jsonEqual(artifact.Observation, result.Issuance.Observation) || artifact.Target != result.Issuance.Target || !jsonEqual(artifact.Selection, p.Selection) || !jsonEqual(artifact.Service, p.Service) || !reflect.DeepEqual(artifact.Entries, p.Included) || !reflect.DeepEqual(artifact.Excluded, p.Excluded) {
		t.Fatal("independent JSON consumer differs from the complete authorized selection")
	}
}

func nativeManifestBindings(t *testing.T, s *workflowServer, f nativeMaterializationFixture) map[string]contract.ID {
	t.Helper()
	var parts []contract.OutputConfigurationSlice
	for _, ref := range f.root.RequiredSupport {
		key, err := stateformat.Key(s.prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := stateformat.InspectRequiredSupportPage(s.object(t, key).body)
		if err != nil {
			t.Fatal("manifest selected support page is invalid", err)
		}
		for _, record := range page.Records {
			if record.Kind != contract.OutputConfigurationSliceSupportKind {
				continue
			}
			part, err := contract.InspectOutputConfigurationSlice(record.Body)
			if err != nil {
				t.Fatal(err)
			}
			if part.ConfigurationDigest == f.root.OutputConfiguration.ConfigurationDigest {
				parts = append(parts, part)
			}
		}
	}
	body, err := contract.JoinOutputConfiguration(f.root.Domain, f.root.OutputConfiguration, parts)
	if err != nil {
		t.Fatal(err)
	}
	configuration, _, err := contract.InspectOutputConfiguration(f.root.Domain, body)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]contract.ID, len(configuration.Bindings))
	for _, binding := range configuration.Bindings {
		result[binding.DestinationID] = binding.IncarnationID
	}
	return result
}

type nativeManifestDestination struct {
	id, service, locator, target, targetContract, data string
	policy                                             bool
}

// These literals use the installed plugins' public target contracts and the
// controlled service's creation suffix. They do not read the projection.
func nativeManifestDestinations(name, account, project, owner string) []nativeManifestDestination {
	aws := "arn:aws:secretsmanager:us-east-1:" + account + ":secret:" + name
	gcp := "projects/" + project + "/secrets/" + name
	environment := "repos/" + owner + "/repo/environments/prod/secrets/" + name
	organization := "orgs/" + owner + "/actions/secrets/" + name
	repository := "repos/" + owner + "/repo/actions/secrets/" + name
	return []nativeManifestDestination{
		{"aws", "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", aws + "-AbCd12?stage=AWSCURRENT", aws, "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1", fmt.Sprintf(`{"account":"%s","region":"us-east-1","name":"%s"}`, account, name), false},
		{"environment", "github-actions/service/v1", environment, environment, "github-actions/target/v1", fmt.Sprintf(`{"scope":3,"coordinate":"%s"}`, environment), false},
		{"gcp", "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", gcp + "/versions/latest", gcp, "ENKV/OUTPUT/GCP-SECRET-MANAGER/TARGET/v1", fmt.Sprintf(`{"project_number":"%s","name":"%s"}`, project, name), false},
		{"organization", "github-actions/service/v1", organization, organization, "github-actions/target/v1", fmt.Sprintf(`{"scope":2,"coordinate":"%s"}`, organization), true},
		{"repository", "github-actions/service/v1", repository, repository, "github-actions/target/v1", fmt.Sprintf(`{"scope":1,"coordinate":"%s"}`, repository), false},
	}
}

func nativeManifestExpected(t *testing.T, f nativeMaterializationFixture, bindings map[string]contract.ID, account, project, owner, target, targetMode, entryMode, service string, names []string, routes map[string][]string, plain map[string]string) string {
	t.Helper()
	id := func(value contract.ID) string { return hex.EncodeToString(value[:]) }
	quote := func(value string) string { body, _ := json.Marshal(value); return string(body) }
	filter := "null"
	if service != "" {
		filter = quote(service)
	}
	result := fmt.Sprintf(`{"schema":"ENKV/CONSUMPTION-MANIFEST/v3","format_contract_id":"ENKV/CONSUMPTION-MANIFEST/v3","config_contract_id":"ENKV/CONSUMPTION-MANIFEST-CONFIG/v1","observation":{"domain_id":"%s","head_revision_id":"%s","snapshot_id":"%s"},"target_recipient_id":"%s","selection":{"target_mode":"%s","entry_mode":"%s"},"service_filter":%s,"entries":[`, id(f.root.Domain), id(f.head.Core.Revision), id(f.root.Snapshot), target, targetMode, entryMode, filter)
	var included, excluded []string
	names = slices.Clone(names)
	slices.Sort(names)
	for _, name := range names {
		entry := `{"name":` + quote(name) + `,"entry_incarnation_id":"` + id(f.entries[name].Incarnation) + `"`
		if value, ok := plain[name]; ok {
			included = append(included, entry+`,"content":{"kind":"plain","value_base64":"`+base64.StdEncoding.EncodeToString([]byte(value))+`"}}`)
			continue
		}
		var destinations []string
		encoding := "raw"
		if name == "BINARY" {
			encoding = "base64"
		}
		for _, destination := range nativeManifestDestinations(name, account, project, owner) {
			if !slices.Contains(routes[name], destination.id) || service != "" && service != destination.service {
				continue
			}
			policy := "null"
			if destination.policy {
				// Literal policy bytes: schema 1, explicit set, two u64 subjects 7 and 11.
				data := []byte{0, 1, 3, 0, 2, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 11}
				body := append([]byte("ENKV/OUTPUT/POLICY/v3\x00"), f.root.Domain[:]...)
				for _, field := range [][]byte{[]byte("github-actions/org-visibility/v1"), data} {
					body = binary.BigEndian.AppendUint32(body, uint32(len(field)))
					body = append(body, field...)
				}
				digest := sha256.Sum256(body)
				policy = fmt.Sprintf(`{"contract_id":"github-actions/org-visibility/v1","data_base64":"%s","digest":"%x"}`, base64.StdEncoding.EncodeToString(data), digest)
			}
			destinations = append(destinations, fmt.Sprintf(`{"destination_id":"%s","binding_incarnation_id":"%s","entry_incarnation_id":"%s","service_contract_id":"%s","consumer_locator":"%s","target_contract_id":"%s","canonical_target":"%s","target_data_base64":"%s","payload_encoding":"%s","consumer_policy":%s}`, destination.id, id(bindings[destination.id]), id(f.entries[name].Incarnation), destination.service, destination.locator, destination.targetContract, destination.target, base64.StdEncoding.EncodeToString([]byte(destination.data)), encoding, policy))
		}
		if len(destinations) != 0 {
			included = append(included, entry+`,"content":{"kind":"secret","destinations":[`+strings.Join(destinations, ",")+`]}}`)
		} else {
			reason := "no-output"
			if len(routes[name]) != 0 {
				reason = "no-matching-service"
			}
			excluded = append(excluded, entry+`,"reason":"`+reason+`"}`)
		}
	}
	compact := result + strings.Join(included, ",") + `],"excluded_entries":[` + strings.Join(excluded, ",") + `],"evidence_limit":"authorized-input-and-exact-bytes"}`
	// The standard-library formatter is independent of the plugin writer.
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, []byte(compact), "", "  "); err != nil {
		t.Fatal("independent expected manifest is invalid", err)
	}
	formatted.WriteByte('\n')
	return formatted.String()
}

// full_only: true
func TestPublicNativeManifestUsesCompleteSelectedRoutesWithoutPrivateCapabilities(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	output := newNativePublicationServer(t)
	binaries := buildNativeOutputExecutables(t, output.server.URL)
	genericBuild := nativeManifestProductionBuild(t)
	binaries.nativePluginFixture = newNativePluginFixture(t, append(slices.Clone(binaries.builds), genericBuild)...)
	for familyIndex, family := range []string{"aws", "gcp"} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recovery-%t", family, recovery), func(t *testing.T) {
				s := newWorkflowServer(t, family, recovery)
				s.childLimit, s.childRequestLimit, s.objectLimit = 19, 2048, 512
				caseIndex := 1 + familyIndex*2
				if recovery {
					caseIndex++
				}
				account, project, owner := fmt.Sprintf("%012d", caseIndex), fmt.Sprint(900000000000+caseIndex), fmt.Sprintf("manifest%d", caseIndex)
				source := filepath.Join(t.TempDir(), "configuration.json")
				if err := os.WriteFile(source, workflowSetup(t, s, recovery), 0600); err != nil {
					t.Fatal(err)
				}
				children := []workflowChild{workflowRun(t, s, binaries.cli, "init", observer.Policy{}, nil, "init", "--source", source, "--source-format", "json", "--json")}
				workflowResult(t, children[0], "success")
				values := map[string]string{"AWS_ONLY": "selected aws secret", "BINARY": "selected binary\n\x00\xff", "GCP_ONLY": "selected gcp secret", "ONLY_OTHER": "selected other recipient secret", "UNROUTED": "selected unrouted secret"}
				nativePublicationSource(t, source, func(value map[string]any) {
					entries := value["entries"].(map[string]any)
					entries["PLAIN"] = map[string]any{"confidentiality": "plain", "recipients": []string{"reader"}, "source": map[string]any{"kind": "supplied", "value": "selected public #value"}}
				})
				for _, name := range []string{"AWS_ONLY", "BINARY", "GCP_ONLY", "ONLY_OTHER", "UNROUTED"} {
					// Set admits only its selected secret without a prepared row.
					nativePublicationSource(t, source, func(value map[string]any) {
						recipients := []string{}
						if name == "BINARY" {
							recipients = []string{"reader"}
						}
						value["entries"].(map[string]any)[name] = map[string]any{"confidentiality": "secret", "recipients": recipients, "source": map[string]any{"kind": "supplied"}}
					})
					child := workflowRun(t, s, binaries.cli, "set", observer.Policy{NoKMS: true}, []byte(values[name]), "set", "--source", source, "--source-format", "json", "--name", name, "--json")
					workflowResult(t, child, "success")
					children = append(children, child)
				}
				nativePublicationSource(t, source, func(value map[string]any) {
					declaration := nativePublicationDeclaration(account, project, owner)
					declaration["routing"] = map[string]any{"entries": map[string]any{"BINARY": []string{"aws", "environment", "gcp", "organization", "repository"}, "AWS_ONLY": []string{"aws"}, "GCP_ONLY": []string{"gcp"}, "ONLY_OTHER": []string{"gcp"}}}
					value["entries"].(map[string]any)["BINARY"].(map[string]any)["output_encoding"] = "base64"
					value["outputs"] = declaration
				})
				applied := workflowRunEnvironment(t, s, binaries.cli, "apply", observer.Policy{}, nil, binaries.Environment(t, source), "apply", "--source", source, "--source-format", "json", "--json")
				workflowResult(t, applied, "success")
				children = append(children, applied)
				targets := slices.DeleteFunc(nativePublicationTargets(account, project, owner), func(target nativePublicationTarget) bool { return target.entry != "BINARY" })
				targets = append(targets, nativePublicationTarget{"ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", "arn:aws:secretsmanager:us-east-1:" + account + ":secret:AWS_ONLY", "aws:arn:aws:secretsmanager:us-east-1:" + account + ":secret:AWS_ONLY-AbCd12", "aws", "AWS_ONLY"}, nativePublicationTarget{"ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", "projects/" + project + "/secrets/GCP_ONLY", "gcp:projects/" + project + "/secrets/GCP_ONLY", "gcp", "GCP_ONLY"})
				expectedOutputs := map[string][]byte{}
				for _, target := range targets {
					value := values[target.entry]
					if target.entry == "BINARY" {
						value = base64.StdEncoding.EncodeToString([]byte(value))
					}
					expectedOutputs[target.key] = []byte(value)
				}
				output.expect(account, expectedOutputs)
				environment := []string{"GITHUB_TOKEN=github_pat_NATIVE_OUTPUT"}
				if family == "aws" {
					environment = append(environment, "GOOGLE_APPLICATION_CREDENTIALS="+nativePublicationADC(t, output), "GCE_METADATA_HOST=127.0.0.1:1")
				} else {
					environment = append(environment, "AWS_ACCESS_KEY_ID=AKIANATIVEOUTPUTTEST", "AWS_SECRET_ACCESS_KEY=offline-output-only", "AWS_EC2_METADATA_DISABLED=true")
				}
				// Publish only the requested entries. The unrequested shared GCP locator
				// remains valid without creation evidence.
				environment = append(binaries.Environment(t, source), environment...)
				published := workflowRunEnvironment(t, s, binaries.cli, "apply", observer.Policy{}, nil, environment, "publish", "--source", source, "--source-format", "json", "--name", "AWS_ONLY", "--name", "BINARY", "--name", "GCP_ONLY", "--json")
				pair := workflowReadPair(t, source)
				f := nativeMaterializationObservation(t, s, source, "", pair)
				domain := hex.EncodeToString(f.root.Domain[:])
				nativePublicationDecode(t, published, nativePublicationExpectedActions(t, domain, targets, "create"), "success")
				children = append(children, published)
				bindings := nativeManifestBindings(t, s, f)
				authority := hex.EncodeToString(pair.descriptor.AuthorityRecipientID[:])
				var reader string
				for _, recipient := range pair.descriptor.Recipients {
					if recipient.RecipientID != pair.descriptor.AuthorityRecipientID {
						reader = hex.EncodeToString(recipient.RecipientID[:])
					}
				}
				if authority == "" || reader == "" || len(bindings) != 5 || len(f.entries) != 6 {
					t.Fatal("manifest fixture is incomplete")
				}
				selectedSource, err := os.ReadFile(source)
				if err != nil {
					t.Fatal(err)
				}
				nativePublicationSource(t, source, func(value map[string]any) {
					value["entries"].(map[string]any)["PLAIN"].(map[string]any)["source"].(map[string]any)["value"] = "unapplied public value"
					value["entries"].(map[string]any)["UNROUTED"].(map[string]any)["recipients"] = []string{"reader"}
					value["outputs"] = nativePublicationDeclaration("999999999999", "899999999999", "unapplied-owner")
				})
				yaml := nativePublicationYAML(t, source)
				images := nativePublicationImages(t, source, yaml, filepath.Join(filepath.Dir(source), pair.reference))
				before := nativePublicationCounters(t, binaries)
				_, head := workflowHead(t, s)
				objects, effects := s.objectCount(), output.effectCount()
				routes := map[string][]string{"BINARY": {"aws", "environment", "gcp", "organization", "repository"}, "AWS_ONLY": {"aws"}, "GCP_ONLY": {"gcp"}, "ONLY_OTHER": {"gcp"}}
				plain := map[string]string{"PLAIN": "selected public #value"}
				names := []string{"AWS_ONLY", "BINARY", "GCP_ONLY", "ONLY_OTHER", "PLAIN", "UNROUTED"}
				for index, provider := range []string{"", "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", "github-actions/service/v1"} {
					out := filepath.Join(t.TempDir(), "manifest.json")
					if err := os.WriteFile(out, []byte("old complete file"), 0644); err != nil {
						t.Fatal(err)
					}
					path, format := source, "json"
					if index%2 != 0 {
						path, format = yaml, "yaml"
					}
					var options []string
					if provider != "" {
						options = []string{"--service", provider}
					}
					child := nativeManifestRun(t, s, binaries.cli, binaries.nativePluginFixture, path, format, out, observer.Policy{}, options...)
					want := nativeManifestExpected(t, f, bindings, account, project, owner, authority, "current-authority", "all-authorized", provider, names, routes, plain)
					nativeManifestInstalled(t, child, out, want)
					children = append(children, child)
				}
				if family == "aws" && !recovery {
					readerRoutes := map[string][]string{"BINARY": routes["BINARY"]}
					for _, selection := range []string{"all", "exact-authorized", "exact-denied"} {
						out := filepath.Join(t.TempDir(), "reader.json")
						selected, mode := []string{"BINARY", "PLAIN"}, "all-authorized"
						options := []string{"--recipient-id", reader, "--service", "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1"}
						if selection == "all" {
							options[0], options[1] = "--recipient", "reader"
						}
						if selection != "all" {
							name := "BINARY"
							if selection == "exact-denied" {
								name = "ONLY_OTHER"
							}
							selected, mode = []string{name}, "exact-names"
							options = append(options, "--name", name)
						}
						child := nativeManifestRun(t, s, binaries.cli, binaries.nativePluginFixture, source, "json", out, observer.Policy{}, options...)
						if selection == "exact-denied" {
							result := nativeManifestResult(t, child)
							d := result.Delivery
							if child.code != 2 || result.Issuance.State != "refused" || result.Issuance.Failure != "target-not-authorized" || result.Issuance.Payload != nil || d.Artifact != nil || d.Replacement != "not-attempted" || d.Cleanup != "not-created" {
								t.Fatal("shared routing granted unauthorized entry access", child.code, result.Issuance.State, result.Issuance.Failure)
							}
							if _, err := os.Lstat(out); !os.IsNotExist(err) {
								t.Fatal("unauthorized manifest created a file", err)
							}
						} else {
							nativeManifestInstalled(t, child, out, nativeManifestExpected(t, f, bindings, account, project, owner, reader, "exact-recipient", mode, "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", selected, readerRoutes, plain))
						}
						children = append(children, child)
					}
					out := filepath.Join(t.TempDir(), "empty.json")
					child := nativeManifestRun(t, s, binaries.cli, binaries.nativePluginFixture, source, "json", out, observer.Policy{}, "--empty-selection")
					nativeManifestInstalled(t, child, out, nativeManifestExpected(t, f, bindings, account, project, owner, authority, "current-authority", "exact-names", "", nil, nil, nil))
					children = append(children, child)
				}
				nativePublicationNoEffects(t, binaries, before)
				nativePublicationUnchanged(t, images)
				_, after := workflowHead(t, s)
				if !reflect.DeepEqual(head, after) || objects != s.objectCount() || effects != output.effectCount() {
					t.Fatal("manifest changed selected state or reached an output service")
				}
				for _, child := range children[8:] {
					for _, value := range values {
						if bytes.Contains(child.out, []byte(value)) || bytes.Contains(child.diagnostic, []byte(value)) {
							t.Fatal("manifest disclosed secret bytes")
						}
					}
				}
				wantChildren := 12
				if family == "aws" && !recovery {
					if err := os.WriteFile(source, selectedSource, 0600); err != nil {
						t.Fatal(err)
					}
					nativePublicationSource(t, source, func(value map[string]any) {
						entries := value["entries"].(map[string]any)
						entries["PLAIN"].(map[string]any)["recipients"] = []string{}
						entries["AWS_ONLY"].(map[string]any)["recipients"] = []string{"reader"}
					})
					// A grant needs an input sealed for the new recipient set.
					prepared := workflowRun(t, s, binaries.cli, "set", observer.Policy{NoKMS: true}, []byte(values["AWS_ONLY"]), "set", "--source", source, "--source-format", "json", "--name", "AWS_ONLY", "--json")
					workflowResult(t, prepared, "success")
					children = append(children, prepared)
					changed := workflowRunEnvironment(t, s, binaries.cli, "apply", observer.Policy{}, nil, binaries.Environment(t, source), "apply", "--source", source, "--source-format", "json", "--json")
					workflowResult(t, changed, "success")
					children = append(children, changed)
					next := nativeMaterializationObservation(t, s, source, reader, workflowReadPair(t, source))
					if next.head.Core.Revision == f.head.Core.Revision {
						t.Fatal("membership update did not advance the selected observation")
					}
					out := filepath.Join(t.TempDir(), "current-membership.json")
					child := nativeManifestRun(t, s, binaries.cli, binaries.nativePluginFixture, source, "json", out, observer.Policy{}, "--recipient-id", reader)
					nextRoutes := map[string][]string{"AWS_ONLY": {"aws"}, "BINARY": routes["BINARY"]}
					nativeManifestInstalled(t, child, out, nativeManifestExpected(t, next, nativeManifestBindings(t, s, next), account, project, owner, reader, "exact-recipient", "all-authorized", "", []string{"AWS_ONLY", "BINARY"}, nextRoutes, nil))
					children = append(children, child)
					wantChildren = 19
					nativePublicationNoEffects(t, binaries, before)
				}
				nativeMaterializationJoined(t, children, wantChildren)
			})
		}
	}
}

func nativeManifestReadCount(child workflowChild, headOnly bool) int {
	count := 0
	for _, event := range child.capture.Events {
		if event.Kind == "http-start" && (event.Operation == "head-read" || !headOnly && event.Operation == "store-read") {
			count++
		}
	}
	return count
}

func nativeManifestGCInterleaving(t *testing.T, cli string, plugins nativePluginFixture, family string, loaded bool) {
	t.Helper()
	s := newWorkflowServer(t, family, false)
	const childrenExpected = 8
	s.requestLimit, s.objectLimit = childrenExpected*workflowChildRequestLimit, 256
	f := nativeMaterializationSetup(t, s, cli, nil)
	children := slices.Clone(f.children)
	oldKey, err := stateformat.Key(s.prefix, *f.root.ValueEntryPages[0])
	if err != nil {
		t.Fatal(err)
	}
	nativePublicationSource(t, f.source, func(source map[string]any) {
		source["entries"].(map[string]any)["PLAIN"].(map[string]any)["source"].(map[string]any)["value"] = "successor public value"
	})
	prepared := workflowRun(t, s, cli, "set-change", observer.Policy{NoKMS: true}, []byte("successor supplied value"), "set", "--source", f.source, "--source-format", "json", "--name", "SUPPLIED", "--json")
	workflowResult(t, prepared, "success")
	children = append(children, prepared)
	pair := workflowReadPair(t, f.source)
	images := nativePublicationImages(t, f.source, filepath.Join(filepath.Dir(f.source), pair.reference))
	gate := &workflowMaterializationGate{owner: "reader", method: http.MethodGet, host: "s3.us-east-1.amazonaws.com", path: "/fixture-bucket/" + oldKey, entered: make(chan struct{}), release: make(chan struct{})}
	if family == "gcp" {
		gate.host, gate.path = "storage.us-central1.rep.googleapis.com", "/download/storage/v1/b/fixture-bucket/o/"+oldKey
	}
	policy := observer.Policy{}
	barrier := ""
	if loaded {
		barrier = filepath.Join(t.TempDir(), "handoff")
		if err := os.Mkdir(barrier, 0700); err != nil {
			t.Fatal(err)
		}
		policy.ManifestBarrier = barrier
	} else {
		s.mu.Lock()
		s.materializationGate = gate
		s.mu.Unlock()
	}
	directory := t.TempDir()
	destination := filepath.Join(directory, "manifest.json")
	const oldFile = "old complete manifest file"
	if err := os.WriteFile(destination, []byte(oldFile), 0600); err != nil {
		t.Fatal(err)
	}
	joined := make(chan workflowChild, 1)
	go func() {
		var child workflowChild
		defer func() { joined <- child }()
		child = nativeManifestRun(t, s, cli, plugins, f.source, "json", destination, policy, "--name", "SUPPLIED", "--name", "PLAIN")
	}()
	var release sync.Once
	releaseChild := func() {
		release.Do(func() {
			if loaded {
				if err := os.WriteFile(filepath.Join(barrier, "release"), nil, 0600); err != nil {
					t.Error("manifest handoff release failed", err)
				}
			} else {
				close(gate.release)
			}
		})
	}
	var child workflowChild
	collected := false
	defer func() {
		releaseChild()
		if !collected {
			select {
			case child = <-joined:
				collected = true
			case <-time.After(60 * time.Second):
				t.Error("manifest process did not join after local release")
			}
		}
		complete := false
		if events := child.capture.Events; len(events) != 0 {
			footer := events[len(events)-1]
			complete = footer.Kind == "footer" && footer.Code == child.code
		}
		t.Logf("manifest held child: loaded=%t joined=%t capture_complete=%t exit=%d", loaded, collected, complete, child.code)
	}()
	if loaded {
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
	waiting:
		for {
			matches, err := filepath.Glob(filepath.Join(barrier, "*.ready"))
			if err != nil {
				t.Fatal(err)
			}
			if len(matches) == 1 {
				break waiting
			}
			if len(matches) > 1 {
				t.Fatal("manifest supplied more than one complete artifact handoff")
			}
			select {
			case child = <-joined:
				collected = true
				t.Fatal("manifest returned before the complete artifact handoff", child.code)
			case <-timer.C:
				t.Fatal("manifest did not reach the complete artifact handoff")
			case <-ticker.C:
			}
		}
	} else {
		select {
		case <-gate.entered:
		case child = <-joined:
			collected = true
			t.Fatal("manifest returned before the unread selected dependency cut", child.code)
		case <-time.After(30 * time.Second):
			t.Fatal("manifest did not reach its unread selected dependency")
		}
	}
	readsAtCut := s.snapshot("reader").reads
	headsAtCut := s.snapshot("reader").headReads
	// The original image remains selected while independent public commands
	// apply its successor and conditionally delete the exact obsolete child.
	applied := workflowRun(t, s, cli, "apply", observer.Policy{}, nil, "apply", "--source", f.source, "--source-format", "json", "--json")
	workflowResult(t, applied, "success")
	children = append(children, applied)
	successor := nativeMaterializationObservation(t, s, f.source, f.recipient, pair)
	nextKey, err := stateformat.Key(s.prefix, *successor.root.ValueEntryPages[0])
	if err != nil || nextKey == oldKey || successor.head.Core.Revision == f.head.Core.Revision || successor.head.Core.PreviousRevision != f.head.Core.Revision {
		t.Fatal("manifest cut did not produce a distinct authentic successor")
	}
	gc := nativeMaterializationGC(t, s, cli, f.source, oldKey)
	children = append(children, gc...)
	current := nativeMaterializationObservation(t, s, f.source, f.recipient, pair)
	if !reflect.DeepEqual(current.root.ValueEntryPages, successor.root.ValueEntryPages) || current.head.Core.Revision == successor.head.Core.Revision {
		t.Fatal("manifest GC did not preserve the successor under its own changed HEAD")
	}
	gcReads := nativeManifestReadCount(gc[0], false)
	if loaded {
		s.mu.Lock()
		s.readerStoreDenied = true
		s.mu.Unlock()
	}
	_, finalHead := workflowHead(t, s)
	objects := s.objectCount()
	releaseChild()
	select {
	case child = <-joined:
		collected = true
	case <-time.After(60 * time.Second):
		t.Fatal("manifest did not join after actual GC")
	}
	children = append(children, child)
	missing := 0
	for _, event := range child.capture.Events {
		if event.Kind == "http-return" && event.ObjectKeySHA256 == workflowDigest([]byte(oldKey)) && event.Status == 404 {
			missing++
		}
	}
	if loaded {
		if missing != 0 || nativeManifestReadCount(child, false) != readsAtCut || s.snapshot("reader").reads != readsAtCut+gcReads {
			t.Fatal("manifest reread Store after complete artifact handoff")
		}
		authority := hex.EncodeToString(f.pair.descriptor.AuthorityRecipientID[:])
		want := nativeManifestExpected(t, f, nil, "", "", "", authority, "current-authority", "exact-names", "", []string{"PLAIN", "SUPPLIED"}, nil, map[string]string{"PLAIN": "public #selected"})
		nativeManifestInstalled(t, child, destination, want)
	} else {
		result := nativeManifestResult(t, child)
		d := result.Delivery
		if child.code != 3 || result.Issuance.State != "unavailable" || result.Issuance.Failure != "selected-object-unavailable" || result.Issuance.Payload != nil || d.Artifact != nil || d.Replacement != "not-attempted" || d.Candidate != "not-observed" || d.Installed != "not-observed" || d.Completion != "incomplete" || d.Cleanup != "not-created" || d.Residue != nil || !bytes.Equal(d.Failure, []byte("null")) {
			t.Fatal("manifest failed to retain an unavailable issuance before native staging", child.code, result.Issuance.State, result.Issuance.Failure)
		}
		if missing != 1 || nativeManifestReadCount(child, false) != readsAtCut+1 || nativeManifestReadCount(child, true) != headsAtCut {
			t.Fatal("manifest restarted after losing its selected unread dependency", missing, nativeManifestReadCount(child, false), readsAtCut, nativeManifestReadCount(child, true))
		}
		body, err := os.ReadFile(destination)
		files, readErr := os.ReadDir(directory)
		if err != nil || string(body) != oldFile || readErr != nil || len(files) != 1 || files[0].Name() != "manifest.json" {
			t.Fatal("failed manifest changed or staged a local artifact")
		}
	}
	nativeMaterializationJoined(t, children, childrenExpected)
	nativePublicationUnchanged(t, images)
	_, after := workflowHead(t, s)
	if !reflect.DeepEqual(finalHead, after) || objects != s.objectCount() || s.children != 0 {
		t.Fatal("manifest changed domain state or lost fixed child admission")
	}
	t.Logf("manifest GC: loaded=%t children=%d old_child_missing=%d reader_reads_at_cut=%d manifest_reads=%d head_reads=%d head_reads_at_cut=%d", loaded, len(children), missing, readsAtCut, nativeManifestReadCount(child, false), nativeManifestReadCount(child, true), headsAtCut)
}

// full_only: true
func TestPublicNativeManifestRefusesUnreadDependencyRemovedByGC(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	cli, _ := workflowExecutables(t)
	plugins := newNativePluginFixture(t, nativeManifestProductionBuild(t))
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) { nativeManifestGCInterleaving(t, cli, plugins, family, false) })
	}
}

// full_only: true
func TestPublicNativeManifestCompletesOriginalArtifactAfterGC(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	cli, _ := workflowExecutables(t)
	plugins := newNativePluginFixture(t, nativeManifestProductionBuild(t))
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) { nativeManifestGCInterleaving(t, cli, plugins, family, true) })
	}
}
