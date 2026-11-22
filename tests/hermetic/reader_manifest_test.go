package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	genericjson "enkv.sh/plugins/manifest-generators/generic-json"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	opentofu "enkv.sh/plugins/manifest-generators/opentofu-tfvars-json"
	manifestsdk "enkv.sh/sdk/manifest-generator"
)

// full_only: false
func TestReaderManifestCallableCompleteMixedArtifact(t *testing.T) {
	projectionEngine, _, selected, env, target := manifestFixture(t, true)
	engine, _, source := readerEngineFixture(t, env, selected)
	engine.validator = projectionEngine.validator
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	pub, priv := env.Custody.Calls()
	requestID := contract.Hash([]byte("manifest callable mixed request"))
	request := hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{"secret", "a/\n雪", ""}})
	got := engine.Manifest(ctx, requestID, request)
	if got.StateResult != contract.ReaderSuccess || got.FailureReason != "" || got.Result.Outcome != ObservedCurrent || got.Payload == nil || got.Observation == nil || got.Artifact == nil {
		t.Fatalf("manifest failed %+v", got)
	}
	if got.Context.OperationID.IsZero() || got.Context.RequestID != requestID || got.Context.Operation != contract.ReaderManifestOperation || got.TargetRecipientID != target {
		t.Fatal("issuer/target context")
	}
	if got.Payload.Observation != (manifestsdk.Observation{DomainID: manifestsdk.ID(env.Domain), HEADRevisionID: manifestsdk.ID(selected.head.Core.Revision), SnapshotID: manifestsdk.ID(selected.root.Snapshot)}) || got.Payload.ArtifactLength != uint64(len(got.Artifact)) || got.Payload.ArtifactDigest != contract.Hash(got.Artifact) || got.Payload.EvidenceLimit != manifestsdk.EvidenceLimit || !reflect.DeepEqual(manifestIncludedNamesForTest(got.Payload), []string{"", "a/\n雪", "secret"}) {
		t.Fatal("complete success payload")
	}
	var doc readerCapacityJSONManifest
	if err := json.Unmarshal(got.Artifact, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != genericjson.Schema || doc.Format != genericjson.FormatContractID || doc.Config != genericjson.ConfigContractID || doc.Target != hex.EncodeToString(target[:]) || len(doc.Entries) != 3 {
		t.Fatal("closed artifact envelope")
	}
	for i, name := range []string{"", "a/\n雪", "secret"} {
		row := doc.Entries[i]
		if row.Name != name {
			t.Fatal("selection order")
		}
		for _, n := range selected.root.Names {
			if n.Name == name {
				id := selected.valueEntry(n.Slot).Incarnation
				if row.Incarnation != hex.EncodeToString(id[:]) {
					t.Fatal("entry identity")
				}
			}
		}
	}
	for i, b := range [][]byte{{}, {0, 10, 65}} {
		decoded, err := base64.StdEncoding.Strict().DecodeString(doc.Entries[i].Content.Plain)
		if err != nil || !bytes.Equal(decoded, b) || doc.Entries[i].Content.Kind != "plain" {
			t.Fatal("exact plain content", err)
		}
	}
	secret := doc.Entries[2]
	if secret.Content.Kind != "secret" || secret.Content.Plain != "" || len(secret.Content.Destinations) != 2 {
		t.Fatal("complete secret alternatives")
	}
	configuration, res := selected.currentOutputConfigurationForApply(ctx)
	if res.Outcome != 0 {
		t.Fatal(res)
	}
	for i, d := range secret.Content.Destinations {
		name := []string{"primary", "secondary"}[i]
		service := []string{"private/reader-service/v1", "aws"}[i]
		if d.Destination != name || d.Incarnation != secret.Incarnation || d.Service != service || d.Locator != name+"-secret?stage=AWSCURRENT" || d.TargetContract != "fixture/target/v1" || d.Target != name+"-secret" || d.TargetData != base64.StdEncoding.EncodeToString([]byte("target:"+name+"-secret")) || d.Encoding != "raw" {
			t.Fatal("complete destination meaning")
		}
		for _, b := range configuration.Bindings {
			if b.DestinationID == name && d.Binding != hex.EncodeToString(b.IncarnationID[:]) {
				t.Fatal("binding identity")
			}
		}
		wantContract, wantData := "fixture/numbers/v1", []byte("3,7")
		if i == 1 {
			wantContract, wantData = "fixture/text/v1", []byte(`["consumer-one","consumer-two"]`)
		}
		wantDigest := independentManifestPolicyDigest(env.Domain, wantContract, wantData)
		if d.Policy == nil || d.Policy.Contract != wantContract || d.Policy.Data != base64.StdEncoding.EncodeToString(wantData) || d.Policy.Digest != hex.EncodeToString(wantDigest[:]) {
			t.Fatal("complete opaque policy")
		}

	}
	request.EntryNames[0] = "mutated caller"
	engine.Close()
	if source.closes != 1 || !json.Valid(got.Artifact) || got.Payload.IncludedEntries[2].Name != "secret" {
		t.Fatal("completion ownership")
	}
	if store.creates != creates || store.cas != cas {
		t.Fatal("Reader wrote state")
	}
	if p, q := env.Custody.Calls(); p != pub || q != priv {
		t.Fatal("Reader used private custody")
	}
}

// full_only: false
func TestReaderManifestCallableAuthenticatedEmptyArtifact(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	engine, candidate, source := readerEngineFixture(t, env, f.session)
	target := f.session.admission.recipient
	candidate.configuration = contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
	got := engine.Manifest(ctx, contract.ID{1}, hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{}}))
	if slices.Contains(candidate.calls, "configuration") {
		t.Fatal("ordinary manifest requested the recovery helper")
	}
	if got.StateResult != contract.ReaderSuccess || got.Payload == nil || got.Artifact == nil || len(candidate.calls) == 0 || source.closes != 1 {
		t.Fatal("empty manifest did not authenticate", got.StateResult, candidate.calls, source.closes)
	}
	var doc readerCapacityJSONManifest
	if err := json.Unmarshal(got.Artifact, &doc); err != nil || doc.Entries == nil || len(doc.Entries) != 0 {
		t.Fatal("expected an empty JSON entry array", err)
	}
	if len(got.Payload.IncludedEntries) != 0 || got.Payload.IncludedEntries == nil {
		t.Fatal("empty selection or issuer")
	}
}

type manifestChangedDeadlineContext struct {
	context.Context
	changed bool
}

func (c *manifestChangedDeadlineContext) Deadline() (time.Time, bool) {
	deadline, ok := c.Context.Deadline()
	if c.changed {
		deadline = deadline.Add(-time.Nanosecond)
	}
	return deadline, ok
}

// full_only: false
func TestReaderManifestRefusesCompleteArtifactOnAnyRequestFailure(t *testing.T) {
	_, _, selected, env, target := manifestFixture(t, true)
	for _, name := range []string{"zero-request", "omitted-target", "omitted-selection", "duplicate", "absent-entry", "absent-target", "cancelled-renderer", "late-admission-deadline"} {
		t.Run(name, func(t *testing.T) {
			engine, _, source := readerEngineFixture(t, env, selected)
			base, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			ctx := &manifestChangedDeadlineContext{Context: base}
			nonce := contract.ID{1}
			request := hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{"", "a/\n雪", "secret"}})
			reason := contract.ReasonInvalidInput
			switch name {
			case "zero-request":
				nonce = contract.ID{}
			case "omitted-target":
				request.TargetRecipientID = contract.ID{}
				reason = contract.ReasonMissingRequiredField
			case "omitted-selection":
				request.EntryNames = nil
				reason = contract.ReasonMissingRequiredField
			case "duplicate":
				request.EntryNames = []string{"", "secret", "secret"}
				reason = contract.ReasonDuplicateEntry
			case "absent-entry":
				request.EntryNames = []string{"", "secret", "~absent"}
				reason = contract.ReasonEntryAbsent
			case "absent-target":
				request.TargetRecipientID = contract.ID{99}
				reason = contract.ReasonTargetAbsent
			default:
				engine.prepareManifestRenderer = func(context.Context, contract.ManifestRendererSelection) (manifestsdk.Renderer, manifestsdk.Failure) {
					return func(c context.Context, view manifestsdk.View) manifestsdk.Result {
						result := genericjson.Render(c, view)
						if name == "cancelled-renderer" {
							cancel()
						} else {
							ctx.changed = true
						}
						return result
					}, ""
				}
				reason = contract.ReasonCancelled
				if name == "late-admission-deadline" {
					reason = contract.ReasonExpired
				}
			}
			got := engine.Manifest(ctx, nonce, request)
			expectedTarget := target
			if name == "zero-request" || name == "omitted-target" || name == "omitted-selection" || name == "duplicate" || name == "absent-target" {
				expectedTarget = contract.ID{}
			}
			if got.Artifact != nil || got.Payload != nil || got.FailureReason != reason || got.StateResult != contract.ReaderRefused || got.TargetRecipientID != expectedTarget || got.Context.RequestID != nonce {
				t.Fatal("partial artifact or wrong failure", got)
			}
			if name == "cancelled-renderer" || name == "late-admission-deadline" {
				if got.Observation == nil || got.Context.OperationID.IsZero() || source.closes != 1 {
					t.Fatal("late failure lost observation or owner")
				}
			}
			if engine.activeDone != nil {
				t.Fatal("failed invocation remains active")
			}
		})
	}
}

// full_only: false
func TestReaderManifestCompletedArtifactSurvivesReaderClose(t *testing.T) {
	fixtureEngine, _, selected, env, target := manifestFixture(t, true)
	engine, candidate, source := readerEngineFixture(t, env, selected)
	engine.validator = fixtureEngine.validator
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	got := engine.Manifest(ctx, contract.ID{1}, hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{"", "a/\n雪", "secret"}}))
	if got.Payload == nil || got.Artifact == nil {
		t.Fatal("fixture manifest refused", got.FailureReason)
	}
	before := contract.Hash(got.Artifact)
	store := env.Store.(*memoryStore)
	store.readHook = func(string, contract.ReadResult) contract.ReadResult {
		t.Fatal("completed artifact re-read Store")
		return contract.ReadResult{}
	}
	defer func() { store.readHook = nil }()
	// Make any later candidate selection unavailable. Completed output keeps
	// fixed selected identities and makes no continued-currentness claim.
	engine.Close()
	candidate.head = contract.ReadResult{Status: contract.ReadMissing}
	source.store = nil
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(got.Artifact, &doc); err != nil || contract.Hash(got.Artifact) != before || got.Observation.HEADRevisionID != manifestsdk.ID(selected.head.Core.Revision) || got.Payload.EvidenceLimit != manifestsdk.EvidenceLimit {
		t.Fatal("completed artifact lost fixed observation", err)
	}
	got.Artifact[0] = '!'
	if got.Payload.ArtifactDigest != before || got.Payload.EvidenceLimit != manifestsdk.EvidenceLimit {
		t.Fatal("mutation created an independent proof claim")
	}
}

func manifestIncludedNamesForTest(p *contract.ManifestPayload) []string {
	names := make([]string, len(p.IncludedEntries))
	for i, row := range p.IncludedEntries {
		names[i] = row.Name
	}
	return names
}

// full_only: false
func TestReaderManifestCapturesScopeBeforeAdmission(t *testing.T) {
	for _, test := range []struct{ name, service, destination string }{
		{"private-service", "private/reader-service/v1", "primary"},
		{"other-service", "aws", "secondary"},
		{"nonmatching-service", "private/nonmatching-service/v1", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, selected, env, target := manifestFixture(t, true)
			engine, _, source := readerEngineFixture(t, env, selected)
			incarnations := make(map[string]manifestsdk.ID)
			for _, row := range selected.root.Names {
				incarnations[row.Name] = manifestsdk.ID(selected.valueEntry(row.Slot).Incarnation)
			}
			included := []manifestsdk.EntryIdentity{{Name: "", EntryIncarnationID: incarnations[""]}, {Name: "a/\n雪", EntryIncarnationID: incarnations["a/\n雪"]}}
			excluded := []manifestsdk.ExcludedEntry{}
			if test.destination == "" {
				excluded = append(excluded, manifestsdk.ExcludedEntry{Name: "secret", EntryIncarnationID: incarnations["secret"], Reason: manifestsdk.NoMatchingService})
			} else {
				included = append(included, manifestsdk.EntryIdentity{Name: "secret", EntryIncarnationID: incarnations["secret"]})
			}
			service := test.service
			request := hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, TargetRecipientID: target, EntryMode: manifestsdk.ExactNames, EntryNames: []string{"secret", "a/\n雪", ""}, ServiceFilter: &service})
			calls, renders := 0, 0
			engine.prepareManifestRenderer = func(_ context.Context, selection contract.ManifestRendererSelection) (manifestsdk.Renderer, manifestsdk.Failure) {
				calls++
				if selection != request.Renderer {
					t.Fatal("selected build differs")
				}
				request.EntryNames[0] = "missing"
				request.TargetRecipientID = contract.ID{99}
				request.TargetMode = manifestsdk.CurrentAuthority
				service = "aws"
				if test.service == "aws" {
					service = "private/reader-service/v1"
				}
				request.Settings[0] = '!'
				return func(ctx context.Context, view manifestsdk.View) manifestsdk.Result {
					renders++
					header := view.Header()
					if header.TargetRecipientID != manifestsdk.ID(target) || !header.HasServiceFilter || header.ServiceFilter != test.service || view.EntryCount() != len(included) || view.ExcludedCount() != len(excluded) {
						t.Fatal("captured projection scope differs")
					}
					for i, want := range included {
						entry, ok := view.Entry(i)
						metadata := entry.Metadata()
						if !ok || metadata.Name != want.Name || metadata.EntryIncarnationID != want.EntryIncarnationID {
							t.Fatal("selected projection entry differs", i)
						}
						if want.Name == "secret" {
							destination, ok := entry.Destination(0)
							d := destination.Metadata()
							if metadata.Kind != manifestsdk.Secret || entry.DestinationCount() != 1 || !ok || d.DestinationID != test.destination || d.ServiceContractID != test.service || d.ConsumerLocator != test.destination+"-secret?stage=AWSCURRENT" {
								t.Fatal("semantic service filter selected different destinations")
							}
							continue
						}
						wantPlain := []byte{}
						if want.Name == "a/\n雪" {
							wantPlain = []byte{0, 10, 65}
						}
						plain := make([]byte, entry.PlainLength())
						n, failure := entry.CopyPlain(0, plain)
						if metadata.Kind != manifestsdk.Plain || entry.DestinationCount() != 0 || failure != "" || n != len(wantPlain) || !bytes.Equal(plain, wantPlain) {
							t.Fatal("service filter changed plain entry", want.Name)
						}
					}
					for i, want := range excluded {
						if row, ok := view.Excluded(i); !ok || row != want {
							t.Fatal("excluded projection entry differs", i)
						}
					}
					return genericjson.Render(ctx, view)
				}, ""
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			got := engine.Manifest(ctx, contract.ID{4}, request)
			if got.StateResult != contract.ReaderSuccess || got.TargetRecipientID != target || got.RequestScope == nil || got.RequestScope.Selection != (manifestsdk.Selection{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames}) || got.RequestScope.ServiceFilter == nil || *got.RequestScope.ServiceFilter != test.service || string(got.RequestScope.Settings) != `{}` || got.Payload == nil || !reflect.DeepEqual(got.Payload.IncludedEntries, included) || !reflect.DeepEqual(got.Payload.ExcludedEntries, excluded) || calls != 1 || renders != 1 || source.closes != 1 {
				t.Fatal("caller mutation changed admitted scope or partition", got.StateResult, got.FailureReason, calls, renders)
			}
		})
	}
}

// full_only: false
func TestReaderManifestOpenTofuUsesCommonTransportAssurance(t *testing.T) {
	for _, damage := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "changed-target"}[damage], func(t *testing.T) {
			_, _, selected, env, target := manifestFixture(t, true)
			engine, _, source := readerEngineFixture(t, env, selected)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			calls := 0
			request := hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{"secret", "a/\n雪", ""}})
			request.FormatContractID, request.ConfigContractID = opentofu.FormatContractID, opentofu.ConfigContractID
			engine.prepareManifestRenderer = func(_ context.Context, selection contract.ManifestRendererSelection) (manifestsdk.Renderer, manifestsdk.Failure) {
				if selection != request.Renderer {
					t.Fatal("selected build differs")
				}
				return func(ctx context.Context, view manifestsdk.View) manifestsdk.Result {
					calls++
					if view.Header().FormatContractID != opentofu.FormatContractID {
						t.Fatal("declared format lost")
					}
					result := opentofu.Render(ctx, view)
					if result.Failure != "" {
						t.Fatal(result.Failure)
					}
					if damage {
						at := bytes.Index(result.Artifact, []byte(`"target_recipient_id":"`)) + len(`"target_recipient_id":"`)
						if at < len(`"target_recipient_id":"`) || at >= len(result.Artifact) {
							t.Fatal("fixture target absent")
						}
						result.Artifact[at] = 'f'
						if target[0]>>4 == 15 {
							result.Artifact[at] = 'e'
						}
					}
					return result
				}, ""
			}
			got := engine.Manifest(ctx, contract.ID{1}, request)
			if calls != 1 || source.closes != 1 || got.StateResult != contract.ReaderSuccess || got.Payload == nil || got.Payload.FormatContractID != opentofu.FormatContractID || got.Payload.EvidenceLimit != "authorized-input-and-exact-bytes" || got.Payload.ArtifactDigest != contract.Hash(got.Artifact) || got.Payload.ArtifactLength != uint64(len(got.Artifact)) {
				t.Fatal("common byte completion failed", got.FailureReason)
			}
			defer clear(got.Artifact)
			var doc struct {
				Enkv struct {
					Schema string `json:"schema"`
					Format string `json:"format_contract_id"`
					Target string `json:"target_recipient_id"`
					Plain  map[string]struct {
						Value string `json:"value"`
					} `json:"plain"`
					Secrets map[string]struct {
						Destinations []json.RawMessage `json:"destinations"`
					} `json:"secrets"`
				} `json:"enkv"`
			}
			if err := json.Unmarshal(got.Artifact, &doc); err != nil {
				t.Fatal("independent consumer refused grammar", err)
			}
			correspondence := doc.Enkv.Target == hex.EncodeToString(target[:])
			if correspondence == damage {
				t.Fatal("independent expected target failed to detect wrong projection")
			}
			if doc.Enkv.Schema != opentofu.Schema || doc.Enkv.Format != opentofu.FormatContractID || len(doc.Enkv.Plain) != 2 || len(doc.Enkv.Secrets) != 1 || doc.Enkv.Plain["a/\n雪"].Value != "AApB" || doc.Enkv.Plain[""].Value != "" || len(doc.Enkv.Secrets["secret"].Destinations) != 2 {
				t.Fatal("complete selected maps differ")
			}
		})
	}
}

// These vectors were derived by literal Python concatenation, without Go code:
// v3 NUL domain, raw nonce, renderer fields, format/config, settings, selectors,
// nil filter, zero target and empty names. Strings/slices use u64 lengths; each
// ID is array length 32 followed by 32 u64 elements. Preimages are 2371/2341 bytes.
// full_only: false
func TestManifestRequestDigestBindsSelectedBuildAndDeclaredFormat(t *testing.T) {
	for _, test := range []struct{ format, config, digest string }{
		{"ENKV/CONSUMPTION-MANIFEST/v3", "ENKV/CONSUMPTION-MANIFEST-CONFIG/v1", "74f332a6264a257885d47e7de38e05bf1fa36bfd8a59f68ebef756a0a77026df"},
		{"private/ini/v1", "private/settings/v1", "862910fdaf849b4453e42c270e6d31cedd1eea2c802ac927166e450b8aa0c82a"},
	} {
		request := hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.CurrentAuthority, EntryMode: manifestsdk.AllAuthorized})
		request.FormatContractID, request.ConfigContractID = test.format, test.config
		owned, err := contract.OwnManifestRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		digest := manifestRequestDigest(contract.ID{1}, owned)
		if hex.EncodeToString(digest[:]) != test.digest {
			t.Fatal("independent request vector differs", test.format, digest)
		}
	}
}

func hermeticManifestRenderer() contract.ManifestRendererSelection {
	return contract.ManifestRendererSelection{Name: "fixture-renderer", Version: "1.0.0", ProtocolID: contract.ID{1}, DescriptorID: contract.ID{2}, ExecutorID: contract.ID{3}, ArtifactContractID: contract.ID{4}, DependencyManifestID: contract.ID{5}, ArtifactID: contract.ID{6}, ArtifactSHA256: contract.ID{7}, ArtifactLength: 1}
}

func hermeticManifestRequest(input contract.ManifestRequest) contract.ManifestRequest {
	input.Renderer = hermeticManifestRenderer()
	input.FormatContractID, input.ConfigContractID = genericjson.FormatContractID, genericjson.ConfigContractID
	input.Settings = []byte(`{}`)
	return input
}

// The protocol policy preimage is the v3 domain, DomainID and two blob32 fields.
// This independent construction does not call the production policy codec.
func independentManifestPolicyDigest(domain contract.ID, identity string, data []byte) contract.ID {
	body := append([]byte("ENKV/OUTPUT/POLICY/v3\x00"), domain[:]...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(identity)))
	body = append(body, identity...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(data)))
	body = append(body, data...)
	return sha256.Sum256(body)
}
