package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	manifestsdk "enkv.sh/sdk/manifest-generator"
	"errors"
	"slices"

	"enkv.sh/core/contract"
	genericjson "enkv.sh/plugins/manifest-generators/generic-json"
)

type liveConsumerManifestEntry struct {
	Name        string `json:"name"`
	Incarnation string `json:"entry_incarnation_id"`
	Content     struct {
		Kind         string `json:"kind"`
		Plain        []byte `json:"value_base64"`
		Destinations []struct {
			Destination string `json:"destination_id"`
			Locator     string `json:"consumer_locator"`
			Encoding    string `json:"payload_encoding"`
		} `json:"destinations"`
	} `json:"content"`
}

func (p *livePublicationScenario) consumerManifest(ctx context.Context) ([]liveConsumerManifestEntry, error) {
	if p.fixture == nil || p.fixture.session == nil {
		return nil, errors.New("consumer Reader fixture unavailable")
	}
	reader := fixtureInstalledPublicReader(p.run.t, p.run.env, p.fixture.session, nil)
	defer reader.Close()
	names := make([]string, len(p.entries))
	for index, entry := range p.entries {
		names[index] = entry.Name
	}
	manifest := reader.Manifest(ctx, fixtureID(p.run.env.Domain, "manifest consumer request"), contract.ManifestRequest{Renderer: contract.ManifestRendererSelection{Name: "fixture-renderer", Version: "1.0.0", ProtocolID: contract.ID{1}, DescriptorID: contract.ID{2}, ExecutorID: contract.ID{3}, ArtifactContractID: contract.ID{4}, DependencyManifestID: contract.ID{5}, ArtifactID: contract.ID{6}, ArtifactSHA256: contract.ID{7}, ArtifactLength: 1}, FormatContractID: genericjson.FormatContractID, ConfigContractID: genericjson.ConfigContractID, Settings: []byte(`{}`), TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: p.input.acting, EntryNames: names})
	if manifest.StateResult != contract.ReaderSuccess || manifest.Artifact == nil {
		return nil, errors.New("consumer Reader manifest refused")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(manifest.Artifact, &fields); err != nil {
		return nil, err
	}
	required := []string{"schema", "format_contract_id", "config_contract_id", "observation", "target_recipient_id", "selection", "service_filter", "entries", "excluded_entries", "evidence_limit"}
	if len(fields) != len(required) {
		return nil, errors.New("consumer Reader manifest envelope differs")
	}
	for _, name := range required {
		if _, present := fields[name]; !present {
			return nil, errors.New("consumer Reader manifest field missing")
		}
	}
	var artifact struct {
		Schema      string `json:"schema"`
		Format      string `json:"format_contract_id"`
		Config      string `json:"config_contract_id"`
		Observation struct {
			Domain   string `json:"domain_id"`
			HEAD     string `json:"head_revision_id"`
			Snapshot string `json:"snapshot_id"`
		} `json:"observation"`
		Target    string                      `json:"target_recipient_id"`
		Selection manifestsdk.Selection       `json:"selection"`
		Entries   []liveConsumerManifestEntry `json:"entries"`
		Excluded  []json.RawMessage           `json:"excluded_entries"`
		Evidence  string                      `json:"evidence_limit"`
	}
	if err := json.Unmarshal(manifest.Artifact, &artifact); err != nil {
		return nil, err
	}
	scope := manifestsdk.Selection{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames}
	payload := manifest.Payload
	digest := sha256.Sum256(manifest.Artifact)
	if artifact.Schema != genericjson.Schema || artifact.Format != genericjson.FormatContractID || artifact.Config != genericjson.ConfigContractID || artifact.Evidence != "authorized-input-and-exact-bytes" || artifact.Selection != scope || artifact.Entries == nil || !bytes.Equal(fields["service_filter"], []byte("null")) || artifact.Excluded == nil || len(artifact.Excluded) != 0 || payload == nil || payload.Selection != scope || payload.ServiceFilter != nil || payload.IncludedEntries == nil || payload.ExcludedEntries == nil || len(payload.ExcludedEntries) != 0 || manifest.RequestScope == nil || manifest.RequestScope.Selection != scope || manifest.RequestScope.ServiceFilter != nil || manifest.Observation == nil || payload.Observation != *manifest.Observation || payload.TargetRecipientID != p.input.acting || manifest.TargetRecipientID != p.input.acting || payload.ArtifactLength != uint64(len(manifest.Artifact)) || payload.ArtifactDigest != contract.ID(digest) {
		return nil, errors.New("consumer Reader manifest scope differs")
	}
	observation := manifest.Observation
	if observation.DomainID != manifestsdk.ID(p.run.env.Domain) || artifact.Target != hex.EncodeToString(p.input.acting[:]) || artifact.Observation.Domain != hex.EncodeToString(observation.DomainID[:]) || artifact.Observation.HEAD != hex.EncodeToString(observation.HEADRevisionID[:]) || artifact.Observation.Snapshot != hex.EncodeToString(observation.SnapshotID[:]) {
		return nil, errors.New("consumer Reader manifest observation differs")
	}
	expectedNames := slices.Clone(names)
	slices.Sort(expectedNames)
	if len(artifact.Entries) != len(expectedNames) || len(payload.IncludedEntries) != len(expectedNames) {
		return nil, errors.New("consumer Reader manifest incomplete")
	}
	for i, row := range artifact.Entries {
		selected := sessionConsumerSelection(p.run.t, p.fixture.session, p.input.acting, expectedNames[i]).Entry
		if row.Name != expectedNames[i] || row.Incarnation != hex.EncodeToString(selected.Incarnation[:]) || payload.IncludedEntries[i] != (manifestsdk.EntryIdentity{Name: expectedNames[i], EntryIncarnationID: manifestsdk.ID(selected.Incarnation)}) {
			return nil, errors.New("consumer Reader manifest partition differs")
		}
	}

	return artifact.Entries, nil
}
