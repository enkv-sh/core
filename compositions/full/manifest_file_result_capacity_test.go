package compositionfull

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"enkv.sh/sdk/artifact"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

// full_only: true
func TestManifestFileResultMaximumExclusionPartitionAndNativePaths(t *testing.T) {
	profile := strings.Repeat("\x01", 256)
	artifactLength := manifest.MaxArtifactBytes
	// Each name has 256 one-byte controls with six-byte JSON escapes.
	// The final two controls select 512 distinct names in exact byte order.
	const rows = 512
	const rawNamePrefixBytes = 254
	const sixByteControls = "\x00\x01\x02\x03\x04\x05\x06\x07\x0b\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
	names := make([]manifest.ExcludedEntry, rows)
	for i := range names {
		var id contract.ID
		binary.BigEndian.PutUint16(id[30:], uint16(i+1))
		names[i] = manifest.ExcludedEntry{Name: strings.Repeat("\x01", rawNamePrefixBytes) + string([]byte{sixByteControls[i/27], sixByteControls[i%27]}), EntryIncarnationID: manifest.ID(id), Reason: manifest.NoMatchingService}
	}
	id := func(b byte) (id contract.ID) {
		for i := range id {
			id[i] = b
		}
		return id
	}
	observation := manifest.Observation{DomainID: manifest.ID(id(1)), HEADRevisionID: manifest.ID(id(2)), SnapshotID: manifest.ID(id(3))}
	selection := manifest.Selection{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}
	provider := strings.Repeat("\x01", 256)
	scope := manifestTestScope(selection)
	scope.Renderer.Name = strings.Repeat("r", 255)
	scope.Renderer.Version = "1.0.0+" + strings.Repeat("a", 122)
	scope.Renderer.ProtocolID = id(1)
	scope.Renderer.DescriptorID = id(2)
	scope.Renderer.ExecutorID = id(3)
	scope.Renderer.ArtifactContractID = id(4)
	scope.Renderer.DependencyManifestID = id(5)
	scope.Renderer.ArtifactID = id(6)
	scope.Renderer.ArtifactSHA256 = id(7)
	scope.Renderer.ArtifactLength = artifact.MaxExecutableBytes
	scope.FormatContractID = profile
	scope.ConfigContractID = profile
	scope.ServiceFilter = &provider
	scope.Settings = []byte(`"` + strings.Repeat("s", 16382) + `"`)
	payload := &contract.ManifestPayload{Renderer: scope.Renderer, FormatContractID: scope.FormatContractID, ConfigContractID: scope.ConfigContractID, Settings: scope.Settings, Observation: observation, TargetRecipientID: id(4), Selection: selection, ServiceFilter: &provider, IncludedEntries: []manifest.EntryIdentity{}, ExcludedEntries: names, ArtifactLength: artifactLength, ArtifactDigest: id(5), EvidenceLimit: manifest.EvidenceLimit}
	issuance := core.PublicManifestResult{Context: core.ReaderOperationContext{Operation: contract.ReaderManifestOperation, OperationID: id(8), RequestID: id(9), ExpectedDomain: id(1)}, StateResult: contract.ReaderSuccess, TargetRecipientID: id(4), Observation: &observation, RequestScope: scope, Payload: payload}
	// Parent components obey the native 255-byte component limit. Its 4,048
	// bytes plus slash and 47-byte leaf produce two exact 4,096-byte paths.
	parent := ""
	for len(parent) < 4048 {
		width := min(255, 4048-len(parent)-1)
		parent += "/" + strings.Repeat("<", width)
	}
	target := parent + "/" + strings.Repeat("t", 47)
	residue := parent + "/.enkv-manifest-" + strings.Repeat("a", 32)
	if len(target) != 4096 || len(residue) != 4096 || filepath.Clean(target) != target || filepath.Clean(residue) != residue {
		t.Fatal("maximum path fixture differs")
	}
	r := ManifestFileResult{Issuance: issuance, Delivery: ManifestDelivery{TargetPath: target, Artifact: &ManifestArtifact{RendererArtifactID: scope.Renderer.ArtifactID, FormatContractID: scope.FormatContractID, Length: payload.ArtifactLength, Digest: payload.ArtifactDigest}, Replacement: ManifestReplacementUnknown, CandidateVerification: ManifestVerified, InstalledVerification: ManifestVerificationNotObserved, NativeCompletion: ManifestNativeIncomplete, CandidateCleanup: ManifestCandidateCleanupUnknown, ResiduePath: residue, Failure: &ManifestFileFailure{Stage: ManifestRenameStage, Reason: ManifestIOFailure}}, SourceCleanup: ManifestSourceComplete, ResultDelivery: ManifestResultNotObserved}

	// Independent closed format literals. IDs 01..05 repeat 32 times; row IDs
	// are the canonical 64-digit hexadecimal forms of integers 1..512. JSON
	// escapes each SOH as six bytes and each '<' in the path as six bytes.
	const selectionJSON = `{"target_mode":"current-authority","entry_mode":"all-authorized"}`
	rendererJSON := `{"name":"` + strings.Repeat("r", 255) + `","version":"1.0.0+` + strings.Repeat("a", 122) + `","protocol_id":"` + strings.Repeat("01", 32) + `","descriptor_id":"` + strings.Repeat("02", 32) + `","executor_id":"` + strings.Repeat("03", 32) + `","artifact_contract_id":"` + strings.Repeat("04", 32) + `","dependency_manifest_id":"` + strings.Repeat("05", 32) + `","artifact_id":"` + strings.Repeat("06", 32) + `","artifact_sha256":"` + strings.Repeat("07", 32) + `","artifact_length":` + fmt.Sprint(artifact.MaxExecutableBytes) + `}`
	semanticJSON := `"` + strings.Repeat(`\u0001`, 256) + `"`
	scopeJSON := `{"renderer":` + rendererJSON + `,"format_contract_id":` + semanticJSON + `,"config_contract_id":` + semanticJSON + `,"settings":"` + base64.StdEncoding.EncodeToString(scope.Settings) + `","selection":` + selectionJSON + `,"service_filter":` + semanticJSON + `}`
	if len(scopeJSON) > 32768 {
		t.Fatal("complete scope exceeds its scratch account", len(scopeJSON))
	}
	observationJSON := `{"domain_id":"` + strings.Repeat("01", 32) + `","head_revision_id":"` + strings.Repeat("02", 32) + `","snapshot_id":"` + strings.Repeat("03", 32) + `"}`
	payloadPrefix := `{"schema":"ManifestPayload/v3",` + scopeJSON[1:len(scopeJSON)-1] + `,"artifact_length":` + fmt.Sprint(artifactLength) + `,"artifact_digest":"` + strings.Repeat("05", 32) + `","evidence_limit":"authorized-input-and-exact-bytes","included_entries":[],"excluded_entries":[`
	contextJSON := `{"operation":"issue-consumption-manifest","operation_id":"` + strings.Repeat("08", 32) + `","request_id":"` + strings.Repeat("09", 32) + `","expected_domain_id":"` + strings.Repeat("01", 32) + `"}`
	jsonPrefix := `{"schema":"ProductResult/v1","operation_kind":"issue-consumption-manifest","state_result":"success","effect_summary":"not-applicable","output_summary":"not-applicable","context":` + contextJSON + `,"observation":` + observationJSON + `,"target_recipient_id":"` + strings.Repeat("04", 32) + `","request_scope":` + scopeJSON + `,"payload":` + payloadPrefix
	humanPrefix := "Manifest: success\nOperation ID: " + strings.Repeat("08", 32) + "\nRequest ID: " + strings.Repeat("09", 32) + "\nTarget recipient: " + strings.Repeat("04", 32) + "\nDomain: " + strings.Repeat("01", 32) + "\nObserved revision: " + strings.Repeat("02", 32) + "\nSnapshot: " + strings.Repeat("03", 32) + "\n"
	humanPrefix += fmt.Sprintf("Format: %q\nSelection: current-authority; all-authorized\nService filter: %q\nArtifact: %d bytes; digest %s\nEvidence limit: authorized-input-and-exact-bytes\n", profile, provider, artifactLength, strings.Repeat("05", 32))
	if len(payloadPrefix) > 32768 || len(jsonPrefix)+4 > 65536 || len(humanPrefix)+4 > 65536 {
		t.Fatal("complete fixed result header exceeds its account", len(jsonPrefix), len(humanPrefix))
	}
	escapedParent := strings.ReplaceAll(parent, "<", `\u003c`)
	deliveryJSON := `{"target_path":"` + escapedParent + `/` + strings.Repeat("t", 47) + `","artifact":{"renderer_artifact_id":"` + strings.Repeat("06", 32) + `","format_contract_id":` + semanticJSON + `,"length":` + fmt.Sprint(artifactLength) + `,"digest":"` + strings.Repeat("05", 32) + `"},"replacement":"unknown","candidate_verification":"verified","installed_verification":"not-observed","native_completion":"incomplete","candidate_cleanup":"unknown","residue_path":"` + escapedParent + `/.enkv-manifest-` + strings.Repeat("a", 32) + `","failure":{"stage":"rename","reason":"io-failure"}}`
	expectedRow := func(i int) string {
		return `{"name":"` + strings.Repeat(`\u0001`, rawNamePrefixBytes) + fmt.Sprintf(`\u%04x\u%04x`, sixByteControls[i/27], sixByteControls[i%27]) + `","entry_incarnation_id":"` + fmt.Sprintf("%064x", i+1) + `","reason":"no-matching-service"}`
	}
	if len(expectedRow(0)) != 1668 {
		t.Fatal("independent exclusion row arithmetic changed", len(expectedRow(0)))
	}
	const safeBound = 512*4096 + 65536
	const fileBound = safeBound + 2*(6*4096+2) + 65536
	if safeBound != 2162688 || fileBound != 2277380 {
		t.Fatal("independent result backing arithmetic changed")
	}
	if safeBound != contract.MaxManifestResultJSONBytes || fileBound+2048 != manifestFileCompactResultLimit || 67*(fileBound+2048) != MaxManifestFileResultJSONBytes || 67*safeBound != MaxManifestIssuanceResultJSONBytes {
		t.Fatal("result contract differs from independent backing account")
	}
	forms := []struct {
		name, prefix, suffix string
		render               func() ([]byte, error)
		maximum              int
	}{
		{"issuance-json", jsonPrefix, `]}}`, func() ([]byte, error) { return RenderManifestResultJSON(issuance) }, safeBound},
		{"issuance-human", humanPrefix, "", func() ([]byte, error) { return RenderManifestResultHuman(issuance) }, safeBound},
		{"native-json", `{"schema":"ManifestFileResult/v2","issuance":` + jsonPrefix, `]}},"delivery":` + deliveryJSON + `,"source_cleanup":"complete","result_delivery":"not-observed"}`, func() ([]byte, error) { return RenderManifestFileJSON(r) }, fileBound},
		{"native-human", fmt.Sprintf("Manifest file: %q\n", target) + humanPrefix, "Local replacement: unknown\nCandidate verification: verified\nInstalled verification: not-observed\nNative completion: incomplete\nCandidate cleanup: unknown\n" + fmt.Sprintf("Residue file: %q\n", residue) + "Local delivery failure: rename; io-failure\nSource cleanup: complete\nResult-stream delivery is not observed by this result.\n", func() ([]byte, error) { return RenderManifestFileHuman(r) }, fileBound},
	}
	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			var expected bytes.Buffer
			emit := func(s string) { expected.WriteString(s) }
			emit(form.prefix)
			rowBytes, separators := 0, 0
			for i := range rows {
				row := expectedRow(i)
				if strings.HasSuffix(form.name, "json") {
					if i > 0 {
						emit(",")
						separators++
					}
				} else {
					row = fmt.Sprintf("Excluded entry %q; incarnation %064x; no-matching-service\n", names[i].Name, i+1)
				}
				rowBytes += len(row)
				emit(row)
			}
			emit(form.suffix)
			// JSON rows have the independently proved fixed width. Human quoted
			// controls can have different widths; each complete literal is counted.
			// No production encoder constructs expected bytes or hashes.
			if expected.Len() != len(form.prefix)+rowBytes+separators+len(form.suffix) || expected.Len() > form.maximum {
				t.Fatal("expected compact stream exceeds its account", expected.Len())
			}
			want := expected.Bytes()
			if strings.HasSuffix(form.name, "json") {
				want = readableExpectedJSON(t, expected.String())
			}
			length := len(want)
			if length > 67*form.maximum {
				t.Fatal("readable stream exceeds its account", length)
			}
			got, err := form.render()
			if err != nil || len(got) != length || cap(got) != length {
				t.Fatal("maximum exact result backing differs", err, len(got), cap(got), length)
			}
			digest := sha256.Sum256(got)
			if !bytes.Equal(got, want) || issuance.Artifact != nil {
				t.Fatal("result retained artifact bytes or extra data")
			}
			t.Logf("form=%s rows=%d bytes=%d row_bytes=1668 target_bytes=4096 residue_bytes=4096 digest=%x", form.name, rows, length, digest)
		})
	}
	// The count pass retains no result backing and stops at the exact ceiling.
	count := readerResultWriter{at: fileBound - 1, maximum: fileBound}
	count.literal("x")
	if count.failed || count.at != fileBound || count.body != nil {
		t.Fatal("exact native count bound refused or allocated")
	}
	count.literal("x")
	if !count.failed || count.at != fileBound || count.body != nil {
		t.Fatal("native count one-over admitted or allocated")
	}
	for _, condition := range []string{"joint-rows-one-over", "name-one-over", "target-one-over", "residue-one-over", "settings-one-over", "semantic-one-over"} {
		t.Run(condition, func(t *testing.T) {
			bad := r
			p := *payload
			bad.Issuance.Payload = &p
			switch condition {
			case "joint-rows-one-over":
				p.IncludedEntries = []manifest.EntryIdentity{{Name: "z", EntryIncarnationID: manifest.ID(id(6))}}
			case "name-one-over":
				p.ExcludedEntries = append([]manifest.ExcludedEntry(nil), names...)
				p.ExcludedEntries[rows-1].Name += "x"
			case "target-one-over":
				bad.Delivery.TargetPath += "t"
			case "residue-one-over":
				bad.Delivery.ResiduePath += "a"
			case "settings-one-over":
				copied := *bad.Issuance.RequestScope
				copied.Settings = append(bytes.Clone(copied.Settings), byte(32))
				bad.Issuance.RequestScope = &copied
				p.Settings = copied.Settings
			case "semantic-one-over":
				copied := *bad.Issuance.RequestScope
				copied.ConfigContractID += "x"
				bad.Issuance.RequestScope = &copied
				p.ConfigContractID = copied.ConfigContractID
			}
			for _, write := range []func(io.Writer) error{func(w io.Writer) error { return WriteManifestFileJSON(t.Context(), w, bad) }, func(w io.Writer) error { return WriteManifestFileHuman(t.Context(), w, bad) }} {
				var out bytes.Buffer
				if err := write(&out); err == nil || out.Len() != 0 {
					t.Fatal("one-over input emitted partial result", condition, err, out.Len())
				}
			}
		})
	}
}
