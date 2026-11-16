package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	compositionaws "enkv.sh/compositions/aws"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	awsprovider "enkv.sh/providers/aws"
	manifest "enkv.sh/sdk/manifest-generator"
)

// full_only: false
func TestReaderRenderingPreservesExactDiagnosticsAndStatus(t *testing.T) {
	change := proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "a/\n雪"}, contract.FieldPlainValue, contract.ComparisonBytes{0}, contract.ComparisonBytes{1})
	r := proposedResult(change)
	for _, state := range []contract.ReaderStateResult{contract.ReaderSuccess, contract.ReaderRefused, contract.ReaderProfileBlocked, contract.ReaderPositiveDefect, contract.ReaderUnavailable, contract.ReaderContention} {
		r.StateResult, r.Verdict = state, contract.ComparisonUnable
		r.Changes = nil
		reason := contract.ReasonInvalidInput
		switch state {
		case contract.ReaderProfileBlocked:
			reason = contract.ReasonUnsupportedProfile
		case contract.ReaderPositiveDefect:
			reason = contract.ReasonSelectedObjectInvalid
		case contract.ReaderUnavailable:
			reason = contract.ReasonPublicFactUnavailable
		case contract.ReaderContention:
			reason = contract.ReasonReadContention
		}
		r.Diagnostics = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "a/\n雪"}, Path: []contract.DiagnosticField{contract.FieldPlainValue}, Outcome: contract.DiagnosticUnable, Reason: reason}}
		fact := string(reason)
		if state == contract.ReaderSuccess {
			r.Verdict = contract.ComparisonMismatch
			r.Changes = []contract.ComparisonChange{change}
			r.Diagnostics = nil
			fact = "changed"
		}
		machine, err := RenderComparisonJSON(r)
		if err != nil || !json.Valid(machine) {
			t.Fatal("machine rendering refused", err)
		}
		var encoded struct {
			Schema  string `json:"schema"`
			Payload struct {
				Schema string `json:"schema"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(machine, &encoded); err != nil || encoded.Schema != "ProductResult/v1" || encoded.Payload.Schema != "ComparisonPayload/v1" {
			t.Fatal("comparison result changed its specified schemas", encoded.Schema, encoded.Payload.Schema, err)
		}
		human, err := RenderComparisonHuman(r)
		if err != nil || bytes.Contains(human, []byte("a/\n")) || !bytes.Contains(human, []byte(`a/\n雪`)) {
			t.Fatal("human rendering lost exact quoted name", err)
		}
		for _, token := range []string{string(r.Verdict), "plain_value", fact, string(state), contract.ComparisonEvidenceLimit} {
			if !strings.Contains(string(machine), token) || !strings.Contains(string(human), token) {
				t.Fatal("renderers lost result fact", token)
			}
		}
		want := 2
		if state == contract.ReaderSuccess {
			want = 1
		}
		if state == contract.ReaderUnavailable || state == contract.ReaderContention {
			want = 3
		}
		if ComparisonExitCode(r) != want {
			t.Fatal("wrong comparison status", state)
		}
	}
}

// full_only: false
func TestReaderDiagnosticRenderingBoundsAndLateRefusal(t *testing.T) {
	var engine *core.ReaderEngine
	r := ConfigurationComparisonResult{PublicComparisonResult: engine.Compare(t.Context(), contract.ID{}, contract.PublicConfiguration{}), InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
	d := contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: strings.Repeat("\x00", 256), Name: strings.Repeat("\x00", 256)}, Path: []contract.DiagnosticField{contract.FieldConsumerPolicy}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable, SourceLocation: &contract.SourceLocation{SourceID: strings.Repeat("s", 64), Line: math.MaxUint64, Column: math.MaxUint64}}
	r.Diagnostics = []contract.Diagnostic{d}
	body, err := RenderComparisonJSON(r)
	if err != nil || len(body) != cap(body) {
		t.Fatal("bounded exact rendering", err)
	}
	var decoded struct {
		Payload struct {
			Diagnostics []json.RawMessage `json:"diagnostics"`
		} `json:"payload"`
	}
	if json.Unmarshal(body, &decoded) != nil || len(decoded.Payload.Diagnostics) != 1 {
		t.Fatal("missing maximum diagnostic")
	}
	// Independent grammar literal: each NUL name byte has six JSON bytes.
	want := `{"subject":{"destination_id":"` + strings.Repeat(`\u0000`, 256) + `","kind":"output_target","name":"` + strings.Repeat(`\u0000`, 256) + `"},"path":[{"field":"consumer_policy"}],"outcome":"unable to verify","reason":"required-public-fact-unavailable","source_location":{"source_id":"` + strings.Repeat("s", 64) + `","line":18446744073709551615,"column":18446744073709551615}}`
	var compact bytes.Buffer
	if err := json.Compact(&compact, decoded.Payload.Diagnostics[0]); err != nil || !bytes.Equal(compact.Bytes(), []byte(want)) || len(want) > 4096 {
		t.Fatal("maximum diagnostic differs from independent grammar", len(want))
	}
	for _, mutate := range []func(*contract.Diagnostic){
		func(v *contract.Diagnostic) { v.Reason = "raw-error-sentinel secret-sentinel" },
		func(v *contract.Diagnostic) { v.Path = []contract.DiagnosticField{"raw-error-sentinel"} },
		func(v *contract.Diagnostic) { v.Subject.Name = strings.Repeat("x", 257) },
		func(v *contract.Diagnostic) {
			v.SourceLocation = &contract.SourceLocation{SourceID: "/private/secret-sentinel", Line: 1, Column: 1}
		},
	} {
		bad := d
		mutate(&bad)
		r.Diagnostics = []contract.Diagnostic{d, bad}
		for _, render := range []func(ConfigurationComparisonResult) ([]byte, error){RenderComparisonJSON, RenderComparisonHuman} {
			got, err := render(r)
			if err != ErrReaderResult || got != nil {
				t.Fatal("late malformed record returned partial rendering")
			}
		}
	}
}

// full_only: false
func TestManifestResultRenderingKeepsIssuerAndTargetWithoutArtifact(t *testing.T) {
	var engine *core.ReaderEngine
	r := engine.Manifest(t.Context(), contract.ID{}, contract.ManifestRequest{})
	var request, target, domain, revision, snapshot, digest contract.ID
	for i := range request {
		request[i] = 1
		target[i] = 2
		domain[i] = 3
		revision[i] = 4
		snapshot[i] = 5
		digest[i] = 6
	}
	r.Context.RequestID = request
	r.TargetRecipientID = target
	r.Observation = &manifest.Observation{DomainID: manifest.ID(domain), HEADRevisionID: manifest.ID(revision), SnapshotID: manifest.ID(snapshot)}
	r.StateResult = contract.ReaderSuccess
	r.FailureReason = ""
	r.Artifact = []byte("secret-sentinel raw-error-sentinel")
	r.RequestScope = manifestTestScope(manifest.Selection{TargetMode: manifest.ExactRecipient, EntryMode: manifest.ExactNames})
	r.Payload = &contract.ManifestPayload{Selection: r.RequestScope.Selection, IncludedEntries: []manifest.EntryIdentity{{Name: "", EntryIncarnationID: manifest.ID(domain)}, {Name: "a/\n雪", EntryIncarnationID: manifest.ID(snapshot)}}, ExcludedEntries: []manifest.ExcludedEntry{}, Observation: *r.Observation, TargetRecipientID: target, Renderer: r.RequestScope.Renderer, FormatContractID: r.RequestScope.FormatContractID, ConfigContractID: r.RequestScope.ConfigContractID, Settings: r.RequestScope.Settings, ArtifactLength: 55, ArtifactDigest: digest, EvidenceLimit: manifest.EvidenceLimit}
	for _, render := range []func(core.PublicManifestResult) ([]byte, error){RenderManifestResultJSON, RenderManifestResultHuman} {
		got, err := render(r)
		if err != nil || bytes.Contains(got, r.Artifact) || !bytes.Contains(got, []byte(strings.Repeat("01", 32))) || !bytes.Contains(got, []byte(strings.Repeat("02", 32))) || !bytes.Contains(got, []byte(manifest.EvidenceLimit)) || len(got) != cap(got) {
			t.Fatal("manifest renderer leaked artifact or lost identities", err)
		}
	}
	for _, condition := range []string{"missing-scope", "missing-renderer", "mismatched-format", "artifact-excess", "wrong-scope", "invalid-provider", "nil-included", "nil-excluded", "overlap", "wrong-exclusion-reason", "wrong-target", "wrong-observation", "failure-artifact"} {
		t.Run(condition, func(t *testing.T) {
			bad := r
			payload := *r.Payload
			bad.Payload = &payload
			scope := *r.RequestScope
			bad.RequestScope = &scope
			switch condition {
			case "missing-scope":
				bad.RequestScope = nil
			case "missing-renderer":
				scope.Renderer.ArtifactID = contract.ID{}
				payload.Renderer.ArtifactID = contract.ID{}
			case "mismatched-format":
				scope.FormatContractID = "different-format/v1"
			case "artifact-excess":
				payload.ArtifactLength = manifest.MaxArtifactBytes + 1
			case "wrong-scope":
				scope.Selection.EntryMode = manifest.AllAuthorized
			case "invalid-provider":
				provider := ""
				payload.ServiceFilter = &provider
				scope.ServiceFilter = &provider
			case "nil-included":
				payload.IncludedEntries = nil
			case "nil-excluded":
				payload.ExcludedEntries = nil
			case "overlap":
				payload.ExcludedEntries = []manifest.ExcludedEntry{{Name: "", EntryIncarnationID: manifest.ID(domain), Reason: manifest.NoOutput}}
			case "wrong-exclusion-reason":
				payload.ExcludedEntries = []manifest.ExcludedEntry{{Name: "z", EntryIncarnationID: manifest.ID(revision), Reason: manifest.NoMatchingService}}
			case "wrong-target":
				payload.TargetRecipientID = domain
			case "wrong-observation":
				payload.Observation.DomainID = manifest.ID(target)
			case "failure-artifact":
				bad.StateResult = contract.ReaderRefused
				bad.FailureReason = contract.ReasonInvalidInput
				bad.Payload = nil
			}
			for _, render := range []func(core.PublicManifestResult) ([]byte, error){RenderManifestResultJSON, RenderManifestResultHuman} {
				if got, err := render(bad); got != nil || err != ErrReaderResult {
					t.Fatal("invalid closed manifest result escaped", condition, err)
				}
			}
		})
	}
	r.Artifact = nil
	if got, err := RenderManifestResultJSON(r); err != nil || got == nil {
		t.Fatal("consumed artifact erases successful issuance", err)
	}

}

// full_only: false
func TestReaderRenderingPreservesMalformedInputAndSectionFailures(t *testing.T) {
	ctx, a, _ := localConfigs(t)
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	store, err := awsprovider.NewStore(a.Store)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewReader(ctx, ReaderConfig{Family: contract.AWS, AWS: &compositionaws.ReaderConfig{Candidate: awsprovider.CandidateReadConfig{Region: a.Store.Region, Bucket: a.Store.Bucket, Prefix: a.Store.Prefix, ExpectedBucketOwner: a.Store.ExpectedBucketOwner, CredentialRoute: a.Store.CredentialRoute, Credentials: a.Store.Credentials, Transport: a.Store.Transport, Timeout: a.Store.Timeout}, ExpectedDomain: a.Store.Domain, ExpectedStore: store.Descriptor(), PublicBasis: core.PublicBasis{Descriptor: []byte{1}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	for _, name := range []string{"zero-recipient", "missing-collections", "malformed-routing-before-limit"} {
		t.Run(name, func(t *testing.T) {
			input := contract.PublicConfiguration{}
			if name == "zero-recipient" {
				input.Recipients = readerPresent([]contract.PublicRecipient{{}})
			}
			if name == "malformed-routing-before-limit" {
				input.Routing = readerPresent([]contract.PublicRoutingRule{{Destinations: readerPresent(make([]string, contract.MaxOutputRouteDestinations+1))}})
			}
			result := ConfigurationComparisonResult{PublicComparisonResult: engine.Compare(ctx, contract.Hash([]byte("malformed semantic input")), input), InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
			if result.StateResult != contract.ReaderRefused || result.Observation != nil || len(result.Diagnostics) == 0 {
				t.Fatal("malformed input lost safe failure", result)
			}
			found := false
			for _, d := range result.Diagnostics {
				if name == "zero-recipient" && d.Subject.Kind == contract.SubjectRecipient && d.Subject.RecipientID.IsZero() && d.Reason == contract.ReasonInvalidInput {
					found = true
				}
				if name == "missing-collections" && d.Subject.Kind == contract.SubjectOutputBinding && d.Subject.DestinationID == "" && d.Reason == contract.ReasonMissingRequiredField {
					found = true
				}
				if name == "malformed-routing-before-limit" && d.Reason == contract.ReasonLimitExceeded {
					found = true
					if d.Subject.Kind != contract.SubjectConfiguration {
						t.Fatal("malformed selector entered safe diagnostic subject", d)
					}
				}
			}
			if !found {
				t.Fatal("regression did not reach intended safe source failure", result.Diagnostics)
			}
			assertReaderRenderings(t, result)
		})
	}
}

// full_only: false
func TestReaderRenderingRejectsOtherOperationContext(t *testing.T) {
	var engine *core.ReaderEngine
	comparison := ConfigurationComparisonResult{PublicComparisonResult: engine.Compare(t.Context(), contract.ID{}, contract.PublicConfiguration{}), InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
	comparison.Context.Operation = "restore-local-signer"
	manifest := engine.Manifest(t.Context(), contract.ID{}, contract.ManifestRequest{})
	manifest.Context.Operation = "prepare-succession"
	for _, render := range []func(ConfigurationComparisonResult) ([]byte, error){RenderComparisonJSON, RenderComparisonHuman} {
		body, err := render(comparison)
		if body != nil || err != ErrReaderResult {
			t.Fatal("Reader renderer admitted another operation")
		}
	}
	for _, render := range []func(core.PublicManifestResult) ([]byte, error){RenderManifestResultJSON, RenderManifestResultHuman} {
		body, err := render(manifest)
		if body != nil || err != ErrReaderResult {
			t.Fatal("Reader manifest renderer admitted another operation")
		}
	}
}

// full_only: false
func TestReaderRenderingPreservesOutputSourceFields(t *testing.T) {
	for _, field := range []contract.DiagnosticField{contract.FieldDestination, contract.FieldOutputEncoding, contract.FieldGroups} {
		t.Run(string(field), func(t *testing.T) {
			subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "destination"}
			var before, after contract.ComparisonValue
			switch field {
			case contract.FieldDestination:
				before = contract.ComparisonDestination{ConfigContractID: "config", ServiceContractID: "service", CanonicalSettings: []byte{'{', '}'}, Capabilities: contract.OutputCapabilityWriteValue}
				after = contract.ComparisonDestination{ConfigContractID: "config", ServiceContractID: "service", CanonicalSettings: []byte{'[', ']'}, Capabilities: contract.OutputCapabilityWriteValue}
			case contract.FieldOutputEncoding:
				subject = contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "plain"}
				before, after = contract.ComparisonUint(1), contract.ComparisonUint(2)
			case contract.FieldGroups:
				subject = contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}
				before, after = contract.ComparisonGroups{}, contract.ComparisonGroups{{"plain"}}
			}
			result := proposedResult(proposedRecord(subject, field, before, after))
			for _, render := range []struct {
				name string
				fn   func(ConfigurationComparisonResult) ([]byte, error)
			}{{"json", RenderComparisonJSON}, {"human", RenderComparisonHuman}} {
				t.Run(render.name, func(t *testing.T) {
					body, err := render.fn(result)
					if err != nil || !bytes.Contains(body, []byte(field)) {
						t.Fatalf("output source diagnostic lost: field=%s err=%v", field, err)
					}
					if render.name == "json" && !json.Valid(body) {
						t.Fatal("invalid comparison JSON")
					}
				})
			}
		})
	}
}
