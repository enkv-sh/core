package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
	genericjson "enkv.sh/plugins/manifest-generators/generic-json"
	gcpprovider "enkv.sh/providers/gcp"
	manifest "enkv.sh/sdk/manifest-generator"
)

type configurationReaderSource struct {
	pair                          *configuration.Pair
	path, generated               string
	editableBytes, generatedBytes []byte
	archive                       installedarchive.Archive
}

func configurationReaderPair(t *testing.T, family string, format configuration.Format, edit func(map[string]any, map[string]any)) configurationReaderSource {
	t.Helper()
	fixture, basisBytes := installedarchive.LoadReader(t, family)
	var image struct{ Descriptor []byte }
	if err := json.Unmarshal(basisBytes, &image); err != nil {
		t.Fatal(err)
	}
	basis, err := contract.DecodeGenesisDescriptorCore(image.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if basis.Recovery != nil {
		t.Fatal("Reader fixture requires explicit disabled Recovery")
	}
	generatedRecipients := map[string]any{}
	recipients := map[string]any{}
	var authority contract.RecipientRecord
	targetRef := ""
	for i, row := range basis.Recipients {
		if row.RecipientID == basis.AuthorityRecipientID {
			authority = row
			continue
		}
		ref := fmt.Sprintf("recipient%d", i)
		recipients[ref] = map[string]any{"id": readerID(row.RecipientID), "display_name": row.DisplayName, "encryption_key": row.CurrentBinding.KeySelector}
		generatedRecipients[ref] = map[string]any{"id": readerID(row.RecipientID), "encryption": configurationReaderKey(*row.CurrentBinding)}
		if row.RecipientID == readerFixtureTarget(basis.DomainID) {
			targetRef = ref
		}
	}
	if authority.CurrentBinding == nil || targetRef == "" {
		t.Fatal("Reader fixture lacks complete enrollment")
	}
	store := map[string]any{"region": fixture.Archive.Location.Region, "bucket": fixture.Archive.Location.Bucket, "prefix": fixture.Archive.Location.PrefixBeforeHEAD}
	if fixture.Archive.Location.ExpectedOwner != "" {
		store["expected_owner"] = fixture.Archive.Location.ExpectedOwner
	}
	authoritySource := map[string]any{"display_name": authority.DisplayName, "signing_key": basis.NormalSigning.KeySelector, "encryption_key": authority.CurrentBinding.KeySelector}
	entries, secrets := map[string]any{}, map[string]any{}
	for _, entry := range []struct {
		name   string
		plain  []byte
		secret bool
	}{{"", []byte{}, false}, {"a/\n雪", []byte{0, 10, 65}, false}, {"encoded", nil, true}, {"secret", nil, true}} {
		confidentiality := "plain"
		source := map[string]any{"kind": "supplied"}
		if entry.secret {
			confidentiality = "secret"
			// Reader compares public meaning only; retained pins cannot claim secret equality.
			secrets[entry.name] = map[string]any{"retained": map[string]any{"incarnation": readerID(contract.Hash([]byte("fixture incarnation " + entry.name))), "material": readerID(contract.Hash([]byte("fixture material " + entry.name)))}}
		} else {
			source["bytes"] = entry.plain
		}
		entries[entry.name] = map[string]any{"confidentiality": confidentiality, "recipients": []string{targetRef}, "source": source}
		if entry.name == "encoded" {
			entries[entry.name].(map[string]any)["output_encoding"] = "base64"
		}
	}
	destinations := map[string]any{}
	outputRecords := map[string]any{}
	var names []string
	for _, profile := range readerFixtureProfiles() {
		binding := contract.NormalOutputBinding{DestinationID: profile.destination, Destination: readerFixtureDestination(profile)}
		for index, name := range []string{"encoded", "secret"} {
			encoding := uint8(contract.OutputEncodingRaw)
			if index == 0 {
				encoding = contract.OutputEncodingBase64
			}
			target := readerFixtureOutputTarget(readerFixtureProfiles(name)[len(names)], encoding)
			binding.Targets = append(binding.Targets, contract.NormalOutputTarget{Name: name, Target: target})
		}
		encoded, err := contract.EncodeNormalOutputBinding(binding)
		if err != nil {
			t.Fatal(err)
		}
		destinations[profile.destination] = map[string]any{"plugin": nil, "canonical": map[string]any{"settings": json.RawMessage(binding.Destination.CanonicalSettings)}}
		outputRecords[profile.destination] = encoded
		names = append(names, profile.destination)
	}
	routing := map[string]any{"default": names, "entries": map[string]any{"": []string{}, "a/\n雪": []string{}, "encoded": names}}

	editable := map[string]any{"schema": "enkv/configuration/v3", "domain": map[string]any{"name": "prod", "provider": family, "store": store, "authority": authoritySource, "recovery": map[string]bool{"enabled": false}}, "recipients": recipients, "entries": entries,
		"outputs": map[string]any{"destinations": destinations, "routing": routing}}
	generated := map[string]any{"schema": "enkv/generated/v2", "file_id": readerID(contract.Hash([]byte("Reader file fixture"))), "domain": map[string]any{"id": readerID(basis.DomainID),
		"authority": map[string]any{"id": readerID(basis.AuthorityRecipientID), "signing": map[string]any{"selector": basis.NormalSigning.KeySelector, "public_key": basis.NormalSigning.SPKI}, "encryption": configurationReaderKey(*authority.CurrentBinding)}, "recovery": map[string]bool{"enabled": false}},
		"canonical_records": map[string]any{"generators": map[string]any{}, "outputs": outputRecords}, "recipients": generatedRecipients, "secrets": secrets, "public_basis": map[string]any{"kind": "genesis", "descriptor": image.Descriptor}}
	if edit != nil {
		edit(editable, generated)
	}
	generatedBody, err := json.Marshal(generated)
	if err != nil {
		t.Fatal(err)
	}
	reference := ".enkv/prod.generated.json"
	editable["generated"] = reference
	var editableBody []byte
	if format == configuration.JSON {
		editableBody, err = json.Marshal(editable)
	} else {
		var buffer bytes.Buffer
		for _, key := range []string{"schema", "domain", "recipients", "entries", "outputs", "plugins", "generated"} {
			field, exists := editable[key]
			if !exists {
				continue
			}
			value, marshalErr := json.Marshal(field)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			fmt.Fprintf(&buffer, "%s: %s\n", key, value)
		}
		editableBody = buffer.Bytes()
	}
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	generatedDir := filepath.Join(dir, ".enkv")
	if err := os.Mkdir(generatedDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "configuration")
	generatedPath := filepath.Join(dir, reference)
	if err := os.WriteFile(generatedPath, generatedBody, 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, editableBody, 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(generatedDir, 0555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Error(err)
		}
		if err := os.Chmod(generatedDir, 0700); err != nil {
			t.Error(err)
		}
	})
	pair, err := configuration.Capture(context.Background(), path, format)
	if err != nil {
		t.Fatal("source fixture capture refused", err)
	}
	t.Cleanup(func() {
		if err := pair.Close(); err != nil {
			t.Error(err)
		}
	})
	return configurationReaderSource{pair: pair, path: path, generated: generatedPath, editableBytes: bytes.Clone(editableBody), generatedBytes: generatedBody, archive: fixture.Archive}
}

func configurationReaderPairWithOutputs(t *testing.T, family string, format configuration.Format, edit func(map[string]any, map[string]any)) configurationReaderSource {
	t.Helper()
	return configurationReaderPair(t, family, format, func(editable, generated map[string]any) {
		for id, destination := range editable["outputs"].(map[string]any)["destinations"].(map[string]any) {
			destination.(map[string]any)["plugin"] = "fixture-" + id
		}
		if edit != nil {
			edit(editable, generated)
		}
	})
}

// The archived selections use fixture-specific output contracts. Derive their
// targets from the installed fixture profiles, independently of the companion.
func compareReaderFixture(ctx context.Context, request contract.ID, trusted, candidate *configuration.Pair, open func(context.Context, ReaderConfig) (*core.ReaderEngine, error)) ConfigurationComparisonResult {
	correlation, err := newConfigurationComparisonResult(request, trusted.Format)
	if err != nil {
		return correlation
	}
	return compareConfigurationWithIdentity(ctx, request, trusted, candidate, open, validateReaderFixtureSource, correlation)
}

func validateReaderFixtureSource(ctx context.Context, trusted, source *configuration.Pair, model *configuration.Model, proposed bool) (core.PublicConfigurationValidation, func(context.Context, core.PublicationPolicyActionInput) (uint8, error), *core.PublicConfigurationValidator, error) {
	if err := configurationNormalizationSourceCheck(trusted, source)(ctx); err != nil {
		return core.PublicConfigurationValidation{}, nil, nil, err
	}
	validator := core.NewPublicConfigurationValidator(func(ctx context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
		for _, binding := range model.Outputs {
			if binding.DestinationID == id && binding.Plugin == "fixture-"+id {
				return readerFixtureInterpretOutput(ctx, id, destination, name, encoding)
			}
		}
		return contract.OutputTarget{}, core.ErrPublicOutputUnavailable
	})
	check := validator.Validate
	if proposed {
		check = validator.ValidateProposed
	}
	result := check(ctx, model.Public)
	model.Public = result.Configuration
	result.Configuration = contract.PublicConfiguration{}
	return result, nil, result.CheckedRouteValidator(), nil
}

func configurationReaderWithoutOutputs(editable, generated map[string]any) {
	editable["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{"default": []string{}}}
	generated["canonical_records"].(map[string]any)["outputs"] = map[string]any{}
}

func configurationReaderKey(key contract.KMSBinding) map[string]any {
	protection := "software"
	if key.ProtectionClass == contract.HardwareProtection {
		protection = "hardware"
	}
	return map[string]any{"selector": key.KeySelector, "public_key": key.SPKI, "binding": map[string]any{"id": readerID(key.BindingID), "incarnation": readerID(key.BindingIncarnationID), "serial": key.BindingSerial, "protection": protection}}
}

func (s configurationReaderSource) assertUnchanged(t *testing.T) {
	t.Helper()
	for _, row := range []struct {
		path string
		body []byte
	}{{s.path, s.editableBytes}, {s.generated, s.generatedBytes}} {
		got, err := os.ReadFile(row.path)
		if err != nil || !bytes.Equal(got, row.body) {
			t.Fatal("Reader changed source bytes", err)
		}
	}
}

func configurationReaderOpener(t *testing.T, source configurationReaderSource, h *readerHTTPFixture, calls *int) func(context.Context, ReaderConfig) (*core.ReaderEngine, error) {
	t.Helper()
	transport, stop := readerHTTPTransport(t, h, []string{"s3.us-east-1.amazonaws.com", "storage.australia-southeast1.rep.googleapis.com"})
	t.Cleanup(stop)
	return func(ctx context.Context, c ReaderConfig) (*core.ReaderEngine, error) {
		*calls++
		if c.Family != source.archive.Family {
			t.Fatal("candidate selected the domain provider")
		}
		if c.AWS != nil {
			if c.AWS.Candidate.Bucket != source.archive.Location.Bucket || c.AWS.ExpectedDomain != source.archive.Domain {
				t.Fatal("candidate replaced baseline construction")
			}
			c.AWS.Candidate.Credentials = readerFixtureCredentials{}
			c.AWS.Candidate.Transport = transport
		} else {
			if c.GCP.Candidate.Bucket != source.archive.Location.Bucket || c.GCP.ExpectedDomain != source.archive.Domain {
				t.Fatal("candidate replaced baseline construction")
			}
			client, err := gcpprovider.NewLocalResponderClient(transport, readerFixtureCredentials{})
			if err != nil {
				t.Fatal(err)
			}
			c.GCP.Candidate.Client = client
		}
		if c.PrepareManifestRenderer == nil {
			c.PrepareManifestRenderer = func(_ context.Context, _ contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure) {
				return genericjson.Render, ""
			}
		}
		return NewReader(ctx, c)
	}
}

func configurationReaderInvalidBinding(t *testing.T, generated map[string]any, id string) map[string]any {
	t.Helper()
	profile := readerFixtureProfiles()[1]
	binding := contract.NormalOutputBinding{DestinationID: id, Destination: readerFixtureDestination(profile), Targets: []contract.NormalOutputTarget{{Name: "absent-source-entry", Target: readerFixtureOutputTarget(profile, contract.OutputEncodingRaw)}}}
	body, err := contract.EncodeNormalOutputBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	configurationCanonicalBacking(generated, "outputs", id, body)
	return map[string]any{"plugin": nil, "canonical": map[string]any{"settings": json.RawMessage(binding.Destination.CanonicalSettings)}}
}

func configurationReaderConflictingTargets(t *testing.T, editable, generated map[string]any, id string) {
	t.Helper()
	outputs := editable["outputs"].(map[string]any)
	routes := outputs["routing"].(map[string]any)
	routes["entries"] = map[string]any{"secret": []string{"first", id}}
	for _, name := range []string{"first", id} {
		profile := readerFixtureProfiles("secret")[1]
		binding := contract.NormalOutputBinding{DestinationID: name, Destination: readerFixtureDestination(profile), Targets: []contract.NormalOutputTarget{{Name: "secret", Target: readerFixtureOutputTarget(profile, contract.OutputEncodingRaw)}}}
		body, err := contract.EncodeNormalOutputBinding(binding)
		if err != nil {
			t.Fatal(err)
		}
		outputs["destinations"].(map[string]any)[name] = map[string]any{"plugin": nil, "canonical": map[string]any{"settings": json.RawMessage(binding.Destination.CanonicalSettings)}}
		configurationCanonicalBacking(generated, "outputs", name, body)
	}
}

// full_only: false
func TestConfigurationPairReaderComparesExactPublicMeaning(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
			t.Run(fmt.Sprintf("%s/%d", family, format), func(t *testing.T) {
				t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
				t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
				source := configurationReaderPairWithOutputs(t, family, format, nil)
				h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
				calls := 0
				open := configurationReaderOpener(t, source, h, &calls)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				result := compareReaderFixture(ctx, contract.Hash([]byte("pair Reader match")), source.pair, nil, open)
				if result.Verdict != contract.ComparisonMatch || result.StateResult != contract.ReaderSuccess || len(result.Diagnostics) != 0 || calls != 1 || result.Observation == nil {
					t.Fatalf("complete pair comparison failed: verdict=%s state=%s diagnostics=%+v calls=%d", result.Verdict, result.StateResult, result.Diagnostics, calls)
				}
				assertReaderRenderings(t, result)
				h.assertNoEffects(t)
				source.assertUnchanged(t)
			})
		}
	}
}

// full_only: false
func TestRecoveredDeclarationRemovalIgnoresUnusedCanonicalBacking(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		t.Run(configurationSourceFormat(format), func(t *testing.T) {
			baseline := configurationReaderPair(t, "aws", format, nil)
			var expected []contract.ComparisonChange
			for _, unused := range []bool{false, true} {
				candidate := configurationReaderPair(t, "aws", format, func(editable, generated map[string]any) {
					editable["entries"] = map[string]any{}
					editable["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
					if unused {
						// Schema 1, nonzero config ID, lifecycle none, zero resource ID, blob32('{}').
						intent := append([]byte{0, 1}, bytes.Repeat([]byte{1}, 32)...)
						intent = append(intent, 1)
						intent = append(intent, make([]byte, 32)...)
						intent = append(intent, 0, 0, 0, 2, '{', '}')
						configurationCanonicalBacking(generated, "generators", "removed-generator", intent)
					} else {
						delete(generated, "canonical_records")
					}
				})
				h := &readerHTTPFixture{archive: baseline.archive, reads: map[string]int{}}
				calls := 0
				open := configurationReaderOpener(t, baseline, h, &calls)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				result := compareConfiguration(ctx, contract.Hash([]byte(fmt.Sprintf("removed declarations %t", unused))), baseline.pair, candidate.pair, open)
				if result.Verdict != contract.ComparisonMismatch || result.StateResult != contract.ReaderSuccess || len(result.Diagnostics) != 0 || calls != 1 {
					t.Fatalf("removal did not reach complete comparison (unused=%t): verdict=%s state=%s diagnostics=%+v calls=%d", unused, result.Verdict, result.StateResult, result.Diagnostics, calls)
				}
				removed := map[string]bool{}
				for _, change := range result.Changes {
					if change.Subject.Kind == contract.SubjectEntry {
						if change.Action != contract.ComparisonRemoved {
							t.Fatal("removal produced an extra entry change", change)
						}
						removed[change.Subject.Name] = true
					}
				}
				if !reflect.DeepEqual(removed, map[string]bool{"": true, "a/\n雪": true, "encoded": true, "secret": true}) {
					t.Fatal("wrong removed entry set", removed)
				}
				if !unused {
					expected = result.Changes
				} else if !reflect.DeepEqual(result.Changes, expected) {
					t.Fatal("unused backing changed the complete comparison result")
				}
				h.assertNoEffects(t)
				baseline.assertUnchanged(t)
				candidate.assertUnchanged(t)
			}
		})
	}
}

// full_only: false
func TestCandidatePairCannotReplaceTrustedConstruction(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
			t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
			baseline := configurationReaderPairWithOutputs(t, family, configuration.JSON, nil)
			candidate := configurationReaderPairWithOutputs(t, family, configuration.YAML, func(editable, generated map[string]any) {
				editable["domain"].(map[string]any)["store"].(map[string]any)["bucket"] = "different-bucket"
				generated["public_basis"].(map[string]any)["descriptor"] = []byte{1}
			})
			h := &readerHTTPFixture{archive: baseline.archive, reads: map[string]int{}}
			calls := 0
			open := configurationReaderOpener(t, baseline, h, &calls)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			result := compareReaderFixture(ctx, contract.Hash([]byte("candidate cannot replace baseline")), baseline.pair, candidate.pair, open)
			expected := []contract.ComparisonChange{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, Path: []contract.DiagnosticField{contract.FieldBucket}, Action: contract.ComparisonChanged, Before: proposedSide(contract.ComparisonText(baseline.archive.Location.Bucket)), After: proposedSide(contract.ComparisonText("different-bucket"))}}
			if result.Verdict != contract.ComparisonMismatch || result.StateResult != contract.ReaderSuccess || calls != 1 || len(result.Diagnostics) != 0 || !reflect.DeepEqual(result.Changes, expected) {
				t.Fatal("candidate altered verification or lost desired difference", result.Verdict, result.StateResult, result.Diagnostics)
			}
			assertReaderRenderings(t, result)
			h.assertNoEffects(t)
			baseline.assertUnchanged(t)
			candidate.assertUnchanged(t)
		})
	}
}

// full_only: false
func TestConfigurationPairRefusalsPrecedeCredentialConstruction(t *testing.T) {
	for _, condition := range []string{"missing-generated", "bad-genesis-proof", "missing-successor-proof", "candidate-malformed", "canceled", "no-deadline"} {
		t.Run(condition, func(t *testing.T) {
			baseline := configurationReaderPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
				if condition == "bad-genesis-proof" {
					generated["public_basis"].(map[string]any)["descriptor"] = []byte{1}
				}
				if condition == "missing-successor-proof" {
					generated["public_basis"] = map[string]any{"kind": "successor", "control": []byte{1}, "selection": []byte{2}, "enrollment": []any{map[string]any{"id": readerID(contract.Hash([]byte("recipient"))), "status": "current", "display_name": ""}}}
				}
			})
			var candidate *configuration.Pair
			if condition == "candidate-malformed" {
				candidate = &configuration.Pair{Format: configuration.JSON}
			}
			trusted := baseline.pair
			if condition == "missing-generated" {
				trusted = &configuration.Pair{Editable: baseline.pair.Editable, Format: baseline.pair.Format}
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			if condition == "canceled" {
				cancel()
			}
			if condition == "no-deadline" {
				ctx = context.Background()
			}
			calls := 0
			result := compareConfiguration(ctx, contract.Hash([]byte("source refusal")), trusted, candidate, func(context.Context, ReaderConfig) (*core.ReaderEngine, error) {
				calls++
				return nil, fmt.Errorf("credential source must not load")
			})
			if calls != 0 || result.Verdict != contract.ComparisonUnable || result.StateResult != contract.ReaderRefused || result.Observation != nil || len(result.Diagnostics) == 0 {
				t.Fatal("invalid source reached credential construction", calls, result.Verdict, result.StateResult)
			}
			if condition == "no-deadline" && (result.SourceFailure != nil || result.PreAdmission == nil || result.PreAdmission.Stage != "context" || result.Result.Outcome != core.AdmissionRefused || result.Result.Reason != core.AdmissionInvalid || result.Diagnostics[0].Reason != contract.ReasonExpired) {
				t.Fatal("context refusal acquired source facts or changed its cause", result)
			}
			assertReaderRenderings(t, result)
			baseline.assertUnchanged(t)
		})
	}
}

// full_only: false
func TestConfigurationPairInstalledValidationPrecedesCredentials(t *testing.T) {
	current := func(t testing.TB, edit func(map[string]any, map[string]any)) func(map[string]any, map[string]any) {
		return func(editable, generated map[string]any) {
			configurationReaderWithoutOutputs(editable, generated)
			basis := generated["public_basis"].(map[string]any)
			descriptor, err := contract.DecodeGenesisDescriptorCore(basis["descriptor"].([]byte))
			if err != nil {
				t.Fatal(err)
			}
			body, err := contract.EncodeGenesisDescriptorCore(configurationCurrentDescriptor(t, descriptor))
			if err != nil {
				t.Fatal(err)
			}
			basis["descriptor"] = body
			if edit != nil {
				edit(editable, generated)
			}
		}
	}
	invalid := func(editable, generated map[string]any) {
		configurationReaderConflictingTargets(t, editable, generated, "second-candidate")
	}
	invalidTrusted := func(editable, generated map[string]any) {
		configurationReaderConflictingTargets(t, editable, generated, "second-trusted")
	}
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family+"/stale-targets-without-selection", func(t *testing.T) {
			trusted := configurationReaderPair(t, family, configuration.JSON, current(t, func(editable, generated map[string]any) {
				editable["outputs"].(map[string]any)["destinations"].(map[string]any)["previous"] = configurationReaderInvalidBinding(t, generated, "previous")
			}))
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			got := compareConfiguration(ctx, contract.Hash([]byte("missing selection for obsolete inventory")), trusted.pair, nil, func(context.Context, ReaderConfig) (*core.ReaderEngine, error) {
				t.Fatal("unresolved source opened credentials")
				return nil, ErrCell
			})
			if got.StateResult != contract.ReaderUnavailable || got.Observation != nil || !got.DiagnosticsComplete || len(got.Diagnostics) != 1 || got.Diagnostics[0].Reason != contract.ReasonPublicFactUnavailable || got.Diagnostics[0].Subject.DestinationID != "previous" {
				t.Fatal("obsolete target inventory became current source evidence", got.StateResult, got.Diagnostics)
			}
			trusted.assertUnchanged(t)
		})
		t.Run(family+"/valid-control", func(t *testing.T) {
			trusted := configurationReaderPair(t, family, configuration.JSON, current(t, nil))
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			baseline, err := configuration.Parse(ctx, trusted.pair)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := configurationReaderConfig(baseline); err != nil {
				t.Fatal("current proof-free public baseline did not reach construction", err)
			}
			calls := 0
			result := compareConfiguration(ctx, contract.Hash([]byte("valid source reaches opener")), trusted.pair, nil, func(context.Context, ReaderConfig) (*core.ReaderEngine, error) {
				calls++
				return nil, fmt.Errorf("controlled unavailable credential source")
			})
			if calls != 1 || result.StateResult != contract.ReaderUnavailable {
				t.Fatal("valid baseline control did not reach the opener", calls, result.StateResult)
			}
		})
		for _, condition := range []string{"trusted-invalid", "candidate-invalid", "trusted-and-candidate-invalid"} {
			t.Run(family+"/"+condition, func(t *testing.T) {
				var trustedEdit, candidateEdit func(map[string]any, map[string]any)
				if condition == "trusted-invalid" {
					trustedEdit = invalid
				} else {
					candidateEdit = invalid
				}
				if condition == "trusted-and-candidate-invalid" {
					trustedEdit = invalidTrusted
				}
				trusted := configurationReaderPair(t, family, configuration.JSON, current(t, trustedEdit))
				candidate := configurationReaderPair(t, family, configuration.JSON, current(t, candidateEdit))
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				baseline, err := configuration.Parse(ctx, trusted.pair)
				if err != nil {
					t.Fatal("trusted semantic fixture must be parseable", err)
				}
				if _, err := configurationReaderConfig(baseline); err != nil {
					t.Fatal("current public baseline blocked source-order regression", err)
				}
				if _, err := configuration.Parse(ctx, candidate.pair); err != nil {
					t.Fatal("candidate semantic fixture must be parseable", err)
				}
				calls := 0
				result := compareConfiguration(ctx, contract.Hash([]byte("installed source validation")), trusted.pair, candidate.pair, func(context.Context, ReaderConfig) (*core.ReaderEngine, error) {
					calls++
					return nil, fmt.Errorf("credentials must not load for invalid public source")
				})
				if calls != 0 || result.StateResult != contract.ReaderRefused || result.Verdict != contract.ComparisonUnable || result.Observation != nil || result.Context.ExpectedDomain != baseline.DomainID {
					t.Fatal("parseable invalid installed-profile source reached credentials or lost source refusal", calls, result.StateResult, result.Verdict)
				}
				conflict, trustedFact, candidateFact := false, false, false
				for _, diagnostic := range result.Diagnostics {
					conflict = conflict || diagnostic.Reason == contract.ReasonDuplicateKey
					trustedFact = trustedFact || diagnostic.Subject.DestinationID == "second-trusted"
					candidateFact = candidateFact || diagnostic.Subject.DestinationID == "second-candidate"
				}
				if !conflict || !result.DiagnosticsComplete || condition == "trusted-and-candidate-invalid" && (!trustedFact || !candidateFact) {
					t.Fatal("source validation diagnostic priority or independent source facts lost")
				}
				for _, scope := range result.CheckedScope {
					if scope.Status != contract.ScopeUnchecked {
						t.Fatal("refused source fabricated checked scope")
					}
				}
				assertReaderRenderings(t, result)
				trusted.assertUnchanged(t)
				candidate.assertUnchanged(t)
			})
		}
	}
}

// full_only: false
func TestConfigurationExecutablePathRefusesDuringIntake(t *testing.T) {
	baseline := configurationReaderPair(t, "aws", configuration.JSON, nil)
	var editable map[string]any
	if json.Unmarshal(baseline.editableBytes, &editable) != nil {
		t.Fatal("editable fixture unavailable")
	}
	editable["outputs"].(map[string]any)["destinations"].(map[string]any)["unused-unsupported"] = map[string]any{"plugin": "private-output", "settings": map[string]any{}, "path": "/untrusted/plugin"}
	directory := t.TempDir()
	reference := editable["generated"].(string)
	dependency := filepath.Join(directory, filepath.FromSlash(reference))
	if os.MkdirAll(filepath.Dir(dependency), 0700) != nil || os.WriteFile(dependency, baseline.generatedBytes, 0600) != nil {
		t.Fatal("generated fixture unavailable")
	}
	body, err := json.Marshal(editable)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "configuration.json")
	if os.WriteFile(source, body, 0600) != nil {
		t.Fatal("editable fixture unavailable")
	}
	pair, err := configuration.Capture(t.Context(), source, configuration.JSON)
	if pair != nil {
		defer func() {
			if err := pair.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	if err == nil {
		_, err = configuration.Parse(t.Context(), pair)
	}
	var diagnostic *configuration.Diagnostic
	if err == nil || !errors.As(err, &diagnostic) || diagnostic.Reason != "unknown-field" {
		t.Fatal("executable source path crossed common intake", err)
	}
}

// full_only: false
func TestConfigurationSourceRefusalPreservesCorePriorityAndOwnedDiagnostics(t *testing.T) {
	request, domain := contract.Hash([]byte("request")), contract.Hash([]byte("domain"))
	profile := core.PublicConfigurationValidation{Valid: true, DiagnosticsComplete: true, Diagnostics: []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "trusted"}, Path: []contract.DiagnosticField{contract.FieldConfigContract}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonUnsupportedProfile, SourceLocation: &contract.SourceLocation{SourceID: "trusted", Line: 2, Column: 3}}}}
	invalid := core.PublicConfigurationValidation{DiagnosticsComplete: true, Diagnostics: []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "candidate"}, Path: []contract.DiagnosticField{contract.FieldDestination}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput}}}
	blocked := core.RefusePublicComparisonSource(request, domain, profile)
	if blocked.StateResult != contract.ReaderProfileBlocked {
		t.Fatal("unsupported profile priority differs")
	}
	refused := core.RefusePublicComparisonSource(request, domain, profile, invalid)
	if refused.StateResult != contract.ReaderRefused || refused.Result.Outcome != core.AdmissionRefused || refused.Observation != nil || refused.Verdict != contract.ComparisonUnable || !refused.DiagnosticsComplete || len(refused.Diagnostics) != 2 || refused.Context.ExpectedDomain != domain {
		t.Fatal("combined source priority or non-authenticated result differs")
	}
	profile.Diagnostics[0].Path[0] = contract.FieldPresence
	profile.Diagnostics[0].SourceLocation.Line = 99
	for _, diagnostic := range refused.Diagnostics {
		if diagnostic.Subject.DestinationID == "trusted" && (diagnostic.Path[0] != contract.FieldConfigContract || diagnostic.SourceLocation.Line != 2) {
			t.Fatal("source-refusal diagnostics borrowed mutable input")
		}
	}
	for _, scope := range refused.CheckedScope {
		if scope.Status != contract.ScopeUnchecked {
			t.Fatal("source refusal fabricated checked scope")
		}
	}
	valid := core.PublicConfigurationValidation{Valid: true, Complete: true, DiagnosticsComplete: true}
	if result := core.RefusePublicComparisonSource(request, domain, valid); result.StateResult == contract.ReaderSuccess || result.Observation != nil {
		t.Fatal("pure source result claimed authenticated success")
	}
	assertReaderRenderings(t, ConfigurationComparisonResult{PublicComparisonResult: refused, InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}})
}

// full_only: false
func TestConfigurationPairLateProofFailureDiscardsPublicDifferences(t *testing.T) {
	baseline := configurationReaderPairWithOutputs(t, "aws", configuration.JSON, nil)
	candidate := configurationReaderPairWithOutputs(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
		editable["entries"].(map[string]any)["a/\n雪"].(map[string]any)["source"].(map[string]any)["bytes"] = []byte{0, 10, 66}
	})
	h := &readerHTTPFixture{archive: baseline.archive, reads: map[string]int{}}
	calls := 0
	open := configurationReaderOpener(t, baseline, h, &calls)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	first := compareReaderFixture(ctx, contract.Hash([]byte("complete candidate comparison")), baseline.pair, candidate.pair, open)
	if first.Verdict != contract.ComparisonMismatch {
		t.Fatal("fixture lacks public difference", first.Verdict)
	}
	_, _, _, _, outputKey := readerFixtureFacts(t, baseline.archive)
	count := h.count(outputKey)
	if count < 2 {
		t.Fatal("fixture did not reach late required child")
	}
	h.reset(false, outputKey, count)
	failed := compareReaderFixture(ctx, contract.Hash([]byte("late source comparison proof failure")), baseline.pair, candidate.pair, open)
	expected := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonSelectedObjectInvalid}}
	if failed.Verdict != contract.ComparisonUnable || failed.StateResult != contract.ReaderPositiveDefect || failed.Observation == nil || !reflect.DeepEqual(failed.Diagnostics, expected) {
		t.Fatal("late child failure retained a provisional difference", failed.Verdict, failed.StateResult, failed.Diagnostics)
	}
	assertReaderRenderings(t, failed)
	h.assertNoEffects(t)
	baseline.assertUnchanged(t)
	candidate.assertUnchanged(t)
}

// full_only: false
func TestConfigurationFileCaptureFailuresPreserveBaselineContext(t *testing.T) {
	baseline := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	request := contract.Hash([]byte("missing candidate capture"))
	result := CompareConfigurationFiles(ctx, request, baseline.path, configuration.JSON, filepath.Join(t.TempDir(), "missing"), configuration.JSON)
	if result.StateResult != contract.ReaderRefused || result.Context.ExpectedDomain != baseline.archive.Domain || result.Context.RequestID != request || result.Context.OperationID.IsZero() || result.Observation != nil {
		t.Fatal("candidate capture replaced known baseline context")
	}
	if result.PreAdmission == nil || result.PreAdmission.Stage != "capture" || result.PreAdmission.RequestNonce != request {
		t.Fatal("candidate capture lost pre-admission context")
	}
	assertReaderRenderings(t, result)
	baseline.assertUnchanged(t)
}
