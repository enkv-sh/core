package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestPrepareMissingCompanionCapturesSourceBeforeConstruction(t *testing.T) {
	for _, parent := range []string{"absent", "existing"} {
		t.Run(parent, func(t *testing.T) {
			var source map[string]any
			if err := json.Unmarshal(initializationSetupSource(t, "aws", false, false), &source); err != nil {
				t.Fatal(err)
			}
			source["recipients"] = map[string]any{}
			source["generated"] = ".enkv/prod.generated.json"
			body, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			body = append([]byte("# keep the exact source\n"), body...)
			directory := t.TempDir()
			path := filepath.Join(directory, "surviving.yaml")
			generated := filepath.Join(directory, ".enkv/prod.generated.json")
			if parent == "existing" {
				if err := os.Mkdir(filepath.Dir(generated), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			prefix := "fixture"
			normal := "arn:aws:kms:us-east-1:123456789012:key/00000001-1111-1111-1111-111111111111"
			request := PrepareRequest{Source: path, Format: configuration.YAML, Recovery: &PrepareRecoveryRequest{Name: "prod", Provider: contract.AWS,
				Bucket: "fixture-bucket", Region: "us-east-1", Prefix: &prefix, NormalSigningKey: &normal}}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			fault := errors.New("controlled reconstruction construction failure")
			constructions := 0
			checkSource := func() {
				t.Helper()
				after, statErr := os.Lstat(path)
				current, readErr := os.ReadFile(path)
				if statErr != nil || readErr != nil || !os.SameFile(before, after) || !bytes.Equal(body, current) {
					t.Fatal("construction changed surviving source bytes or native identity", statErr, readErr)
				}
				if _, err := os.Lstat(generated); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("construction installed an unauthenticated companion", err)
				}
			}
			result, err := prepareConfiguration(ctx, request, func(_ context.Context, config ReconstructionConfig) (*core.ReconstructionEngine, error) {
				constructions++
				checkSource()
				if config.Family != contract.AWS || config.AWS == nil || config.AWS.Candidate.Bucket != "fixture-bucket" || config.AWS.Candidate.Prefix != "fixture" || config.AWS.Normal == nil || config.AWS.Normal.KeyARN != normal {
					t.Fatal("local source replaced independently selected recovery inputs")
				}
				return nil, fault
			})
			if constructions != 1 || !errors.Is(err, fault) {
				if result != nil {
					record := prepareResultWire(t, result)
					t.Logf("prepare branch=%v recovery=%v delivery=%v diagnostics=%v", record["branch"], record["recovery"], record["local_delivery"], record["diagnostics"])
				}
				t.Fatal("confirmed missing companion did not reach reconstruction after exact source capture", constructions, err)
			}
			checkSource()
			record := prepareResultWire(t, result)
			if record["branch"] != "reconstruction" || record["recovery"].(map[string]any)["status"] != "failed" || record["local_delivery"].(map[string]any)["outcome"] != "not-recorded" || !errors.Is(err, ErrPrepare) {
				t.Fatal("construction failure fabricated recovery or local delivery")
			}
		})
	}
}

// full_only: false
func TestCompanionMergeRejectsConflictingSurvivingFacts(t *testing.T) {
	for _, condition := range []string{"recipient-missing-id", "recipient-foreign-id", "recipient-current-key", "store", "authority-signing", "authority-encryption", "recovery-mode", "plain-as-secret"} {
		t.Run(condition, func(t *testing.T) {
			projection, basis, _ := configurationReconstructionProjection(t, "aws")
			current, err := ReconstructionConfiguration(t.Context(), projection, basis, ReconstructionConfigurationOptions{Name: "restored", FileID: contract.ID{0x72}})
			projection.Close()
			if err != nil {
				t.Fatal(err)
			}
			var emitted bytes.Buffer
			if err := configuration.EmitEditable(&emitted, current, configuration.JSON); err != nil {
				t.Fatal(err)
			}
			var source map[string]any
			decoder := json.NewDecoder(bytes.NewReader(emitted.Bytes()))
			decoder.UseNumber()
			if err := decoder.Decode(&source); err != nil {
				t.Fatal(err)
			}
			domain := source["domain"].(map[string]any)
			recipients := source["recipients"].(map[string]any)
			references := make([]string, 0, len(recipients))
			for reference := range recipients {
				references = append(references, reference)
			}
			sort.Strings(references)
			if len(references) == 0 {
				t.Fatal("authenticated fixture lacks an additional recipient")
			}
			row := recipients[references[0]].(map[string]any)
			wantReason := "prepare-selected-key"
			switch condition {
			case "recipient-missing-id":
				delete(row, "id")
				wantReason = "missing-prepared-recipient"
			case "recipient-foreign-id":
				row["id"] = readerID(contract.Hash([]byte("unregistered source recipient")))
				wantReason = "missing-prepared-recipient"
			case "recipient-current-key":
				selector := domain["authority"].(map[string]any)["encryption_key"]
				if selector == row["encryption_key"] {
					t.Fatal("current-key conflict fixture reused the selected recipient key")
				}
				row["encryption_key"] = selector
			case "store":
				domain["store"].(map[string]any)["bucket"] = "other-fixture-bucket"
				wantReason = "store-mismatch"
			case "authority-signing":
				domain["authority"].(map[string]any)["signing_key"] = "arn:aws:kms:us-east-1:123456789012:key/77777777-1111-1111-1111-111111111111"
			case "authority-encryption":
				domain["authority"].(map[string]any)["encryption_key"] = row["encryption_key"]
			case "recovery-mode":
				if current.RecoveryEnabled {
					t.Fatal("Reader fixture unexpectedly has Recovery enabled")
				}
				domain["recovery"] = map[string]any{"enabled": true,
					"signing_key": "arn:aws:kms:us-east-1:123456789012:key/77777777-1111-1111-1111-111111111111", "encryption_key": "arn:aws:kms:us-east-1:123456789012:key/88888888-1111-1111-1111-111111111111"}
				wantReason = "recovery-mode-mismatch"
			case "plain-as-secret":
				name, found := "", false
				for _, entry := range current.Entries {
					if !entry.Secret {
						name, found = entry.Name, true
						break
					}
				}
				if !found {
					t.Fatal("authenticated fixture lacks a committed plain entry")
				}
				entry := source["entries"].(map[string]any)[name].(map[string]any)
				entry["confidentiality"], entry["source"] = "secret", map[string]any{"kind": "supplied"}
				wantReason = "sealed-context-mismatch"
			}
			body, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "surviving.json")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			generated := filepath.Join(filepath.Dir(path), current.Generated)
			output, captured, err := configuration.BeginCompanionReconstruction(t.Context(), path, configuration.JSON)
			if err != nil {
				t.Fatal("conflict fixture failed before its recovered-fact join", err)
			}
			t.Cleanup(func() {
				if err := output.Close(); err != nil {
					t.Error(err)
				}
			})
			merged, err := configuration.MergeReconstructedCompanion(t.Context(), captured, current)
			var diagnostic *configuration.Diagnostic
			if merged != nil || !errors.As(err, &diagnostic) || diagnostic.Reason != wantReason || !errors.Is(err, configuration.ErrSourceInvalid) {
				t.Fatal("surviving conflict was hidden or inferred from another fact", err)
			}
			if !reflect.DeepEqual(*captured, configuration.Model{}) || !reflect.DeepEqual(*current, configuration.Model{}) {
				t.Fatal("failed merge retained consumed semantic owners")
			}
			after, statErr := os.Lstat(path)
			actual, readErr := os.ReadFile(path)
			if statErr != nil || readErr != nil || !os.SameFile(before, after) || !bytes.Equal(actual, body) {
				t.Fatal("merge conflict changed surviving source", statErr, readErr)
			}
			if _, err := os.Lstat(generated); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("merge conflict delivered an unauthenticated companion", err)
			}
		})
	}
}

// full_only: false
func TestCompanionMergePreservesCanonicalAndAuthorIntent(t *testing.T) {
	projection, _, _ := configurationReconstructionProjection(t, "aws")
	basis, err := projection.CopyPublicBasis(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	current, err := ReconstructionConfiguration(t.Context(), projection, basis, ReconstructionConfigurationOptions{Name: "restored", FileID: contract.ID{0x73}})
	projection.Close()
	if err != nil {
		t.Fatal(err)
	}
	wantPins := map[string]configuration.Pin{}
	for _, entry := range current.Entries {
		if entry.Secret && entry.Generated == nil && entry.Retained != nil {
			wantPins[entry.Name] = *entry.Retained
		}
	}
	var emitted, baselineGenerated bytes.Buffer
	if err := configuration.EmitEditable(&emitted, current, configuration.JSON); err != nil {
		t.Fatal(err)
	}
	if err := configuration.EmitGenerated(&baselineGenerated, current); err != nil {
		t.Fatal(err)
	}
	var baseline struct {
		Records map[string]map[string]string `json:"canonical_records"`
	}
	if err := json.Unmarshal(baselineGenerated.Bytes(), &baseline); err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	decoder := json.NewDecoder(bytes.NewReader(emitted.Bytes()))
	decoder.UseNumber()
	if err := decoder.Decode(&source); err != nil {
		t.Fatal(err)
	}
	source["domain"].(map[string]any)["authority"].(map[string]any)["display_name"] = "Pending Authority label"
	recipients := source["recipients"].(map[string]any)
	references := make([]string, 0, len(recipients))
	for reference := range recipients {
		references = append(references, reference)
	}
	sort.Strings(references)
	if len(references) == 0 {
		t.Fatal("authenticated fixture lacks a recipient")
	}
	oldReference := references[0]
	row := recipients[oldReference].(map[string]any)
	wantRecipientID := row["id"].(string)
	row["display_name"] = "Pending Reader label"
	delete(recipients, oldReference)
	recipients["renamed-source"] = row
	entries := source["entries"].(map[string]any)
	plainName, foundPlain := "", false
	for _, entry := range current.Entries {
		if !entry.Secret {
			plainName, foundPlain = entry.Name, true
			break
		}
	}
	if !foundPlain || entries["pending-generated"] != nil {
		t.Fatal("pending intent fixture lacks a distinct current plain entry")
	}
	for _, value := range entries {
		entry := value.(map[string]any)
		members := entry["recipients"].([]any)
		for i, member := range members {
			if member == oldReference {
				members[i] = "renamed-source"
			}
		}
	}
	entries["pending-generated"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "private-generator", "epoch": 7, "retirement": "manual", "settings": map[string]any{"pending": "generated author"}}}
	wantEntries := make([]string, 0, len(entries))
	for name := range entries {
		wantEntries = append(wantEntries, name)
	}
	sort.Strings(wantEntries)
	outputs := source["outputs"].(map[string]any)
	destinations := outputs["destinations"].(map[string]any)
	ids := make([]string, 0, len(destinations))
	for id := range destinations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) == 0 || destinations["pending-author-output"] != nil {
		t.Fatal("pending intent fixture lacks a distinct canonical destination")
	}
	canonicalID := ids[0]
	canonical := destinations[canonicalID].(map[string]any)["canonical"].(map[string]any)
	settings := canonical["settings"].(map[string]any)
	settings["pending_public_label"] = "preserved"
	wantSettings, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	destinations["pending-author-output"] = map[string]any{"plugin": "private-output", "settings": map[string]any{"pending": "output author"}}
	outputs["routing"] = map[string]any{"default": []string{}, "entries": map[string]any{plainName: []string{canonicalID, "pending-author-output"}, "pending-generated": []string{}}}
	outputs["groups"] = [][]string{{plainName}}
	body, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	body = append(append([]byte("\n "), body...), '\n')
	path := filepath.Join(t.TempDir(), "surviving.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(filepath.Dir(path), current.Generated)
	output, captured, err := configuration.BeginCompanionReconstruction(t.Context(), path, configuration.JSON)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := output.Close(); err != nil {
			t.Error(err)
		}
	})
	merged, err := configuration.MergeReconstructedCompanion(t.Context(), captured, current)
	if err != nil {
		t.Fatal("valid pending source intent could not retain authenticated backing", err)
	}
	if merged.Authority.DisplayName != "Pending Authority label" || !reflect.DeepEqual(merged.Public.Groups.Value, [][]string{{plainName}}) || len(merged.Recipients) != len(references) || len(merged.Outputs) != len(ids)+1 || len(merged.Entries) != len(entries) {
		t.Fatal("merge lost the complete desired public sets or labels")
	}
	renamed := false
	for _, recipient := range merged.Recipients {
		if recipient.Reference == "renamed-source" {
			renamed = recipient.DisplayName == "Pending Reader label" && readerID(recipient.ID) == wantRecipientID
		}
	}
	if !renamed {
		t.Fatal("local reference/label edit changed authenticated recipient identity")
	}
	staged, err := output.Stage(t.Context(), merged)
	if err != nil {
		t.Fatal("pending author/canonical source could not form a strict complete pair", err)
	}
	wantDestinations := append(slices.Clone(ids), "pending-author-output")
	sort.Strings(wantDestinations)
	gotDestinations := make([]string, len(staged.Outputs))
	for i, binding := range staged.Outputs {
		gotDestinations[i] = binding.DestinationID
		if binding.DestinationID == canonicalID {
			var gotSettings, expected any
			decode := func(body []byte, target *any) error {
				reader := json.NewDecoder(bytes.NewReader(body))
				reader.UseNumber()
				return reader.Decode(target)
			}
			if decode(binding.Binding.Destination.CanonicalSettings, &gotSettings) != nil || decode(wantSettings, &expected) != nil || !reflect.DeepEqual(gotSettings, expected) || binding.Binding.Targets != nil {
				t.Fatal("canonical edit used stale settings or retained stale proposed targets")
			}
		}
		if binding.DestinationID == "pending-author-output" && (binding.Plugin != "private-output" || string(binding.Settings) != `{"pending":"output author"}`) {
			t.Fatal("merge replaced ordinary output settings or local selection")
		}
	}
	if !slices.Equal(gotDestinations, wantDestinations) {
		t.Fatal("merge changed the complete desired destination set")
	}
	generatedEntry := false
	gotEntries := make([]string, len(staged.Entries))
	for i, entry := range staged.Entries {
		gotEntries[i] = entry.Name
		if entry.Secret && entry.Generated == nil {
			pin, exists := wantPins[entry.Name]
			if !exists || entry.Retained == nil || *entry.Retained != pin || len(entry.Sealed) != 0 {
				t.Fatal("source merge changed the committed input association")
			}
			delete(wantPins, entry.Name)
		}
		if entry.Name == "pending-generated" {
			generatedEntry = entry.Secret && entry.Generated != nil && entry.Generated.Plugin == "private-generator" && entry.Generated.Epoch == 7 && entry.Generated.Retirement == "manual" && string(entry.Generated.Settings) == `{"pending":"generated author"}` && len(entry.Generated.Intent) == 0 && entry.Retained == nil && len(entry.Sealed) == 0
		}
	}
	if !generatedEntry || len(staged.Routes) != 3 || !slices.Equal(gotEntries, wantEntries) || len(wantPins) != 0 {
		t.Fatal("new generated declaration acquired a value or lost desired routing")
	}
	wantRoutes := map[string][]string{plainName: {canonicalID, "pending-author-output"}, "pending-generated": {}}
	sort.Strings(wantRoutes[plainName])
	defaultSeen := false
	for _, route := range staged.Routes {
		if route.Default {
			defaultSeen = len(route.Destinations) == 0
			continue
		}
		want, ok := wantRoutes[route.EntryName]
		if !ok || !slices.Equal(route.Destinations, want) {
			t.Fatal("merge changed desired routing presence or values")
		}
		delete(wantRoutes, route.EntryName)
	}
	if !defaultSeen || len(wantRoutes) != 0 {
		t.Fatal("merge omitted an explicit empty default or entry override")
	}
	if _, err := output.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	generatedBody, err := os.ReadFile(generated)
	if err != nil {
		t.Fatal(err)
	}
	var delivered struct {
		Records map[string]map[string]string `json:"canonical_records"`
	}
	if err := json.Unmarshal(generatedBody, &delivered); err != nil || !reflect.DeepEqual(delivered.Records["outputs"], baseline.Records["outputs"]) || len(delivered.Records["generators"]) != 0 {
		t.Fatal("companion lost exact authenticated baseline records or invented generated backing", err)
	}
	after, statErr := os.Lstat(path)
	actual, readErr := os.ReadFile(path)
	if statErr != nil || readErr != nil || !os.SameFile(before, after) || !bytes.Equal(actual, body) {
		t.Fatal("pending-intent recovery rewrote surviving source", statErr, readErr)
	}
}

// full_only: false
func TestPrepareMissingCompanionPreservesSurvivingIntent(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			projection, basis, selected := configurationReconstructionProjection(t, family)
			model, err := ReconstructionConfiguration(t.Context(), projection, basis, ReconstructionConfigurationOptions{Name: "restored", FileID: contract.ID{0x71}})
			projection.Close()
			if err != nil {
				t.Fatal(err)
			}
			var supplied configuration.Entry
			for _, entry := range model.Entries {
				if entry.Secret && entry.Generated == nil && entry.Retained != nil {
					supplied = entry
					break
				}
			}
			if supplied.Name == "" || supplied.Retained == nil {
				t.Fatal("authenticated fixture lacks a committed supplied secret")
			}

			wantPin := *supplied.Retained
			selectedOutput := supplied.OutputEncoding
			supplied.OutputEncoding = contract.OutputEncodingBase64
			if selectedOutput == contract.OutputEncodingBase64 {
				supplied.OutputEncoding = contract.OutputEncodingRaw
			}
			model.Outputs, model.Routes = nil, nil
			model.Entries = []configuration.Entry{supplied, {Name: "pending-plain", Plain: []byte("surviving public input"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingBase64}}
			model.Authority.DisplayName = "Pending Authority label"
			model.Public.Groups = contract.PublicField[[][]string]{State: contract.PublicPresent, Value: [][]string{}}
			if err := configuration.RefreshPublic(model); err != nil {
				t.Fatal("desired source fixture public facts are inconsistent", err)
			}
			var editable, companion bytes.Buffer
			editable.WriteString("# preserve this surviving source comment\n")
			if err := configuration.EmitEditable(&editable, model, configuration.YAML); err != nil {
				t.Fatal(err)
			}
			if err := configuration.EmitGenerated(&companion, model); err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			path := filepath.Join(directory, "surviving.yaml")
			generated := filepath.Join(directory, model.Generated)
			if err := os.Mkdir(filepath.Dir(generated), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, editable.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(generated, companion.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(generated); err != nil {
				t.Fatal(err)
			}
			request := prepareRecoveryRequestForTest(configurationReaderSource{archive: selected.archive}, path, configuration.YAML)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			constructions := 0
			open := func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error) {
				constructions++
				return core.NewInstalledReconstruction(core.ReconstructionInstallation{Candidate: selected, Normal: selected,
					Construct: func(context.Context, contract.StoreConfiguration) (core.PublicSelectedReader, core.Result) {
						return selected, core.Result{}
					}, Verify: func(_ context.Context, pins contract.ReconstructionVerificationPins, _ time.Time) (core.ReconstructionVerifier, error) {
						return &configurationReconstructionVerifier{source: selected, pins: pins}, nil
					}, CloseInstalled: func() {}})
			}
			result, err := prepareConfiguration(ctx, request, open)
			if err != nil || constructions != 1 || PrepareExitCode(result, nil) != 0 {
				if result != nil {
					record := prepareResultWire(t, result)
					t.Logf("prepare branch=%v recovery=%v delivery=%v diagnostics=%v", record["branch"], record["recovery"], record["local_delivery"], record["diagnostics"])
				}
				t.Fatal("confirmed missing companion did not reconstruct from independently authenticated state", constructions, err)
			}
			record := prepareResultWire(t, result)
			if record["branch"] != "reconstruction" || record["recovery"].(map[string]any)["status"] != "complete" || record["local_delivery"].(map[string]any)["outcome"] != "recorded" {
				t.Fatal("companion recovery lost authenticated recovery or recorded delivery")
			}
			after, err := os.Lstat(path)
			body, readErr := os.ReadFile(path)
			if err != nil || readErr != nil || !os.SameFile(before, after) || !bytes.Equal(body, editable.Bytes()) {
				t.Fatal("companion recovery changed surviving source identity or bytes", err, readErr)
			}
			pair, err := configuration.Capture(ctx, path, configuration.YAML)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := pair.Close(); err != nil {
					t.Error(err)
				}
			}()
			recovered, err := configuration.Parse(ctx, pair)
			if err != nil || recovered.FileID == model.FileID || recovered.Authority.DisplayName != "Pending Authority label" || len(recovered.Entries) != 2 || len(recovered.Outputs) != 0 {
				t.Fatal("companion recovery discarded surviving additions, edits or removals", err)
			}
			wantNames := []string{supplied.Name, "pending-plain"}
			sort.Strings(wantNames)
			gotNames := make([]string, len(recovered.Entries))
			for i, entry := range recovered.Entries {
				gotNames[i] = entry.Name
			}
			if !slices.Equal(gotNames, wantNames) {
				t.Fatal("companion recovery changed the complete desired entry set", gotNames, wantNames)
			}
			for _, entry := range recovered.Entries {
				if entry.Name == supplied.Name {
					if !entry.Secret || entry.Generated != nil || entry.Retained == nil || *entry.Retained != wantPin || len(entry.Sealed) != 0 || len(entry.Plain) != 0 || !slices.Equal(entry.Recipients, supplied.Recipients) || entry.InputEncoding != supplied.InputEncoding || entry.OutputEncoding != supplied.OutputEncoding || entry.OutputEncoding == selectedOutput {
						t.Fatal("companion recovery did not restore exact committed supplied input facts")
					}
				} else if entry.Secret || entry.Generated != nil || entry.Retained != nil || len(entry.Sealed) != 0 || len(entry.Recipients) != 0 || entry.PlainBase64 || !bytes.Equal(entry.Plain, []byte("surviving public input")) || entry.InputEncoding != contract.InputEncodingRaw || entry.OutputEncoding != contract.OutputEncodingBase64 {
					t.Fatal("companion recovery changed unapplied plain input facts")
				}
			}
			request.Recovery = nil
			again, err := prepareConfiguration(ctx, request, open)
			if err != nil || constructions != 1 || prepareResultWire(t, again)["branch"] != "existing" {
				t.Fatal("later prepare reconstructed an already delivered companion", constructions, err)
			}
		})
	}
}
