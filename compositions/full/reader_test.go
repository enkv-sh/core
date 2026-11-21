package compositionfull

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"slices"
	"testing"
	"time"

	compositionaws "enkv.sh/compositions/aws"
	"enkv.sh/compositions/configuration"
	compositiongcp "enkv.sh/compositions/gcp"
	core "enkv.sh/core"
	"enkv.sh/core/contract"
	awsprovider "enkv.sh/providers/aws"
	gcpprovider "enkv.sh/providers/gcp"
)

// full_only: false
func TestNewReaderSelectsExactlyOneInstalledProvider(t *testing.T) {
	ctx, a, g := localConfigs(t)
	as, err := awsprovider.NewStore(a.Store)
	if err != nil {
		t.Fatal(err)
	}
	gs, err := gcpprovider.NewStore(ctx, g.Store)
	if err != nil {
		t.Fatal(err)
	}
	ac := compositionaws.ReaderConfig{Candidate: awsprovider.CandidateReadConfig{Region: a.Store.Region, Bucket: a.Store.Bucket, Prefix: a.Store.Prefix, ExpectedBucketOwner: a.Store.ExpectedBucketOwner, CredentialRoute: a.Store.CredentialRoute, Credentials: a.Store.Credentials, Transport: a.Store.Transport, Timeout: a.Store.Timeout}, ExpectedDomain: a.Store.Domain, ExpectedStore: as.Descriptor(), PublicBasis: core.PublicBasis{Descriptor: []byte{1}}}
	gc := compositiongcp.ReaderConfig{Candidate: gcpprovider.CandidateReadConfig{Client: g.Store.Client, Region: g.Store.Region, Bucket: g.Store.Bucket, Prefix: g.Store.Prefix, CredentialRoute: g.Store.CredentialRoute}, ExpectedDomain: g.Store.Domain, ExpectedStore: gs.Descriptor(), PublicBasis: core.PublicBasis{Descriptor: []byte{1}}}
	// Provider input does not choose full composition interpretation.
	for _, c := range []ReaderConfig{{Family: contract.AWS, AWS: &ac}, {Family: contract.GCP, GCP: &gc}} {
		engine, err := NewReader(ctx, c)
		if err != nil || engine == nil {
			t.Fatal("selected Reader did not construct", c.Family, err)
		}
		engine.Close()
	}
	if ac.Validator != nil || gc.Validator != nil {
		t.Fatal("composition changed caller configuration")
	}
	for _, c := range []ReaderConfig{{}, {Family: contract.AWS}, {Family: contract.GCP}, {Family: contract.AWS, GCP: &gc}, {Family: contract.GCP, AWS: &ac}, {Family: contract.AWS, AWS: &ac, GCP: &gc}, {Family: contract.GCP, AWS: &ac, GCP: &gc}} {
		engine, err := NewReader(ctx, c)
		if engine != nil {
			engine.Close()
		}
		if err != ErrCell || engine != nil {
			t.Fatal("missing or second provider admitted", c.Family, err)
		}
	}
}

func readerPresent[T any](v T) contract.PublicField[T] {
	return contract.PublicField[T]{State: contract.PublicPresent, Value: v}
}

// full_only: false
func TestReaderInstallsOnlySuppliedPublicOutputInterpreter(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	model, err := configuration.Parse(ctx, source.pair)
	if err != nil {
		t.Fatal(err)
	}
	config, err := configurationReaderConfig(model)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	wanted := model.Public.OutputBindings.Value[0]
	rows := map[string]contract.OutputTarget{}
	for _, row := range wanted.Targets.Value {
		rows[row.EntryName] = configurationCanonicalTarget(row)
	}
	config.InterpretOutput = func(callCtx context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
		calls++
		if callCtx.Err() != nil || id != wanted.DestinationID || destination.ConfigContractID != wanted.Destination.Value.ConfigContractID {
			t.Fatal("interpreter lost exact source binding")
		}
		row, ok := rows[name]
		if !ok || row.PayloadEncoding != encoding {
			t.Fatal("interpreter received an unrelated entry")
		}
		return row, nil
	}
	installed, err := readerConfigWithValidator(config)
	if err != nil {
		t.Fatal(err)
	}
	if config.AWS.Validator != nil {
		t.Fatal("Reader changed caller configuration")
	}
	validator := installed.AWS.Validator
	if got := validator.Validate(ctx, model.Public); !got.Valid || !got.Complete || calls != 0 {
		t.Fatal("canonical source required an interpreter", got.Diagnostics, calls)
	}
	model.Public.OutputBindings.Value[0].Targets.State = contract.PublicUnavailable
	model.Public.OutputBindings.Value[0].Targets.Value = nil
	if got := validator.Validate(ctx, model.Public); !got.Valid || !got.Complete || calls != 2 {
		t.Fatal("source derivation did not use its exact supplied interpreter", got.Diagnostics, calls)
	}
	canceled, end := context.WithCancel(ctx)
	end()
	calls = 0
	if got := validator.Validate(canceled, model.Public); got.Valid || calls != 0 {
		t.Fatal("cancelled validation invoked interpreter")
	}
	source.assertUnchanged(t)
}

// full_only: false
func TestReaderKeepsCanonicalGeneratorIntentWithoutPlugin(t *testing.T) {
	// Independent schema1 framing: config32, None1, zero resource32 and exact JSON.
	intent := append([]byte{0, 1}, bytes.Repeat([]byte{69}, 32)...)
	intent = append(intent, 1)
	intent = append(intent, make([]byte, 32)...)
	settings := []byte(`{"size":17}`)
	intent = binary.BigEndian.AppendUint32(intent, uint32(len(settings)))
	intent = append(intent, settings...)
	source := configurationReaderPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
		configurationReaderWithoutOutputs(editable, generated)
		editable["entries"].(map[string]any)["secret"].(map[string]any)["source"] = map[string]any{"kind": "generated", "plugin": nil, "epoch": 7, "canonical": map[string]any{"settings": json.RawMessage(settings)}}
		configurationCanonicalBacking(generated, "generators", "secret", intent)
		editable["plugins"] = map[string]any{"unused-renderer": map[string]any{"version": "1.0.0"}}
		delete(generated["secrets"].(map[string]any), "secret")
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	model, err := configuration.Parse(ctx, source.pair)
	if err != nil {
		t.Fatal(err)
	}
	plugins, routes, err := configurationNormalizePlugins(ctx, source.pair, source.pair, model)
	if err != nil || plugins != nil || routes == nil {
		t.Fatal("canonical recovery acquired an unrelated plugin", err)
	}
	entry := slices.IndexFunc(model.Entries, func(row configuration.Entry) bool { return row.Name == "secret" })
	if entry < 0 || model.Entries[entry].Generated.Plugin != "" || model.Entries[entry].Generated.Settings != nil || !bytes.Equal(model.Entries[entry].Generated.Intent, intent) {
		t.Fatal("canonical bytes or unset selection changed")
	}
	if got := validateInstalledConfiguration(ctx, model.Public); !got.Valid || !got.Complete {
		t.Fatal("canonical intent failed common validation", got.Diagnostics)
	}
	source.assertUnchanged(t)
}
