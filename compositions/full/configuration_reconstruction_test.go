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
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/installedarchive"
)

// This fixture supplies installed dependencies, not a projection constructor.
// Core authenticates the signed archive and delivers its real public owner.
type configurationReconstructionArchive struct {
	archive                        installedarchive.Archive
	configuration                  contract.StoreConfiguration
	descriptor                     contract.Descriptor
	verified                       map[string]int
	selectedCloses, verifierCloses int
}

func (s *configurationReconstructionArchive) CandidateLocation() contract.StoreLocation {
	return s.archive.Location
}
func (s *configurationReconstructionArchive) ReadHEAD(ctx context.Context) contract.ReadResult {
	return s.Read(ctx, s.archive.Location.PrefixBeforeHEAD+"/HEAD", contract.MaxHeadLength)
}
func (s *configurationReconstructionArchive) ReadHEADGuarded(ctx context.Context, owner string) contract.ReadResult {
	if owner != s.archive.Location.ExpectedOwner {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	return s.ReadHEAD(ctx)
}
func (s *configurationReconstructionArchive) ReadConfiguration(ctx context.Context, domain, store contract.ID) contract.ReadResult {
	key, err := contract.StoreConfigurationKeyForID(s.archive.Family, s.archive.Location.PrefixBeforeHEAD, domain, store)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	return s.Read(ctx, key, contract.MaxStoreConfigurationLength)
}
func (s *configurationReconstructionArchive) ReadRoot(ctx context.Context, ref contract.Ref) contract.ReadResult {
	key, err := format.Key(s.archive.Location.PrefixBeforeHEAD, ref)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	return s.Read(ctx, key, contract.MaxRootLength)
}
func (s *configurationReconstructionArchive) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if ctx == nil || ctx.Err() != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable}
	}
	o, ok := s.archive.Object(key)
	if !ok {
		return contract.ReadResult{Status: contract.ReadMissing}
	}
	if len(o.Body) > int(limit) {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	return contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(o.Body), Token: o.Token}
}
func (s *configurationReconstructionArchive) Descriptor() contract.Descriptor { return s.descriptor }
func (s *configurationReconstructionArchive) StoreConfiguration() contract.StoreConfiguration {
	return s.configuration
}
func (s *configurationReconstructionArchive) Close() { s.selectedCloses++ }

// Qualify against the archive's separately recorded operator signing resource;
// no selected object supplies its own trust decision.
func (s *configurationReconstructionArchive) QualifySigningBinding(ctx context.Context, b contract.PublicSigningBinding) contract.SigningQualificationResult {
	if ctx.Err() != nil || b.Provider != s.archive.Family || b.KeySelector != s.archive.SignerSelector || !bytes.Equal(b.SPKI, s.archive.SignerPublicKey) || b.Role != contract.NormalSigningRole {
		return contract.SigningQualificationResult{Reason: contract.ReasonConstruction}
	}
	digest, err := contract.SigningBindingDigest(b)
	if err != nil {
		return contract.SigningQualificationResult{Reason: contract.ReasonConstruction}
	}
	return contract.SigningQualificationResult{Qualified: 1, TargetRole: contract.NormalSignerTarget, Provider: b.Provider, SigningBindingDigest: digest}
}

type configurationReconstructionVerifier struct {
	source *configurationReconstructionArchive
	pins   contract.ReconstructionVerificationPins
}

func (v *configurationReconstructionVerifier) Verify(ctx context.Context, s contract.ConsumerSelection) contract.CryptoResultCode {
	if ctx.Err() != nil || s.DomainID != v.pins.DomainID || s.SnapshotID != v.pins.SnapshotID || s.HEADDigest != v.pins.HEADDigest || s.HEADToken != v.pins.HEADToken || s.Binding.SubjectID != v.source.archive.AuthorityID {
		return contract.CryptoInvalidInput
	}
	v.source.verified[s.Entry.Name]++
	return contract.CryptoSuccess
}
func (v *configurationReconstructionVerifier) Close() { v.source.verifierCloses++ }

func configurationReconstructionProjection(t *testing.T, family string) (*core.ReconstructionProjection, core.PublicBasis, *configurationReconstructionArchive) {
	t.Helper()
	fixture, body := installedarchive.LoadReader(t, family)
	var saved struct{ Descriptor []byte }
	if err := json.Unmarshal(body, &saved); err != nil {
		t.Fatal(err)
	}
	a := fixture.Archive
	return configurationReconstructionArchiveProjection(t, a, saved.Descriptor, map[string]int{"encoded": 1, "secret": 1})
}

func configurationReconstructionArchiveProjection(t *testing.T, a installedarchive.Archive, descriptor []byte, verified map[string]int) (*core.ReconstructionProjection, core.PublicBasis, *configurationReconstructionArchive) {
	t.Helper()
	headObject := a.MustObject(t, a.Location.PrefixBeforeHEAD+"/HEAD")
	head, err := format.DecodeHead(headObject.Body)
	if err != nil {
		t.Fatal(err)
	}
	key, err := contract.StoreConfigurationKeyForID(a.Family, a.Location.PrefixBeforeHEAD, a.Domain, head.Core.Store)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := contract.DecodeStoreConfiguration(a.MustObject(t, key).Body)
	if err != nil {
		t.Fatal(err)
	}
	source := &configurationReconstructionArchive{archive: a, configuration: stored, verified: map[string]int{}, descriptor: contract.Descriptor{Family: a.Family, Identity: head.Core.Store, Coordinate: head.Core.Coordinate, NonBody: head.Core.NonBody, Prefix: a.Location.PrefixBeforeHEAD, HeadKey: a.Location.PrefixBeforeHEAD + "/HEAD"}}
	engine, err := core.NewInstalledReconstruction(core.ReconstructionInstallation{Candidate: source, Normal: source, ExpectedDomain: a.Domain,
		Construct: func(_ context.Context, c contract.StoreConfiguration) (core.PublicSelectedReader, core.Result) {
			if c != stored {
				t.Error("selected construction changed")
			}
			return source, core.Result{}
		},
		Verify: func(_ context.Context, pins contract.ReconstructionVerificationPins, _ time.Time) (core.ReconstructionVerifier, error) {
			return &configurationReconstructionVerifier{source: source, pins: pins}, nil
		}, CloseInstalled: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	projection, result := engine.Reconstruct(ctx)
	if projection == nil || result.Outcome != core.ObservedCurrent {
		t.Fatal("archive reconstruction refused", result)
	}
	t.Cleanup(projection.Close)
	if !reflect.DeepEqual(source.verified, verified) || source.selectedCloses != 1 || source.verifierCloses != 1 {
		t.Fatal("complete verify/discard or dependency join differs")
	}
	return projection, core.PublicBasis{Descriptor: bytes.Clone(descriptor)}, source
}

// Complete local loss must preserve an exact 32 MiB stored output declaration.
// The formats run sequentially and do not retain each other's parsed model.
// full_only: true
func TestReconstructionConfigurationPreservesNearLimitOutputDeclaration(t *testing.T) {
	directory := filepath.Join("..", "..", "crypto", "testsupport", "installedarchive", "testdata")
	archive := installedarchive.ReadOutputBoundsFixture(t, filepath.Join(directory, "reconstruction-output-bounds.json.gz"))
	body, err := os.ReadFile(filepath.Join(directory, "reconstruction-output-bounds.basis.json"))
	if err != nil || len(body) > 64<<10 {
		t.Fatal("independent output bounds basis unavailable", err)
	}
	var saved struct{ Descriptor []byte }
	if err := json.Unmarshal(body, &saved); err != nil {
		t.Fatal(err)
	}
	projection, basis, _ := configurationReconstructionArchiveProjection(t, archive, saved.Descriptor, map[string]int{})
	model, err := ReconstructionConfiguration(t.Context(), projection, basis, ReconstructionConfigurationOptions{Name: "restored", FileID: contract.Hash([]byte("output bounds fresh local identity"))})
	if err != nil {
		t.Fatal("valid selected output declaration cannot be reconstructed", err)
	}
	policy := contract.OutputPolicy{ContractID: "p", Data: bytes.Repeat([]byte{7}, 516098)}
	capabilities := contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot
	want := contract.NormalOutputBinding{DestinationID: "d", Destination: contract.OutputDestination{ConfigContractID: "c", ServiceContractID: "s", CanonicalSettings: []byte(`{}`), Policy: policy, Capabilities: capabilities}}
	for i := 0; i < 64; i++ {
		suffix := strconv.Itoa(100 + i)[1:]
		name := strings.Repeat("é", 127) + suffix
		target := contract.OutputTarget{ServiceContractID: "s", TargetContractID: "t", CanonicalTarget: "t" + suffix, PayloadEncoding: contract.OutputEncodingBase64, LocatorRequiresCreation: true, Policy: policy, Capabilities: capabilities}
		if i == 0 {
			target.TargetData = bytes.Repeat([]byte{11}, 2161)
		}
		want.Targets = append(want.Targets, contract.NormalOutputTarget{Name: name, Target: target})
	}
	if len(model.Outputs) != 1 || !reflect.DeepEqual(model.Outputs[0].Binding, want) || len(model.Entries) != 64 || len(model.Plugins) != 0 {
		t.Fatal("reconstructed stored output differs from independent field literals")
	}
	for _, encoding := range []configuration.Format{configuration.JSON, configuration.YAML} {
		t.Run(map[configuration.Format]string{configuration.JSON: "json", configuration.YAML: "yaml"}[encoding], func(t *testing.T) {
			var editable, generated bytes.Buffer
			if err := configuration.EmitEditable(&editable, model, encoding); err != nil {
				t.Fatal(err)
			}
			if err := configuration.EmitGenerated(&generated, model); err != nil {
				t.Fatal(err)
			}
			if int64(editable.Len())+int64(generated.Len()) > configuration.MaxPairBytes {
				t.Fatal("supported output declaration exceeds the complete pair limit")
			}
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, ".enkv"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, model.Generated), generated.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "configuration")
			if err := os.WriteFile(path, editable.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			pair, err := configuration.Capture(t.Context(), path, encoding)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := pair.Close(); err != nil {
					t.Error(err)
				}
			}()
			again, err := configuration.Parse(t.Context(), pair)
			if err != nil {
				t.Fatal("reconstructed maximum pair did not reparse", err)
			}
			validated := validateInstalledConfiguration(t.Context(), again.Public)
			if !validated.Valid || !validated.Complete || !reflect.DeepEqual(validated.Configuration, model.Public) || len(again.Outputs) != 1 || !reflect.DeepEqual(again.Outputs[0].Binding, want) || !reflect.DeepEqual(again.Basis, model.Basis) || !reflect.DeepEqual(again.Observation, model.Observation) {
				t.Fatal("reconstructed maximum pair changed exact selected semantics")
			}
			t.Logf("output bounds pair: editable_bytes=%d generated_bytes=%d total_bytes=%d", editable.Len(), generated.Len(), editable.Len()+generated.Len())
		})
	}
}

// full_only: false
func TestReconstructionConfigurationEmitsAuthenticatedCompletePair(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
			t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
			projection, basis, source := configurationReconstructionProjection(t, family)
			before := make([]core.ReconstructionPart, projection.PartCount())
			for i := range before {
				var ok bool
				before[i], ok = projection.CopyPart(i)
				if !ok {
					t.Fatal("complete projection part unavailable")
				}
			}
			baseline := configurationReaderPair(t, family, configuration.JSON, nil)
			expected, err := configuration.Parse(context.Background(), baseline.pair)
			if err != nil {
				t.Fatal(err)
			}
			want := validateInstalledConfiguration(context.Background(), expected.Public)
			if !want.Valid || !want.Complete {
				t.Fatal("independent current configuration fixture incomplete")
			}
			options := ReconstructionConfigurationOptions{Name: "restored", FileID: contract.Hash([]byte("reconstruction fresh local identity"))}
			model, err := ReconstructionConfiguration(context.Background(), projection, basis, options)
			if err != nil {
				t.Fatal(err)
			}
			assertReconstructedSharedRouting(t, model.Public)
			if len(model.Plugins) != 0 {
				t.Fatal("complete-loss reconstruction invented local plugin preferences")
			}
			if !reflect.DeepEqual(model.Public, want.Configuration) {
				for _, field := range []struct {
					name      string
					got, want any
				}{
					{"store", model.Public.Store, want.Configuration.Store}, {"authority", model.Public.Authority, want.Configuration.Authority},
					{"recovery", model.Public.Recovery, want.Configuration.Recovery}, {"recipients", model.Public.Recipients, want.Configuration.Recipients},
					{"entries", model.Public.Entries, want.Configuration.Entries}, {"outputs", model.Public.OutputBindings, want.Configuration.OutputBindings},
					{"groups", model.Public.Groups, want.Configuration.Groups}, {"routing", model.Public.Routing, want.Configuration.Routing},
				} {
					if !reflect.DeepEqual(field.got, field.want) {
						t.Error("whole public field differs:", field.name)
					}
				}
				t.Fatal("complete current public configuration differs")
			}
			if model.FileID != options.FileID || model.DomainID != source.archive.Domain || model.DomainName != "restored" || model.Generated != ".enkv/restored.generated.json" || len(model.Recipients) != 2 {
				t.Fatal("local identity or unassigned recipient lost")
			}
			parts, err := source.archive.SelectedParts()
			if err != nil {
				t.Fatal(err)
			}
			pins := map[string]configuration.Pin{}
			for _, part := range parts {
				switch part.Kind {
				case "configuration":
					if !bytes.Equal(part.Body, model.Observation.StoreConfiguration) {
						t.Fatal("exact selected configuration lost")
					}
				case "HEAD":
					if !bytes.Equal(part.Body, model.Observation.Head) {
						t.Fatal("exact selected HEAD lost")
					}
				case "value page":
					page, err := format.DecodeValueEntryPage(part.Body)
					if err != nil {
						t.Fatal(err)
					}
					for _, e := range page.Slots {
						if e != nil && e.ConfidentialityClass == contract.Secret {
							pins[e.Name] = configuration.Pin{Incarnation: e.Incarnation, Material: e.ValueState}
						}
					}
				}
			}
			for _, entry := range model.Entries {
				if entry.Secret {
					if entry.Retained == nil || *entry.Retained != pins[entry.Name] || len(entry.Sealed) != 0 {
						t.Fatal("exact retained identity lost or secret resealed")
					}
				}
			}
			second, err := ReconstructionConfiguration(context.Background(), projection, basis, ReconstructionConfigurationOptions{Name: "other", FileID: options.FileID})
			if err != nil || !reflect.DeepEqual(second.Public, model.Public) || second.Generated != ".enkv/other.generated.json" {
				t.Fatal("local name changed authenticated facts", err)
			}
			if projection.PartCount() != len(before) {
				t.Fatal("normalization changed selected owner set")
			}
			for i, want := range before {
				got, ok := projection.CopyPart(i)
				if !ok || !reflect.DeepEqual(got, want) {
					t.Fatal("normalization changed selected public/encrypted owner")
				}
			}
			projection.Close()
			clear(basis.Descriptor)
			if !bytes.Equal(model.Basis.Descriptor, expected.Basis.Descriptor) {
				t.Fatal("model borrowed caller trust backing")
			}
			for _, encoding := range []configuration.Format{configuration.JSON, configuration.YAML} {
				var editable, generated bytes.Buffer
				if err := configuration.EmitEditable(&editable, model, encoding); err != nil {
					t.Fatal(err)
				}
				if err := configuration.EmitGenerated(&generated, model); err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(editable.Bytes(), []byte("plugins")) || bytes.Contains(generated.Bytes(), []byte("plugins")) {
					t.Fatal("complete-loss reconstruction emitted local installation preferences")
				}
				dir := t.TempDir()
				if err := os.Mkdir(filepath.Join(dir, ".enkv"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, model.Generated), generated.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, "chosen-configuration")
				if err := os.WriteFile(path, editable.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
				pair, err := configuration.Capture(context.Background(), path, encoding)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := pair.Close(); err != nil {
						t.Error(err)
					}
				})
				again, err := configuration.Parse(context.Background(), pair)
				if err != nil {
					t.Fatal(err)
				}
				validated := validateInstalledConfiguration(context.Background(), again.Public)
				if !validated.Valid || !validated.Complete || !reflect.DeepEqual(validated.Configuration, model.Public) || !reflect.DeepEqual(again.Basis, model.Basis) || !reflect.DeepEqual(again.Observation, model.Observation) {
					t.Fatal("emitted pair changed complete current meaning")
				}
				for _, e := range again.Entries {
					if e.Secret && (e.Retained == nil || *e.Retained != pins[e.Name] || len(e.Sealed) != 0) {
						t.Fatal("emitted retained identity changed")
					}
				}
				h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
				calls := 0
				open := configurationReaderOpener(t, baseline, h, &calls)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				compared := compareConfiguration(ctx, contract.Hash([]byte("reconstructed pair comparison")), pair, nil, open)
				cancel()
				if compared.Verdict != contract.ComparisonMatch || compared.StateResult != contract.ReaderSuccess || len(compared.Diagnostics) != 0 || calls != 1 || compared.Observation == nil {
					t.Fatal("emitted pair did not match installed current state", compared.Verdict, compared.StateResult, compared.Diagnostics)
				}
				h.assertNoEffects(t)
			}
			baseline.assertUnchanged(t)
		})
	}
}

// full_only: false
func TestReconstructionConfigurationRequiresExistingCompleteTrustAndLocalIdentity(t *testing.T) {
	projection, basis, _ := configurationReconstructionProjection(t, "aws")
	valid := ReconstructionConfigurationOptions{Name: "restored", FileID: contract.Hash([]byte("new identity"))}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name       string
		ctx        context.Context
		projection *core.ReconstructionProjection
		basis      core.PublicBasis
		options    ReconstructionConfigurationOptions
	}{
		{"nil projection", context.Background(), nil, basis, valid},
		{"zero projection", context.Background(), &core.ReconstructionProjection{}, basis, valid},
		{"no basis", context.Background(), projection, core.PublicBasis{}, valid},
		{"malformed basis", context.Background(), projection, core.PublicBasis{Descriptor: []byte{1}}, valid},
		{"incomplete current basis", context.Background(), projection, core.PublicBasis{Control: []byte{1}}, valid},
		{"zero file", context.Background(), projection, basis, ReconstructionConfigurationOptions{Name: "restored"}},
		{"invalid name", context.Background(), projection, basis, ReconstructionConfigurationOptions{Name: "../restored", FileID: valid.FileID}},
		{"cancelled", cancelled, projection, basis, valid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if model, err := ReconstructionConfiguration(tc.ctx, tc.projection, tc.basis, tc.options); err == nil || model != nil {
				t.Fatal("invalid reconstruction handoff emitted a model")
			}
		})
	}
	_, body := installedarchive.LoadReader(t, "gcp")
	var saved struct{ Descriptor []byte }
	if err := json.Unmarshal(body, &saved); err != nil {
		t.Fatal(err)
	}
	if err := projection.CheckPublicBasis(context.Background(), core.PublicBasis{Descriptor: saved.Descriptor}); err == nil {
		t.Fatal("foreign control/store trust accepted")
	}
	projection.Close()
	if _, err := ReconstructionConfiguration(context.Background(), projection, basis, valid); !errors.Is(err, ErrReconstructionConfiguration) {
		t.Fatal("closed projection accepted", err)
	}
}

func assertReconstructedSharedRouting(t *testing.T, configuration contract.PublicConfiguration) {
	t.Helper()
	destinations := []string{"aws", "gcp", "github-environment", "github-organization", "github-repository"}
	want := map[contract.PublicRoutingKey][]string{
		{EntrySelector: contract.PublicDefaultRoute}:                     destinations,
		{EntrySelector: contract.PublicNamedEntry, EntryName: ""}:        {},
		{EntrySelector: contract.PublicNamedEntry, EntryName: "a/\n雪"}:   {},
		{EntrySelector: contract.PublicNamedEntry, EntryName: "encoded"}: destinations,
	}
	if configuration.Routing.State != contract.PublicPresent || len(configuration.Routing.Value) != len(want) {
		t.Fatal("reconstructed routing lost declared override presence", configuration.Routing)
	}
	for _, rule := range configuration.Routing.Value {
		expected, present := want[rule.Key]
		if !present || rule.Destinations.State != contract.PublicPresent || !slices.Equal(rule.Destinations.Value, expected) {
			t.Fatal("reconstructed routing changed inherited, empty or equal-default meaning", rule)
		}
		delete(want, rule.Key)
	}
	if len(want) != 0 {
		t.Fatal("reconstruction omitted a declared route", want)
	}
}
