package configuration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

func successorID(n byte) contract.ID {
	var id contract.ID
	for i := range id {
		id[i] = n
	}
	return id
}

// These file tests use structurally valid public data, not an admitted Core
// proof. Core tests separately qualify the delivered candidate and its trust.
func successorFileFixture(t *testing.T, selected Format) (*Pair, *Model, ReplacementRequest, SuccessorMaterial) {
	t.Helper()
	setup := sourceSetupJSON
	if selected == YAML {
		setup = sourceSetupYAML
	}
	recipientKey := `{"selector":"` + sourceEncryptionSelector + `","public_key":"` + sourceEncryptionSPKI + `","binding":{"id":"` + sourceID4 + `","incarnation":"` + sourceID5 + `","serial":1,"protection":"software"}}`
	row := `{"id":"` + strings.Repeat("06", 32) + `","encryption":` + recipientKey + `}`
	generated := strings.Replace(sourceGeneratedJSON, `"recipients":{}`, `"recipients":{"unreferenced":`+row+`,"chosen":`+row+`}`, 1)
	envelope := base64.StdEncoding.EncodeToString(sourceEditEnvelope(t, "opaque"))
	generated = strings.Replace(generated, `"secrets":{}`, `"secrets":{"opaque":{"sealed":"`+envelope+`"}}`, 1)
	if selected == JSON {
		setup = strings.Replace(setup, `"recipients":{}`, `"recipients":{"chosen":{"id":"`+preparedSourceRecipientID+`","display_name":"pending-name","encryption_key":"`+sourceEncryptionSelector+`"}}`, 1)
	} else {
		setup = strings.Replace(setup, "recipients: {}", "# retained comment\nrecipients:\n  chosen:\n    id: \""+preparedSourceRecipientID+"\"\n    display_name: pending-name # retain this\n    encryption_key: "+sourceEncryptionSelector, 1)
	}
	pair := writePair(t, setup, generated, selected)
	m, err := Parse(t.Context(), pair)
	if err != nil {
		t.Fatal(err)
	}
	public, err := base64.StdEncoding.DecodeString(sourceSigningSPKI)
	if err != nil {
		t.Fatal(err)
	}
	encryption, err := base64.StdEncoding.DecodeString(sourceEncryptionSPKI)
	if err != nil {
		t.Fatal(err)
	}
	store, err := contract.StoreConfigurationID(contract.StoreConfiguration{Provider: m.Provider, ConstructionProfile: contract.StoreConstructionProfile, DomainID: m.DomainID, Region: m.Store.Region, Bucket: m.Store.Bucket, PrefixBeforeHEAD: m.Store.PrefixBeforeHEAD, ExpectedOwner: m.Store.ExpectedOwner})
	if err != nil {
		t.Fatal(err)
	}
	binding := contract.BindingSubject{Domain: m.DomainID, Coordinate: successorID(9), Store: store, Trust: successorID(8), PublicKey: contract.Hash(public), Interpretation: successorID(11), ControlIncarnationID: successorID(12), Epoch: 1}
	signing := contract.PublicSigningBinding{Schema: contract.CanonicalSchema, Role: contract.NormalSigningRole, Provider: contract.AWS, SigningProfile: contract.P256SigningProfile, BindingID: successorID(13), KeySelector: sourceSigningSelector, SPKI: public, Fingerprint: contract.Hash(public), Binding: binding}
	kek := contract.KMSBinding{BindingID: successorID(4), BindingIncarnationID: successorID(5), BindingSerial: 1, Provider: contract.AWS, WrapProfile: contract.RSAOAEPWrapProfile, ProtectionClass: contract.SoftwareProtection, KeySelector: sourceEncryptionSelector, SPKI: encryption, Fingerprint: contract.Hash(encryption)}
	control := contract.ControlCore{CurrentControl: contract.CurrentControl{CurrentControlFields: contract.CurrentControlFields{Schema: contract.CanonicalSchema, Profile: contract.MaterialCryptoProfile, DomainID: m.DomainID, Provider: contract.AWS, StoreID: store, CoordinateID: binding.Coordinate, NonBodyID: successorID(10), TrustInterpretationID: contract.TrustInterpretationID(), CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), AuthorityRecipientID: m.Authority.ID, AccessIncarnationID: successorID(14), AccessGeneration: 1}, NormalSigning: signing}, AuthorityKMSBinding: kek}
	token := contract.Token{Family: contract.AWS, Value: `"etag"`}
	core := format.HeadCore{Form: format.SuccessorHead, Domain: m.DomainID, Revision: successorID(20), PreviousRevision: successorID(21), PreviousDigest: successorID(22), PreviousToken: token, Root: format.Ref{Kind: format.RootKind, Format: format.Version, Domain: m.DomainID, Object: successorID(23), Digest: successorID(24), Length: 123}, Store: store, Trust: binding.Trust, Coordinate: binding.Coordinate, NonBody: control.NonBodyID, Interpretation: binding.Interpretation, Epoch: 1}
	body, err := format.EncodeHeadCore(core)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := contract.MatchHeadCondition(token)
	if err != nil {
		t.Fatal(err)
	}
	conditional, err := format.EncodeConditionalPlan(format.ConditionalPlan{Family: contract.AWS, Store: store, Coordinate: core.Coordinate, NonBody: core.NonBody, Condition: condition, HeadCore: contract.Hash(body), HeadCoreLength: uint32(len(body))})
	if err != nil {
		t.Fatal(err)
	}
	// Value intent: 70 + 119 + 6 name bytes + 32 membership bytes.
	// Complete intent adds 80 framing bytes and the 581-byte minimum registry.
	subject := contract.LifecycleSubject{OperationKind: contract.OperationApplyDeclaration, Operation: successorID(25), Request: successorID(26), Recipient: m.Authority.ID, KeyBinding: kek.BindingID, Fingerprint: kek.Fingerprint, BindingVersion: 1, IdentityPlan: contract.DigestLength{Digest: successorID(27), Length: 337}, HeadCore: contract.Hash(body), HeadCoreLength: uint32(len(body)), ConditionalPlan: contract.Hash(conditional), BeforeValueEntryCount: 1, AfterValueEntryCount: 1, BeforeRawBytes: 5, AfterRawBytes: 5, BeforeAccessRoot: successorID(28), AfterAccessRoot: successorID(29), BeforeMembershipCount: 1, AfterMembershipCount: 1, Normal: contract.NormalSection{Intent: contract.DigestLength{Digest: successorID(30), Length: 888}, PublicState: contract.DigestLength{Digest: successorID(31), Length: 187}, Union: contract.DescriptorVector{Digest: successorID(32), Length: 282, Count: 1}, Changed: 1}, Grant: contract.GrantSection{Grants: contract.DescriptorVector{Digest: successorID(33), Length: 61}}, Exclusion: contract.ExclusionSection{Exclusions: contract.DescriptorVector{Digest: successorID(34), Length: 65}, Retirements: contract.DescriptorVector{Digest: successorID(35), Length: 66}}}
	sig := []byte{0x30, 6, 2, 1, 1, 2, 1, 1}
	candidate, err := format.EncodeHead(format.Head{Core: core, AuthKind: format.LifecycleAuth, Subject: subject, K1: bytes.Clone(sig), AuthorizationSignature: bytes.Clone(sig)})
	if err != nil {
		t.Fatal(err)
	}
	successor := kek
	successor.BindingID = successorID(36)
	successor.BindingSerial = 2
	successor.KeySelector = strings.Replace(sourceEncryptionSelector, "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333", 1)
	request := ReplacementRequest{Target: ReplaceRecipient, RecipientReference: "chosen", EncryptionSelector: successor.KeySelector, Authorizer: contract.NormalSigningRole, MaterialSource: "authority"}
	material := SuccessorMaterial{Control: control, Recipients: []ReplacementRecipientFact{{RecipientID: successorID(6), Encryption: kek}, {RecipientID: successorID(6), Encryption: successor}}, Basis: m.Basis, RequestIdentity: successorID(37), SignedCandidate: candidate}
	return pair, m, request, material
}

// full_only: false
func TestSuccessorPairPreservesSourceAndUnrelatedGeneratedFacts(t *testing.T) {
	for _, encoding := range []Format{JSON, YAML} {
		t.Run(map[Format]string{JSON: "json", YAML: "yaml"}[encoding], func(t *testing.T) {
			pair, _, request, material := successorFileFixture(t, encoding)
			pair = pairWithPluginRequirements(t, pair, encoding)
			m, err := Parse(t.Context(), pair)
			if err != nil {
				t.Fatal(err)
			}
			beforeEditable, _ := io.ReadAll(io.NewSectionReader(pair.Editable, 0, pair.Editable.Size()))
			beforeGenerated, _ := io.ReadAll(io.NewSectionReader(pair.Generated, 0, pair.Generated.Size()))
			path := filepath.Join(t.TempDir(), "successor")
			output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, output)
			if output.Existing() != nil {
				t.Fatal("absent output selected observation")
			}
			result, err := output.Publish(t.Context(), material)
			if err != nil {
				t.Fatal(err)
			}
			if !output.Delivered() {
				t.Fatal("successful readback lacked delivery fact")
			}
			if result.Model.DomainName != m.DomainName || result.Model.Generated != generatedPath(m.DomainName) || result.Pair.Generated.OriginalPath() == pair.Generated.OriginalPath() {
				t.Fatal("successor changed local name or reused source satellite")
			}
			requirePreservedPlugins(t, maintenanceImageBytes(t, result.Pair.Editable))
			if err := output.CheckUnchanged(t.Context()); err != nil {
				t.Fatal("owned readback pins failed", err)
			}
			if result.Model.FileID != m.FileID || len(result.Model.GeneratedRecipients) != 2 || result.Model.GeneratedRecipients[0].Reference != "unreferenced" || result.Model.GeneratedRecipients[1].Reference != "chosen" {
				t.Fatal("complete generated order or FileID changed")
			}
			if result.Model.GeneratedRecipients[0].Encryption.Binding.Serial != 1 || result.Model.GeneratedRecipients[1].Encryption.Binding.Serial != 2 || result.Model.Recipients[0].DisplayName != "pending-name" {
				t.Fatal("untargeted row or pending display intent changed")
			}
			if !bytes.Equal(result.Model.Replacement.SignedCandidate, material.SignedCandidate) || result.Model.Replacement.RequestIdentity != material.RequestIdentity {
				t.Fatal("actual candidate correlation lost")
			}
			sourceEditable, err := os.ReadFile(pair.Editable.OriginalPath())
			if err != nil || !bytes.Equal(sourceEditable, beforeEditable) {
				t.Fatal("editable source changed", err)
			}
			sourceGenerated, err := os.ReadFile(pair.Generated.OriginalPath())
			if err != nil || !bytes.Equal(sourceGenerated, beforeGenerated) {
				t.Fatal("generated source changed", err)
			}
			generated, _ := io.ReadAll(io.NewSectionReader(result.Pair.Generated, 0, result.Pair.Generated.Size()))
			sourceSecret := beforeGenerated[bytes.Index(beforeGenerated, []byte(`"secrets":`)):bytes.Index(beforeGenerated, []byte(`,"public_basis":`))]
			if !bytes.Contains(generated, sourceSecret) {
				t.Fatal("opaque sealed proposal bytes changed")
			}
			if encoding == YAML {
				editable, _ := os.ReadFile(path)
				if !bytes.Contains(editable, []byte("# retained comment")) || !bytes.Contains(editable, []byte("# retain this")) {
					t.Fatal("unrelated comments changed")
				}
			}
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			again, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, again)
			if again.Existing() == nil {
				t.Fatal("existing exact output did not select observation")
			}
			if _, err := again.Publish(t.Context(), material); !errors.Is(err, ErrEdit) {
				t.Fatal("existing output allowed publication", err)
			}
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("close removed installed output", err)
			}
		})
	}
}

// full_only: false
func TestSuccessorOutputRefusesChangedArgumentsAndAliases(t *testing.T) {
	pair, _, request, material := successorFileFixture(t, JSON)
	path := filepath.Join(t.TempDir(), "successor")
	output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSourceOwner(t, output)
	if _, err := output.Publish(t.Context(), material); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{"target", "reference", "selector", "authorizer", "route"} {
		t.Run(damage, func(t *testing.T) {
			changed := request
			switch damage {
			case "target":
				changed.Target = ReplaceAuthority
				changed.RecipientReference = ""
			case "reference":
				changed.RecipientReference = "other"
			case "selector":
				changed.EncryptionSelector = sourceEncryptionSelector
			case "authorizer":
				changed.Authorizer = contract.RecoverySigningRole
			case "route":
				changed.MaterialSource = "recovery"
			}
			if o, err := PrepareSuccessorOutput(t.Context(), pair, path, changed); err == nil {
				if o != nil {
					closeSourceOwner(t, o)
				}
				t.Fatal("changed exact command accepted")
			}
		})
	}
	for _, alias := range []string{pair.Editable.OriginalPath(), pair.Generated.OriginalPath()} {
		if o, err := PrepareSuccessorOutput(t.Context(), pair, alias, request); err == nil {
			if o != nil {
				closeSourceOwner(t, o)
			}
			t.Fatal("source alias accepted")
		}
	}
	for _, kind := range []string{"hardlink", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			alias := path + "-" + kind
			var err error
			if kind == "hardlink" {
				err = os.Link(pair.Editable.OriginalPath(), alias)
			} else {
				err = os.Symlink(path, alias)
			}
			if err != nil {
				t.Fatal(err)
			}
			if o, err := PrepareSuccessorOutput(t.Context(), pair, alias, request); err == nil {
				if o != nil {
					closeSourceOwner(t, o)
				}
				t.Fatal("linked output accepted")
			}
		})
	}
}

// full_only: false
func TestSuccessorPairFailureRetainsInstalledNamesAndBlocksReuse(t *testing.T) {
	for _, damage := range []string{"write", "file-sync", "conflict", "directory-sync", "readback", "source-change"} {
		t.Run(damage, func(t *testing.T) {
			pair, _, request, material := successorFileFixture(t, JSON)
			path := filepath.Join(t.TempDir(), "successor")
			output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, output)
			operations := output.io
			sentinel := errors.New("controlled file failure")
			switch damage {
			case "write":
				output.io.write = func(*os.File, []byte) (int, error) { return 0, sentinel }
			case "file-sync":
				output.io.syncFile = func(*os.File) error { return sentinel }
			case "conflict":
				output.io.phase = func(phase string) error {
					if phase == "before-editable-install" {
						return os.WriteFile(path, []byte("concurrent"), 0600)
					}
					return nil
				}
			case "directory-sync":
				output.io.syncDir = func(dir string) error {
					if _, err := os.Stat(path); err == nil {
						return sentinel
					}
					return operations.syncDir(dir)
				}
			case "readback":
				output.io.readback = func(ctx context.Context, actual string, image *Image, predecessor bool) error {
					if actual == path {
						return sentinel
					}
					return operations.readback(ctx, actual, image, predecessor)
				}
			case "source-change":
				output.io.syncFile = func(f *os.File) error {
					if err := os.WriteFile(pair.Generated.OriginalPath(), []byte("changed"), 0600); err != nil {
						return err
					}
					return operations.syncFile(f)
				}
			}
			_, failure := output.Publish(t.Context(), material)
			if failure == nil || output.Delivered() {
				t.Fatal("failed delivery succeeded", failure)
			}
			if damage != "conflict" && damage != "source-change" && !errors.Is(failure, sentinel) {
				t.Fatal("publication lost cause", failure)
			}
			if _, err := output.Publish(t.Context(), material); !errors.Is(err, ErrEdit) {
				t.Fatal("failed publication allowed repeat", err)
			}
			published := damage == "conflict" || damage == "directory-sync" || damage == "readback"
			_, statErr := os.Stat(path)
			if published != (statErr == nil) {
				t.Fatal("wrong installed-name disposition", statErr)
			}
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			if published {
				captured, err := Capture(t.Context(), path, JSON)
				if captured != nil || !errors.Is(err, ErrPendingEdit) {
					t.Fatal("uncertain pair did not refuse capture", err)
				}
				if damage == "conflict" {
					if _, err := RecoverEdit(t.Context(), path, JSON); err == nil {
						t.Fatal("recovery overwrote foreign output")
					}
					if got, err := os.ReadFile(path); err != nil || string(got) != "concurrent" {
						t.Fatal("foreign bytes changed", err)
					}
				} else {
					if _, err := RecoverEdit(t.Context(), path, JSON); err != nil {
						t.Fatal("saved candidate did not recover", err)
					}
					observed, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
					if err != nil {
						t.Fatal(err)
					}
					if observed.Existing() == nil {
						t.Fatal("recovery lost exact observation")
					}
					if err := observed.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

// full_only: false
func TestSuccessorOutputTelemetryExcludesSourceAndSelectors(t *testing.T) {
	pair, _, request, material := successorFileFixture(t, JSON)
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
	output, err := PrepareSuccessorOutput(ctx, pair, filepath.Join(t.TempDir(), "sentinel-successor"), request)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSourceOwner(t, output)
	if _, err := output.Publish(ctx, material); err != nil {
		t.Fatal(err)
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 100))
	if len(records) == 0 {
		t.Fatal("missing source telemetry")
	}
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	body, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"sentinel-successor", sourceEncryptionSelector, request.EncryptionSelector, "pending-name"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatal("telemetry exposed configuration content")
		}
	}
}

// full_only: false
func TestSuccessorOutputRefusesTamperedPreservedScope(t *testing.T) {
	for _, damage := range []string{"editable-intent", "plugin-version", "inactive-row", "candidate", "metadata-source", "source-commitment", "unknown-field", "duplicate-field"} {
		t.Run(damage, func(t *testing.T) {
			pair, _, request, material := successorFileFixture(t, JSON)
			pair = pairWithPluginRequirements(t, pair, JSON)
			path := filepath.Join(t.TempDir(), "successor")
			output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
			if err != nil {
				t.Fatal(err)
			}
			readback, err := output.Publish(t.Context(), material)
			if err != nil {
				t.Fatal(err)
			}
			editable, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			generated, err := os.ReadFile(readback.Pair.Generated.OriginalPath())
			if err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "editable-intent":
				editable = bytes.Replace(editable, []byte("pending-name"), []byte("altered-name"), 1)
			case "plugin-version":
				requirePreservedPlugins(t, editable)
				editable = bytes.Replace(editable, []byte(sourcePluginRequirements), []byte(strings.Replace(sourcePluginRequirements, "1.2.3", "1.2.4", 1)), 1)
			case "inactive-row":
				index := bytes.Index(generated, []byte(`"unreferenced":`))
				if index < 0 {
					t.Fatal("inactive row missing")
				}
				generated = append(bytes.Clone(generated[:index]), bytes.Replace(generated[index:], []byte(`"serial":1`), []byte(`"serial":9`), 1)...)
			case "candidate":
				generated = bytes.Replace(generated, []byte(base64.StdEncoding.EncodeToString(material.SignedCandidate)), []byte("AQ=="), 1)
			case "source-commitment":
				identity, err := pairIdentity(pair)
				if err != nil {
					t.Fatal(err)
				}
				generated = bytes.Replace(generated, []byte(hex.EncodeToString(identity.Editable.Digest[:])), []byte(strings.Repeat("63", 32)), 1)
			case "metadata-source":
				oldLength := []byte(`"editable_length": ` + strconv.FormatInt(pair.Editable.Size(), 10))
				newLength := []byte(`"editable_length": ` + strconv.FormatInt(pair.Editable.Size()+1, 10))
				generated = bytes.Replace(generated, oldLength, newLength, 1)
			case "unknown-field":
				generated = bytes.Replace(generated, []byte(`"kind": "key-replacement/v1"`), []byte(`"kind": "key-replacement/v1","unknown":1`), 1)
			case "duplicate-field":
				generated = bytes.Replace(generated, []byte(`"target": "recipient"`), []byte(`"target": "recipient","target":"recipient"`), 1)
			}
			if damage != "editable-intent" {
				reference := readback.Model.Generated
				if err := os.WriteFile(filepath.Join(filepath.Dir(path), reference), generated, 0600); err != nil {
					t.Fatal(err)
				}
				editable = bytes.Replace(editable, []byte(readback.Model.Generated), []byte(reference), 1)
			}
			if err := os.WriteFile(path, editable, 0600); err != nil {
				t.Fatal(err)
			}
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			if observed, err := PrepareSuccessorOutput(t.Context(), pair, path, request); err == nil {
				if observed != nil {
					closeSourceOwner(t, observed)
				}
				t.Fatal("tampered exact output accepted")
			}
		})
	}
}

// full_only: false
func TestSuccessorOutputSourceMetadataIsInertForAnotherOutput(t *testing.T) {
	pair, _, request, material := successorFileFixture(t, YAML)
	path := filepath.Join(t.TempDir(), "successor")
	output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := output.Publish(t.Context(), material); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	nextSource, err := Capture(t.Context(), path, YAML)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSourceOwner(t, nextSource)
	nextModel, err := Parse(t.Context(), nextSource)
	if err != nil || nextModel.Replacement == nil {
		t.Fatal("source metadata lost", err)
	}
	nextIdentity, err := pairIdentity(nextSource)
	if err != nil {
		t.Fatal(err)
	}
	if nextModel.Replacement.Source == nextIdentity {
		t.Fatal("fixture does not contain historical source pins")
	}
	next, err := PrepareSuccessorOutput(t.Context(), nextSource, filepath.Join(t.TempDir(), "successor-next"), request)
	if err != nil {
		t.Fatal("historical source metadata controlled new output", err)
	}
	defer closeSourceOwner(t, next)
	if next.Existing() != nil {
		t.Fatal("source metadata selected observation")
	}
}

// full_only: false
func TestSuccessorOutputRefusesPartialPairsAndChangedSourceDependency(t *testing.T) {
	for _, damage := range []string{"unrelated-pair", "missing-generated", "changed-source-generated"} {
		t.Run(damage, func(t *testing.T) {
			pair, _, request, material := successorFileFixture(t, JSON)
			path := filepath.Join(t.TempDir(), "successor")
			if damage == "unrelated-pair" {
				body, err := os.ReadFile(pair.Editable.OriginalPath())
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
				if err != nil {
					t.Fatal(err)
				}
				result, err := output.Publish(t.Context(), material)
				if err != nil {
					t.Fatal(err)
				}
				generated := result.Pair.Generated.OriginalPath()
				if err := output.Close(); err != nil {
					t.Fatal(err)
				}
				if damage == "missing-generated" {
					if err := os.Remove(generated); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.WriteFile(pair.Generated.OriginalPath(), []byte("changed"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if observed, err := PrepareSuccessorOutput(t.Context(), pair, path, request); err == nil {
				if observed != nil {
					closeSourceOwner(t, observed)
				}
				t.Fatal("partial/changed pair accepted")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("refusal removed output", err)
			}
		})
	}
}

// full_only: false
func TestSuccessorOutputRefusesChangedOutputDirectory(t *testing.T) {
	for _, damage := range []string{"replacement", "symlink", "mode"} {
		t.Run(damage, func(t *testing.T) {
			pair, _, request, material := successorFileFixture(t, JSON)
			dir := filepath.Join(filepath.Dir(pair.Editable.OriginalPath()), "delivery")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "successor")
			output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, output)
			switch damage {
			case "replacement", "symlink":
				moved := dir + "-old"
				if err := os.Rename(dir, moved); err != nil {
					t.Fatal(err)
				}
				if damage == "replacement" {
					if err := os.Mkdir(dir, 0700); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Symlink(moved, dir); err != nil {
						t.Fatal(err)
					}
				}
			case "mode":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if delivered, err := output.Publish(t.Context(), material); err == nil || delivered != nil {
				t.Fatal("changed delivery directory accepted")
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("changed directory received output", err)
			}
		})
	}
	pair, _, request, _ := successorFileFixture(t, JSON)
	alias := filepath.Join(filepath.Dir(pair.Editable.OriginalPath()), "alias")
	if err := os.Symlink(filepath.Dir(pair.Editable.OriginalPath()), alias); err != nil {
		t.Fatal(err)
	}
	if output, err := PrepareSuccessorOutput(t.Context(), pair, filepath.Join(alias, "successor"), request); err == nil {
		if output != nil {
			closeSourceOwner(t, output)
		}
		t.Fatal("symlink delivery directory accepted")
	}
}

// full_only: false
func TestSuccessorOutputCancellationRetainsPublishedPair(t *testing.T) {
	pair, _, request, material := successorFileFixture(t, JSON)
	path := filepath.Join(t.TempDir(), "successor")
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if output, err := PrepareSuccessorOutput(canceled, pair, path, request); !errors.Is(err, context.Canceled) || output != nil {
		t.Fatal("capture cancellation cause lost", err)
	}
	output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSourceOwner(t, output)
	if delivered, err := output.Publish(canceled, material); !errors.Is(err, context.Canceled) || delivered != nil {
		t.Fatal("publication cancellation cause lost", err)
	}
	active, cancel := context.WithCancel(t.Context())
	defer cancel()
	operations := output.io
	output.io.syncDir = func(dir string) error {
		if _, err := os.Stat(path); err == nil {
			cancel()
		}
		return operations.syncDir(dir)
	}
	if delivered, err := output.Publish(active, material); !errors.Is(err, context.Canceled) || delivered != nil {
		t.Fatal("late cancellation did not block delivery", err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("late cancellation removed published pair", err)
	}
}

// full_only: false
func TestSuccessorOutputChecksBothSourceAndDeliveredPins(t *testing.T) {
	for _, phase := range []string{"absent-conflict", "published-change", "existing-change"} {
		t.Run(phase, func(t *testing.T) {
			pair, _, request, material := successorFileFixture(t, JSON)
			path := filepath.Join(t.TempDir(), "successor")
			output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, output)
			if err := output.CheckUnchanged(t.Context()); err != nil {
				t.Fatal("unchanged absent admission refused", err)
			}
			if phase != "absent-conflict" {
				if _, err := output.Publish(t.Context(), material); err != nil {
					t.Fatal(err)
				}
				if err := output.CheckUnchanged(t.Context()); err != nil {
					t.Fatal("unchanged published admission refused", err)
				}
				if phase == "existing-change" {
					if err := output.Close(); err != nil {
						t.Fatal(err)
					}
					output, err = PrepareSuccessorOutput(t.Context(), pair, path, request)
					if err != nil {
						t.Fatal(err)
					}
					defer closeSourceOwner(t, output)
					if err := output.CheckUnchanged(t.Context()); err != nil {
						t.Fatal("unchanged observed output refused", err)
					}
				}
			}
			if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := output.CheckUnchanged(t.Context()); err == nil {
				t.Fatal("changed output pins accepted")
			}
		})
	}
}

// full_only: false
func TestSuccessorOutputPreflightRetainsProtectedTargetOnSourceRefusal(t *testing.T) {
	pair, _, request, material := successorFileFixture(t, JSON)
	path := filepath.Join(t.TempDir(), "successor")
	output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := output.Publish(t.Context(), material); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{"missing-source", "bad-source", "wrong-target", "wrong-reference"} {
		t.Run(damage, func(t *testing.T) {
			capture, err := CaptureSuccessorOutput(t.Context(), path, JSON)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, capture)
			if target, known := capture.Target(); !known || target != ReplaceRecipient {
				t.Fatal("protected target was not fixed before source work")
			}
			source := pair
			changed := request
			switch damage {
			case "missing-source":
				source = nil
			case "bad-source":
				raw := filepath.Join(filepath.Dir(path), "malformed-source")
				if err := os.WriteFile(raw, []byte(`{"invalid":true}`), 0600); err != nil {
					t.Fatal(err)
				}
				image, err := captureFileForSuccessorTest(t, raw)
				if err != nil {
					t.Fatal(err)
				}
				source = &Pair{Editable: image, Format: JSON}
			case "wrong-target":
				changed.Target = ReplaceAuthority
				changed.RecipientReference = ""
			case "wrong-reference":
				changed.RecipientReference = "unreferenced"
			}
			prepared, err := PrepareSuccessorOutputFromCapture(t.Context(), source, capture, changed)
			var refusal *SuccessorOutputRefusal
			if prepared != nil || !errors.As(err, &refusal) || refusal.Target != ReplaceRecipient {
				t.Fatal("source/refusal lost protected target", err)
			}
		})
	}
}

func captureFileForSuccessorTest(t *testing.T, path string) (*Image, error) {
	t.Helper()
	image, err := capture(t.Context(), path, MaxPairBytes)
	if err == nil {
		t.Cleanup(func() {
			if err := image.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	return image, err
}

// full_only: false
func TestSuccessorOutputRefusesSharedSatelliteBeforeWriterOwnership(t *testing.T) {
	for _, alias := range []string{"same-directory", "generated-hardlink"} {
		t.Run(alias, func(t *testing.T) {
			pair, model, request, _ := successorFileFixture(t, JSON)
			path := filepath.Join(filepath.Dir(pair.Editable.OriginalPath()), "other-editable")
			if alias == "generated-hardlink" {
				path = filepath.Join(t.TempDir(), "successor")
				if err := os.Mkdir(filepath.Join(filepath.Dir(path), ".enkv"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(pair.Generated.OriginalPath(), filepath.Join(filepath.Dir(path), generatedPath(model.DomainName))); err != nil {
					t.Fatal(err)
				}
			}
			output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
			if output != nil || !errors.Is(err, ErrEdit) {
				t.Fatal("aliased stable satellite admitted", err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("alias admission wrote editable output", err)
			}
			if _, err := os.Lstat(coordinationPath(path, ".enkv-locks")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("alias acquired writer ownership", err)
			}
		})
	}
}

// full_only: false
func TestSuccessorExistingOutputObservationRemainsReadOnly(t *testing.T) {
	pair, _, request, material := successorFileFixture(t, JSON)
	path := filepath.Join(t.TempDir(), "successor")
	output, err := PrepareSuccessorOutput(t.Context(), pair, path, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := output.Publish(t.Context(), material); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	type capturedFile struct {
		mode os.FileMode
		body string
	}
	snapshot := func() map[string]capturedFile {
		t.Helper()
		files := map[string]capturedFile{}
		for _, root := range []string{filepath.Dir(pair.Editable.OriginalPath()), filepath.Dir(path)} {
			if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				body := []byte(nil)
				if info.Mode().IsRegular() {
					body, err = os.ReadFile(path)
				}
				files[path] = capturedFile{info.Mode(), string(body)}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		return files
	}
	for _, root := range []string{filepath.Dir(pair.Editable.OriginalPath()), filepath.Dir(path)} {
		if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			mode := os.FileMode(0400)
			if info.IsDir() {
				mode = 0500
			}
			t.Cleanup(func() {
				if err := os.Chmod(path, info.Mode().Perm()); err != nil {
					t.Error(err)
				}
			})
			return os.Chmod(path, mode)
		}); err != nil {
			t.Fatal(err)
		}
	}
	readonly, err := Capture(t.Context(), pair.Editable.OriginalPath(), JSON)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSourceOwner(t, readonly)
	before := snapshot()
	observed, err := PrepareSuccessorOutput(t.Context(), readonly, path, request)
	if err != nil {
		t.Fatal(err)
	}
	if observed.editor != nil || observed.Existing() == nil {
		t.Fatal("existing output acquired a writer")
	}
	if err := observed.CheckUnchanged(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := observed.Publish(t.Context(), material); !errors.Is(err, ErrEdit) {
		t.Fatal("existing output allowed mutation", err)
	}
	if err := observed.Close(); err != nil {
		t.Fatal(err)
	}
	after := snapshot()
	if len(after) != len(before) {
		t.Fatal("observation changed file inventory")
	}
	for path, want := range before {
		if after[path] != want {
			t.Fatal("observation changed source/output bytes or modes")
		}
	}
}
