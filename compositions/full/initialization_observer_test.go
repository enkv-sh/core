package compositionfull

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// configurationCurrentDescriptor reuses public key fixture material only. It
// supplies current proof-free assembly metadata; it does not migrate a signed
// archive or claim that any stored selection authenticates under this basis.
func configurationCurrentDescriptor(t testing.TB, d contract.GenesisDescriptorCore) contract.GenesisDescriptorCore {
	t.Helper()
	d.InterpretationID, d.TrustInterpretationID = contract.InterpretationID(), contract.TrustInterpretationID()
	d.CompatibilityID, d.CryptoSupportID = contract.CompatibilityID(), contract.CryptoSupportID()
	d.NormalSigning.Binding.Interpretation = d.InterpretationID
	if d.Recovery != nil {
		recovery := *d.Recovery
		recovery.Signing.Binding.Interpretation = d.InterpretationID
		d.Recovery = &recovery
	}
	body, err := contract.EncodeGenesisDescriptorCore(d)
	if err != nil {
		t.Fatal("current proof-free descriptor fixture", err)
	}
	owned, err := contract.DecodeGenesisDescriptorCore(body)
	if err != nil {
		t.Fatal("current proof-free descriptor fixture", err)
	}
	return owned
}

// This fixture proves the local pair/descriptor gate, not a selected ready
// genesis. Its public descriptor uses real canonical archive keys, updated to
// the installed assembly facts. Its structurally valid manifest has no Store
// backing; a sentinel opener prevents any claim of authenticated exact resume.
func initializationObservationSource(t *testing.T, format configuration.Format, edit func(map[string]any, map[string]any)) (configurationReaderSource, *configuration.Model, contract.GenesisDescriptorCore, []byte) {
	return initializationObservationConfiguredSource(t, format, nil, edit)
}

func initializationObservationConfiguredSource(t *testing.T, format configuration.Format, configure func(*contract.GenesisDescriptorCore, map[string]any, map[string]any), edit func(map[string]any, map[string]any)) (configurationReaderSource, *configuration.Model, contract.GenesisDescriptorCore, []byte) {
	t.Helper()
	source := configurationReaderPair(t, "gcp", format, func(editable, generated map[string]any) {
		editable["entries"] = map[string]any{}
		editable["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
		delete(generated, "canonical_records")
		generated["secrets"] = map[string]any{}
		basis := generated["public_basis"].(map[string]any)
		d, err := contract.DecodeGenesisDescriptorCore(basis["descriptor"].([]byte))
		if err != nil {
			t.Fatal(err)
		}
		d = configurationCurrentDescriptor(t, d)
		if configure != nil {
			configure(&d, editable, generated)
		}
		body, err := contract.EncodeGenesisDescriptorCore(d)
		if err != nil {
			t.Fatal("current proof-free descriptor fixture", err)
		}
		basis["descriptor"] = body
		if edit != nil {
			edit(editable, generated)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	m, err := configuration.Parse(ctx, source.pair)
	if err != nil || !m.Resolved || len(m.Entries) != 0 || !validResolvedConfiguration(ctx, m) {
		t.Fatal("resolved observation fixture did not pass ordinary validation", err)
	}
	// Every challenged pair must reach the missing relation gate. A failure at
	// old assembly admission or syntax is not evidence for this regression.
	if _, err := configurationReaderConfig(m); err != nil {
		t.Fatal("current-compatible descriptor fixture failed public basis admission", err)
	}
	d, err := contract.DecodeGenesisDescriptorCore(m.Basis.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	manifest := initializationObservationManifest(t, d, m.Basis.Descriptor)
	return source, m, d, manifest
}

func initializationObservationManifest(t *testing.T, d contract.GenesisDescriptorCore, body []byte) []byte {
	t.Helper()
	id := func(name string) contract.ID { return contract.Hash([]byte("observer local fixture " + name)) }
	normal, err := contract.NewBindingRequest(d.NormalSigning.Binding)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := contract.SigningBindingDigest(d.NormalSigning)
	if err != nil {
		t.Fatal(err)
	}
	m := contract.GenesisBootstrapManifestCore{DescriptorDigest: contract.Hash(body), RequestCoreDigest: id("original request"), GenesisPlanDigest: id("plan"),
		NormalBindingSubjectDigest: normal.Digest(), HeadCoreDigest: id("head"), HeadCoreLength: 349, ConditionalPlanDigest: id("conditional"),
		RecoveryMode: d.RecoveryMode(), Signers: []contract.GenesisSignerPlanRow{{TargetRole: contract.NormalSigningRole, SigningBindingDigest: signing}}}
	if d.Recovery != nil {
		basis, err := contract.NewK3BasisRequest(d.Recovery.Signing)
		if err != nil {
			t.Fatal(err)
		}
		signing, err := contract.SigningBindingDigest(d.Recovery.Signing)
		if err != nil {
			t.Fatal(err)
		}
		m.K3BasisSubjectDigest, m.K3InitChallengeCoreDigest = basis.Digest(), id("K3 challenge")
		m.Signers = append(m.Signers, contract.GenesisSignerPlanRow{TargetRole: contract.RecoverySignerTarget, SigningBindingDigest: signing})
	}
	bindings, err := d.BindingTable()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range bindings {
		digest, err := contract.PublicBindingDigest(row.Binding)
		if err != nil {
			t.Fatal(err)
		}
		m.PublicBindings = append(m.PublicBindings, contract.GenesisPublicBindingRow{SubjectKind: row.SubjectKind, SubjectID: row.SubjectID, BindingID: row.Binding.BindingID, PublicBindingDigest: digest})
		if row.SubjectID == d.AuthorityRecipientID || row.SubjectKind == contract.RecoveryWrapSubject {
			m.Probes = append(m.Probes, contract.InitProbePlanRow{ProbeID: id("private probe " + readerID(row.SubjectID)), SubjectKind: row.SubjectKind, SubjectID: row.SubjectID, BindingID: row.Binding.BindingID, PublicBindingDigest: digest})
		}
	}
	ref := func(kind contract.Kind, name string, index uint16) contract.Ref {
		return contract.Ref{Kind: kind, Format: contract.CanonicalSchema, Domain: d.DomainID, Object: id(name), Digest: id(name + " body"), Length: 1, Index: index}
	}
	for i := 0; i < (len(d.Recipients)+7)/8; i++ {
		m.Immutable = append(m.Immutable, ref(contract.RecipientKind, string(rune('a'+i))+" recipient page", uint16(i)))
	}
	m.Immutable = append(m.Immutable, ref(contract.AdministrativeIndexKind, "admin", 0), ref(contract.RequiredSupportKind, "receipt and output", 0), ref(contract.RequiredSupportKind, "receipt indexes", 1), ref(contract.RootKind, "root", 0))
	encoded, err := contract.EncodeGenesisBootstrapManifestCore(m)
	if err != nil {
		t.Fatal("structural manifest fixture", err)
	}
	return encoded
}

func initializationObservationManifestFile(t *testing.T, source configurationReaderSource, d contract.GenesisDescriptorCore, body []byte) {
	t.Helper()
	directory := filepath.Dir(source.generated)
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(initializationManifestPath(source.path, d.ManifestArtifactID), body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0555); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestInitializationObserverJoinsResolvedFactsBeforeResourceOpen(t *testing.T) {
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPublic, err := x509.MarshalPKIXPublicKey(&signing.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	encryption, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	encryptionPublic, err := x509.MarshalPKIXPublicKey(&encryption.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	changeID := func(name string) string { return readerID(contract.Hash([]byte("different observation " + name))) }
	role := func(generated map[string]any) map[string]any {
		return generated["domain"].(map[string]any)["authority"].(map[string]any)
	}
	firstRecipient := func(rows map[string]any) string {
		var names []string
		for name := range rows {
			names = append(names, name)
		}
		slices.Sort(names)
		if len(names) == 0 {
			t.Fatal("fixture has no additional recipient")
		}
		return names[0]
	}
	mutations := map[string]func(map[string]any, map[string]any){
		"exact":        nil,
		"authority-id": func(_ map[string]any, g map[string]any) { role(g)["id"] = changeID("authority") },
		"authority-binding-id": func(_ map[string]any, g map[string]any) {
			role(g)["encryption"].(map[string]any)["binding"].(map[string]any)["id"] = changeID("binding")
		},
		"authority-binding-incarnation": func(_ map[string]any, g map[string]any) {
			role(g)["encryption"].(map[string]any)["binding"].(map[string]any)["incarnation"] = changeID("binding incarnation")
		},
		"authority-binding-serial": func(_ map[string]any, g map[string]any) {
			role(g)["encryption"].(map[string]any)["binding"].(map[string]any)["serial"] = uint64(2)
		},
		"authority-binding-protection": func(_ map[string]any, g map[string]any) {
			b := role(g)["encryption"].(map[string]any)["binding"].(map[string]any)
			if b["protection"] == "hardware" {
				b["protection"] = "software"
			} else {
				b["protection"] = "hardware"
			}
		},
		"signing-public-key": func(_ map[string]any, g map[string]any) {
			role(g)["signing"].(map[string]any)["public_key"] = signingPublic
		},
		"encryption-public-key": func(_ map[string]any, g map[string]any) {
			role(g)["encryption"].(map[string]any)["public_key"] = encryptionPublic
		},
		"signing-selector": func(e, g map[string]any) {
			key := role(g)["signing"].(map[string]any)
			parts := strings.Split(key["selector"].(string), "/")
			parts[7] += "-different"
			key["selector"] = strings.Join(parts, "/")
			e["domain"].(map[string]any)["authority"].(map[string]any)["signing_key"] = key["selector"]
		},
		"authority-display-name": func(e, _ map[string]any) {
			e["domain"].(map[string]any)["authority"].(map[string]any)["display_name"] = "Different Authority"
		},
		"recipient-id": func(e map[string]any, g map[string]any) {
			rows := g["recipients"].(map[string]any)
			reference := firstRecipient(rows)
			rows[reference].(map[string]any)["id"] = changeID("recipient")
			e["recipients"].(map[string]any)[reference].(map[string]any)["id"] = changeID("recipient")
		},
		"recipient-binding-id": func(_ map[string]any, g map[string]any) {
			rows := g["recipients"].(map[string]any)
			rows[firstRecipient(rows)].(map[string]any)["encryption"].(map[string]any)["binding"].(map[string]any)["id"] = changeID("recipient binding")
		},
		"recipient-display-name": func(e, _ map[string]any) {
			rows := e["recipients"].(map[string]any)
			rows[firstRecipient(rows)].(map[string]any)["display_name"] = "Different Recipient"
		},
		"missing-recipient": func(e, g map[string]any) {
			rows := g["recipients"].(map[string]any)
			name := firstRecipient(rows)
			delete(rows, name)
			delete(e["recipients"].(map[string]any), name)
		},
		"manifest-descriptor":     nil,
		"manifest-normal-binding": nil,
		"manifest-normal-signer":  nil,
		"manifest-public-binding": nil,
		"manifest-probe-subject":  nil,
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			source, model, d, manifest := initializationObservationSource(t, configuration.JSON, mutation)
			manifest = initializationObservationDamageManifest(t, d, manifest, name)
			if name == "manifest-descriptor" {
				m, err := contract.DecodeGenesisBootstrapManifestCore(manifest)
				if err != nil {
					t.Fatal(err)
				}
				m.DescriptorDigest = contract.Hash([]byte("different descriptor"))
				manifest, err = contract.EncodeGenesisBootstrapManifestCore(m)
				if err != nil {
					t.Fatal(err)
				}
			}
			initializationObservationManifestFile(t, source, d, manifest)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			calls := 0
			result, err := observeConfigurationInitialization(ctx, source.path, model, func(context.Context, *configuration.Model) (initializationResources, error) {
				calls++
				return initializationResources{}, ErrCell
			})
			want := 0
			if name == "exact" {
				want = 1
			}
			if calls != want || err == nil || result.StateResult != contract.InitializationRefused || result.Payload != nil || len(result.Receipt) != 0 {
				t.Fatalf("resource open count=%d want=%d; state=%s", calls, want, result.StateResult)
			}
			source.assertUnchanged(t)
		})
	}
}

// full_only: false
func TestInitializationObservationBasisAllowsDraftOutputAndRepresentationChanges(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		source, model, d, manifest := initializationObservationSource(t, format, func(editable, generated map[string]any) {
			binding := contract.NormalOutputBinding{DestinationID: "unused", Destination: readerFixtureDestination(readerFixtureProfiles()[1])}
			body, err := contract.EncodeNormalOutputBinding(binding)
			if err != nil {
				t.Fatal("canonical draft output fixture refused", err)
			}
			configurationCanonicalBacking(generated, "outputs", "unused", body)
			editable["outputs"] = map[string]any{"destinations": map[string]any{"unused": map[string]any{
				"plugin": nil, "canonical": map[string]any{"settings": json.RawMessage(binding.Destination.CanonicalSettings)},
			}}, "routing": map[string]any{}}
		})
		if requirements, err := configurationPluginRequirements(model); err != nil || len(requirements) != 0 {
			t.Fatal("canonical draft output acquired an installation requirement", err)
		}
		if !validInitializationObservationBasis(model, d, manifest) {
			t.Fatal("draft output changed exact genesis descriptor relation")
		}
		if format == configuration.YAML {
			// Comments change the source digest, without asserting equality to
			// the original pre-delivery SetupDigest retained by Core.
			body := append([]byte("# operator comment\n"), source.editableBytes...)
			if err := os.Chmod(source.path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(source.path, body, 0444); err != nil {
				t.Fatal(err)
			}
			pair, err := configuration.Capture(t.Context(), source.path, format)
			if err != nil {
				t.Fatal(err)
			}
			changed, parseErr := configuration.Parse(t.Context(), pair)
			closeErr := pair.Close()
			if parseErr != nil || closeErr != nil || !validInitializationObservationBasis(changed, d, manifest) {
				t.Fatal("source comment changed exact genesis descriptor relation", parseErr, closeErr)
			}
		}
	}
}

// full_only: false
func TestInitializationObserverJoinsEnabledRecoveryBeforeResourceOpen(t *testing.T) {
	newSigning := func() []byte {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		body, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	newEncryption := func() []byte {
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			t.Fatal(err)
		}
		body, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	signing, otherSigning := newSigning(), newSigning()
	encryption, otherEncryption := newEncryption(), newEncryption()
	id := func(name string) contract.ID { return contract.Hash([]byte("Recovery observation fixture " + name)) }
	selector := func(original, suffix string) string {
		parts := strings.Split(original, "/")
		if len(parts) != 10 {
			t.Fatal("fixture lacks exact GCP key-version selector")
		}
		parts[7] = "observer" + suffix
		return strings.Join(parts, "/")
	}
	configure := func(d *contract.GenesisDescriptorCore, editable, generated map[string]any) {
		signingBinding := d.NormalSigning
		signingBinding.Role, signingBinding.BindingID = contract.RecoverySigningRole, id("signing binding")
		signingBinding.KeySelector = selector(signingBinding.KeySelector, "-recovery-signing")
		signingBinding.SPKI, signingBinding.Fingerprint = signing, contract.Hash(signing)
		signingBinding.Binding.Trust, signingBinding.Binding.PublicKey = id("trust"), signingBinding.Fingerprint
		signingBinding.Binding.ControlIncarnationID = id("control incarnation")
		var encryptionBinding contract.KMSBinding
		for _, row := range d.Recipients {
			if row.RecipientID == d.AuthorityRecipientID {
				encryptionBinding = *row.CurrentBinding
			}
		}
		encryptionBinding.BindingID, encryptionBinding.BindingIncarnationID = id("encryption binding"), id("encryption incarnation")
		encryptionBinding.KeySelector = selector(encryptionBinding.KeySelector, "-recovery-encryption")
		encryptionBinding.SPKI, encryptionBinding.Fingerprint = encryption, contract.Hash(encryption)
		d.Recovery = &contract.RecoveryBindings{RoleID: id("role"), Signing: signingBinding, KMS: encryptionBinding}
		editable["domain"].(map[string]any)["recovery"] = map[string]any{"enabled": true, "signing_key": signingBinding.KeySelector, "encryption_key": encryptionBinding.KeySelector}
		generated["domain"].(map[string]any)["recovery"] = map[string]any{"enabled": true,
			"signing": map[string]any{"selector": signingBinding.KeySelector, "public_key": signing}, "encryption": configurationReaderKey(encryptionBinding)}
	}
	recovery := func(generated map[string]any) map[string]any {
		return generated["domain"].(map[string]any)["recovery"].(map[string]any)
	}
	mutations := map[string]func(map[string]any, map[string]any){
		"exact": nil,
		"signing-public-key": func(_ map[string]any, g map[string]any) {
			recovery(g)["signing"].(map[string]any)["public_key"] = otherSigning
		},
		"encryption-public-key": func(_ map[string]any, g map[string]any) {
			recovery(g)["encryption"].(map[string]any)["public_key"] = otherEncryption
		},
		"binding-id": func(_ map[string]any, g map[string]any) {
			recovery(g)["encryption"].(map[string]any)["binding"].(map[string]any)["id"] = readerID(id("different binding"))
		},
		"binding-incarnation": func(_ map[string]any, g map[string]any) {
			recovery(g)["encryption"].(map[string]any)["binding"].(map[string]any)["incarnation"] = readerID(id("different incarnation"))
		},
		"binding-serial": func(_ map[string]any, g map[string]any) {
			recovery(g)["encryption"].(map[string]any)["binding"].(map[string]any)["serial"] = uint64(2)
		},
		"binding-protection": func(_ map[string]any, g map[string]any) {
			b := recovery(g)["encryption"].(map[string]any)["binding"].(map[string]any)
			if b["protection"] == "hardware" {
				b["protection"] = "software"
			} else {
				b["protection"] = "hardware"
			}
		},
		"signing-selector": func(e, g map[string]any) {
			key := recovery(g)["signing"].(map[string]any)
			key["selector"] = selector(key["selector"].(string), "-different")
			e["domain"].(map[string]any)["recovery"].(map[string]any)["signing_key"] = key["selector"]
		},
		"encryption-selector": func(e, g map[string]any) {
			key := recovery(g)["encryption"].(map[string]any)
			key["selector"] = selector(key["selector"].(string), "-different")
			e["domain"].(map[string]any)["recovery"].(map[string]any)["encryption_key"] = key["selector"]
		},
		"disabled-mode": func(e, g map[string]any) {
			e["domain"].(map[string]any)["recovery"] = map[string]any{"enabled": false}
			g["domain"].(map[string]any)["recovery"] = map[string]any{"enabled": false}
		},
		"K3-basis-digest":           nil,
		"manifest-normal-binding":   nil,
		"manifest-normal-signer":    nil,
		"manifest-public-binding":   nil,
		"manifest-probe-subject":    nil,
		"manifest-recovery-signer":  nil,
		"manifest-recovery-mode":    nil,
		"manifest-recovery-binding": nil,
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			source, model, d, manifest := initializationObservationConfiguredSource(t, configuration.JSON, configure, mutation)
			manifest = initializationObservationDamageManifest(t, d, manifest, name)
			if d.Recovery == nil {
				t.Fatal("enabled Recovery descriptor fixture lost its role")
			}
			if name == "K3-basis-digest" {
				m, err := contract.DecodeGenesisBootstrapManifestCore(manifest)
				if err != nil {
					t.Fatal(err)
				}
				m.K3BasisSubjectDigest = id("different K3 basis digest")
				manifest, err = contract.EncodeGenesisBootstrapManifestCore(m)
				if err != nil {
					t.Fatal(err)
				}
			}
			initializationObservationManifestFile(t, source, d, manifest)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			calls := 0
			result, err := observeConfigurationInitialization(ctx, source.path, model, func(context.Context, *configuration.Model) (initializationResources, error) {
				calls++
				return initializationResources{}, ErrCell
			})
			want := 0
			if name == "exact" {
				want = 1
			}
			if calls != want || err == nil || result.StateResult != contract.InitializationRefused || result.Payload != nil || len(result.Receipt) != 0 {
				t.Fatalf("resource open count=%d want=%d; state=%s", calls, want, result.StateResult)
			}
			source.assertUnchanged(t)
		})
	}
}

// Every damaged manifest remains structurally valid. Its failure must be the
// descriptor relation, before any credential or remote resource is opened.
func initializationObservationDamageManifest(t *testing.T, d contract.GenesisDescriptorCore, body []byte, damage string) []byte {
	t.Helper()
	if !strings.HasPrefix(damage, "manifest-") || damage == "manifest-descriptor" {
		return body
	}
	m, err := contract.DecodeGenesisBootstrapManifestCore(body)
	if err != nil {
		t.Fatal(err)
	}
	different := contract.Hash([]byte("coherent manifest damage " + damage))
	switch damage {
	case "manifest-normal-binding":
		m.NormalBindingSubjectDigest = different
	case "manifest-normal-signer":
		m.Signers[0].SigningBindingDigest = different
	case "manifest-recovery-signer":
		m.Signers[1].SigningBindingDigest = different
	case "manifest-recovery-mode":
		m.RecoveryMode = 0
		m.K3BasisSubjectDigest, m.K3InitChallengeCoreDigest = contract.ID{}, contract.ID{}
		m.Signers, m.Probes = m.Signers[:1], m.Probes[:1]
		m.PublicBindings = m.PublicBindings[:len(m.PublicBindings)-1]
	case "manifest-public-binding", "manifest-recovery-binding":
		index := 0
		if damage == "manifest-recovery-binding" {
			index = len(m.PublicBindings) - 1
		}
		old := m.PublicBindings[index]
		m.PublicBindings[index].BindingID = different
		m.PublicBindings[index].PublicBindingDigest = different
		for i := range m.Probes {
			if m.Probes[i].SubjectID == old.SubjectID && m.Probes[i].SubjectKind == old.SubjectKind {
				m.Probes[i].BindingID, m.Probes[i].PublicBindingDigest = different, different
			}
		}
	case "manifest-probe-subject":
		found := false
		for _, row := range m.PublicBindings {
			if row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID != d.AuthorityRecipientID {
				m.Probes[0].SubjectID, m.Probes[0].BindingID, m.Probes[0].PublicBindingDigest = row.SubjectID, row.BindingID, row.PublicBindingDigest
				found = true
				break
			}
		}
		if !found {
			t.Fatal("fixture lacks non-Authority probe subject")
		}
	default:
		t.Fatal("unknown manifest damage")
	}
	body, err = contract.EncodeGenesisBootstrapManifestCore(m)
	if err != nil {
		t.Fatal("damaged manifest is not structurally valid", err)
	}
	return body
}
