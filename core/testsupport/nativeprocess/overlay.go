package nativeprocess

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

//go:embed runtime.go.txt
var runtimeTemplate string

var runtimeSource = strings.ReplaceAll(runtimeTemplate, "NATIVE_CAPTURE_MAX_BYTES", strconv.Itoa(MaxCaptureBytes))

//go:embed recovery.go.txt
var recoverySource string

//go:embed sourcekind.go.txt
var sourceKindSource string

type Source struct{ Target, OriginalSHA256, Replacement, ReplacementSHA256 string }
type Overlay struct{ Path, Manifest, SHA256, ManifestSHA256 string }

// BuildOverlay adds local observation, bounded transport and Store-return faults,
// and a plaintext equality observer before the reconstruction owner discards it.
func BuildOverlay(root, directory string) (Overlay, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(directory) {
		return Overlay{}, errors.New("native overlay requires absolute paths")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return Overlay{}, err
	}
	mapping := map[string]string{}
	var sources []Source
	save := func(target string, original, replacement []byte) error {
		identity := sha256.Sum256([]byte(target))
		path := filepath.Join(directory, hex.EncodeToString(identity[:])+filepath.Ext(target))
		if err := os.WriteFile(path, replacement, 0600); err != nil {
			return err
		}
		mapping[target] = path
		sources = append(sources, Source{Target: target, OriginalSHA256: digest(original), Replacement: path, ReplacementSHA256: digest(replacement)})
		return nil
	}
	const storeResultDefer = "defer func() { loseReply, captureErr := nativeProcessStoreResult(nativeStore, uint8(result.Status), uint8(result.Reason), result.NotSent); if result.Status == contract.WriteAcknowledged { if captureErr != nil { result = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonConstruction, NotSent: result.NotSent} } else if loseReply { result = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport} } } }()"
	edits := []struct{ path, old, next string }{
		{"compositions/full/manifest_file.go", "\tif !r.preflight() {\n", "\tif err := nativeProcessManifestHandoff(ctx); err != nil { r.failIO(ManifestPreflightStage, err); return r.facts }\n\tif !r.preflight() {\n"},
		{"compositions/aws/materialization.go", "route, err := provider.NewKeyAccess(", "if err := nativeProcessConstruction(\"key-access\", admission.Recipient.Binding.KeySelector); err != nil { return nil, err }\n\t\troute, err := provider.NewKeyAccess("},
		{"compositions/gcp/materialization.go", "route, err := provider.NewKeyAccess(", "if err := nativeProcessConstruction(\"key-access\", admission.Recipient.Binding.KeySelector); err != nil { return nil, err }\n\t\troute, err := provider.NewKeyAccess("},
		{"compositions/configuration/write.go", "remove: os.Remove, phase: func(string) error { return nil }, freeBytes: availableEditBytes,", "remove: os.Remove, phase: nativeProcessLocalEditPhase, freeBytes: availableEditBytes,"},
		{"compositions/configuration/write.go", "func (s *EditSession) unknown(c *EditCandidate, cause error) *UnknownEdit {", "func (s *EditSession) unknown(c *EditCandidate, cause error) *UnknownEdit {\n\tnativeProcessLocalEditUnknown()"},
		{"compositions/configuration/write.go", "func (o *EditObservation) Close() error {", "func (o *EditObservation) Close() (resultErr error) {\n\tnativeOwned := nativeProcessLocalEditOwned(o)\n\tdefer func() { nativeProcessLocalEditDisposed(nativeOwned, resultErr) }()"},
		{"compositions/full/configuration_keys_aws.go", "anchor, err := awsprovider.NewPublicSigningAnchor(", "if err := nativeProcessConstruction(\"signing-metadata\", selector); err != nil { return nil, err }\n\t\t\t\tanchor, err := awsprovider.NewPublicSigningAnchor("},
		{"compositions/full/configuration_keys_aws.go", "public, fingerprint, protection, result := awsprovider.ResolveEncryptionKey(", "if err := nativeProcessConstruction(\"encryption-metadata\", selector); err != nil { return nil, err }\n\t\t\t\tpublic, fingerprint, protection, result := awsprovider.ResolveEncryptionKey("},
		{"compositions/full/configuration_keys_aws.go", "return awsprovider.NewTrust(", "if err := nativeProcessConstruction(\"signer\", binding.KeySelector); err != nil { return nil, err }\n\t\t\t\treturn awsprovider.NewTrust("},
		{"compositions/full/configuration_keys_aws.go", "return awsprovider.NewKeyAccess(", "if err := nativeProcessConstruction(\"key-access\", binding.KeySelector); err != nil { return nil, err }\n\t\t\t\treturn awsprovider.NewKeyAccess("},
		{"compositions/full/configuration_keys_aws.go", "return awsprovider.NewPublicEncryptionQualifier(", "if err := nativeProcessConstruction(\"public-qualifier\", binding.KeySelector); err != nil { return nil, err }\n\t\t\t\treturn awsprovider.NewPublicEncryptionQualifier("},
		{"compositions/full/configuration_keys_gcp.go", "anchor, err := gcpprovider.NewPublicSigningAnchor(", "if err := nativeProcessConstruction(\"signing-metadata\", selector); err != nil { return nil, err }\n\t\t\t\tanchor, err := gcpprovider.NewPublicSigningAnchor("},
		{"compositions/full/configuration_keys_gcp.go", "public, fingerprint, protection, result := gcpprovider.ResolveEncryptionKey(", "if err := nativeProcessConstruction(\"encryption-metadata\", selector); err != nil { return nil, err }\n\t\t\t\tpublic, fingerprint, protection, result := gcpprovider.ResolveEncryptionKey("},
		{"compositions/full/configuration_keys_gcp.go", "return gcpprovider.NewTrust(", "if err := nativeProcessConstruction(\"signer\", binding.KeySelector); err != nil { return nil, err }\n\t\t\t\treturn gcpprovider.NewTrust("},
		{"compositions/full/configuration_keys_gcp.go", "return gcpprovider.NewKeyAccess(", "if err := nativeProcessConstruction(\"key-access\", binding.KeySelector); err != nil { return nil, err }\n\t\t\t\treturn gcpprovider.NewKeyAccess("},
		{"compositions/full/configuration_keys_gcp.go", "return gcpprovider.NewPublicEncryptionQualifier(", "if err := nativeProcessConstruction(\"public-qualifier\", binding.KeySelector); err != nil { return nil, err }\n\t\t\t\treturn gcpprovider.NewPublicEncryptionQualifier("},
		{"providers/aws/store.go", "func (s *Store) write(ctx context.Context, key string, token contract.Token, body []byte, cas bool) contract.WriteResult {", "func (s *Store) write(ctx context.Context, key string, token contract.Token, body []byte, cas bool) (result contract.WriteResult) {\n\tnativeConditionKind, nativeConditionValue := \"absent\", []byte(nil)\n\tif cas { nativeConditionKind, nativeConditionValue = \"match\", []byte(token.Value) }\n\tctx, nativeStore := nativeProcessBeginStore(ctx, key, \"store-write\", nativeConditionKind, nativeConditionValue)\n\t" + storeResultDefer + "\n"},
		{"providers/gcp/store.go", "func (s *Store) write(ctx context.Context, key string, generation int64, body []byte) contract.WriteResult {", "func (s *Store) write(ctx context.Context, key string, generation int64, body []byte) (result contract.WriteResult) {\n\tnativeConditionKind, nativeConditionValue := \"absent\", []byte(nil)\n\tif generation != 0 { nativeConditionKind, nativeConditionValue = \"match\", []byte(strconv.FormatInt(generation, 10)) }\n\tctx, nativeStore := nativeProcessBeginStore(ctx, key, \"store-write\", nativeConditionKind, nativeConditionValue)\n\t" + storeResultDefer + "\n"},
		{"providers/aws/store.go", "\t\tkeyLimit(s.config.Prefix, s.config.Domain, key) == 0 || token.Family != contract.AWS || !token.Valid() {\n\t\treturn contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}\n\t}\n", "\t\tkeyLimit(s.config.Prefix, s.config.Domain, key) == 0 || token.Family != contract.AWS || !token.Valid() {\n\t\treturn contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}\n\t}\n\tctx, nativeStore := nativeProcessBeginStore(ctx, key, \"store-delete\", \"match\", []byte(token.Value))\n\t" + storeResultDefer + "\n"},
		{"providers/gcp/store.go", "\tif err != nil || generation <= 0 || strconv.FormatInt(generation, 10) != token.Value {\n\t\treturn contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}\n\t}\n\tctx, ok := s.config.Client.begin(ctx, s.host, maxJSON)", "\tif err != nil || generation <= 0 || strconv.FormatInt(generation, 10) != token.Value {\n\t\treturn contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}\n\t}\n\tctx, nativeStore := nativeProcessBeginStore(ctx, key, \"store-delete\", \"match\", []byte(token.Value))\n\t" + storeResultDefer + "\n\tctx, ok := s.config.Client.begin(ctx, s.host, maxJSON)"},
		{"providers/gcp/transport.go", "private := httptransport.PrivateContext(ctx)", "private := httptransport.PrivateContext(ctx)\n\tif scope, ok := ctx.Value(nativeProcessStoreKey{}).(*nativeProcessStoreScope); ok { private = context.WithValue(private, nativeProcessStoreKey{}, scope) }"},
		{"compositions/full/cmd/enkv/apply.go", "ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)", "base, stop := nativeProcessCommandBase()\n\tdefer stop()\n\tctx, cancel := context.WithTimeout(base, 5*time.Minute)"},
		{"compositions/full/cmd/enkv/secret_access.go", "func runEnvelopeRekey(args []string, out, diagnostic io.Writer) int {\n\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)", "func runEnvelopeRekey(args []string, out, diagnostic io.Writer) int {\n\tbase, stop := nativeProcessCommandBase()\n\tdefer stop()\n\tctx, cancel := context.WithTimeout(base, 5*time.Minute)"},
		{"compositions/full/cmd/enkv/secret_access.go", "func runRecipientRetirement(args []string, out, diagnostic io.Writer) int {\n\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)", "func runRecipientRetirement(args []string, out, diagnostic io.Writer) int {\n\tbase, stop := nativeProcessCommandBase()\n\tdefer stop()\n\tctx, cancel := context.WithTimeout(base, 5*time.Minute)"},
		{"providers/aws/transport.go", "r.GetBody = nil", "nativeRole, nativeErr := nativeProcessPrepareAWS(r)\n\tif nativeErr != nil { return nil, nativeErr }\n\tr.GetBody = nil"},
		{"providers/aws/transport.go", "resp, err := t.next.RoundTrip(r)", "resp, err := nativeProcessRoundTrip(t.next, r, nativeRole)"},
		{"providers/gcp/transport.go", "response, err := s.base.RoundTrip(frozen)", "response, err := nativeProcessRoundTrip(s.base, frozen, nativeProcessGCPRole(frozen))"},
		{"providers/aws/credentials/credentials_default.go", "return installed.Credentials, nil", "if sourceErr := nativeProcessAWSDefaultEndpoints(ctx, installed.BaseEndpoint, installed.ConfigSources); sourceErr != nil { return nil, sourceErr }\n\treturn nativeProcessStandardCredentials{source: installed.Credentials}, nil"},
		{"providers/gcp/credentials/credentials_default.go", "universe, err := selected.UniverseDomain(ctx)", "if sourceErr := nativeProcessObserveADC(selected.JSON()); sourceErr != nil { return nil, sourceErr }\n\tuniverse, err := selected.UniverseDomain(ctx)"},
		{"crypto/reconstruction_verifier.go", "plain, _, code := openConsumerValue(ctx, a, route, selected, index, packetContext)", "if observed, code := nativeProcessObserveRecovery(ctx, a, route, selected); observed { return code }\n\tplain, _, code := openConsumerValue(ctx, a, route, selected, index, packetContext)"},
		{"crypto/reconstruction_verifier.go", "\treturn sessionCancellation(ctx, a)\n}\n\nfunc reconstructionSelectionMatches", "\tnativeProcessPlaintext(selected.Entry.Name, plain)\n\treturn sessionCancellation(ctx, a)\n}\n\nfunc reconstructionSelectionMatches"},
		{"compositions/full/cmd/enkv/main.go", "func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }", "func main() { code := run(os.Args[1:], os.Stdout, os.Stderr); nativeProcessFinish(code); os.Exit(code) }"},
	}
	originals := map[string][]byte{}
	replacements := map[string]string{}
	for _, edit := range edits {
		target := filepath.Join(root, filepath.FromSlash(edit.path))
		body, ok := replacements[target]
		if !ok {
			original, err := os.ReadFile(target)
			if err != nil {
				return Overlay{}, err
			}
			originals[target] = original
			body = string(original)
		}
		if strings.Count(body, edit.old) != 1 {
			return Overlay{}, errors.New("native overlay source anchor differs")
		}
		replacements[target] = strings.Replace(body, edit.old, edit.next, 1)
	}
	targets := make([]string, 0, len(replacements))
	for target := range replacements {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	for _, target := range targets {
		replacement := replacements[target]
		if target == filepath.Join(root, "providers", "aws", "credentials", "credentials_default.go") {
			replacement += `
type nativeProcessStandardCredentials struct { source aws.CredentialsProvider }
func (p nativeProcessStandardCredentials) Retrieve(ctx context.Context) (aws.Credentials, error) {
	value, err := p.source.Retrieve(ctx)
	if err != nil { return value, err }
	if err := nativeProcessObserveAWS(value.Source, value.CanExpire, value.SessionToken == ""); err != nil { return aws.Credentials{}, err }
	return value, nil
}
`
		}
		if err := save(target, originals[target], []byte(replacement)); err != nil {
			return Overlay{}, err
		}
	}
	descriptors := "\nfunc nativeProcessOutputDescriptor(provider string) []byte {\nswitch provider {\n"
	for _, plugin := range []struct{ provider, name, pkg string }{{"aws", "aws-secrets-manager", "awssm"}, {"gcp", "gcp-secret-manager", "gcpsm"}} {
		module := filepath.Join(filepath.Dir(root), "enkv-extensions", "plugins", "outputs", plugin.name)
		descriptorPath := filepath.Join(module, "cmd", "enkv-output-"+plugin.name, "plugin.json")
		descriptor, err := os.ReadFile(descriptorPath)
		if err != nil || !json.Valid(descriptor) {
			return Overlay{}, errors.New("output observer descriptor refused")
		}
		if err := save(descriptorPath, descriptor, descriptor); err != nil {
			return Overlay{}, err
		}
		descriptors += "case " + strconv.Quote(plugin.provider) + ": return []byte(" + strconv.Quote(string(descriptor)) + ")\n"
		path := filepath.Join(module, "internal", plugin.pkg, "discovery.go")
		original, err := os.ReadFile(path)
		if err != nil {
			return Overlay{}, err
		}
		body := string(original)
		var edits [][2]string
		if plugin.provider == "aws" {
			edits = [][2]string{
				{"return installed.Credentials, nil", "if err := nativeProcessOutputAWSEndpoints(ctx, installed.BaseEndpoint, installed.ConfigSources); err != nil { return nil, err }; return installed.Credentials, nil"},
				{"expiry := time.Time{}", "if err := nativeProcessObserveOutputAWS(value.Source, value.CanExpire, value.SessionToken == \"\"); err != nil { return nil, time.Time{}, err }; expiry := time.Time{}"},
			}
		} else {
			edits = [][2]string{
				{"selected, err := authcredentials.DetectDefault(", "client, clientErr := nativeProcessOutputCredentialClient(&http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}); if clientErr != nil { return credentialSource{}, clientErr }; selected, err := authcredentials.DetectDefault("},
				{"Client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},", "Client: client,"},
				{"return credentialSource{selected, quota}, nil", "if err := nativeProcessObserveOutputADC(selected.JSON(), quota); err != nil { return credentialSource{}, err }; return credentialSource{selected, quota}, nil"},
			}
		}
		for _, edit := range edits {
			if strings.Count(body, edit[0]) != 1 {
				return Overlay{}, errors.New("output credential observer anchor differs")
			}
			body = strings.Replace(body, edit[0], edit[1], 1)
		}
		if err := save(path, original, []byte(body)); err != nil {
			return Overlay{}, err
		}
		target := filepath.Join(module, "internal", plugin.pkg, "nativeprocess_observer.go")
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			return Overlay{}, errors.New("output credential observer target exists")
		}
		observer := strings.Replace(runtimeSource, "package nativeprocessruntime", "package "+plugin.pkg, 1) + sourceKindSource
		if err := save(target, nil, []byte(observer)); err != nil {
			return Overlay{}, err
		}
	}
	descriptors += "}; return nil\n}\n"
	for _, unit := range []struct{ directory, pkg string }{{"providers/aws", "awsprovider"}, {"providers/gcp", "gcp"}, {"providers/aws/credentials", "credentials"}, {"providers/gcp/credentials", "credentials"}, {"crypto", "crypto"}, {"compositions/aws", "compositionaws"}, {"compositions/gcp", "compositiongcp"}, {"compositions/configuration", "configuration"}, {"compositions/full", "compositionfull"}, {"compositions/full/cmd/enkv", "main"}, {"tests/live/publicprocess", "main"}} {
		target := filepath.Join(root, filepath.FromSlash(unit.directory), "nativeprocess_observer.go")
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			return Overlay{}, errors.New("native observer target already exists")
		}
		body := strings.Replace(runtimeSource, "package nativeprocessruntime", "package "+unit.pkg, 1)
		if unit.directory == "providers/aws/credentials" || unit.directory == "providers/gcp/credentials" {
			body += sourceKindSource
		}
		if unit.directory == "compositions/configuration" {
			body += localEditObserverSource
		}
		if unit.directory == "tests/live/publicprocess" {
			body += descriptors
		}
		if err := save(target, nil, []byte(body)); err != nil {
			return Overlay{}, err
		}
	}
	recoveryTarget := filepath.Join(root, "crypto", "nativeprocess_recovery.go")
	if _, err := os.Lstat(recoveryTarget); !os.IsNotExist(err) {
		return Overlay{}, errors.New("native Recovery observer target exists")
	}
	if err := save(recoveryTarget, nil, []byte(recoverySource)); err != nil {
		return Overlay{}, err
	}
	encoded, err := json.Marshal(struct{ Replace map[string]string }{mapping})
	if err != nil {
		return Overlay{}, err
	}
	path := filepath.Join(directory, "overlay.json")
	if err = os.WriteFile(path, encoded, 0600); err != nil {
		return Overlay{}, err
	}
	manifest, err := json.Marshal(sources)
	if err != nil {
		return Overlay{}, err
	}
	manifestPath := filepath.Join(directory, "sources.json")
	if err = os.WriteFile(manifestPath, manifest, 0600); err != nil {
		return Overlay{}, err
	}
	return Overlay{Path: path, Manifest: manifestPath, SHA256: digest(encoded), ManifestSHA256: digest(manifest)}, nil
}

const localEditObserverSource = `
func nativeProcessLocalEditSelected() bool {
	p, err := nativeProcessLoad()
	return err == nil && p.Fault == "local-edit-unknown" && p.FaultOrdinal == 1
}

func nativeProcessLocalEditPhase(phase string) error {
	if phase != "generated-installed" || !nativeProcessLocalEditSelected() { return nil }
	if err := nativeProcessRecord(nativeProcessEvent{Kind:"local-edit-fault", Count:1}); err != nil { return err }
	return nativeProcessRefused
}

func nativeProcessLocalEditUnknown() {
	if nativeProcessLocalEditSelected() {
		_ = nativeProcessRecord(nativeProcessEvent{Kind:"local-edit-unknown", Count:1})
	}
}

type nativeProcessLocalEditOwnership struct {
	files []*os.File
	private, durable []string
}

func nativeProcessLocalEditOwned(o *EditObservation) *nativeProcessLocalEditOwnership {
	if o == nil || !nativeProcessLocalEditSelected() { return nil }
	owned := &nativeProcessLocalEditOwnership{}
	if o.predecessor != nil {
		for _, image := range []*Image{o.predecessor.Editable, o.predecessor.Generated} {
			if image != nil && image.file != nil {
				owned.files = append(owned.files, image.file)
				owned.private = append(owned.private, image.temporaryName)
			}
		}
	}
	if o.candidate != nil && o.candidate.durable {
		for _, image := range []*Image{o.candidate.pair.Editable, o.candidate.pair.Generated} {
			if image != nil && image.file != nil {
				owned.files = append(owned.files, image.file)
				owned.durable = append(owned.durable, image.file.Name())
			}
		}
	}
	return owned
}

func nativeProcessLocalEditDisposed(owned *nativeProcessLocalEditOwnership, closeErr error) {
	if owned == nil { return }
	matched := closeErr == nil && len(owned.files) == 4 && len(owned.private) == 2 && len(owned.durable) == 2
	for _, file := range owned.files {
		_, err := file.Stat()
		matched = matched && errors.Is(err, os.ErrClosed)
	}
	for _, path := range owned.private {
		_, err := os.Lstat(path)
		matched = matched && path != "" && errors.Is(err, os.ErrNotExist)
	}
	for _, path := range owned.durable {
		info, err := os.Lstat(path)
		matched = matched && err == nil && info.Mode().IsRegular()
	}
	_ = nativeProcessRecord(nativeProcessEvent{Kind:"local-edit-disposed", Count:uint32(len(owned.files)), Matched:matched})
}
`

func digest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
