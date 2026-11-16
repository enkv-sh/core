package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

const publicTokenSourceSuffix = ".token-evidence.json"

// Only newly created fixed public inventories acquire original source evidence.
// A legacy decoded image never gains provenance by being saved again.
func (i *objectInventory) savePublicTokenSource() error {
	name := filepath.Base(i.path)
	if name != "public-controlled-inventory.json" && name != "public-cleanup-inventory.json" {
		return nil
	}
	if i.originalTokenSource == nil {
		if _, err := os.Lstat(i.path); err == nil {
			if _, err := os.Lstat(i.path + publicTokenSourceSuffix); errors.Is(err, os.ErrNotExist) {
				return nil
			} else if err != nil {
				return errInventory
			}
			var source records.PublicConfigurationTokenSource
			body, err := publicEvidenceReadJSON(i.path+publicTokenSourceSuffix, &source)
			clear(body)
			if err != nil || source.Validate() != nil || source.RunID != i.image.RunID || source.Prefix != i.image.Prefix || source.Binding != i.image.Binding || source.Domain != i.image.Domain {
				return errInventory
			}
			i.originalTokenSource = &source
		} else if !errors.Is(err, os.ErrNotExist) {
			return errInventory
		}
		if i.originalTokenSource == nil {
			if len(i.image.Intents) != 0 || len(i.image.CleanupAttempts) != 0 {
				return nil
			}
			if _, err := os.Lstat(i.path + publicTokenSourceSuffix); !errors.Is(err, os.ErrNotExist) {
				return errInventory
			}
			i.originalTokenSource = &records.PublicConfigurationTokenSource{Version: 1, RunID: i.image.RunID, Prefix: i.image.Prefix, Binding: i.image.Binding, Domain: i.image.Domain, Observations: []records.PublicConfigurationTokenObservation{}}
		}
	}
	if i.originalTokenSource.Validate() != nil {
		return errInventory
	}
	return writePrivateJSON(i.path+publicTokenSourceSuffix, i.originalTokenSource)
}

// The caller holds the existing inventory mutex. This observes typed input
// before legacy JSON string encoding; these bytes never become call authority.
func (i *objectInventory) observePublicToken(kind string, index, target int, ordinal uint8, key, digest string, size uint64, token contract.Token) {
	if i.originalTokenSource == nil {
		return
	}
	i.originalTokenSource.Observations = append(i.originalTokenSource.Observations, records.PublicConfigurationTokenObservation{Kind: kind, Index: uint32(index), TargetIntent: uint32(target), AttemptOrdinal: ordinal, Key: key, Digest: digest, Bytes: size, Token: records.PublicConfigurationToken{Family: token.Family, Value: append([]byte(nil), []byte(token.Value)...)}})
}

// Read, qualify and hash one stable original image, without another decode read.
func publicEvidenceReadJSON(path string, value any) ([]byte, error) {
	if _, err := records.SafePath(filepath.Dir(path), filepath.Base(path)); err != nil {
		return nil, errInventory
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		return nil, errInventory
	}
	body, err := records.ReadJSONBytes(path, records.MaximumJSONBytes)
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !records.SameLocalFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) || int64(len(body)) != before.Size() {
		clear(body)
		return nil, errInventory
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		clear(body)
		return nil, errInventory
	}
	return body, nil
}

// Match the legacy JSON projection to the original bytes without treating its
// normalized string as a source of the original token.
func publicLegacyTokenMatches(original records.PublicConfigurationToken, persisted contract.Token) bool {
	encoded, err := json.Marshal(contract.Token{Family: original.Family, Value: string(original.Value)})
	if err != nil {
		return false
	}
	var normalized contract.Token
	return json.Unmarshal(encoded, &normalized) == nil && normalized == persisted
}

func publicInventoryEvidence(path string) (records.PublicConfigurationInventoryEvidence, string, error) {
	var result records.PublicConfigurationInventoryEvidence
	var image inventoryImage
	body, err := publicEvidenceReadJSON(path, &image)
	if err != nil {
		return result, "", errInventory
	}
	defer clear(body)
	if image.Version != 1 || image.RecoveryLocations != nil {
		return result, "", errInventory
	}
	var source records.PublicConfigurationTokenSource
	sourceBody, err := publicEvidenceReadJSON(path+publicTokenSourceSuffix, &source)
	if err != nil {
		return result, "", errInventory
	}
	defer clear(sourceBody)
	if source.Validate() != nil || source.RunID != image.RunID || source.Prefix != image.Prefix || source.Binding != image.Binding || source.Domain != image.Domain {
		return result, "", errInventory
	}
	result = records.PublicConfigurationInventoryEvidence{RunID: image.RunID, Prefix: image.Prefix, Binding: image.Binding, Domain: image.Domain, TokenSource: &source, OriginalTokenSourceSHA256: bodyDigest(sourceBody)}
	// Legacy JSON can replace invalid UTF-8 and exceed the original token bound.
	// Only this detached validation image receives source-proved original bytes.
	// The persisted image and every cleanup/send decision keep their old owner.
	policyImage := image
	policyImage.Intents = append([]objectIntent(nil), image.Intents...)
	policyImage.CleanupAttempts = append([]cleanupAttempt(nil), image.CleanupAttempts...)
	originals := map[struct {
		kind  string
		index uint32
	}]records.PublicConfigurationTokenObservation{}
	for _, row := range source.Observations {
		key := struct {
			kind  string
			index uint32
		}{row.Kind, row.Index}
		if _, exists := originals[key]; exists {
			return records.PublicConfigurationInventoryEvidence{}, "", errInventory
		}
		originals[key] = row
	}
	used := 0
	for index, row := range image.Intents {
		projected := records.PublicConfigurationObjectIntent{Key: row.Key, Digest: row.Digest, Bytes: row.Bytes, Kind: row.Kind, State: row.State}
		if row.ConditionToken != nil {
			original, ok := originals[struct {
				kind  string
				index uint32
			}{"intent-condition", uint32(index)}]
			if !ok || original.TargetIntent != uint32(index) || original.AttemptOrdinal != 0 || original.Key != row.Key || original.Digest != row.Digest || original.Bytes != row.Bytes || !publicLegacyTokenMatches(original.Token, *row.ConditionToken) {
				return records.PublicConfigurationInventoryEvidence{}, "", errInventory
			}
			token := original.Token
			token.Value = append([]byte(nil), token.Value...)
			projected.ConditionToken = &token
			used++
			policyToken := contract.Token{Family: token.Family, Value: string(token.Value)}
			policyImage.Intents[index].ConditionToken = &policyToken
		}
		result.Intents = append(result.Intents, projected)
	}
	keys := make([]string, 0, len(image.Deleted))
	for key := range image.Deleted {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		result.Deleted = append(result.Deleted, records.PublicConfigurationDeleted{Key: key, Cutoff: uint32(image.Deleted[key])})
	}
	for index, row := range image.CleanupAttempts {
		original, ok := originals[struct {
			kind  string
			index uint32
		}{"cleanup-condition", uint32(index)}]
		if !ok || original.TargetIntent != uint32(row.TargetIntent) || original.AttemptOrdinal != row.Ordinal || original.Key != row.Key || original.Digest != row.Digest || original.Bytes != row.Bytes || !publicLegacyTokenMatches(original.Token, row.Token) {
			return records.PublicConfigurationInventoryEvidence{}, "", errInventory
		}
		token := original.Token
		token.Value = append([]byte(nil), token.Value...)
		policyImage.CleanupAttempts[index].Token = contract.Token{Family: token.Family, Value: string(token.Value)}
		projected := records.PublicConfigurationCleanupAttempt{TargetIntent: uint32(row.TargetIntent), Ordinal: row.Ordinal, Recovery: row.Recovery, GrantRunID: row.GrantRunID, CaseSHA256: row.CaseSHA256, LimitsSHA256: row.LimitsSHA256, Key: row.Key, Digest: row.Digest, Bytes: row.Bytes, Token: token, Cutoff: uint32(row.Cutoff), State: row.State}
		if row.Failure != nil {
			copy := *row.Failure
			projected.Failure = &copy
		}
		result.CleanupAttempts = append(result.CleanupAttempts, projected)
		used++
	}
	if used != len(source.Observations) {
		return records.PublicConfigurationInventoryEvidence{}, "", errInventory
	}
	if _, err := policyImage.unknownEffects(); err != nil {
		return records.PublicConfigurationInventoryEvidence{}, "", errInventory
	}
	return result, bodyDigest(body), nil
}

func publicWriteEvidence(inv records.Invocation, input liveRunInput) error {
	if len(input.Scenarios) != 1 {
		return errInventory
	}
	var ledger publicOwnership
	body, err := publicEvidenceReadJSON(publicLedgerPath(inv), &ledger)
	if err != nil {
		return errInventory
	}
	defer clear(body)
	if ledger.Version != 1 || ledger.RunID != input.RunID || ledger.Prefix != input.Prefix || ledger.Binding != settingsBinding(input.Settings) || !ledger.PreflightEmpty || ledger.Source != filepath.Join(inv.StateDir, "public-source", "configuration.json") {
		return errInventory
	}
	result := records.PublicConfigurationEvidenceSnapshot{Version: 1, RunID: input.RunID, Scenario: input.Scenarios[0], Provider: input.Settings.Provider, RecoveryMode: input.RecoveryMode, Prefix: input.Prefix, Binding: ledger.Binding, PreflightEmpty: ledger.PreflightEmpty, OriginalOwnershipSHA256: bodyDigest(body)}
	if input.Generator != nil {
		var original records.GeneratorFixtureLedger
		image, err := publicEvidenceReadJSON(input.GeneratorCleanupLedger, &original)
		if err != nil {
			return errInventory
		}
		defer clear(image)
		ledger, err := records.ReadGeneratorFixtureLedger(input.GeneratorCleanupLedger, input.RunID, input.Generator.Account)
		if err != nil || !ledger.Clean() || !reflect.DeepEqual(original, ledger) {
			return errInventory
		}
		joinedPath := filepath.Join(inv.StateDir, "generator-writer-joined.json")
		joinedBody, err := records.ReadJSONBytes(joinedPath, 4096)
		if err != nil {
			return errInventory
		}
		var joined records.GeneratorFixtureJoined
		if json.Unmarshal(joinedBody, &joined) != nil || records.ReadGeneratorFixtureJoined(joinedPath, input.RunID, input.Scenarios[0]) != nil {
			clear(joinedBody)
			return errInventory
		}
		result.Generator = &records.PublicConfigurationGeneratorEvidence{Account: ledger.Account, Resources: ledger.Resources, WriterJoined: joined, OriginalLedgerSHA256: bodyDigest(image), OriginalJoinedSHA256: bodyDigest(joinedBody)}
		clear(joinedBody)
		fixturePath := filepath.Join(inv.StateDir, records.PublicGeneratorFixtureCleanupName)
		if _, err := os.Lstat(fixturePath); err == nil {
			var fixture records.PublicGeneratorFixtureCleanup
			body, err := publicEvidenceReadJSON(fixturePath, &fixture)
			if err != nil {
				return errInventory
			}
			original, err := records.ReadPublicGeneratorFixtureCleanupBytes(body, input.RunID, input.Scenarios[0], ledger.Account)
			if err != nil {
				return errInventory
			}
			result.Generator.FixtureCleanup, result.Generator.OriginalFixtureCleanupSHA256 = &original, bodyDigest(body)
		} else if !errors.Is(err, os.ErrNotExist) {
			return errInventory
		}
		if result.Generator.Validate(input.RunID, input.Scenarios[0]) != nil {
			return errInventory
		}
	}
	result.Outputs = ledger.Outputs
	domains := map[contract.ID]bool{}
	if ledger.Domain != "" {
		raw, err := hex.DecodeString(ledger.Domain)
		var id contract.ID
		if err != nil || len(raw) != len(id) || hex.EncodeToString(raw) != ledger.Domain {
			return errInventory
		}
		copy(id[:], raw)
		if id.IsZero() {
			return errInventory
		}
		domains[id] = true
	}
	for index, row := range ledger.Captures {
		relative, err := filepath.Rel(inv.StateDir, row.Path)
		if err != nil || !row.Complete || row.Ordinal != uint16(index) {
			return errInventory
		}
		exact, err := records.SafePath(inv.StateDir, relative)
		if err != nil || exact != row.Path || filepath.Base(relative) != "capture.jsonl" || !strings.HasPrefix(filepath.Base(filepath.Dir(relative)), "public-command-") || filepath.Dir(filepath.Dir(relative)) != "." {
			return errInventory
		}
		sum, size, err := publicCaptureImage(row.Path, row.ExitCode)
		if err != nil || sum != row.SHA256 || size != row.Bytes {
			return errInventory
		}
		result.Captures = append(result.Captures, records.PublicConfigurationCaptureReceipt{Ordinal: row.Ordinal, ParentWorker: row.ParentWorker, ParentNonce: row.ParentNonce, ParentRole: row.ParentRole, Actor: row.Actor, NativeKind: row.NativeKind, SourceRelative: filepath.ToSlash(relative), Complete: row.Complete, ExitCode: row.ExitCode, SHA256: row.SHA256, Bytes: row.Bytes})
	}
	if result.Generator != nil {
		var captures []nativeprocess.Capture
		for _, receipt := range ledger.Captures {
			capture, digest, err := nativeprocess.ReadCaptureWithDigest(receipt.Path)
			if err != nil || hex.EncodeToString(digest[:]) != receipt.SHA256 {
				return errInventory
			}
			captures = append(captures, capture)
		}
		if result.Generator.ValidateCaptures(captures) != nil {
			return errInventory
		}
	}
	if ledger.ControlledInventory != "" {
		if ledger.ControlledInventory != filepath.Join(inv.StateDir, "public-controlled-inventory.json") {
			return errInventory
		}
		controlled, sum, err := publicInventoryEvidence(ledger.ControlledInventory)
		if err != nil {
			return errInventory
		}
		result.Controlled = &controlled
		result.OriginalControlledSHA256 = sum
	} else {
		for _, path := range []string{filepath.Join(inv.StateDir, "public-controlled-inventory.json"), filepath.Join(inv.StateDir, "public-controlled-inventory.json") + publicTokenSourceSuffix} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return errInventory
			}
		}
	}
	cleanup, sum, err := publicInventoryEvidence(filepath.Join(inv.StateDir, "public-cleanup-inventory.json"))
	if err != nil {
		return errInventory
	}
	result.Cleanup, result.OriginalCleanupSHA256 = cleanup, sum
	inventories := []records.PublicConfigurationInventoryEvidence{cleanup}
	if result.Controlled != nil {
		inventories = append(inventories, *result.Controlled)
	}
	for _, image := range inventories {
		for _, row := range image.Intents {
			if id, ok := publicObjectDomain(input.Prefix, row.Key); ok {
				domains[id] = true
			}
		}
	}
	for id := range domains {
		result.Domains = append(result.Domains, id)
	}
	sort.Slice(result.Domains, func(i, j int) bool { return bytes.Compare(result.Domains[i][:], result.Domains[j][:]) < 0 })
	return records.WritePublicConfigurationEvidenceSnapshot(filepath.Join(inv.OutputDir, "public-configuration-evidence.json"), result)
}

// full_only: false
func TestPublicOriginalTokenEvidencePreservesTypedBytes(t *testing.T) {
	for _, name := range []string{"aws-high-byte", "aws-utf8", "aws-replacement-character", "aws-256", "gcp-max", "empty"} {
		t.Run(name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			token := contract.Token{Family: contract.AWS, Value: string([]byte{'"', 0x80, '"'})}
			switch name {
			case "aws-utf8":
				token.Value = "\"é\""
			case "aws-replacement-character":
				token.Value = "\"�\""
			case "aws-256":
				token.Value = string(append(append([]byte{'"'}, bytes.Repeat([]byte{0x80}, 254)...), '"'))
			case "gcp-max":
				token = contract.Token{Family: contract.GCP, Value: "9223372036854775807"}
			}
			image := inventoryImage{Version: 1, RunID: liveProtocolRun, Prefix: "enkv-test/" + liveProtocolRun + "/proof", Binding: strings.Repeat("a", 64), Domain: contract.Hash([]byte("domain")), Deleted: map[string]int{}}
			inventory := &objectInventory{path: filepath.Join(dir, "public-controlled-inventory.json"), image: image}
			if inventory.save() != nil {
				t.Fatal("original empty source not initialized")
			}
			if name != "empty" {
				index, err := inventory.begin(image.Prefix+"/HEAD", []byte("head"), "compare_and_swap", []contract.Token{token})
				if err != nil || !inventory.finish(index, contract.WriteResult{Status: contract.WriteAcknowledged}) {
					t.Fatal("original typed input not saved")
				}
			}
			originalImage, err := os.ReadFile(inventory.path)
			if err != nil {
				t.Fatal("original inventory image unavailable")
			}
			defer clear(originalImage)
			projected, _, err := publicInventoryEvidence(inventory.path)
			if err != nil {
				t.Fatal("original source did not qualify", err)
			}
			afterImage, err := os.ReadFile(inventory.path)
			if err != nil || !bytes.Equal(originalImage, afterImage) {
				t.Fatal("evidence projection changed original inventory bytes")
			}
			clear(afterImage)
			if name == "empty" {
				if projected.TokenSource == nil || len(projected.TokenSource.Observations) != 0 {
					t.Fatal("complete empty source erased")
				}
				return
			}
			if len(projected.Intents) != 1 || projected.Intents[0].ConditionToken == nil || !bytes.Equal(projected.Intents[0].ConditionToken.Value, []byte(token.Value)) {
				t.Fatal("original bytes changed after JSON round trip")
			}
			var persisted inventoryImage
			if records.ReadJSON(inventory.path, &persisted) != nil || !publicLegacyTokenMatches(*projected.Intents[0].ConditionToken, *persisted.Intents[0].ConditionToken) {
				t.Fatal("original source not associated with exact legacy projection")
			}
			if name == "aws-256" && (len(token.Value) != 256 || len(persisted.Intents[0].ConditionToken.Value) != 764 || persisted.Intents[0].ConditionToken.Valid()) {
				t.Fatal("maximum opaque legacy normalization fixture does not exercise expansion")
			}
			reopened := &objectInventory{path: inventory.path, image: persisted}
			next, err := reopened.begin(image.Prefix+"/HEAD", []byte("next"), "compare_and_swap", []contract.Token{token})
			if err != nil || !reopened.finish(next, contract.WriteResult{Status: contract.WriteAcknowledged}) {
				t.Fatal("reopened original source did not observe new typed input")
			}
			again, _, err := publicInventoryEvidence(reopened.path)
			if err != nil || len(again.Intents) != 2 || !bytes.Equal(again.Intents[1].ConditionToken.Value, []byte(token.Value)) {
				t.Fatal("reopened original source lost exact occurrence")
			}
			// A new process can qualify both original files; it cannot obtain provenance by resaving only the decoded inventory.
			legacy := &objectInventory{path: filepath.Join(dir, "public-cleanup-inventory.json"), image: persisted}
			if legacy.save() != nil {
				t.Fatal("legacy inventory save behavior changed")
			}
			if _, _, err := publicInventoryEvidence(legacy.path); err == nil {
				t.Fatal("legacy source was backfilled")
			}
		})
	}
}

// full_only: false
func TestPublicOriginalTokenEvidenceRejectsMissingOrChangedFacts(t *testing.T) {
	for _, name := range []string{"missing-source", "wrong-run", "wrong-prefix", "wrong-binding", "wrong-domain", "wrong-index", "wrong-kind", "wrong-target", "wrong-ordinal", "wrong-key", "wrong-digest", "wrong-size", "duplicate", "missing-observation", "changed-token", "extra-observation", "partial-inventory"} {
		t.Run(name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			image := inventoryImage{Version: 1, RunID: liveProtocolRun, Prefix: "enkv-test/" + liveProtocolRun + "/proof", Binding: strings.Repeat("a", 64), Domain: contract.Hash([]byte("domain")), Deleted: map[string]int{}}
			inventory := &objectInventory{path: filepath.Join(dir, "public-controlled-inventory.json"), image: image}
			if inventory.save() != nil {
				t.Fatal("source fixture unavailable")
			}
			index, err := inventory.begin(image.Prefix+"/HEAD", []byte("head"), "compare_and_swap", []contract.Token{{Family: contract.AWS, Value: `"original"`}})
			if err != nil || !inventory.finish(index, contract.WriteResult{Status: contract.WriteAcknowledged}) {
				t.Fatal("typed fixture unavailable")
			}
			source := *inventory.originalTokenSource
			source.Observations = append([]records.PublicConfigurationTokenObservation(nil), source.Observations...)
			row := &source.Observations[0]
			switch name {
			case "missing-source":
				if os.Remove(inventory.path+publicTokenSourceSuffix) != nil {
					t.Fatal("source removal failed")
				}
			case "wrong-run":
				source.RunID = strings.Repeat("b", 32)
			case "wrong-prefix":
				source.Prefix += "-other"
			case "wrong-binding":
				source.Binding = strings.Repeat("b", 64)
			case "wrong-domain":
				source.Domain = contract.Hash([]byte("other domain"))
			case "wrong-index":
				row.Index = 1
				row.TargetIntent = 1
			case "wrong-kind":
				row.Kind = "cleanup-condition"
				row.AttemptOrdinal = 1
			case "wrong-target":
				row.TargetIntent = 1
			case "wrong-ordinal":
				row.AttemptOrdinal = 1
			case "wrong-key":
				row.Key += "-other"
			case "wrong-digest":
				row.Digest = strings.Repeat("b", 64)
			case "wrong-size":
				row.Bytes++
			case "duplicate":
				source.Observations = append(source.Observations, *row)
			case "missing-observation":
				source.Observations = nil
			case "changed-token":
				row.Token.Value = []byte(`"changed"`)
			case "extra-observation":
				extra := *row
				extra.Index = 1
				extra.TargetIntent = 1
				source.Observations = append(source.Observations, extra)
			case "partial-inventory":
				inventory.image.Intents = nil
				if records.WriteJSON(inventory.path, inventory.image, 0600) != nil {
					t.Fatal("partial image fixture failed")
				}
			}
			if name != "missing-source" && records.WriteJSON(inventory.path+publicTokenSourceSuffix, source, 0600) != nil {
				t.Fatal("changed source fixture failed")
			}
			if _, _, err := publicInventoryEvidence(inventory.path); err == nil {
				t.Fatal("missing or foreign original fact accepted")
			}
		})
	}
}

type publicEvidenceCleanupRead struct {
	contract.Store
	body    []byte
	token   contract.Token
	removed bool
}

func (s *publicEvidenceCleanupRead) Read(_ context.Context, _ string, _ uint32) contract.ReadResult {
	if s.removed {
		return contract.ReadResult{Status: contract.ReadMissing}
	}
	return contract.ReadResult{Status: contract.ReadOK, Body: append([]byte(nil), s.body...), Token: s.token}
}

// full_only: false
func TestPublicOriginalCleanupTokenPrecedesConditionalDelete(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prefix := "enkv-test/" + liveProtocolRun + "/proof"
	key := prefix + "/HEAD"
	body := []byte("head")
	inventory := &objectInventory{path: filepath.Join(dir, "public-cleanup-inventory.json"), image: inventoryImage{Version: 1, RunID: liveProtocolRun, Prefix: prefix, Binding: strings.Repeat("a", 64), Domain: contract.Hash([]byte("domain")), Deleted: map[string]int{}}}
	if inventory.save() != nil {
		t.Fatal("cleanup source initialization failed")
	}
	original := contract.Token{Family: contract.AWS, Value: `"mutation"`}
	index, err := inventory.begin(key, body, "compare_and_swap", []contract.Token{original})
	if err != nil || !inventory.finish(index, contract.WriteResult{Status: contract.WriteAcknowledged}) {
		t.Fatal("original mutation fixture failed")
	}
	observed := contract.Token{Family: contract.AWS, Value: string([]byte{'"', 0x80, '"'})}
	store := &publicEvidenceCleanupRead{body: body, token: observed}
	calls := 0
	remove := func(_ context.Context, gotKey string, gotToken contract.Token) error {
		calls++
		if gotKey != key || gotToken != observed {
			t.Fatal("conditional input changed")
		}
		proof, _, err := publicInventoryEvidence(inventory.path)
		if err != nil || len(proof.CleanupAttempts) != 1 || proof.CleanupAttempts[0].State != "pending" || !bytes.Equal(proof.CleanupAttempts[0].Token.Value, []byte(observed.Value)) || !bytes.Equal(proof.Intents[0].ConditionToken.Value, []byte(original.Value)) {
			t.Fatal("exact distinct original condition was not durable before delete")
		}
		store.removed = true
		return nil
	}
	if inventory.remove(t.Context(), store, remove, key, map[string]bool{bodyDigest(body): true}) != nil || calls != 1 {
		t.Fatal("conditional cleanup did not join exactly once")
	}
	proof, _, err := publicInventoryEvidence(inventory.path)
	if err != nil || proof.CleanupAttempts[0].State != "settled" || len(proof.TokenSource.Observations) != 2 {
		t.Fatal("cleanup settlement erased original source")
	}
}

// full_only: false
func TestPublicCaptureRegistrationPreservesExactOriginalParent(t *testing.T) {
	for _, damage := range []string{"none", "worker", "nonce", "role", "actor", "native-kind", "path", "ordinal", "exit"} {
		t.Run(damage, func(t *testing.T) {
			inv, _ := liveProtocolInvocation(t, "writer")
			dir := inv.StateDir
			ledger := publicOwnership{Version: 1, RunID: inv.RunID, PreflightEmpty: true}
			if records.WriteJSON(publicLedgerPath(inv), ledger, 0600) != nil {
				t.Fatal("ledger fixture failed")
			}
			child := filepath.Join(dir, "public-command-1")
			if os.Mkdir(child, 0700) != nil {
				t.Fatal("child directory failed")
			}
			path := filepath.Join(child, "capture.jsonl")
			if os.WriteFile(path, []byte(`{"kind":"footer"}`+"\n"), 0600) != nil {
				t.Fatal("capture fixture failed")
			}
			registration := publicCaptureReceipt{Path: path, ParentWorker: inv.Worker, ParentNonce: inv.Nonce, ParentRole: inv.Role, Actor: "operator-alias", NativeKind: "consumer"}
			if publicCaptureReceiptUpdate(inv, registration, false) != nil {
				t.Fatal("original intent failed")
			}
			switch damage {
			case "worker":
				registration.ParentWorker = "other"
			case "nonce":
				registration.ParentNonce = strings.Repeat("b", 32)
			case "role":
				registration.ParentRole = "fresh_after"
			case "actor":
				registration.Actor = "other"
			case "native-kind":
				registration.NativeKind = "cli"
			case "path":
				registration.Path = filepath.Join(dir, "capture.jsonl")
			case "ordinal":
				registration.Ordinal = 2
			case "exit":
				registration.ExitCode = 2
			}
			if err := publicCaptureReceiptUpdate(inv, registration, true); (err == nil) != (damage == "none") {
				t.Fatal("foreign parent or terminal changed original registration")
			}
			if damage == "none" {
				if records.ReadJSON(publicLedgerPath(inv), &ledger) != nil || len(ledger.Captures) != 1 {
					t.Fatal("joined registration unavailable")
				}
				row := ledger.Captures[0]
				if row.Ordinal != 0 || row.Actor != "operator-alias" || row.NativeKind != "consumer" || row.Bytes != 18 || row.ExitCode != 0 || !row.Complete || row.SHA256 != bodyDigest([]byte(`{"kind":"footer"}`+"\n")) {
					t.Fatal("exact registered facts changed")
				}
			}
		})
	}
}

// full_only: false
func TestPublicCleanupRetainsOriginalArtifactAndNewCaptureParent(t *testing.T) {
	for _, condition := range []string{"same-owner", "cleanup", "non-cleanup", "output-owner", "other-runs", "ledger-owner", "artifact-bytes", "artifact-path"} {
		t.Run(condition, func(t *testing.T) {
			inv, _ := liveProtocolInvocation(t, "cleanup")
			owner, _, _, err := records.PrivateOwner(inv.StateDir)
			if err != nil {
				t.Fatal(err)
			}
			build := filepath.Join(owner, "build")
			a := publicProcessArtifact{}
			for _, item := range []struct {
				name string
				path *string
				hash *string
				mode os.FileMode
			}{
				{"enkv-public", &a.CLI, &a.CLISHA256, 0700},
				{"enkv-public-reconstruct", &a.Consumer, &a.ConsumerSHA256, 0700},
				{"public-configuration-overlay/overlay.json", &a.Overlay.Path, &a.Overlay.SHA256, 0400},
				{"public-configuration-overlay/sources.json", &a.Overlay.Manifest, &a.Overlay.ManifestSHA256, 0400},
			} {
				*item.path = filepath.Join(build, filepath.FromSlash(item.name))
				body := []byte("owned fixture " + item.name)
				*item.hash = bodyDigest(body)
				if os.MkdirAll(filepath.Dir(*item.path), 0700) != nil || os.WriteFile(*item.path, body, item.mode) != nil {
					t.Fatal("original artifact fixture")
				}
			}
			if condition != "same-owner" {
				inv = liveProtocolRecoveryOutput(t, inv)
			}
			switch condition {
			case "non-cleanup":
				inv.Role = "writer"
			case "output-owner":
				inv.RunID = liveProtocolRun
			case "other-runs":
				inv.OutputDir = filepath.Join(t.TempDir(), "tests/live/runs", liveProtocolRecovery, "private/output")
			case "artifact-bytes":
				if os.WriteFile(a.CLI, []byte("changed"), 0700) != nil {
					t.Fatal("changed artifact fixture")
				}
			case "artifact-path":
				a.CLI = filepath.Join(filepath.Dir(inv.OutputDir), "build", "enkv-public")
			}
			wantArtifact := condition == "same-owner" || condition == "cleanup" || condition == "ledger-owner"
			if publicArtifactValid(inv, a) != wantArtifact {
				t.Error("public artifact did not bind original state and current output owners")
			}
			ledgerID := liveProtocolRun
			if condition == "ledger-owner" {
				ledgerID = inv.RunID
			}
			ledger := publicOwnership{Version: 1, RunID: ledgerID, PreflightEmpty: true}
			if records.WriteJSON(publicLedgerPath(inv), ledger, 0600) != nil {
				t.Fatal("original ledger fixture")
			}
			capture := filepath.Join(inv.StateDir, "public-command-1", "capture.jsonl")
			if os.Mkdir(filepath.Dir(capture), 0700) != nil || os.WriteFile(capture, []byte("{\"kind\":\"footer\"}\n"), 0600) != nil {
				t.Fatal("capture fixture")
			}
			registration := publicCaptureReceipt{Path: capture, ParentWorker: inv.Worker, ParentNonce: inv.Nonce, ParentRole: inv.Role, Actor: "operator-alias", NativeKind: "cli"}
			wantCapture := condition == "same-owner" || condition == "cleanup" || condition == "artifact-bytes" || condition == "artifact-path"
			if err := publicCaptureReceiptUpdate(inv, registration, false); (err == nil) != wantCapture {
				t.Fatal("capture intent changed original ownership or new parent identity", err)
			}
			if wantCapture {
				if err := publicCaptureReceiptUpdate(inv, registration, true); err != nil || records.ReadJSON(publicLedgerPath(inv), &ledger) != nil || ledger.RunID != liveProtocolRun || len(ledger.Captures) != 1 || ledger.Captures[0].ParentNonce != inv.Nonce || ledger.Captures[0].ParentWorker != inv.Worker || ledger.Captures[0].ParentRole != inv.Role || !ledger.Captures[0].Complete {
					t.Fatal("joined cleanup capture lost the original ledger or new parent", err)
				}
			}
		})
	}
}

// full_only: false
func TestPublicOutputCleanupRefusesArtifactBeforeSourceMutation(t *testing.T) {
	inv, input := liveProtocolInvocation(t, "cleanup")
	input.Scenarios = []string{"public-configuration.manifest/atomic_public_file"}
	inv.Scenario = input.Scenarios[0]
	input.PublicConfiguration = &publicConfigurationInput{Outputs: &records.PublicOutputScopes{
		Repository:   records.PublicOutputScope{Owner: "owner", Repository: "repository"},
		Organization: records.PublicOutputScope{Owner: "owner", Visibility: "selected", Repositories: []uint64{101, 202}},
		Environment:  records.PublicOutputScope{Owner: "owner", Repository: "repository", Environment: "environment"},
	}}
	source := filepath.Join(inv.StateDir, "source.json")
	document := map[string]any{"generated": "generated.json", "outputs": publicManifestDeclaration(input)}
	body, err := json.Marshal(document)
	if err != nil || os.WriteFile(source, body, 0600) != nil || os.WriteFile(filepath.Join(inv.StateDir, "generated.json"), []byte("literal generated companion"), 0400) != nil {
		t.Fatal("original source fixture")
	}
	ledger := publicOwnership{Domain: strings.Repeat("a", 64)}
	facts := publicProcessFacts{RunID: input.RunID, Prefix: input.Prefix, Domain: ledger.Domain, Outputs: publicExpectedOutputCoordinates(input)}
	for i := range facts.Outputs {
		facts.Outputs[i].CoordinateID = bodyDigest([]byte(facts.Outputs[i].PhysicalTarget))
		facts.Outputs[i].BindingID = strings.Repeat("b", 64)
	}
	if records.WriteJSON(filepath.Join(inv.StateDir, "after.json"), facts, 0400) != nil {
		t.Fatal("original selected output facts")
	}
	var refusal any
	func() {
		defer func() { refusal = recover() }()
		publicCleanupOutputs(recoveryCustodyRefusalTB{TB: t}, t.Context(), inv, input, nil, source, ledger)
	}()
	if message, ok := refusal.(recoveryCustodyRefusal); !ok || string(message) != "public process admission refused" {
		t.Fatal("output cleanup did not admit its artifact before source preparation", refusal)
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(after, body) {
		t.Fatal("refused output cleanup changed its original source")
	}
}

// full_only: false
func TestPublicConfigurationEvidenceHandoffRequiresWholeOriginalSet(t *testing.T) {
	for _, damage := range []string{"none", "controlled", "fixture-cleanup", "fixture-missing-source", "fixture-unknown", "fixture-delete-save-failed", "fixture-receipt-save-failed", "missing-capture", "changed-capture", "wrong-bytes", "wrong-exit", "wrong-ordinal", "wrong-source", "unexpected-controlled", "source-less-cleanup", "existing-output"} {
		t.Run(damage, func(t *testing.T) {
			state, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(state, "output")
			if os.Mkdir(output, 0700) != nil {
				t.Fatal("output directory failed")
			}
			inv := records.Invocation{RunID: liveProtocolRun, StateDir: state, OutputDir: output, Worker: "cleanup", Nonce: strings.Repeat("b", 32), Role: "cleanup"}
			input := liveRunInput{RunID: inv.RunID, Prefix: "enkv-test/" + inv.RunID + "/proof", RecoveryMode: "disabled", Scenarios: []string{"public-configuration.empty-initialization/empty_initialization"}, Settings: liveSettings{Provider: liveProvider()}}
			domain := contract.Hash([]byte("domain"))
			binding := settingsBinding(input.Settings)
			cleanup := &objectInventory{path: filepath.Join(state, "public-cleanup-inventory.json"), image: inventoryImage{Version: 1, RunID: input.RunID, Prefix: input.Prefix, Binding: binding, Domain: domain, Deleted: map[string]int{}}}
			if cleanup.save() != nil {
				t.Fatal("empty original cleanup failed")
			}
			captureDir := filepath.Join(state, "public-command-1")
			if os.Mkdir(captureDir, 0700) != nil {
				t.Fatal("capture directory failed")
			}
			capture := filepath.Join(captureDir, "capture.jsonl")
			captureBody, exitCode := []byte(`{"kind":"footer"}`+"\n"), 0
			if strings.HasPrefix(damage, "fixture-") {
				if err := os.Chmod(state, 0700); err != nil {
					t.Fatal(err)
				}
				account, target, attempt := strings.Repeat("c", 32), strings.Repeat("d", 32), strings.Repeat("e", 64)
				input.Scenarios = []string{"public-configuration.generated-manual-lifecycle/generated_manual_lifecycle"}
				input.PublicConfiguration = &publicConfigurationInput{}
				input.Generator = &liveGeneratorSettings{Account: account}
				input.GeneratorCleanupLedger = filepath.Join(state, "generator-cleanup.json")
				if records.NewGeneratorFixtureLedger(input.GeneratorCleanupLedger, input.RunID, account) != nil || records.WriteGeneratorFixtureJoined(filepath.Join(state, "generator-writer-joined.json"), input.RunID, input.Scenarios[0]) != nil {
					t.Fatal("generator originals unavailable")
				}
				if records.UpdateGeneratorFixtureLedger(input.GeneratorCleanupLedger, input.RunID, account, func(ledger *records.GeneratorFixtureLedger) error {
					if err := ledger.BeginCreate(attempt); err != nil {
						return err
					}
					return ledger.RecordCreate(attempt, target)
				}) != nil {
					t.Fatal("qualified generator create unavailable")
				}
				captureBody = nil
				for _, event := range []nativeprocess.Event{{Kind: "generator-entry", GeneratorAccount: account, GeneratorAttempt: attempt, GeneratorAction: 1}, {Kind: "generator-return", GeneratorAccount: account, GeneratorAttempt: attempt, GeneratorAction: 1, GeneratorTarget: target, GeneratorQualified: true}, {Kind: "footer", Code: 3}} {
					body, err := json.Marshal(event)
					if err != nil {
						t.Fatal(err)
					}
					captureBody = append(append(captureBody, body...), '\n')
				}
				exitCode = 3
				t.Setenv("CLOUDFLARE_API_TOKEN", "Management_bearer_0123456789_ABCDEFGHIJKLMN")
				fixturePath := filepath.Join(state, records.PublicGeneratorFixtureCleanupName)
				if damage == "fixture-receipt-save-failed" && os.Mkdir(fixturePath, 0700) != nil {
					t.Fatal("receipt refusal fixture unavailable")
				}
				budget := &runBudget{limits: liveLimits{Requests: 1, BodyBytes: operationBodyAllowance, GeneratorRetires: 1}, keys: map[string]bool{}}
				calls := 0
				transport := cloudflareFixtureRoundTrip(func(request *http.Request) (*http.Response, error) {
					calls++
					if request.Method != http.MethodDelete || request.URL.Path != "/client/v4/accounts/"+account+"/tokens/"+target {
						t.Fatal("fixture cleanup changed target")
					}
					if damage == "fixture-unknown" {
						return cloudflareFixtureReply(503, "private-response-sentinel"), nil
					}
					if damage == "fixture-delete-save-failed" {
						if os.Rename(input.GeneratorCleanupLedger, input.GeneratorCleanupLedger+".retained") != nil || os.Mkdir(input.GeneratorCleanupLedger, 0700) != nil {
							t.Fatal("ledger refusal fixture unavailable")
						}
					}
					return cloudflareFixtureReply(200, `{"success":true,"errors":[],"messages":[],"result":{"id":"`+target+`"}}`), nil
				})
				err := cleanupCloudflareFixtureWithTransport(context.Background(), input, budget, transport)
				wantCleanup := damage == "fixture-cleanup" || damage == "fixture-missing-source"
				if (err == nil) != wantCleanup || calls != 1 {
					t.Fatal("exact fixture cleanup unavailable", err, calls)
				}
				if damage == "fixture-missing-source" && os.Remove(fixturePath) != nil {
					t.Fatal("receipt source removal failed")
				}
				if damage == "fixture-unknown" || damage == "fixture-delete-save-failed" {
					if _, err := os.Lstat(fixturePath); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("unsettled delete fabricated a receipt")
					}
				}
			}
			if os.WriteFile(capture, captureBody, 0600) != nil {
				t.Fatal("capture fixture failed")
			}
			sum, size, err := publicCaptureImage(capture, exitCode)
			if err != nil {
				t.Fatal("capture evidence failed")
			}
			registration := publicCaptureReceipt{Path: capture, SHA256: sum, Complete: true, Ordinal: 0, ParentWorker: "writer", ParentNonce: strings.Repeat("a", 32), ParentRole: "writer", Actor: "operator-alias", NativeKind: "cli", Bytes: size, ExitCode: exitCode}
			ledger := publicOwnership{Version: 1, RunID: input.RunID, Prefix: input.Prefix, Binding: binding, Domain: hex.EncodeToString(domain[:]), Source: filepath.Join(state, "public-source", "configuration.json"), PreflightEmpty: true, Captures: []publicCaptureReceipt{registration}}
			switch damage {
			case "controlled":
				controlled := &objectInventory{path: filepath.Join(state, "public-controlled-inventory.json"), image: cleanup.image}
				if controlled.save() != nil {
					t.Fatal("controlled original source failed")
				}
				ledger.ControlledInventory = controlled.path
			case "missing-capture":
				if os.Remove(capture) != nil {
					t.Fatal("capture removal failed")
				}
			case "changed-capture":
				if os.WriteFile(capture, []byte(`{"kind":"footer","code":2}`+"\n"), 0600) != nil {
					t.Fatal("capture damage failed")
				}
			case "wrong-bytes":
				ledger.Captures[0].Bytes++
			case "wrong-exit":
				ledger.Captures[0].ExitCode = 2
			case "wrong-ordinal":
				ledger.Captures[0].Ordinal = 2
			case "wrong-source":
				ledger.Source = filepath.Join(state, "other.json")
			case "unexpected-controlled":
				if records.WriteJSON(filepath.Join(state, "public-controlled-inventory.json"), cleanup.image, 0600) != nil {
					t.Fatal("unexpected controlled fixture failed")
				}
			case "source-less-cleanup":
				if os.Remove(cleanup.path+publicTokenSourceSuffix) != nil {
					t.Fatal("source removal failed")
				}
			case "existing-output":
				if os.WriteFile(filepath.Join(output, "public-configuration-evidence.json"), []byte("existing"), 0600) != nil {
					t.Fatal("existing output fixture failed")
				}
			}
			if records.WriteJSON(publicLedgerPath(inv), ledger, 0600) != nil {
				t.Fatal("ledger fixture failed")
			}
			good := damage == "none" || damage == "controlled" || damage == "fixture-cleanup"
			if err := publicWriteEvidence(inv, input); (err == nil) != good {
				t.Fatal("handoff accepted partial, foreign or changed originals", err)
			}
			if good {
				expected := records.PublicConfigurationEvidenceBinding{RunID: input.RunID, Scenario: input.Scenarios[0], Provider: input.Settings.Provider, RecoveryMode: input.RecoveryMode, Prefix: input.Prefix, Binding: binding}
				proof, err := records.ReadPublicConfigurationEvidenceSnapshot(filepath.Join(output, "public-configuration-evidence.json"), expected)
				if err != nil || proof.OriginalOwnershipSHA256 == "" || proof.OriginalCleanupSHA256 == "" || len(proof.Captures) != 1 || proof.Captures[0].Actor != "operator-alias" || proof.Captures[0].SourceRelative != "public-command-1/capture.jsonl" || proof.Cleanup.TokenSource == nil || len(proof.Cleanup.TokenSource.Observations) != 0 || (proof.Controlled != nil) != (damage == "controlled") {
					t.Fatal("complete original snapshot changed")
				}
				if damage == "fixture-cleanup" && (proof.Generator == nil || proof.Generator.FixtureCleanup == nil || len(proof.Generator.FixtureCleanup.AcknowledgedDeletes) != 1 || proof.Generator.OriginalFixtureCleanupSHA256 == "") {
					t.Fatal("fixture cleanup proof lost its original source")
				}
			}
		})
	}
}

// full_only: false
func TestPublicOriginalTokenEvidenceIncludesAuthorizedRecoveryAttempts(t *testing.T) {
	for _, name := range []string{"gcp-present", "gcp-granted-missing", "aws-granted-present", "aws-granted-missing", "legacy-source-missing"} {
		t.Run(name, func(t *testing.T) {
			inventory, store := testInventory(t)
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			inventory.path = filepath.Join(dir, "public-cleanup-inventory.json")
			inventory.image.RunID = liveProtocolRun
			inventory.image.Binding = strings.Repeat("a", 64)
			inventory.image.Domain = contract.Hash([]byte("original source recovery domain"))
			if strings.HasPrefix(name, "aws-") {
				store.desc.Family = contract.AWS
			}
			if name == "legacy-source-missing" {
				if records.WriteJSON(inventory.path, inventory.image, 0600) != nil {
					t.Fatal("legacy fixture failed")
				}
			} else if inventory.save() != nil {
				t.Fatal("fresh recovery source failed")
			}
			key := inventory.image.Prefix + "/" + hex.EncodeToString(inventory.image.Domain[:]) + "/root/0/" + bodyDigest([]byte("unique original recovery object"))
			body := []byte("owned")
			if inventory.write(t.Context(), key, body, "create", func() contract.WriteResult { return store.Create(t.Context(), key, body) }).Status != contract.WriteAcknowledged {
				t.Fatal("original owned object failed")
			}
			inventory.stop()
			firstSends := 0
			missing := strings.HasSuffix(name, "missing") && name != "legacy-source-missing"
			if err := inventory.cleanup(t.Context(), store, func(ctx context.Context, got string, token contract.Token) error {
				firstSends++
				if missing {
					if err := testDelete(store)(ctx, got, token); err != nil {
						t.Fatal(err)
					}
				}
				return inventoryControlledTransportError{}
			}); err == nil || firstSends != 1 || len(inventory.image.CleanupAttempts) != 1 {
				t.Fatal("original controlled cleanup failure was not retained")
			}
			var durable inventoryImage
			if readPrivateJSON(inventory.path, &durable) != nil {
				t.Fatal("durable original inventory failed")
			}
			originalFailure := durable.CleanupAttempts[0].Failure
			originalToken := durable.CleanupAttempts[0].Token
			recovered := &objectInventory{path: inventory.path, image: durable, stopped: true}
			sends := 0
			remove := func(ctx context.Context, got string, token contract.Token) error {
				sends++
				if got != key || token != originalToken {
					t.Fatal("recovery changed its original exact target")
				}
				if name != "legacy-source-missing" {
					proof, _, err := publicInventoryEvidence(recovered.path)
					if err != nil || len(proof.CleanupAttempts) != 2 || proof.CleanupAttempts[1].State != "pending" || !bytes.Equal(proof.CleanupAttempts[1].Token.Value, []byte(originalToken.Value)) {
						t.Fatal("new recovery source was not durable before delete")
					}
				}
				return testDelete(store)(ctx, got, token)
			}
			if strings.HasPrefix(name, "aws-") {
				err = recovered.recoverGrantedCleanup(t.Context(), store, remove, awsInventoryGrant(t, recovered))
			} else if name == "gcp-granted-missing" {
				err = recovered.recoverGrantedCleanup(t.Context(), store, remove, controlledCleanupGrant(2))
			} else {
				err = recovered.recoverCleanup(t.Context(), store, remove, 0, 2)
			}
			wantSends := 1
			if missing {
				wantSends = 0
			}
			if err != nil || sends != wantSends || !reflect.DeepEqual(originalFailure, recovered.image.CleanupAttempts[0].Failure) {
				t.Fatal("original recovery gates, failure history or send count changed", err, sends)
			}
			proof, _, err := publicInventoryEvidence(recovered.path)
			if name == "legacy-source-missing" {
				if err == nil {
					t.Fatal("legacy recovery invented original source")
				}
				if _, err := os.Lstat(recovered.path + publicTokenSourceSuffix); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("legacy recovery backfilled a companion")
				}
				return
			}
			if err != nil || len(proof.CleanupAttempts) != 2 || len(proof.TokenSource.Observations) != 2 || proof.CleanupAttempts[1].Ordinal != 2 || proof.CleanupAttempts[1].State != "settled" || !bytes.Equal(proof.CleanupAttempts[0].Token.Value, proof.CleanupAttempts[1].Token.Value) {
				t.Fatal("new authorized recovery occurrence missing from complete original set", err)
			}
		})
	}
}
