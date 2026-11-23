package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func publicWriteSource(t testing.TB, path string, document map[string]any) {
	t.Helper()
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil || os.WriteFile(path, append(body, '\n'), 0600) != nil {
		t.Fatal("public editable source write failed")
	}
}
func publicRewritePortableSource(t testing.TB, path string, document map[string]any) {
	t.Helper()
	if os.Chmod(path, 0600) != nil {
		t.Fatal("portable source rewrite permission unavailable")
	}
	defer func() {
		if os.Chmod(path, 0400) != nil {
			t.Fatal("portable source read-only permission restore failed")
		}
	}()
	publicWriteSource(t, path, document)
}
func publicSourceDocument(t testing.TB, path string) map[string]any {
	t.Helper()
	body, err := os.ReadFile(path)
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err != nil || len(body) > 1<<20 || decoder.Decode(&document) != nil {
		t.Fatal("public editable source unavailable")
	}
	return document
}
func publicSetupSource(t testing.TB, input liveRunInput, path string) {
	t.Helper()
	s := input.Settings
	store := map[string]any{"region": s.Region, "bucket": s.Bucket, "prefix": input.Prefix}
	if s.Provider == "aws" {
		store["expected_owner"] = s.Account
	}
	recovery := map[string]any{"enabled": input.RecoveryMode == "enabled"}
	if input.RecoveryMode == "enabled" {
		recovery["signing_key"], recovery["encryption_key"] = s.RecoveryKeyID, s.RecoveryKEKID
	}
	publicWriteSource(t, path, map[string]any{"schema": "enkv/configuration/v3", "domain": map[string]any{"name": "prod", "provider": s.Provider, "store": store, "authority": map[string]any{"display_name": "Authority", "signing_key": s.KeyID, "encryption_key": s.AuthorityKEKID}, "recovery": recovery}, "recipients": map[string]any{"consumer": map[string]any{"display_name": "Consumer", "encryption_key": s.ReaderKEKID}}, "entries": map[string]any{}, "outputs": map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}})
}

type publicPairImage struct {
	Files     map[string][]byte
	Directory string
	Inventory []string
}

func publicSourceInventory(directory string) ([]string, error) {
	var inventory []string
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return errInventory
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			relative += "/"
		}
		inventory = append(inventory, filepath.ToSlash(relative))
		if len(inventory) > 1024 {
			return errInventory
		}
		return nil
	})
	return inventory, err
}

// Snapshot the exact editable file and every referenced immutable dependency,
// plus the local source directory inventory so new artifacts cannot go unseen.
// Apply and Reader run from a distinct working directory and cannot write these.
func publicSourceImage(t testing.TB, source string) publicPairImage {
	t.Helper()
	document := publicSourceDocument(t, source)
	paths := []string{source}
	if ref, ok := document["generated"].(string); ok {
		paths = append(paths, filepath.Join(filepath.Dir(source), filepath.FromSlash(ref)))
	}
	image := publicPairImage{Files: make(map[string][]byte, len(paths)), Directory: filepath.Dir(source)}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatal("public pair source unavailable")
		}
		body, err := os.ReadFile(path)
		if err != nil || len(body) > 8<<20 {
			t.Fatal("public pair source exceeds fixture limit")
		}
		image.Files[path] = body
	}
	var err error
	image.Inventory, err = publicSourceInventory(image.Directory)
	if err != nil {
		t.Fatal("public source directory inventory unavailable")
	}
	return image
}
func publicImageMatches(image publicPairImage) bool {
	inventory, err := publicSourceInventory(image.Directory)
	if err != nil || !slices.Equal(inventory, image.Inventory) {
		return false
	}
	for path, want := range image.Files {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			return false
		}
	}
	return true
}
func publicImageUnchanged(t testing.TB, image publicPairImage) {
	t.Helper()
	if !publicImageMatches(image) {
		t.Fatal("read-only public operation changed source bytes or local file inventory")
	}
}
func publicPortablePair(t testing.TB, source, directory string) string {
	t.Helper()
	image := publicSourceImage(t, source)
	if os.MkdirAll(directory, 0700) != nil {
		t.Fatal("portable pair directory unavailable")
	}
	for path, body := range image.Files {
		rel, err := filepath.Rel(filepath.Dir(source), path)
		if err != nil || strings.HasPrefix(rel, "..") {
			t.Fatal("portable pair route refused")
		}
		target := filepath.Join(directory, rel)
		if os.MkdirAll(filepath.Dir(target), 0700) != nil || os.WriteFile(target, body, 0400) != nil {
			t.Fatal("portable pair delivery failed")
		}
	}
	return filepath.Join(directory, filepath.Base(source))
}
func publicReadDomain(t testing.TB, source string) contract.ID {
	t.Helper()
	id, err := publicSourceDomain(source)
	if err != nil {
		t.Fatal("delivered public Domain unavailable")
	}
	return id
}
func publicSourceDomain(source string) (contract.ID, error) {
	var id contract.ID
	editable, err := os.ReadFile(source)
	var document struct {
		Generated string `json:"generated"`
	}
	if err != nil || json.Unmarshal(editable, &document) != nil || document.Generated == "" {
		return id, errInventory
	}
	ref := document.Generated
	body, err := os.ReadFile(filepath.Join(filepath.Dir(source), filepath.FromSlash(ref)))
	var generated struct {
		Domain struct {
			ID string `json:"id"`
		} `json:"domain"`
	}
	if err != nil || len(body) > 8<<20 || json.Unmarshal(body, &generated) != nil {
		return id, errInventory
	}
	raw, err := hex.DecodeString(generated.Domain.ID)
	if err != nil || len(raw) != len(id) {
		return id, errInventory
	}
	copy(id[:], raw)
	if id.IsZero() {
		return id, errInventory
	}
	return id, nil
}
func publicRecoveryBinding(t testing.TB, source string) []byte {
	t.Helper()
	document := publicSourceDocument(t, source)
	ref, ok := document["generated"].(string)
	if !ok {
		t.Fatal("public Recovery basis missing")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(source), filepath.FromSlash(ref)))
	var generated struct {
		Basis struct{ Descriptor, Control []byte } `json:"public_basis"`
	}
	if err != nil || json.Unmarshal(body, &generated) != nil {
		t.Fatal("public Recovery basis unavailable")
	}
	var recovery *contract.RecoveryBindings
	if len(generated.Basis.Control) > 0 {
		control, err := contract.DecodeControlCore(generated.Basis.Control)
		if err != nil {
			t.Fatal("public successor Recovery basis refused")
		}
		recovery = control.Recovery
	} else {
		descriptor, err := contract.DecodeGenesisDescriptorCore(generated.Basis.Descriptor)
		if err != nil {
			t.Fatal("public genesis Recovery basis refused")
		}
		recovery = descriptor.Recovery
	}
	if recovery == nil {
		t.Fatal("public Recovery basis disabled")
	}
	encoded, err := contract.EncodeBindingTable([]contract.BindingTableRow{{SubjectKind: contract.RecoveryWrapSubject, SubjectID: recovery.RoleID, Binding: recovery.KMS}})
	if err != nil {
		t.Fatal("public Recovery binding refused")
	}
	return encoded
}

func publicRecipientBinding(t testing.TB, input liveRunInput, source string) ([]byte, string) {
	t.Helper()
	document := publicSourceDocument(t, source)
	ref, ok := document["generated"].(string)
	if !ok {
		t.Fatal("trusted Recipient generated reference unavailable")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(source), filepath.FromSlash(ref)))
	var generated struct {
		Recipients map[string]struct {
			ID         string
			Encryption struct {
				Selector  string
				PublicKey []byte `json:"public_key"`
				Binding   struct {
					ID, Incarnation, Protection string
					Serial                      uint64
				}
			}
		}
	}
	if err != nil || json.Unmarshal(body, &generated) != nil {
		t.Fatal("trusted Recipient public metadata unavailable")
	}
	row, ok := generated.Recipients["consumer"]
	if !ok || row.Encryption.Selector != input.Settings.ReaderKEKID {
		t.Fatal("trusted Recipient selector differs")
	}
	id := func(text string) contract.ID {
		raw, err := hex.DecodeString(text)
		var value contract.ID
		if err != nil || len(raw) != len(value) {
			t.Fatal("trusted Recipient identity malformed")
		}
		copy(value[:], raw)
		if value.IsZero() {
			t.Fatal("trusted Recipient identity empty")
		}
		return value
	}
	family := contract.AWS
	if input.Settings.Provider == "gcp" {
		family = contract.GCP
	}
	protection := contract.HardwareProtection
	if row.Encryption.Binding.Protection == "software" {
		protection = contract.SoftwareProtection
	} else if row.Encryption.Binding.Protection != "hardware" {
		t.Fatal("trusted Recipient protection malformed")
	}
	binding := contract.KMSBinding{BindingID: id(row.Encryption.Binding.ID), BindingIncarnationID: id(row.Encryption.Binding.Incarnation), BindingSerial: row.Encryption.Binding.Serial, Provider: family, WrapProfile: contract.RSAOAEPWrapProfile, ProtectionClass: protection, KeySelector: row.Encryption.Selector, SPKI: row.Encryption.PublicKey, Fingerprint: contract.Hash(row.Encryption.PublicKey)}
	encoded, err := contract.EncodeBindingTable([]contract.BindingTableRow{{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: id(row.ID), Binding: binding}})
	if err != nil {
		t.Fatal("trusted Recipient binding malformed")
	}
	return encoded, row.Encryption.Selector
}
