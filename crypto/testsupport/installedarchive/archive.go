// Package installedarchive holds signed, local-only selected-state fixtures for
// installed provider reconstruction tests. It contains public object bytes only.
package installedarchive

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

//go:embed testdata/aws.json testdata/gcp.json
var archives embed.FS

type Object struct {
	Key        string
	TokenWire  []byte
	Body       []byte
	BodySHA256 string
	Token      contract.Token `json:"-"`
}

type Archive struct {
	ArchiveVersion   int
	Family           contract.Family
	Domain           contract.ID
	Location         contract.StoreLocation
	SignerID         contract.ID
	SignerSelector   string
	SignerPublicKey  []byte
	CustodyID        contract.ID
	AuthorityID      contract.ID
	AuthorityBinding contract.KMSBinding
	HeadDigest       contract.ID
	Revision         contract.ID
	ObjectCount      int
	ObjectFileBytes  uint64
	Objects          []Object
}

type ExpectedValue struct {
	Name  string
	Bytes []byte
}

// PublicationLossContinuation carries only parent-verified public/encrypted
// observations and actual remote object backing. Support Parts can be spans;
// they cannot be used as replacement physical page bodies. A separate normal
// test grant is required before any later mutation.
type PublicationLossContinuation struct {
	Location                               contract.StoreLocation
	Domain, Revision, Snapshot, HEADDigest contract.ID
	HEADToken                              contract.Token
	Parts                                  []Part
	Result                                 RecoveryResult
	Objects                                []Object
}

// RecoveryFixture stays in the provider parent. It is never child input.
type PrivateValue struct {
	Name, Path string
	Length     uint32
}

type RecoveryFixture struct {
	Oracles []PrivateValue
	Archive Archive
	Values  []ExpectedValue
	Secrets int
}

func ReadRecoveryFixture(t testing.TB, path string) RecoveryFixture {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("parent fixture unavailable")
	}
	fixture, readErr := decodeRecoveryFixture(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal("parent recovery fixture refused")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal("parent fixture carrier removal")
	}
	return fixture
}

func decodeRecoveryFixture(reader io.Reader) (RecoveryFixture, error) {
	return decodeRecoveryFixtureBounded(reader, 64<<20, 32<<20, false)
}

func decodeRecoveryFixtureBounded(reader io.Reader, jsonLimit, bodyLimit int64, maximumGenerated bool) (RecoveryFixture, error) {
	refused := errors.New("parent recovery fixture refused")
	limited := &io.LimitedReader{R: reader, N: jsonLimit + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var fixture RecoveryFixture
	err := decoder.Decode(&fixture)
	var extra any
	trailing := decoder.Decode(&extra)
	a := &fixture.Archive
	if err != nil || trailing != io.EOF || limited.N <= 0 || a.ArchiveVersion != 1 || a.Family != a.Location.Provider || !contract.StoreLocationValid(a.Location) || a.Domain.IsZero() || a.HeadDigest.IsZero() || a.Revision.IsZero() || a.ObjectCount != len(a.Objects) || a.ObjectCount < 1 || a.ObjectCount > 4096 || len(fixture.Values) > contract.CryptoMaxValueEntries || len(fixture.Oracles) > contract.CryptoMaxValueEntries || len(fixture.Values) != 0 && len(fixture.Oracles) != 0 {
		return RecoveryFixture{}, refused
	}
	keys := make(map[string]bool, len(a.Objects))
	var total, fileBytes uint64
	for i := range a.Objects {
		item := &a.Objects[i]
		if maximumGenerated && (len(item.Key) > contract.MaxStoreObjectKeyLength || len(item.TokenWire) > 261) {
			return RecoveryFixture{}, refused
		}
		token, n, err := contract.ParseToken(item.TokenWire)
		total += uint64(len(item.Body))
		fileBytes += uint64(28) + uint64(len(item.Key)) + uint64(len(item.TokenWire)) + uint64(len(item.Body))
		if item.Key == "" || keys[item.Key] || !strings.HasPrefix(item.Key, a.Location.PrefixBeforeHEAD+"/") || total > uint64(bodyLimit) || err != nil || n != len(item.TokenWire) || !token.Valid() || token.Family != a.Family || fmt.Sprintf("%x", sha256.Sum256(item.Body)) != item.BodySHA256 {
			return RecoveryFixture{}, refused
		}
		keys[item.Key], item.Token = true, token
	}
	if fileBytes != a.ObjectFileBytes {
		return RecoveryFixture{}, refused
	}
	parts, err := a.SelectedParts()
	if err != nil {
		return RecoveryFixture{}, fmt.Errorf("parent recovery fixture selected parts: %w", err)
	}
	var root format.Root
	for _, part := range parts {
		if part.Kind == "root" {
			root, err = format.DecodeRoot(part.Body)
		}
	}
	if maximumGenerated {
		if err != nil || root.Domain != a.Domain || len(a.Objects) != int(root.ChildCount)+3 || fixture.Secrets != 128 || root.SecretCount != 128 || root.ValueEntryCount != 128 || root.Generated.GeneratedCurrent != 128 || len(fixture.Values) != 0 || len(fixture.Oracles) != 0 {
			return RecoveryFixture{}, refused
		}
		return fixture, nil
	}
	if err != nil || root.Domain != a.Domain || fixture.Secrets != int(root.SecretCount) || len(fixture.Values)+len(fixture.Oracles) != len(root.Names) {
		return RecoveryFixture{}, refused
	}
	names, paths := make(map[string]bool, len(root.Names)), make(map[string]bool, len(fixture.Oracles))
	for _, value := range fixture.Values {
		if names[value.Name] || len(value.Bytes) > contract.CryptoMaxRawValue {
			return RecoveryFixture{}, refused
		}
		names[value.Name] = true
	}
	for _, value := range fixture.Oracles {
		if names[value.Name] || paths[value.Path] || !filepath.IsAbs(value.Path) || filepath.Clean(value.Path) != value.Path || value.Length > contract.CryptoMaxRawValue {
			return RecoveryFixture{}, refused
		}
		names[value.Name], paths[value.Path] = true, true
	}
	for _, named := range root.Names {
		if !names[named.Name] {
			return RecoveryFixture{}, refused
		}
	}
	return fixture, nil
}

// Load returns one fixed archive. Each body and token is checked before the
// provider mock can expose it to the production read path.
func Load(t testing.TB, family string) Archive {
	t.Helper()
	if family != "aws" && family != "gcp" {
		t.Fatal("unknown installed archive")
	}
	body, err := archives.ReadFile("testdata/" + family + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var a Archive
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&a); err != nil {
		t.Fatal("invalid installed archive", err)
	}
	if a.ArchiveVersion != 1 || !contract.StoreLocationValid(a.Location) ||
		a.Family != a.Location.Provider || a.Domain.IsZero() || a.SignerID.IsZero() ||
		a.CustodyID.IsZero() || a.AuthorityID.IsZero() || a.HeadDigest.IsZero() ||
		len(a.Objects) != a.ObjectCount || a.ObjectCount != 13 {
		t.Fatal("invalid installed archive identity")
	}
	seen := make(map[string]bool, len(a.Objects))
	var total uint64
	for i := range a.Objects {
		item := &a.Objects[i]
		digest := sha256.Sum256(item.Body)
		if seen[item.Key] || item.Key == "" || hex.EncodeToString(digest[:]) != item.BodySHA256 {
			t.Fatal("invalid installed archive object")
		}
		seen[item.Key] = true
		token, n, err := contract.ParseToken(item.TokenWire)
		if err != nil || n != len(item.TokenWire) || !token.Valid() {
			t.Fatal("invalid installed archive token", err)
		}
		item.Token = token
		total += uint64(28) + uint64(len(item.Key)) + uint64(len(item.TokenWire)) + uint64(len(item.Body))
	}
	if total != a.ObjectFileBytes {
		t.Fatalf("installed archive size %d != %d", total, a.ObjectFileBytes)
	}
	head, ok := a.Object(a.Location.PrefixBeforeHEAD + "/HEAD")
	if !ok || contract.Hash(head.Body) != a.HeadDigest {
		t.Fatal("installed archive HEAD differs")
	}
	return a
}

func (a Archive) Object(key string) (Object, bool) {
	for _, item := range a.Objects {
		if item.Key == key {
			return item, true
		}
	}
	return Object{}, false
}

func (a Archive) MustObject(t testing.TB, key string) Object {
	t.Helper()
	item, ok := a.Object(key)
	if !ok {
		t.Fatalf("missing installed archive object %q", key)
	}
	return item
}
