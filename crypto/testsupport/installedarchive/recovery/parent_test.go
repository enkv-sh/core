package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/installedarchive"
)

// full_only: false
func TestRefusedObservationDiagnosticsKeepOnlyBoundedResultScalars(t *testing.T) {
	want := ObservedResult{Outcome: 8, Reason: 4}
	for _, row := range []struct {
		name, body, diagnostic string
	}{
		{"mismatch", `{"Result":{"Outcome":6,"Reason":12,"Evidence":0},"Private":"private observation sentinel"}`, "observation_mismatch outcome=6 reason=12 evidence=0"},
		{"unexpected_data", `{"Result":{"Outcome":8,"Reason":4,"Evidence":0},"Private":"private observation sentinel"}`, "observation_mismatch outcome=8 reason=4 evidence=0"},
		{"invalid", `{"Result":"private observation sentinel"}`, "observation_invalid"},
		{"oversized", strings.Repeat("private observation sentinel", 100), "size_exceeded"},
		{"missing", "", "unavailable"},
	} {
		t.Run(row.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "observation.json")
			if row.name != "missing" {
				if err := os.WriteFile(path, []byte(row.body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := CheckRefusedResult(path, want)
			if err == nil || err.Error() != "refused reconstruction check failed: category="+row.diagnostic {
				t.Fatal("refusal diagnostic did not retain only the expected safe facts")
			}
			if strings.Contains(err.Error(), "private observation sentinel") || strings.Contains(err.Error(), path) {
				t.Fatal("refusal diagnostic released private observation data or path")
			}
			if row.name == "missing" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal diagnostic lost its private file cause")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "refusal.json")
	if WriteRefusedResult(path, want) != nil || CheckRefusedResult(path, want) != nil {
		t.Fatal("exact refusal no longer passes")
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString(" ")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || CheckRefusedResult(path, want) == nil {
		t.Fatal("noncanonical refusal bytes passed")
	}
}

// full_only: false
func TestCopiedLocationArchiveDerivesExactFileTotals(t *testing.T) {
	base := installedarchive.Load(t, "aws")
	for _, row := range []struct {
		name, prefix    string
		keys, copied    [2]string
		original, total uint64
	}{
		// Files have 8-byte magic and 8/4/8-byte length fields. After copying,
		// ASCII keys contain 21/27 bytes; token/body lengths are 2+3/3+0.
		{"ascii", "team/prod", [2]string{"team/prod/HEAD", "team/prod/value-long"}, [2]string{"team/prod-copied/HEAD", "team/prod-copied/value-long"}, 98, 112},
		// The multibyte copied keys contain 18/20 bytes, giving 51+51 bytes.
		{"multibyte", "環境", [2]string{"環境/HEAD", "環境/値頁"}, [2]string{"環境-copied/HEAD", "環境-copied/値頁"}, 88, 102},
	} {
		for _, initial := range []uint64{0, row.original, ^uint64(0)} {
			t.Run(fmt.Sprintf("%s/initial=%d", row.name, initial), func(t *testing.T) {
				archive := base
				archive.Location.PrefixBeforeHEAD = row.prefix
				archive.ObjectCount, archive.ObjectFileBytes = 2, initial
				archive.Objects = []installedarchive.Object{
					{Key: row.keys[0], TokenWire: []byte{1, 2}, Body: []byte{3, 4, 5}, BodySHA256: "first-body", Token: base.Objects[0].Token},
					{Key: row.keys[1], TokenWire: []byte{6, 7, 8}, BodySHA256: "empty-body", Token: base.Objects[1].Token},
				}
				before, err := json.Marshal(archive)
				if err != nil {
					t.Fatal(err)
				}
				copied := copiedLocationArchive(archive)
				after, err := json.Marshal(archive)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) {
					t.Fatal("copy changed original archive")
				}
				metadata := copied
				metadata.Objects, metadata.ObjectFileBytes = archive.Objects, archive.ObjectFileBytes
				if !reflect.DeepEqual(metadata, archive) {
					t.Fatal("copy changed authenticated archive metadata")
				}
				if len(copied.Objects) != 2 || &copied.Objects[0] == &archive.Objects[0] {
					t.Fatal("copy did not preserve an independent object list")
				}
				for i, object := range copied.Objects {
					want := archive.Objects[i]
					want.Key = row.copied[i]
					if !reflect.DeepEqual(object, want) {
						t.Fatal("copy changed object body or token", i)
					}
				}
				if copied.ObjectFileBytes != row.total {
					t.Fatalf("copied object-file total %d != independently derived %d", copied.ObjectFileBytes, row.total)
				}
			})
		}
	}
}

// full_only: false
func TestVerifiedPublicationContinuationRequiresExactReturnedSelection(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			archive := installedarchive.Load(t, provider)
			parts, err := archive.SelectedParts()
			if err != nil {
				t.Fatal(err)
			}
			headObject, ok := archive.Object(archive.Location.PrefixBeforeHEAD + "/HEAD")
			head, err := format.DecodeHead(headObject.Body)
			if !ok || err != nil {
				t.Fatal("independent archive HEAD unavailable", err)
			}
			provenance := Provenance{Domain: archive.Domain, Revision: archive.Revision, Snapshot: head.Core.Root.Object, HEADDigest: archive.HeadDigest, HEADToken: headObject.Token}
			path := filepath.Join(t.TempDir(), "observations.json")
			if err := WriteReturnedParts(path, provenance, parts); err != nil {
				t.Fatal(err)
			}
			carrier, err := verifiedPublicationContinuation(archive, path)
			if err != nil || !reflect.DeepEqual(carrier.Objects, archive.Objects) || !reflect.DeepEqual(carrier.Parts, parts) || carrier.HEADToken != headObject.Token || carrier.HEADDigest != archive.HeadDigest {
				t.Fatal("verified actual backing/parts differed", err)
			}
			body, err := json.Marshal(carrier)
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"Oracles", "Values", "Resources", "CustodyID", "SignerID", "AuthorityBinding", "DomainBasis"} {
				if bytes.Contains(body, []byte("\""+field+"\":")) {
					t.Fatal("private or old authority field escaped", field)
				}
			}
			for _, damage := range []string{"wrong_token", "wrong_digest", "missing_part", "refused", "trailing"} {
				t.Run(damage, func(t *testing.T) {
					observation := Observation{Provenance: provenance, Parts: parts, Result: ObservedResult{Outcome: 2, Evidence: 1}}
					switch damage {
					case "wrong_token":
						observation.Provenance.HEADToken.Value += "changed"
					case "wrong_digest":
						observation.Provenance.HEADDigest[0] ^= 1
					case "missing_part":
						observation.Parts = parts[:len(parts)-1]
					case "refused":
						observation.Result = ObservedResult{Outcome: 5}
					}
					encoded, err := json.Marshal(observation)
					if err != nil {
						t.Fatal(err)
					}
					encoded = append(encoded, '\n')
					if damage == "trailing" {
						encoded = append(encoded, 'x')
					}
					if err := os.WriteFile(path, encoded, 0600); err != nil {
						t.Fatal(err)
					}
					if _, err := verifiedPublicationContinuation(archive, path); err == nil {
						t.Fatal("unverified selection carrier released")
					}
				})
			}
		})
	}
}
