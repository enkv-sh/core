package plugininstallation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"enkv.sh/sdk/artifact"
)

// These literals reuse the artifact package's independent Python JSON,
// big-endian dependency framing and documented identity preimages. Executable
// and source hashes use the published SHA-256("abc") vector.
const boundedPackageMetadata = `{"schema":"enkv/plugin-artifact/v2","purpose":"plugin-executable","name":"generic-json","role":"manifest-generator","version":"1.0.0","main_module":"example.test/plugin","command":"example.test/plugin","platform":"linux/amd64","toolchain":"go1.27.0","build_options":[],"contracts":[{"kind":"wire","identity":"0100000000000000000000000000000000000000000000000000000000000000","version":9}],"family":{"schema":2,"facts":{"schema":2,"descriptor":{"schema":1,"name":"generic-json","role":"manifest-generator","version":"1.0.0","wire":{"kind":"wire","identity":"0100000000000000000000000000000000000000000000000000000000000000","version":9},"generator":null,"output":null,"manifest":{"config_contract_id":"private-settings/v1","format_contract_id":"private-reference/v1"}},"descriptor_id":"cf3309d300871e9a325a766504b5ee08c16a945ab1fd172701ae3e7f0f16c368","executor_id":"2d69c1f99a3b8187fb7649d5b3d925eefb91a92e5fd0f3c575a7fec6f9df44d4","artifact_contract_id":"bc44c21e3a4a4d95537e9e25c3231502a7dfab00b521eea344bbc02e45e6d54e","dependency_manifest_id":"b1581dd698f9775616dd523619bdc4ec9ae1b86ee97e40606ec89098ef7fcdac","artifact_sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","artifact_length":3,"module":"example.test/plugin","command":"example.test/plugin","go_version":"go1.27.0","native_tuple":"linux/amd64"},"dependency":{"sha256":"202dcc7ed3a82e524d4d72e691dd1c4c5884da41f6a8c8e2aa1ae4936e1385f7","length":588}},"executable":{"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","length":3},"sources":[{"module":"example.test/plugin","digest":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}],"resolved":[{"path":"example.test/plugin","version":"","sum":"","replacement":null}],"compiled":[{"path":"example.test/plugin","version":"(devel)","sum":"","replacement":null}]}`
const boundedPackageDependencyHex = "0003000002467b22726f6c65223a226d616e69666573742d67656e657261746f72222c226d61696e5f6d6f64756c65223a226578616d706c652e746573742f706c7567696e222c22636f6d6d616e64223a226578616d706c652e746573742f706c7567696e222c22706c6174666f726d223a226c696e75782f616d643634222c22746f6f6c636861696e223a22676f312e32372e30222c226275696c645f6f7074696f6e73223a5b5d2c22636f6e747261637473223a5b7b226b696e64223a2277697265222c226964656e74697479223a2230313030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c2276657273696f6e223a397d5d2c22736f7572636573223a5b7b226d6f64756c65223a226578616d706c652e746573742f706c7567696e222c22646967657374223a2262613738313662663866303163666561343134313430646535646165323232336230303336316133393631373761396362343130666636316632303031356164227d5d2c227265736f6c766564223a5b7b2270617468223a226578616d706c652e746573742f706c7567696e222c2276657273696f6e223a22222c2273756d223a22222c227265706c6163656d656e74223a6e756c6c7d5d2c22636f6d70696c6564223a5b7b2270617468223a226578616d706c652e746573742f706c7567696e222c2276657273696f6e223a2228646576656c29222c2273756d223a22222c227265706c6163656d656e74223a6e756c6c7d5d7d"

// full_only: false
func TestPackageDirectoryEnumerationIsBounded(t *testing.T) {
	directory := tempDirectory(t)
	metadata := []byte(boundedPackageMetadata)
	plugin := []byte("abc")
	dependency, err := hex.DecodeString(boundedPackageDependencyHex)
	if err != nil {
		t.Fatal(err)
	}
	identity := sha256.Sum256(metadata)
	for name, body := range map[string][]byte{"metadata.json": metadata, "plugin": plugin, "dependencies.bin": dependency} {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if contents, err := localContents(t.Context(), directory, identity); err != nil || !reflect.DeepEqual(contents.MetadataBytes, metadata) {
		t.Fatalf("valid local metadata: contents %#v, error %v", contents, err)
	}
	record := artifact.ArchiveRecord{
		Schema: "enkv/plugin-archive/v1", Purpose: "plugin-archive", Artifact: identity,
		Name: "generic-json", Version: "1.0.0", Platform: "linux/amd64",
		Archive: artifact.ArchiveFile{Filename: "private-renderer.tar.gz", SHA256: sha256.Sum256([]byte("unobserved archive")), Length: 1},
		Members: []artifact.ArchiveMember{
			{Name: "dependencies.bin", Length: uint64(len(dependency)), SHA256: sha256.Sum256(dependency)},
			{Name: "metadata.json", Length: uint64(len(metadata)), SHA256: sha256.Sum256(metadata)},
			{Name: "plugin", Length: uint64(len(plugin)), SHA256: sha256.Sum256(plugin)},
		},
	}
	if err := partialPackage(t.Context(), directory, record); err != nil {
		t.Fatalf("valid package members: %v", err)
	}
	for i := range 8192 {
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("extra-%04d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	checkAllocations := func(t *testing.T, read func()) {
		t.Helper()
		// A fixed member refusal must not allocate one entry per extra file.
		if allocations := testing.AllocsPerRun(3, read); allocations > 2048 {
			t.Fatalf("directory refusal allocated %.0f objects; maximum 2048", allocations)
		}
	}
	t.Run("proof", func(t *testing.T) {
		coordinator := &Coordinator{}
		checkAllocations(t, func() {
			record, metadataSig, archiveBytes, err := coordinator.readProof(t.Context(), directory, artifact.Selection{Artifact: identity})
			if !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(record, artifact.ArchiveRecord{}) || metadataSig != nil || archiveBytes != nil {
				t.Fatalf("extra proof members: record %#v, error %v", record, err)
			}
		})
	})
	t.Run("partial-package", func(t *testing.T) {
		checkAllocations(t, func() {
			if err := partialPackage(t.Context(), directory, record); !errors.Is(err, ErrIdentity) {
				t.Fatalf("extra package members: %v", err)
			}
		})
	})
	t.Run("local", func(t *testing.T) {
		checkAllocations(t, func() {
			contents, err := localContents(t.Context(), directory, identity)
			if !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(contents, artifact.PackageContents{}) {
				t.Fatalf("extra local members: contents %#v, error %v", contents, err)
			}
		})
	})
}
