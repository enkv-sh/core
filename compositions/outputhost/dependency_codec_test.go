package outputhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// full_only: false
func TestDependencyManifestIndependentFixedBytes(t *testing.T) {
	// Python json.dumps with explicit fields, struct.pack and hashlib supplied
	// these current-schema literals; no production codec supplied expected bytes.
	rows := []struct {
		platform, body, sha256, identity string
		length                           int
	}{
		{"darwin/arm64", "{\"role\":\"output\",\"main_module\":\"example.test/output\",\"command\":\"example.test/output/cmd/deliver\",\"platform\":\"darwin/arm64\",\"toolchain\":\"go1.27.3\",\"build_options\":[],\"contracts\":[],\"sources\":[{\"module\":\"example.test/output\",\"digest\":\"0100000000000000000000000000000000000000000000000000000000000000\"}],\"resolved\":[{\"path\":\"example.test/output\",\"version\":\"\",\"sum\":\"\",\"replacement\":null}],\"compiled\":[{\"path\":\"example.test/output\",\"version\":\"(devel)\",\"sum\":\"\",\"replacement\":null}]}", "74f6bc53cdfec15ac212856934e8fd95a7f4058226d1f02c3483d775b6164643", "e7552db1ba362e44a4187e13a69a5eff60d0726cf5ad6a31590565920ccd72f3", 484},
		{"linux/amd64", "{\"role\":\"output\",\"main_module\":\"example.test/output\",\"command\":\"example.test/output/cmd/deliver\",\"platform\":\"linux/amd64\",\"toolchain\":\"go1.27.3\",\"build_options\":[],\"contracts\":[],\"sources\":[{\"module\":\"example.test/output\",\"digest\":\"0100000000000000000000000000000000000000000000000000000000000000\"}],\"resolved\":[{\"path\":\"example.test/output\",\"version\":\"\",\"sum\":\"\",\"replacement\":null}],\"compiled\":[{\"path\":\"example.test/output\",\"version\":\"(devel)\",\"sum\":\"\",\"replacement\":null}]}", "b529704f8acb77dbc465194743a76cacef648b4dee2b6bc49fb2607ce65bd180", "d7d9aef85402c312cd71ad8d8a36d74d96d86c799afd5ee70ea8a98620495e27", 483},
	}
	for _, row := range rows {
		t.Run(row.platform, func(t *testing.T) {
			body := binary.BigEndian.AppendUint16(nil, 3)
			body = binary.BigEndian.AppendUint32(body, uint32(len(row.body)))
			body = append(body, row.body...)
			digest := sha256.Sum256(body)
			if len(body) != row.length || hex.EncodeToString(digest[:]) != row.sha256 {
				t.Fatal("independent fixture differs")
			}
			manifest, err := DecodeDependencyManifest(body)
			if err != nil || manifest.Facts == nil || manifest.Facts.Platform != row.platform {
				t.Fatal("current exact facts refused", err)
			}
			encoded, err := EncodeDependencyManifest(manifest)
			if err != nil || !bytes.Equal(encoded, body) {
				t.Fatal("canonical dependency bytes changed", err)
			}
			id, err := DependencyManifestID(body)
			if err != nil || hex.EncodeToString(id[:]) != row.identity {
				t.Fatal("role-bound dependency identity differs", err)
			}
		})
	}
}

// full_only: false
func TestDependencyManifestRejectsRemovedFormatsWithoutReinterpretation(t *testing.T) {
	manifest := fixtureDependencyManifest(t, "example.test/output", "deliver")
	body, err := EncodeDependencyManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, schema := range []uint16{1, 2} {
		old := bytes.Clone(body)
		binary.BigEndian.PutUint16(old, schema)
		if _, err := DecodeDependencyManifest(old); err == nil {
			t.Fatal("removed dependency layout accepted")
		}
		if _, err := DependencyManifestID(old); err == nil {
			t.Fatal("removed dependency layout gained current identity")
		}
	}
}
