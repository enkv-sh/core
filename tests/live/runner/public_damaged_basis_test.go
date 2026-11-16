package core

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// full_only: false
func TestPublicDamagedPortableBasisPreservesStablePair(t *testing.T) {
	const reference = ".enkv/prod.generated.json"
	for _, kind := range []string{"genesis", "successor"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			source := filepath.Join(directory, "source.json")
			publicWriteSource(t, source, map[string]any{"domain": map[string]any{"name": "prod"}, "generated": reference})
			basis := map[string]any{"kind": kind, "descriptor": []byte{1}}
			if kind == "successor" {
				basis = map[string]any{"kind": kind, "control": []byte{1}, "selection": []byte{2}, "enrollment": []any{}}
			}
			generated, err := json.Marshal(map[string]any{"public_basis": basis})
			if err != nil || os.Mkdir(filepath.Join(directory, ".enkv"), 0700) != nil || os.WriteFile(filepath.Join(directory, reference), generated, 0600) != nil {
				t.Fatal("public pair fixture unavailable")
			}
			original := publicSourceImage(t, source)
			copied := publicPortablePair(t, source, t.TempDir())
			publicDamagePortableBasis(t, copied)
			editable, err := os.ReadFile(copied)
			if err != nil || !bytes.Equal(editable, original.Files[source]) {
				t.Error("basis damage changed editable source or stable reference")
			}
			inventory, err := publicSourceInventory(filepath.Dir(copied))
			if err != nil || !slices.Equal(inventory, original.Inventory) {
				t.Error("basis damage changed pair inventory")
			}
			basis["kind"] = "damaged"
			want, err := json.Marshal(map[string]any{"public_basis": basis})
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(filepath.Dir(copied), reference))
			if err != nil || !bytes.Equal(got, want) {
				t.Error("stable satellite does not contain only the intended basis damage")
			}
			for _, path := range []string{copied, filepath.Join(filepath.Dir(copied), reference)} {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != 0400 {
					t.Error("damaged portable pair lost read-only permissions")
				}
			}
			publicImageUnchanged(t, original)
		})
	}
}
