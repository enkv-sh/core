package records

import (
	"os"
	"path/filepath"
	"testing"
)

// full_only: false
func TestStockPluginRecoveryPinsBindPrivateModesAndExactBytes(t *testing.T) {
	for _, mode := range []os.FileMode{0400, 0600} {
		t.Run(mode.String(), func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "retained.bin")
			if err := os.WriteFile(path, []byte("abc"), mode); err != nil {
				t.Fatal(err)
			}
			file := StockPluginFile{Path: path, SHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Length: 3}
			pin, body, err := ReadStockPluginRecoveryPin(file, false)
			if err != nil || string(body) != "abc" || pin.Mode != uint32(mode) || pin.Verify() != nil {
				t.Fatal("exact retained private bytes refused", err)
			}
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
			if pin.Verify() == nil {
				t.Fatal("changed file mode retained admission")
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("abd"), 0600); err != nil {
				t.Fatal(err)
			}
			if pin.Verify() == nil {
				t.Fatal("changed same-length bytes retained admission")
			}
		})
	}
}

// full_only: false
func TestStockPluginRecoveryPinsRefuseSDKCredentialPaths(t *testing.T) {
	for _, component := range []string{".aws", ".config"} {
		t.Run(component, func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, component, "owned-synthetic-file")
			if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, []byte("abc"), 0600) != nil {
				t.Fatal("controlled SDK path unavailable")
			}
			file := StockPluginFile{Path: path, SHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Length: 3}
			if _, _, err := ReadStockPluginRecoveryPin(file, false); err == nil {
				t.Fatal("SDK credential subtree entered recovery evidence")
			}
		})
	}
}
