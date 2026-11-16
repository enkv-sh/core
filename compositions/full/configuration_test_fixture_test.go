package compositionfull

import (
	"os"
	"testing"
)

func protectedConfigurationTestDirectory(t *testing.T) string {
	t.Helper()
	parent := os.Getenv("ENKV_TEST_PROTECTED_FIXTURES")
	if parent == "" {
		t.Fatal("protected fixtures require the test runner's managed private directory")
	}
	dir, err := os.MkdirTemp(parent, "configuration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error("protected fixture cleanup", err)
		}
	})
	return dir
}
