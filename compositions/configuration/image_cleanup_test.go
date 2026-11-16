package configuration

import (
	"errors"
	"os"
	"testing"
)

// full_only: false
func TestTemporaryImageClosePreservesReusedNames(t *testing.T) {
	for _, owner := range []string{"captured-pair", "committed-candidate", "committed-installation", "replaced-private-image"} {
		t.Run(owner, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			var temporary string
			var closeOwner func() error
			switch owner {
			case "captured-pair":
				pair := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
				temporary, closeOwner = pair.Editable.file.Name(), pair.Close
			case "committed-candidate", "committed-installation":
				session, _ := beginSourceEdit(t, JSON, true)
				candidate, _ := stageSourceEdit(t, session, sourceGeneratedJSON+"\n")
				if _, err := session.Commit(t.Context(), candidate); err != nil {
					t.Fatal(err)
				}
				temporary, closeOwner = candidate.editableTemp, session.Close
				if owner == "committed-installation" {
					temporary += ".install"
				}
			case "replaced-private-image":
				pair := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
				image, err := capture(t.Context(), pair.Editable.OriginalPath(), MaxPairBytes)
				if err != nil {
					t.Fatal(err)
				}
				temporary, closeOwner = image.file.Name(), image.Close
				if err := os.Remove(temporary); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("old temporary name is still occupied", err)
			}
			const foreign = "replacement owned by another caller"
			if err := os.WriteFile(temporary, []byte(foreign), 0600); err != nil {
				t.Fatal(err)
			}
			closeErr := closeOwner()
			body, readErr := os.ReadFile(temporary)
			if readErr != nil || string(body) != foreign {
				t.Fatal("closing an old image removed its reused pathname", closeErr, readErr)
			}
			if owner == "replaced-private-image" && closeErr == nil {
				t.Fatal("closing a replaced private image lost its ownership refusal")
			}
		})
	}
}
