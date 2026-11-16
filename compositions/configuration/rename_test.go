//go:build darwin || linux

package configuration

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func renameUnchangedBytes(t *testing.T, body string, model *Model) []byte {
	t.Helper()
	spans := []Span{model.Spans[model.DomainNameSpan], model.Spans[model.GeneratedSpan]}
	sort.Slice(spans, func(i, j int) bool { return spans[i].Offset < spans[j].Offset })
	var out []byte
	end := int64(0)
	for _, span := range spans {
		if span.Offset < end || span.Length <= 0 || span.Offset+span.Length > int64(len(body)) {
			t.Fatal("invalid rename field location")
		}
		out = append(out, body[end:span.Offset]...)
		out = append(out, []byte("<changed-field>")...)
		end = span.Offset + span.Length
	}
	return append(out, body[end:]...)
}

// full_only: false
func TestLocalDomainRenamePreservesPair(t *testing.T) {
	for _, format := range []Format{JSON, YAML} {
		t.Run(fmt.Sprint(format), func(t *testing.T) {
			editable := sourceSetupJSON
			if format == YAML {
				editable = "# before domain\n" + sourceSetupYAML + "# after settings\n"
			}
			editable = sourceWithPlugins(editable, format, sourcePluginRequirements)
			envelope := sourceEditEnvelope(t, "untouched")
			generated := strings.Replace(sourceGeneratedJSON, `"secrets":{}`, `"secrets":{"untouched" : { "sealed" : "`+base64.StdEncoding.EncodeToString(envelope)+`" }}`, 1)
			pair := writePair(t, editable, generated, format)
			before, err := Parse(t.Context(), pair)
			if err != nil {
				t.Fatal(err)
			}
			path, oldGenerated := pair.Editable.OriginalPath(), pair.Generated.OriginalPath()
			beforeBytes := readSource(t, path)
			session, err := BeginRename(t.Context(), path, format, "staging")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := session.Close(); err != nil {
					t.Error(err)
				}
			})
			candidate, prepared, err := session.StageRename(t.Context())
			if err != nil || prepared == nil || prepared.DomainName != "staging" || prepared.Generated != ".enkv/staging.generated.json" {
				t.Fatal("rename did not stage the requested local name", err)
			}
			delivery, err := session.Commit(t.Context(), candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			editablePath, generatedPath := delivery.Paths()
			if editablePath != path || generatedPath != filepath.Join(filepath.Dir(path), ".enkv/staging.generated.json") {
				t.Fatal("rename moved the editable file or selected another satellite")
			}
			if _, err := os.Lstat(oldGenerated); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rename retained its obsolete satellite", err)
			}
			if readSource(t, generatedPath) != generated {
				t.Fatal("rename changed generated public or encrypted record bytes")
			}
			afterPair, err := Capture(t.Context(), path, format)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := afterPair.Close(); err != nil {
					t.Error(err)
				}
			})
			after, err := Parse(t.Context(), afterPair)
			if err != nil {
				t.Fatal(err)
			}
			if before.FileID != after.FileID || before.DomainID != after.DomainID || before.Provider != after.Provider || before.Store != after.Store || !reflect.DeepEqual(before.Authority, after.Authority) || before.RecoveryEnabled != after.RecoveryEnabled {
				t.Fatal("local rename changed domain, storage or key facts")
			}
			if !bytes.Equal(renameUnchangedBytes(t, beforeBytes, before), renameUnchangedBytes(t, readSource(t, path), after)) {
				t.Fatal("rename changed bytes outside the local name and reference")
			}
			requirePreservedPlugins(t, []byte(readSource(t, path)))
		})
	}
}

// full_only: false
func TestLocalDomainRenameRefusesDestinations(t *testing.T) {
	for _, condition := range []string{"same-name", "invalid-name", "occupied", "symlink", "hardlink", "directory"} {
		t.Run(condition, func(t *testing.T) {
			pair := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
			path := pair.Editable.OriginalPath()
			oldGenerated := pair.Generated.OriginalPath()
			before := readSource(t, path)
			name := "staging"
			destination := filepath.Join(filepath.Dir(path), ".enkv/staging.generated.json")
			switch condition {
			case "same-name":
				name = "prod"
			case "invalid-name":
				name = "../staging"
			case "occupied":
				if err := os.WriteFile(destination, []byte("occupied"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(oldGenerated, destination); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(oldGenerated, destination); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(destination, 0700); err != nil {
					t.Fatal(err)
				}
			}
			session, err := BeginRename(t.Context(), path, JSON, name)
			if session != nil {
				if closeErr := session.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if session != nil || err == nil {
				t.Fatal("rename admitted an invalid or occupied destination")
			}
			if readSource(t, path) != before || readSource(t, oldGenerated) != sourceGeneratedJSON {
				t.Fatal("refused rename changed the original pair")
			}
			if condition == "occupied" && readSource(t, destination) != "occupied" {
				t.Fatal("refused rename overwrote the occupied destination")
			}
		})
	}
}

// full_only: false
func TestLocalDomainRenameCleanupRecovery(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprintf("foreign-%t", foreign), func(t *testing.T) {
			pair := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
			path, obsolete := pair.Editable.OriginalPath(), pair.Generated.OriginalPath()
			session, err := BeginRename(t.Context(), path, JSON, "staging")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := session.Close(); err != nil {
					t.Error(err)
				}
			})
			candidate, _, err := session.StageRename(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			failed := false
			session.io.remove = func(target string) error {
				if target == obsolete {
					failed = true
					return os.ErrPermission
				}
				return os.Remove(target)
			}
			_, commitErr := session.Commit(t.Context(), candidate)
			if !failed || !errors.Is(commitErr, ErrPendingEdit) {
				t.Fatal("obsolete cleanup failure did not retain pending recovery", commitErr)
			}
			var unknown *UnknownEdit
			if errors.As(commitErr, &unknown) && unknown.Observation != nil {
				if err := unknown.Observation.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			pending, err := Capture(t.Context(), path, JSON)
			if pending != nil {
				if closeErr := pending.Close(); closeErr != nil {
					t.Error(closeErr)
				}
				t.Fatal("consumer admitted pending cleanup")
			}
			if !errors.Is(err, ErrPendingEdit) {
				t.Fatal("pending cleanup lost its refusal", err)
			}
			if foreign {
				if err := os.WriteFile(obsolete, []byte("foreign edit"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := readSource(t, path)
			generated := filepath.Join(filepath.Dir(path), ".enkv/staging.generated.json")
			if readSource(t, generated) != sourceGeneratedJSON {
				t.Fatal("rename candidate was not retained exactly")
			}
			delivery, err := RecoverEdit(t.Context(), path, JSON)
			if foreign {
				if delivery != nil || err == nil || readSource(t, obsolete) != "foreign edit" {
					t.Fatal("recovery removed a foreign obsolete image", err)
				}
			} else {
				if delivery == nil || err != nil {
					t.Fatal("exact cleanup recovery failed", err)
				}
				if _, err := os.Lstat(obsolete); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("recovery retained obsolete image", err)
				}
				resolved, err := Capture(t.Context(), path, JSON)
				if err != nil {
					t.Fatal("recovered pair cannot be captured", err)
				}
				if err := resolved.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if readSource(t, path) != before || readSource(t, generated) != sourceGeneratedJSON {
				t.Fatal("cleanup recovery changed candidate bytes")
			}
		})
	}
}
