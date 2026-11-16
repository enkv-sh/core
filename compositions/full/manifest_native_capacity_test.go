//go:build (darwin && arm64) || (linux && amd64)

package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

// The file boundary receives complete opaque bytes after Reader issuance.
// Projection and child-owner maxima are checked at their separate boundaries.
func manifestNativeMaximumIssuance(t *testing.T, format string) core.PublicManifestResult {
	t.Helper()
	scope := manifestTestScope(manifest.Selection{TargetMode: manifest.ExactRecipient, EntryMode: manifest.ExactNames})
	scope.FormatContractID = format
	scope.ConfigContractID = strings.Repeat("C", 256)
	scope.Settings = []byte(`"` + strings.Repeat("s", 16382) + `"`)
	service := strings.Repeat("S", 256)
	scope.ServiceFilter = &service
	observation := manifest.Observation{DomainID: manifest.ID{1}, HEADRevisionID: manifest.ID{2}, SnapshotID: manifest.ID{3}}
	included := make([]manifest.EntryIdentity, 512)
	for i := range included {
		included[i] = manifest.EntryIdentity{Name: fmt.Sprintf("%03d", i) + strings.Repeat("n", 253), EntryIncarnationID: manifest.ID{byte(i/256 + 1), byte(i)}}
	}
	artifact := bytes.Repeat([]byte{0xa7}, int(manifest.MaxArtifactBytes))
	digest := sha256.Sum256(artifact)
	payload := &contract.ManifestPayload{Renderer: scope.Renderer, FormatContractID: scope.FormatContractID, ConfigContractID: scope.ConfigContractID, Settings: scope.Settings, Selection: scope.Selection, ServiceFilter: scope.ServiceFilter, Observation: observation, TargetRecipientID: contract.ID{4}, IncludedEntries: included, ExcludedEntries: []manifest.ExcludedEntry{}, ArtifactLength: uint64(len(artifact)), ArtifactDigest: contract.ID(digest), EvidenceLimit: manifest.EvidenceLimit}
	return core.PublicManifestResult{Context: core.ReaderOperationContext{Operation: contract.ReaderManifestOperation, RequestID: contract.ID{8}, OperationID: contract.ID{9}, ExpectedDomain: contract.ID{1}}, Result: core.Result{Outcome: core.ObservedCurrent, ObservedRevision: contract.ID{2}, ObservedSnapshotID: contract.ID{3}, Evidence: core.AuthenticatedClosure}, StateResult: contract.ReaderSuccess, TargetRecipientID: payload.TargetRecipientID, Observation: &payload.Observation, RequestScope: scope, Payload: payload, Artifact: artifact}
}

// full_only: true
func TestManifestNativeMaximumArtifactOwnershipAndReadback(t *testing.T) {
	for _, profile := range []string{strings.Repeat("F", 256)} {
		t.Run(profile, func(t *testing.T) {
			for _, lateFailure := range []bool{false, true} {
				t.Run(map[bool]string{false: "complete", true: "late-installed-read"}[lateFailure], func(t *testing.T) {
					issuance := manifestNativeMaximumIssuance(t, profile)
					owned := issuance.Artifact
					length, digest := len(owned), issuance.Payload.ArtifactDigest
					path := filepath.Join(t.TempDir(), "maximum.json")
					target, initial := newManifestFileTarget(path, nil, nil)
					if target == nil {
						t.Fatal("maximum native target refused", initial)
					}
					nativeWrite, nativeRead, nativeClose := target.io.write, target.io.read, target.io.close
					writes, closes := 0, 0
					var window *byte
					readBytes := map[ManifestFileStage]int{}
					eof := map[ManifestFileStage]bool{}
					failed := false
					target.io.write = func(file *os.File, body []byte) (int, error) {
						writes++
						if len(body) != length || cap(body) != length || &body[0] != &owned[0] {
							t.Error("native write did not borrow the exact encoder backing")
						}
						return nativeWrite(file, body)
					}
					target.io.read = func(file *os.File, body []byte, stage ManifestFileStage) (int, error) {
						if cap(body) > 64*1024 || len(body) == 0 {
							t.Fatal("readback escaped its bounded window")
						}
						if window == nil {
							window = &body[0]
						} else if window != &body[0] {
							t.Fatal("candidate and installed readback used different backing")
						}
						if lateFailure && stage == ManifestInstalledVerifyStage && readBytes[stage] == length {
							failed = true
							return 0, errors.New("synthetic late installed read")
						}
						n, err := nativeRead(file, body, stage)
						readBytes[stage] += n
						if errors.Is(err, io.EOF) {
							eof[stage] = true
						}
						return n, err
					}
					target.io.close = func(file *os.File, stage ManifestFileStage) error {
						closes++
						if owned[0] != 0xa7 {
							t.Error("artifact released before native close settlement")
						}
						return nativeClose(file, stage)
					}
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
					defer cancel()
					result := installConfigurationManifest(ctx, issuance, target, initial)
					issuance.Artifact = nil
					if result.Issuance.Artifact != nil || writes != 1 || closes != 5 || !eof[ManifestCandidateVerifyStage] || readBytes[ManifestInstalledVerifyStage] != length || result.Delivery.Artifact == nil || result.Delivery.Artifact.Digest != digest || result.Delivery.Artifact.Length != uint64(length) {
						t.Fatal("maximum artifact ownership or native settlement differs", writes, closes, readBytes, result.Delivery)
					}
					if lateFailure {
						if !failed || result.Delivery.Replacement != ManifestReplaced || result.Delivery.CandidateVerification != ManifestVerified || result.Delivery.InstalledVerification != ManifestVerificationNotObserved || result.Delivery.NativeCompletion != ManifestNativeIncomplete || result.Delivery.CandidateCleanup != ManifestCandidateRenamed || result.Delivery.Failure == nil || result.Delivery.Failure.Stage != ManifestInstalledVerifyStage {
							t.Fatal("late maximum read failure lost known native facts", result.Delivery)
						}
					} else if !eof[ManifestInstalledVerifyStage] || result.Delivery.NativeCompletion != ManifestNativeComplete || result.Delivery.Failure != nil {
						t.Fatal("maximum native completion failed", result.Delivery)
					}
					for _, b := range owned {
						if b != 0 {
							t.Fatal("owning file boundary did not clear its complete artifact after settlement")
						}
					}
					t.Logf("artifact_bytes=%d selected_entries=512 readback_capacity=65536 native_closes=%d late_failure=%t", length, closes, lateFailure)
				})
			}
		})
	}
}
