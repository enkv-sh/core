//go:build ((darwin && arm64) || (linux && amd64)) && cgo

package manifesthost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	manifest "enkv.sh/sdk/manifest-generator"
)

func nativeMaximumProjection(t *testing.T) *manifest.Projection {
	t.Helper()
	p := nativeProjection("unused")
	service := strings.Repeat("S", 256)
	p.ServiceFilter = &service
	p.Settings = []byte(`"` + strings.Repeat("s", 16382) + `"`)
	p.Entries = make([]manifest.Entry, 0, 512)
	p.ResolvedEntries = make([]manifest.EntryIdentity, 0, 512)
	targetIndex := 0
	for i := 0; i < 512; i++ {
		e := manifest.Entry{Name: fmt.Sprintf("%03d", i) + strings.Repeat("n", 253), EntryIncarnationID: manifest.ID{byte(i/256 + 1), byte(i)}, Kind: manifest.Secret}
		if i < 129 {
			e.Kind = manifest.Plain
			n := 65536
			if i >= 127 {
				n = 32768
			}
			e.PlainValue = bytes.Repeat([]byte{byte(i)}, n)
		} else {
			count := 2
			if i < 387 {
				count = 3
			}
			e.Destinations = make([]manifest.Destination, count)
			for j := range e.Destinations {
				// Two complete field maxima coexist with the exact public aggregate.
				policyLength := 28728
				if targetIndex < 2 {
					policyLength = manifest.MaxPolicyBytes
				} else if targetIndex < 406 {
					policyLength = 28727
				}
				e.Destinations[j] = manifest.Destination{DestinationID: fmt.Sprintf("%03d", j) + strings.Repeat("d", 253), ServiceContractID: service, ConsumerLocator: strings.Repeat("l", 1024), TargetContractID: strings.Repeat("T", 256), CanonicalTarget: strings.Repeat("t", 1024), TargetData: bytes.Repeat([]byte{0x5a}, 4096), PolicyContractID: strings.Repeat("P", 256), PolicyData: bytes.Repeat([]byte{0x7f}, policyLength), BindingIncarnationID: manifest.ID{7}, EntryIncarnationID: e.EntryIncarnationID, PolicyDigest: manifest.ID{8}, PayloadEncoding: manifest.EncodingRaw, PolicyPresent: true}
				targetIndex++
			}
		}
		p.ResolvedEntries = append(p.ResolvedEntries, manifest.EntryIdentity{Name: e.Name, EntryIncarnationID: e.EntryIncarnationID})
		p.Entries = append(p.Entries, e)
	}
	raw, output, targets := 0, 0, 0
	for _, e := range p.Entries {
		raw += len(e.PlainValue)
		for _, d := range e.Destinations {
			targets++
			output += len(d.DestinationID) + len(d.ServiceContractID) + len(d.ConsumerLocator) + len(d.TargetContractID) + len(d.CanonicalTarget) + len(d.TargetData) + len(d.PolicyContractID) + len(d.PolicyData)
		}
	}
	if raw != 8<<20 || output != 36<<20 || targets != 1024 {
		t.Fatal("joint maximum axes differ", raw, output, targets)
	}
	if f := manifest.Validate(t.Context(), p); f != "" {
		t.Fatal(f)
	}
	return p
}

// full_only: true
func TestNativeManifestMaximumOwnersAndLateFailure(t *testing.T) {
	f := buildNativeFixture(t, true, false, testFormat)
	stage := nativeStageDirectory(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	n, err := NewNative(ctx, f.path, f.metadata, f.dependency)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture owns a format-independent byte pattern. Expected bytes do not
	// use a renderer or runtime verifier to derive the artifact commitment.
	h := sha256.New()
	window := bytes.Repeat([]byte{0xa7}, 49152)
	remaining := int(manifest.MaxArtifactBytes)
	for remaining > 0 {
		count := min(remaining, len(window))
		_, _ = h.Write(window[:count])
		remaining -= count
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	for _, late := range []bool{false, true} {
		t.Run(fmt.Sprint(late), func(t *testing.T) {
			p := nativeMaximumProjection(t)
			defer func() {
				for i := range p.Entries {
					clear(p.Entries[i].PlainValue)
				}
			}()
			if late {
				p.TargetRecipientID = manifest.ID{9}
			}
			result := n.Render(ctx, manifest.Borrow(p))
			defer clear(result.Artifact[:cap(result.Artifact)])
			assertNativeSettled(t, f, stage)
			file, err := os.Open(f.measurement)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(io.LimitReader(file, 4097))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || len(body) > 4096 {
				t.Fatal("unbounded measurement", readErr, closeErr)
			}
			var measured map[string]uint64
			if err := json.Unmarshal(body, &measured); err != nil {
				t.Fatal(err)
			}
			if measured["artifact_capacity"] != manifest.MaxArtifactBytes || measured["disposed"] != 1 || measured["entry_capacity"] != 512 || measured["resolved_capacity"] != 512 || measured["raw_capacity"] != 8<<20 || measured["destination_capacity"] != 1024 || measured["max_policy_capacity"] != manifest.MaxPolicyBytes || measured["entry_size"] != 104 || measured["destination_size"] != 248 || measured["projection_size"] != 312 || measured["projection_backing"] > 46650470 {
				t.Fatal("native owners exceed their derived account", measured)
			}
			if late {
				if result.Failure != manifest.InvalidResult || result.Artifact != nil {
					t.Fatal("late child failure transferred bytes", result.Failure)
				}
			} else {
				metadata, failure := manifest.MeasureArtifact(ctx, result.Artifact)
				if result.Failure != "" || failure != "" || metadata.Length != manifest.MaxArtifactBytes || metadata.Digest != digest || uint64(cap(result.Artifact)) != manifest.MaxArtifactBytes {
					t.Fatal("maximum exact bytes differ", result.Failure, failure)
				}
			}
			if len(p.Entries) != 512 || p.Entries[1].PlainValue[0] != 1 {
				t.Fatal("borrowed parent owners changed before native settlement")
			}
		})
	}
	// Parent and child retain projections while child and host own their complete
	// artifacts. Included/excluded row storage is conservatively overcounted.
	const projection = 312 + 30 + 2*256 + 256 + 16 + 16384 + 512*(104+48+64+256) + 1024*248 + (8 << 20) + (36 << 20)
	const native = 2*projection + 2*246313668 + 4*49152 + 65536
	if projection != 46650470 || native != 586190420 || unsafe.Sizeof(manifest.Projection{}) != 312 || unsafe.Sizeof(manifest.Entry{}) != 104 || unsafe.Sizeof(manifest.Destination{}) != 248 {
		t.Fatal("native backing account differs")
	}
}
