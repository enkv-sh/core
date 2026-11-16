package manifesthost

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	manifest "enkv.sh/sdk/manifest-generator"
)

func statusLiteral(code byte, length uint64) []byte {
	b := append(append([]byte("ENKV/MANIFEST/v2\x00"), bytes.Repeat([]byte{8}, 32)...), code)
	return binary.BigEndian.AppendUint64(b, length)
}

// full_only: false
func TestManifestReplyChecksExactStreamsBeforeReturn(t *testing.T) {
	for _, condition := range []string{"complete", "failure", "unknown", "short-status", "extra-status", "zero-success", "over-limit", "failure-length", "failure-artifact", "short-artifact", "extra-artifact", "wrong-correlation", "cancelled"} {
		t.Run(condition, func(t *testing.T) {
			status := statusLiteral(0, 2)
			body := []byte("{}")
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			switch condition {
			case "failure":
				status = statusLiteral(1, 0)
				body = nil
			case "unknown":
				status = statusLiteral(7, 0)
			case "short-status":
				status = status[:len(status)-1]
			case "extra-status":
				status = append(status, 0)
			case "zero-success":
				status = statusLiteral(0, 0)
			case "over-limit":
				status = statusLiteral(0, manifest.MaxArtifactBytes+1)
			case "failure-length":
				status = statusLiteral(1, 2)
			case "failure-artifact":
				status = statusLiteral(1, 0)
			case "short-artifact":
				body = body[:1]
			case "extra-artifact":
				body = append(body, 0)
			case "wrong-correlation":
				status[17]++
			case "cancelled":
				cancel()
			}
			r, err := readReply(ctx, manifest.ID(bytes.Repeat([]byte{8}, 32)), manifest.MaxArtifactBytes, bytes.NewReader(body), bytes.NewReader(status))
			defer clear(r.Artifact[:cap(r.Artifact)])
			if condition == "complete" {
				if err != nil || r.Failure != "" || string(r.Artifact) != "{}" || len(r.Artifact) != cap(r.Artifact) {
					t.Fatal(r, err)
				}
				return
			}
			if condition == "failure" {
				if err != nil || r.Failure != manifest.InvalidInput || r.Artifact != nil {
					t.Fatal(r, err)
				}
				return
			}
			if err == nil {
				t.Fatal("incomplete exchange accepted", r)
			}
			if condition == "over-limit" && r.Artifact != nil {
				t.Fatal("allocated before status bound")
			}
		})
	}
}

type manifestArtifactReadProbe struct{ calls int }

func (p *manifestArtifactReadProbe) Read([]byte) (int, error) { p.calls++; return 0, io.EOF }

// full_only: false
func TestManifestReplyRejectsExcessBeforeArtifactRead(t *testing.T) {
	for _, maximum := range []uint64{manifest.MaxArtifactBytes, 16420} {
		probe := &manifestArtifactReadProbe{}
		r, err := readReply(t.Context(), manifest.ID(bytes.Repeat([]byte{8}, 32)), maximum, probe, bytes.NewReader(statusLiteral(0, maximum+1)))
		if err == nil || r.Artifact != nil || probe.calls != 0 {
			t.Fatal("operation excess allocated or read artifact", maximum, probe.calls)
		}
	}
	probe := &manifestArtifactReadProbe{}
	r, err := readReply(t.Context(), manifest.ID{}, manifest.MaxArtifactBytes, probe, bytes.NewReader(statusLiteral(0, 2)))
	if err != ErrAdmission || r.Artifact != nil || probe.calls != 0 {
		t.Fatal("uncorrelated exchange reached artifact")
	}
}

// full_only: true
func TestManifestReplyRetainsGenericAllocationCeiling(t *testing.T) {
	for _, tc := range []struct {
		name      string
		length    uint64
		allocated bool
	}{
		{"maximum", manifest.MaxArtifactBytes, true}, {"first-excess", manifest.MaxArtifactBytes + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := &manifestArtifactReadProbe{}
			r, err := readReply(t.Context(), manifest.ID(bytes.Repeat([]byte{8}, 32)), manifest.MaxArtifactBytes, probe, bytes.NewReader(statusLiteral(0, tc.length)))
			defer clear(r.Artifact[:cap(r.Artifact)])
			if err == nil {
				t.Fatal("short artifact or excess accepted")
			}
			if !tc.allocated {
				if r.Artifact != nil || probe.calls != 0 {
					t.Fatal("excess allocated or read artifact")
				}
			} else if uint64(len(r.Artifact)) != tc.length || uint64(cap(r.Artifact)) != tc.length || probe.calls != 1 {
				t.Fatal("allocation was not exact", len(r.Artifact), cap(r.Artifact), probe.calls)
			}
		})
	}
}
