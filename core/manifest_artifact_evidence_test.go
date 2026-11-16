package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

// full_only: false
func TestManifestArtifactEvidenceDoesNotClaimFormatCorrespondence(t *testing.T) {
	projection := manifestRendererProjection()
	const wrong = "selected:a=eHl6\n"
	renderer := func(context.Context, manifest.View) manifest.Result {
		owned := make([]byte, len(wrong))
		copy(owned, wrong)
		return manifest.Result{Artifact: owned}
	}
	body, metadata, failed := renderManifestArtifact(t.Context(), projection, renderer)
	defer clear(body)
	// Python hashlib.sha256(b"selected:a=eHl6\n"); no renderer or runtime codec
	// supplies this expected commitment.
	want := contract.ID{0xaf, 0xe3, 0xea, 0x70, 0xfd, 0xde, 0x47, 0xe8, 0x51, 0xc8, 0x66, 0x64, 0xb9, 0x63, 0xc5, 0x6a, 0x67, 0xd7, 0x83, 0x87, 0xf1, 0x6c, 0x23, 0x58, 0x71, 0x9d, 0x6a, 0x6f, 0xd6, 0xd2, 0xfa, 0x20}
	if failed.Outcome != 0 || string(body) != wrong || metadata.Length != uint64(len(wrong)) || contract.ID(metadata.Digest) != want || manifest.EvidenceLimit != "authorized-input-and-exact-bytes" {
		t.Fatal("common exact-byte evidence changed", failed, metadata)
	}
	// The author's consumer decodes both the control and the wrong returned value.
	consume := func(body []byte) ([]byte, bool) {
		prefix, encoded, ok := strings.Cut(string(body), ":a=")
		if !ok || prefix != "selected" || !strings.HasSuffix(encoded, "\n") {
			return nil, false
		}
		value, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(encoded, "\n"))
		return value, err == nil
	}
	control, ok := consume([]byte("selected:a=YWJj\n"))
	if !ok || !bytes.Equal(control, projection.Entries[0].PlainValue) {
		t.Fatal("independent consumer control failed")
	}
	value, ok := consume(body)
	if !ok || bytes.Equal(value, projection.Entries[0].PlainValue) {
		t.Fatal("independent consumer did not expose wrong selected content")
	}
}
