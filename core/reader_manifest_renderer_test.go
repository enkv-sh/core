package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

func manifestRendererProjection() *manifest.Projection {
	return &manifest.Projection{Schema: manifest.Schema, FormatContractID: "private-format/v1", ConfigContractID: "private-settings/v1", Settings: []byte(`{}`),
		Observation: manifest.Observation{DomainID: manifest.ID{1}, HEADRevisionID: manifest.ID{2}, SnapshotID: manifest.ID{3}}, TargetRecipientID: manifest.ID{4},
		Selection: manifest.Selection{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized},
		Entries:   []manifest.Entry{{Name: "a", EntryIncarnationID: manifest.ID{5}, Kind: manifest.Plain, PlainValue: []byte("abc")}}, ResolvedEntries: []manifest.EntryIdentity{{Name: "a", EntryIncarnationID: manifest.ID{5}}}, ExcludedEntries: []manifest.ExcludedEntry{}}
}

// full_only: false
func TestManifestRendererReturnChecksCommonByteContract(t *testing.T) {
	for _, condition := range []string{"complete", "malformed", "wrong-observation", "wrong-plain-copy", "missing-row", "trailing", "spare-capacity", "missing-artifact", "unknown-failure", "failure-with-artifact", "cancel-after-render"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p := manifestRendererProjection()
			var supplied []byte
			renderer := func(ctx context.Context, v manifest.View) manifest.Result {
				r := manifestFixtureRender(ctx, v)
				if r.Failure != "" {
					t.Fatal("fixture rendering refused", r.Failure)
				}
				switch condition {
				case "malformed":
					r.Artifact[0] = '['
				case "wrong-observation", "missing-row":
					r.Artifact[0] = 'x'
				case "wrong-plain-copy":
					e, _ := v.Entry(0)
					var window [3]byte
					n, f := e.CopyPlain(0, window[:])
					if n != 3 || f != "" {
						t.Fatal("plain view refused")
					}
					window[0] = 'x'
					r.Artifact[0] = window[0]
				case "trailing":
					old := r.Artifact
					r.Artifact = make([]byte, len(old)+1)
					copy(r.Artifact, old)
					r.Artifact[len(old)] = ' '
					clear(old)
				case "spare-capacity":
					old := r.Artifact
					larger := make([]byte, len(old)+8)
					copy(larger, old)
					clear(old)
					for i := len(old); i < len(larger); i++ {
						larger[i] = 0xff
					}
					r.Artifact = larger[:len(old)]
				case "missing-artifact":
					clear(r.Artifact)
					r.Artifact = nil
				case "unknown-failure":
					r.Failure = "untrusted callback text"
				case "failure-with-artifact":
					r.Failure = manifest.InvalidInput
				case "cancel-after-render":
					cancel()
				}
				supplied = r.Artifact[:cap(r.Artifact)]
				return r
			}
			body, metadata, f := renderManifestArtifact(ctx, p, renderer)
			if condition == "complete" || condition == "malformed" || condition == "wrong-observation" || condition == "wrong-plain-copy" || condition == "missing-row" || condition == "trailing" {
				if f.Outcome != 0 || len(body) == 0 || len(body) != cap(body) || unsafe.SliceData(body) != unsafe.SliceData(supplied) || metadata.Length != uint64(len(body)) || metadata.Digest != sha256.Sum256(body) {
					t.Fatal("complete exact byte backing was not transferred", f)
				}
				clear(body)
				return
			}
			want := contract.ReasonInvalidInput
			if condition == "cancel-after-render" {
				want = contract.ReasonCancelled
			}
			if body != nil || metadata != (manifest.Metadata{}) || f.diagnostic != want || f.Outcome == 0 {
				t.Fatal("invalid common return admitted", f)
			}
			if bytes.Count(supplied, []byte{0}) != len(supplied) {
				t.Fatal("refused artifact capacity was not cleared")
			}
			if string(p.Entries[0].PlainValue) != "abc" {
				t.Fatal("view copy changed verifier expectation")
			}
		})
	}
}

// full_only: false
func TestManifestRendererFailureMapsClosedCodes(t *testing.T) {
	for _, test := range []struct {
		code   manifest.Failure
		reason contract.DiagnosticReason
	}{
		{manifest.InvalidInput, contract.ReasonInvalidInput}, {manifest.InvalidResult, contract.ReasonInvalidInput}, {manifest.InvalidUTF8, contract.ReasonInvalidUTF8}, {manifest.LimitExceeded, contract.ReasonLimitExceeded}, {manifest.Cancelled, contract.ReasonCancelled}, {manifest.Expired, contract.ReasonExpired},
	} {
		t.Run(string(test.code), func(t *testing.T) {
			body, metadata, f := renderManifestArtifact(t.Context(), manifestRendererProjection(), func(context.Context, manifest.View) manifest.Result { return manifest.Result{Failure: test.code} })
			if body != nil || metadata != (manifest.Metadata{}) || f.Outcome == 0 || f.diagnostic != test.reason {
				t.Fatal("failure mapping changed", f)
			}
		})
	}
}

// full_only: false
func TestManifestRendererValidatesBeforeCallback(t *testing.T) {
	for _, condition := range []string{"nil-renderer", "nil-projection", "invalid-utf8", "limit"} {
		t.Run(condition, func(t *testing.T) {
			p := manifestRendererProjection()
			calls := 0
			renderer := manifest.Renderer(func(context.Context, manifest.View) manifest.Result {
				calls++
				return manifest.Result{Failure: manifest.InvalidInput}
			})
			want := contract.ReasonInvalidInput
			switch condition {
			case "nil-renderer":
				renderer = nil
			case "nil-projection":
				p = nil
			case "invalid-utf8":
				p.Entries[0].Name = string([]byte{255})
				want = contract.ReasonInvalidUTF8
			case "limit":
				p.Entries[0].Name = strings.Repeat("x", 257)
				want = contract.ReasonLimitExceeded
			}
			body, _, f := renderManifestArtifact(t.Context(), p, renderer)
			if body != nil || f.diagnostic != want || calls != 0 {
				t.Fatal("invalid projection reached renderer", f, calls)
			}
		})
	}
}

// full_only: false
func TestManifestProjectionReleaseClearsOwnedPlainCapacity(t *testing.T) {
	p := manifestRendererProjection()
	owned := make([]byte, 16)
	for i := range owned {
		owned[i] = 255
	}
	p.Entries[0].PlainValue = owned[:3]
	releaseManifestProjection(p)
	if bytes.Count(owned, []byte{0}) != len(owned) || p.Entries != nil || p.ResolvedEntries != nil || p.ExcludedEntries != nil {
		t.Fatal("released projection retains owned backing")
	}
}

func manifestFixtureRender(_ context.Context, v manifest.View) manifest.Result {
	var plain [3]byte
	e, ok := v.Entry(0)
	if ok {
		_, _ = e.CopyPlain(0, plain[:])
	}
	body := make([]byte, len("opaque:")+len(plain))
	copy(body, "opaque:")
	copy(body[len("opaque:"):], plain[:])
	return manifest.Result{Artifact: body}
}

func manifestFixtureRequest() contract.ManifestRequest {
	return contract.ManifestRequest{Renderer: contract.ManifestRendererSelection{Name: "private-renderer", Version: "1.0.0", ProtocolID: contract.ID{1}, DescriptorID: contract.ID{2}, ExecutorID: contract.ID{3}, ArtifactContractID: contract.ID{4}, DependencyManifestID: contract.ID{5}, ArtifactID: contract.ID{6}, ArtifactSHA256: contract.ID{7}, ArtifactLength: 1}, FormatContractID: "private-format/v1", ConfigContractID: "private-settings/v1", Settings: []byte(`{}`), TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}
}
