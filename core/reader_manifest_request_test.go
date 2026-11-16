package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

// full_only: false
func TestReaderManifestRefusesNilEngine(t *testing.T) {
	var e *ReaderEngine
	got := e.Manifest(context.Background(), contract.ID{1}, contract.ManifestRequest{TargetMode: manifest.ExactRecipient, EntryMode: manifest.ExactNames, TargetRecipientID: contract.ID{2}, EntryNames: []string{}})
	if got.Artifact != nil || got.Payload != nil || got.FailureReason != contract.ReasonInvalidInput {
		t.Fatal(fmt.Sprint(got))
	}
}

// full_only: false
func TestManifestOperationBindsExactRequestAndOperation(t *testing.T) {
	original := manifestFixtureRequest()
	original.TargetMode = manifest.ExactRecipient
	original.EntryMode = manifest.ExactNames
	original.TargetRecipientID = contract.ID{2}
	original.EntryNames = []string{"", "snow/雪"}
	base := manifestRequestDigest(contract.ID{1}, original)
	for _, change := range []struct {
		nonce  contract.ID
		mutate func(*contract.ManifestRequest)
	}{
		{contract.ID{3}, func(*contract.ManifestRequest) {}},
		{contract.ID{1}, func(r *contract.ManifestRequest) { r.TargetRecipientID = contract.ID{4} }},
		{contract.ID{1}, func(r *contract.ManifestRequest) { r.EntryNames = []string{"snow/雪"} }},
		{contract.ID{1}, func(r *contract.ManifestRequest) { r.EntryNames = []string{"", "snow/雪", "zero"} }},
	} {
		changed := original
		change.mutate(&changed)
		if manifestRequestDigest(change.nonce, changed) == base {
			t.Fatal("request identity omitted a semantic field")
		}
	}
	for _, change := range []func(*contract.ManifestRequest){
		func(r *contract.ManifestRequest) {
			r.TargetMode = manifest.CurrentAuthority
			r.TargetRecipientID = contract.ID{}
		},
		func(r *contract.ManifestRequest) { r.EntryMode = manifest.AllAuthorized; r.EntryNames = nil },
		func(r *contract.ManifestRequest) { p := "private-service/v1"; r.ServiceFilter = &p },
		func(r *contract.ManifestRequest) { p := "private-service/v2"; r.ServiceFilter = &p },
		func(r *contract.ManifestRequest) { r.FormatContractID += "different" }, func(r *contract.ManifestRequest) { r.ConfigContractID += "different" }, func(r *contract.ManifestRequest) { r.Settings = []byte(`{"x":1}`) },
		func(r *contract.ManifestRequest) { r.Renderer.Name += "different" }, func(r *contract.ManifestRequest) { r.Renderer.Version = "2.0.0" }, func(r *contract.ManifestRequest) { r.Renderer.ProtocolID[0]++ }, func(r *contract.ManifestRequest) { r.Renderer.DescriptorID[0]++ }, func(r *contract.ManifestRequest) { r.Renderer.ExecutorID[0]++ }, func(r *contract.ManifestRequest) { r.Renderer.ArtifactContractID[0]++ }, func(r *contract.ManifestRequest) { r.Renderer.DependencyManifestID[0]++ }, func(r *contract.ManifestRequest) { r.Renderer.ArtifactID[0]++ }, func(r *contract.ManifestRequest) { r.Renderer.ArtifactSHA256[0]++ }, func(r *contract.ManifestRequest) { r.Renderer.ArtifactLength++ },
	} {
		changed := original
		change(&changed)
		if manifestRequestDigest(contract.ID{1}, changed) == base {
			t.Fatal("tagged scope omitted from request identity")
		}
	}
	a := readerAdmission{operation: contract.ReaderManifestOperation, request: base, domain: contract.ID{3}, deadline: time.Unix(1, 0)}
	one := readerOperationID(a, contract.ID{4}, contract.ID{5})
	a.operation = contract.ReaderCompareOperation
	if readerOperationID(a, contract.ID{4}, contract.ID{5}) == one {
		t.Fatal("operation identity omitted operation")
	}

	first, err := contract.OwnManifestRequest(original)
	if err != nil {
		t.Fatal(err)
	}
	original.EntryNames = []string{"snow/雪", ""}
	second, err := contract.OwnManifestRequest(original)
	if err != nil {
		t.Fatal(err)
	}
	if manifestRequestDigest(contract.ID{1}, first) != manifestRequestDigest(contract.ID{1}, second) {
		t.Fatal("exact name capture did not canonicalize order")
	}
}
