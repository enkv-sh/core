package core

import (
	"testing"

	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

// full_only: false
func TestManifestRequestBindsEachSemanticServiceValue(t *testing.T) {
	providers := []string{"private-service/v1", "another-service/v1", "unlisted-service/v9"}
	request := manifestFixtureRequest()
	ids := []contract.ID{manifestRequestDigest(contract.ID{1}, request)}
	for _, provider := range providers {
		request.ServiceFilter = &provider
		owned, err := contract.OwnManifestRequest(request)
		if err != nil {
			t.Fatal("supported provider request refused", err)
		}
		current := manifestRequestDigest(contract.ID{1}, owned)
		for _, prior := range ids {
			if current == prior {
				t.Fatal("request identity does not distinguish the exact provider scope", provider)
			}
		}
		ids = append(ids, current)
	}
}

// full_only: false
func TestManifestPartitionRejectsCrossSetIncarnationWithMatchingUnion(t *testing.T) {
	m := manifestRendererProjection()
	incarnation := manifest.ID{99}
	m.ExcludedEntries = []manifest.ExcludedEntry{{Name: "z", EntryIncarnationID: incarnation, Reason: manifest.NoOutput}}
	m.ResolvedEntries = append(m.ResolvedEntries, manifest.EntryIdentity{Name: "z", EntryIncarnationID: incarnation})
	body, _, failure := renderManifestArtifact(t.Context(), m, manifestFixtureRender)
	if failure.Outcome != 0 || len(body) == 0 {
		t.Fatal("valid distinct partition refused", failure)
	}
	clear(body)
	shared := m.Entries[len(m.Entries)-1].EntryIncarnationID
	m.ExcludedEntries[0].EntryIncarnationID = shared
	m.ResolvedEntries[len(m.ResolvedEntries)-1].EntryIncarnationID = shared
	body, _, failure = renderManifestArtifact(t.Context(), m, manifestFixtureRender)
	if body != nil || failure.Outcome == 0 || failure.diagnostic != contract.ReasonInvalidInput {
		t.Fatal("cross-set incarnation overlap admitted despite the exact union count", failure)
	}
}
