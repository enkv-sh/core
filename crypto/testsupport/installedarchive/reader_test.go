package installedarchive

import (
	"bytes"
	"encoding/json"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestReaderArchivesKeepIndependentBasisAndMixedNames(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			fixture, basis := LoadReader(t, family)
			var public struct {
				Schema     int    `json:"schema"`
				Kind       string `json:"kind"`
				Descriptor []byte `json:"descriptor"`
			}
			if json.Unmarshal(basis, &public) != nil || public.Schema != 2 || public.Kind != "genesis" {
				t.Fatal("independent setup basis grammar differs")
			}
			descriptor, err := contract.DecodeGenesisDescriptorCore(public.Descriptor)
			if err != nil || descriptor.DomainID != fixture.Archive.Domain || descriptor.Provider != fixture.Archive.Family || descriptor.AuthorityRecipientID != fixture.Archive.AuthorityID {
				t.Fatal("separate basis does not describe selected fixture")
			}
			if fixture.Values[0].Name != "" || len(fixture.Values[0].Bytes) != 0 || fixture.Values[1].Name != "a/\n雪" || !bytes.Equal(fixture.Values[1].Bytes, []byte{0, 10, 65}) || fixture.Values[2].Name != "encoded" || !bytes.Equal(fixture.Values[2].Bytes, []byte("enkv first secret test value")) || fixture.Values[3].Name != "secret" || !bytes.Equal(fixture.Values[3].Bytes, fixture.Values[2].Bytes) {
				t.Fatal("mixed fixture literal differs")
			}
			parts, err := fixture.Archive.SelectedParts()
			if err != nil {
				t.Fatal(err)
			}
			var root format.Root
			for _, part := range parts {
				if part.Kind == "root" {
					root, err = format.DecodeRoot(part.Body)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if len(root.Names) != 4 || root.SecretCount != 2 || root.OutputConfiguration.BindingCount != 5 {
				t.Fatal("selected mixed fixture lost profile groups")
			}
			// Repeated loads must not share mutable body or independently supplied basis.
			fixture.Archive.Objects[0].Body[0] ^= 1
			basis[0] ^= 1
			next, nextBasis := LoadReader(t, family)
			if bytes.Equal(fixture.Archive.Objects[0].Body, next.Archive.Objects[0].Body) || bytes.Equal(basis, nextBasis) {
				t.Fatal("fixed fixture returned shared mutable backing")
			}
		})
	}
}
