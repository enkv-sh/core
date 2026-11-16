package core

import (
	"bytes"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestOutputRouteUsesEntryReplacementBeforeDefault(t *testing.T) {
	entry, inherited := contract.ID{1}, contract.ID{2}
	configuration := contract.OutputConfiguration{DefaultDestinations: []string{"a", "b"}, Routes: []contract.OutputRoute{{EntryIncarnationID: entry, Destinations: []string{"c"}}}}
	if got := resolveOutputRoute(configuration, inherited); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatal("inherited route differs", got)
	}
	if got := resolveOutputRoute(configuration, entry); !reflect.DeepEqual(got, []string{"c"}) {
		t.Fatal("entry replacement merged with default", got)
	}
	configuration.Routes[0].Destinations = []string{}
	if got := resolveOutputRoute(configuration, entry); got == nil || len(got) != 0 {
		t.Fatal("explicit empty replacement fell through", got)
	}
	configuration.Routes[0].Destinations = []string{"a", "b"}
	configuration.DefaultDestinations = []string{"changed"}
	if got := resolveOutputRoute(configuration, entry); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatal("equal-to-default replacement lost its declared meaning", got)
	}
	if got := resolveOutputRoute(configuration, inherited); !reflect.DeepEqual(got, []string{"changed"}) {
		t.Fatal("default edit did not reach inherited entry", got)
	}
}

// full_only: false
func TestManifestPlainProjectionUsesLogicalContent(t *testing.T) {
	for _, input := range []uint8{contract.InputEncodingRaw, contract.InputEncodingBase64} {
		for _, output := range []uint8{contract.OutputEncodingRaw, contract.OutputEncodingBase64} {
			ctx, selected, _, _ := materializationAdmissionFixture(t)
			for _, entry := range selected.image.pages[0].Slots[:2] {
				entry.InputEncoding, entry.OutputEncoding = input, output
				entry.ValueBytes, entry.ContentLength, entry.RetainedLength = []byte("ABC"), 3, 3
				if input == contract.InputEncodingBase64 {
					entry.ValueBytes, entry.RetainedLength = []byte("QUJD"), 4
				}
			}
			projection, failed := buildOwnedManifestSelection(ctx, selected, manifestFixtureRequest())
			if failed.Outcome != 0 || projection == nil || len(projection.Entries) != 2 {
				t.Fatal("selected plain projection refused", failed)
			}
			var owned [][]byte
			for _, entry := range projection.Entries {
				if string(entry.PlainValue) != "ABC" {
					t.Fatal("manifest exposed retained encoding instead of logical content", input, output)
				}
				owned = append(owned, entry.PlainValue[:cap(entry.PlainValue)])
			}
			selected.image.pages[0].Slots[0].ValueBytes[0] = '!'
			for _, entry := range projection.Entries {
				if string(entry.PlainValue) != "ABC" {
					t.Fatal("manifest borrowed retained input", entry.Name)
				}
			}
			releaseManifestProjection(projection)
			for _, value := range owned {
				if !bytes.Equal(value, make([]byte, len(value))) {
					t.Fatal("manifest logical owner was not cleared")
				}
			}
		}
	}
}
