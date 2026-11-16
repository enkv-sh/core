package recovery

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"enkv.sh/crypto/testsupport/installedarchive"
)

// full_only: false
func TestAWSResponderMissingObjectsKeepVendorEnvelope(t *testing.T) {
	archive := installedarchive.Load(t, "aws")
	remote := NewRecoveryResponder(t, archive, installedarchive.RecoveryResources{})
	transport := relayTestTransport(t, remote.Address(), remote.Certificate())
	defer transport.CloseIdleConnections()
	for _, suffix := range []string{"missing", "missing-configuration", "missing-support"} {
		q, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://s3."+archive.Location.Region+".amazonaws.com/"+archive.Location.Bucket+"/"+archive.Location.PrefixBeforeHEAD+"/"+suffix, nil)
		if err != nil {
			t.Fatal(err)
		}
		q.Header.Set("Authorization", "synthetic signed request")
		q.Header.Set("X-Amz-Expected-Bucket-Owner", archive.Location.ExpectedOwner)
		response, err := transport.RoundTrip(q)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || response.StatusCode != 404 || response.Header.Get("Content-Type") != "application/xml" || !strings.Contains(string(body), "<Code>NoSuchKey</Code>") {
			t.Fatal("missing object vendor envelope differs")
		}
	}
	if remote.Counts().Reads != 3 || remote.Counts().Unknown != 0 || remote.ExternalMutations() != 0 {
		t.Fatal("missing object controls changed remote effects")
	}
}

// full_only: false
func TestRemoteObjectRemovalDerivesExactFileTotals(t *testing.T) {
	// Each file has an 8-byte magic and 8/4/8-byte lengths. Literal payloads
	// below yield 34, 33 and 35 bytes, independently of archive metadata.
	objects := []installedarchive.Object{
		{Key: "a", TokenWire: []byte{1, 2}, Body: []byte{3, 4, 5}},
		{Key: "bb", TokenWire: []byte{6, 7, 8}},
		{Key: "ccc", Body: []byte{9, 10, 11, 12}},
	}
	for _, initial := range []uint64{0, 102, ^uint64(0)} {
		for _, row := range []struct {
			key   string
			count int
			bytes uint64
		}{
			{"a", 2, 68}, {"bb", 2, 69}, {"ccc", 2, 67}, {"absent", 3, 102},
		} {
			t.Run(fmt.Sprintf("initial=%d/key=%s", initial, row.key), func(t *testing.T) {
				original := Archive{Objects: objects, ObjectCount: 3, ObjectFileBytes: initial}
				after := withoutRemoteObject(original, row.key)
				if after.ObjectCount != row.count || len(after.Objects) != row.count || after.ObjectFileBytes != row.bytes {
					t.Fatal("remaining object-file total differs", after.ObjectCount, after.ObjectFileBytes)
				}
				if original.ObjectFileBytes != initial || len(original.Objects) != 3 {
					t.Fatal("removal changed caller archive")
				}
				for _, object := range after.Objects {
					if object.Key == row.key {
						t.Fatal("removed object remains")
					}
				}
			})
		}
	}
	after := withoutRemoteObject(Archive{Objects: objects[:1], ObjectCount: 1, ObjectFileBytes: 0}, "a")
	if after.ObjectCount != 0 || len(after.Objects) != 0 || after.ObjectFileBytes != 0 {
		t.Fatal("last object removal did not yield empty archive", after.ObjectFileBytes)
	}
	after = withoutRemoteObject(after, "absent")
	if after.ObjectCount != 0 || after.ObjectFileBytes != 0 {
		t.Fatal("empty removal changed accounting")
	}
}
