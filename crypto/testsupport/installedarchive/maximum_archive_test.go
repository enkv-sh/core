package installedarchive

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// full_only: true
// Exercises the complete maximum-current-intent archive at each refusal boundary.
func TestMaximumIntentArchiveRejectsGZIPDamageAndBounds(t *testing.T) {
	if MaximumIntentArchiveBodyBytes != 537202688 || MaximumIntentArchiveJSONBytes != 720465592 || MaximumIntentArchiveGZIPBytes != 67108864 || maximumIntentArchiveObjects != 259 {
		t.Fatal("fixed maximum archive bounds differ")
	}
	encoded, err := os.ReadFile(filepath.Join("testdata", "maximum-intents-aws.json.gz"))
	if err != nil {
		t.Fatal("maximum archive baseline unavailable")
	}
	if _, err := decodeMaximumIntentFixture(bytes.NewReader(encoded), MaximumIntentArchiveGZIPBytes); err != nil {
		t.Fatal("valid maximum single-member baseline refused")
	}
	if len(encoded) < 18 {
		t.Fatal("maximum gzip baseline has no complete trailer")
	}
	var second bytes.Buffer
	writer := gzip.NewWriter(&second)
	if _, err := writer.Write([]byte("{}")); err != nil {
		t.Fatal("second member construction failed")
	}
	if err := writer.Close(); err != nil {
		t.Fatal("second member completion failed")
	}
	// Sequential cases decode the actual fixture. No maximum-sized padding is
	// allocated; the first-excess intake case uses the same member at its size.
	for _, name := range []string{"checksum", "size", "truncated-byte", "truncated-trailer", "second-member", "trailing-byte"} {
		t.Run(name, func(t *testing.T) {
			body := bytes.Clone(encoded)
			switch name {
			case "checksum":
				body[len(body)-8] ^= 1
			case "size":
				body[len(body)-4] ^= 1
			case "truncated-byte":
				body = body[:len(body)-1]
			case "truncated-trailer":
				body = body[:len(body)-8]
			case "second-member":
				body = append(body, second.Bytes()...)
			case "trailing-byte":
				body = append(body, 0)
			}
			if _, err := decodeMaximumIntentFixture(bytes.NewReader(body), MaximumIntentArchiveGZIPBytes); err == nil {
				t.Fatal("damaged maximum gzip envelope accepted")
			}
		})
	}
	if _, err := decodeMaximumIntentFixture(bytes.NewReader(encoded), int64(len(encoded))); err != nil {
		t.Fatal("exact compressed intake limit refused")
	}
	if _, err := decodeMaximumIntentFixture(bytes.NewReader(encoded), int64(len(encoded)-1)); err == nil {
		t.Fatal("compressed intake first excess accepted")
	}
}

// full_only: true
// Exercises the complete maximum-current-intent archive at each refusal boundary.
func TestMaximumIntentArchiveRejectsIncompleteSelectedClosure(t *testing.T) {
	archive := ReadMaximumIntentFixture(t, filepath.Join("testdata", "maximum-intents-aws.json.gz"))
	fixture := RecoveryFixture{Archive: archive, Secrets: 128}
	encoded, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal("maximum baseline JSON unavailable")
	}
	var bodyBytes int64
	for _, object := range archive.Objects {
		bodyBytes += int64(len(object.Body))
	}
	if bodyBytes < 1 || len(archive.Objects) < 2 {
		t.Fatal("maximum baseline physical closure is empty")
	}
	if _, err := decodeRecoveryFixtureBounded(bytes.NewReader(encoded), int64(len(encoded)), bodyBytes, true); err != nil {
		t.Fatal("exact JSON and body limits refused the valid baseline")
	}
	// The existing bounded decoder is tested at actual fixture sizes, including
	// the first byte beyond each gate, without allocating the absolute JSON ceiling.
	if _, err := decodeRecoveryFixtureBounded(bytes.NewReader(encoded), int64(len(encoded)-1), bodyBytes, true); err == nil {
		t.Fatal("expanded JSON first excess accepted")
	}
	if _, err := decodeRecoveryFixtureBounded(bytes.NewReader(encoded), int64(len(encoded)), bodyBytes-1, true); err == nil {
		t.Fatal("selected body first excess accepted")
	}
	retotal := func(a *Archive) {
		a.ObjectCount = len(a.Objects)
		a.ObjectFileBytes = 0
		for _, object := range a.Objects {
			a.ObjectFileBytes += uint64(28 + len(object.Key) + len(object.TokenWire) + len(object.Body))
		}
	}
	for _, name := range []string{"missing-object", "extra-object", "secrets", "unexpected-values", "unexpected-oracles"} {
		t.Run(name, func(t *testing.T) {
			current := fixture
			current.Archive.Objects = append([]Object(nil), archive.Objects...)
			switch name {
			case "missing-object":
				current.Archive.Objects = current.Archive.Objects[:len(current.Archive.Objects)-1]
			case "extra-object":
				body := []byte{0}
				digest := sha256.Sum256(body)
				current.Archive.Objects = append(current.Archive.Objects, Object{Key: archive.Location.PrefixBeforeHEAD + "/unselected-fixture-object", TokenWire: bytes.Clone(archive.Objects[0].TokenWire), Body: body, BodySHA256: fmt.Sprintf("%x", digest)})
			case "secrets":
				current.Secrets = 127
			case "unexpected-values":
				current.Values = []ExpectedValue{{Name: "public extra value"}}
			case "unexpected-oracles":
				current.Oracles = []PrivateValue{{Name: "public extra oracle", Path: "/parent-oracle", Length: 1}}
			}
			retotal(&current.Archive)
			if name == "extra-object" {
				if _, err := current.Archive.SelectedParts(); err != nil {
					t.Fatal("extra-object control changed the selected closure")
				}
			}
			if name == "missing-object" {
				if _, err := current.Archive.SelectedParts(); err == nil {
					t.Fatal("missing-object case removed no selected object")
				}
			}
			body, err := json.Marshal(current)
			if err != nil {
				t.Fatal("maximum damaged fixture JSON unavailable")
			}
			if _, err := decodeRecoveryFixtureBounded(bytes.NewReader(body), MaximumIntentArchiveJSONBytes, MaximumIntentArchiveBodyBytes, true); err == nil {
				t.Fatal("maximum generated fixture admitted incomplete closure or private oracle input")
			}
		})
	}
}
