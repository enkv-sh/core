package installedarchive

import (
	"bytes"
	"embed"
	"testing"

	"enkv.sh/core/contract"
)

//go:embed testdata/reader-aws.json testdata/reader-aws-basis.json testdata/reader-gcp.json testdata/reader-gcp-basis.json
var readerArchives embed.FS

// LoadReader returns a fixed signed mixed archive and the independent public
// basis exported by its setup process. Native admission validates that basis;
// candidate Store metadata cannot supply it. No private oracle is retained.
func LoadReader(t testing.TB, family string) (RecoveryFixture, []byte) {
	t.Helper()
	if family != "aws" && family != "gcp" {
		t.Fatal("unknown Reader archive")
	}
	body, err := readerArchives.ReadFile("testdata/reader-" + family + ".json")
	if err != nil {
		t.Fatal("Reader archive unavailable")
	}
	fixture, err := decodeRecoveryFixture(bytes.NewReader(body))
	if err != nil {
		t.Fatal("Reader archive refused:", err)
	}
	want := contract.AWS
	if family == "gcp" {
		want = contract.GCP
	}
	if fixture.Archive.Family != want || len(fixture.Oracles) != 0 || len(fixture.Values) != 4 || fixture.Secrets != 2 {
		t.Fatal("Reader archive shape differs")
	}
	basis, err := readerArchives.ReadFile("testdata/reader-" + family + "-basis.json")
	if err != nil {
		t.Fatal("Reader independent basis unavailable")
	}
	return fixture, basis
}
