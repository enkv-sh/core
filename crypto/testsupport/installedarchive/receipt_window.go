package installedarchive

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"enkv.sh/core/contract"
)

// ReadReceiptWindowFixture loads the existing signed-capacity export without
// removing its source files. Its terminal history is synthetic; the native
// public consumer qualifies the actual full selected state independently.
func ReadReceiptWindowFixture(t testing.TB, archivePath, indexPath string) (RecoveryFixture, contract.MutationReceiptIndexes) {
	t.Helper()
	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatal("receipt window archive unavailable")
	}
	fixture, readErr := decodeRecoveryFixture(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || fixture.Archive.Family != contract.AWS || fixture.Secrets != 0 || len(fixture.Oracles) != 0 || len(fixture.Values) != 1 || fixture.Values[0].Name != "seed" || !bytes.Equal(fixture.Values[0].Bytes, []byte{0}) {
		t.Fatal("receipt window archive shape refused")
	}
	file, err = os.Open(indexPath)
	if err != nil {
		t.Fatal("receipt window index fixture unavailable")
	}
	limited := &io.LimitedReader{R: file, N: (1 << 20) + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var indexes contract.MutationReceiptIndexes
	readErr = decoder.Decode(&indexes)
	trailing := decoder.Decode(new(any))
	closeErr = file.Close()
	if readErr != nil || trailing != io.EOF || closeErr != nil || limited.N <= 0 || len(indexes.Successes) != 256 || len(indexes.Failures) != 256 || len(indexes.Order) != 512 {
		t.Fatal("receipt window index fixture shape refused")
	}
	if _, _, _, err := indexes.Descriptors(); err != nil {
		t.Fatal("receipt window index fixture relation refused")
	}
	return fixture, indexes
}
