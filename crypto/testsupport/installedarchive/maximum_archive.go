package installedarchive

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"enkv.sh/core/contract"
)

// A valid Root owns at most 256 children (format.validAggregate); every child
// kind has a ceiling at most 2 MiB. HEAD, Root and the 4 KiB helper are separate.
const MaximumIntentArchiveBodyBytes = contract.MaxChildPages*contract.MaxRequiredSupportPageLength + contract.MaxHeadLength + contract.MaxRootLength + contract.MaxStoreConfigurationLength
const maximumIntentArchiveObjects = contract.MaxChildPages + 3

// JSON base64 rounds each body independently: reserve 4 bytes per object.
// The 4 MiB remainder covers 259*(6*658 escaped key bytes +348 base64 token
// bytes +2048 JSON/hash/numeric bytes), 128 names and the bounded archive header.
const MaximumIntentArchiveJSONBytes = 4*((MaximumIntentArchiveBodyBytes+2)/3) + 4*maximumIntentArchiveObjects + (4 << 20)
const MaximumIntentArchiveGZIPBytes = 64 << 20

// WriteMaximumIntentFixture stores public/encrypted objects only. Producer
// history is synthetic; expected secret bytes stay outside this archive.
func WriteMaximumIntentFixture(t testing.TB, path string, archive Archive) {
	t.Helper()
	var total uint64
	for _, object := range archive.Objects {
		total += uint64(len(object.Body))
	}
	if total > MaximumIntentArchiveBodyBytes || len(archive.Objects) > maximumIntentArchiveObjects {
		t.Fatal("maximum archive physical bound refused")
	}
	body, err := json.Marshal(RecoveryFixture{Archive: archive, Secrets: 128})
	if err != nil || len(body) > MaximumIntentArchiveJSONBytes || len(archive.Objects) > maximumIntentArchiveObjects {
		t.Fatal("maximum archive encoded bound refused")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("maximum archive output unavailable")
	}
	compressed := gzip.NewWriter(file)
	_, writeErr := compressed.Write(body)
	gzipErr := compressed.Close()
	closeErr := file.Close()
	clear(body)
	info, statErr := os.Stat(path)
	if writeErr != nil || gzipErr != nil || closeErr != nil || statErr != nil || info.Size() > MaximumIntentArchiveGZIPBytes {
		t.Fatal("maximum archive compression incomplete")
	}
}

func ReadMaximumIntentFixture(t testing.TB, path string) Archive {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("maximum intent archive unavailable")
	}
	archive, readErr := decodeMaximumIntentFixture(file, MaximumIntentArchiveGZIPBytes)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("maximum archive bounded single gzip member refused: close_failed=%t", closeErr != nil)
	}
	return archive
}

func decodeMaximumIntentFixture(reader io.Reader, compressedLimit int64) (Archive, error) {
	refused := errors.New("maximum archive bounded single gzip member refused")
	limited := &io.LimitedReader{R: reader, N: compressedLimit + 1}
	buffered := bufio.NewReader(limited)
	compressed, err := gzip.NewReader(buffered)
	if err != nil {
		return Archive{}, errors.Join(refused, err)
	}
	compressed.Multistream(false)
	fixture, readErr := decodeRecoveryFixtureBounded(compressed, MaximumIntentArchiveJSONBytes, MaximumIntentArchiveBodyBytes, true)
	gzipErr := compressed.Close()
	_, trailing := buffered.Peek(1)
	if readErr != nil || gzipErr != nil || trailing != io.EOF || limited.N <= 0 || len(fixture.Archive.Objects) > maximumIntentArchiveObjects || fixture.Archive.Family != contract.AWS {
		return Archive{}, errors.Join(refused, readErr, gzipErr)
	}
	return fixture.Archive, nil
}
