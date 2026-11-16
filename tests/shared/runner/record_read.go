package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	records "enkv.sh/core/internal/testrecords"
)

const (
	gitRevisionHexLength = 40
	sha256HexLength      = 2 * sha256.Size
)

func validSource(value records.Source) bool {
	if value.Algorithm == "" && hasRawSourceFields(value) {
		return false
	}
	if value.Algorithm != "" {
		return rawSourceValid(value)
	}
	if value.Revision == "" {
		return value.ObservationIncomplete && !value.Dirty && value.DirtyDiffSHA256 == nil && value.PublicSourcesSHA256 == ""
	}
	if !hexString(value.Revision, gitRevisionHexLength) || value.PublicSourcesSHA256 != "" && !hexString(value.PublicSourcesSHA256, sha256HexLength) {
		return false
	}
	if value.Dirty {
		return value.DirtyDiffSHA256 != nil && hexString(*value.DirtyDiffSHA256, sha256HexLength)
	}
	return value.DirtyDiffSHA256 == nil
}

func hexString(value string, length int) bool {
	if len(value) != length {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func readRecordBytes(path string) ([]byte, error) {
	refused := errors.New("local record unavailable")
	if _, err := records.SafePath(filepath.Dir(path), filepath.Base(path)); err != nil {
		return nil, refused
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > records.MaximumJSONBytes {
		return nil, refused
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, refused
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !records.SameLocalFile(before, after) {
		return nil, refused
	}
	body, err := io.ReadAll(io.LimitReader(file, records.MaximumJSONBytes+1))
	if err != nil || len(body) > records.MaximumJSONBytes {
		return nil, refused
	}
	return body, nil
}
