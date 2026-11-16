package core

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"enkv.sh/core/contract"
)

// This is a test-Store disk safety bound, not a product capacity limit. The
// caller owns the private directory through testing.TB.TempDir cleanup.
const fixtureBodyFileLimit uint64 = 48 << 30

type fixtureBodyFiles struct {
	mu        sync.Mutex
	directory string
	next      uint64
	used      uint64
}

func (files *fixtureBodyFiles) write(body []byte) (stored, error) {
	files.mu.Lock()
	defer files.mu.Unlock()
	if files.used > fixtureBodyFileLimit || uint64(len(body)) > fixtureBodyFileLimit-files.used {
		return stored{}, errors.New("fixture body file limit")
	}
	files.next++
	path := filepath.Join(files.directory, fmt.Sprintf("%016x", files.next))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return stored{}, err
	}
	remaining := body
	for len(remaining) != 0 && err == nil {
		var n int
		n, err = file.Write(remaining)
		if n == 0 && err == nil {
			err = io.ErrShortWrite
		}
		remaining = remaining[n:]
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return stored{}, errors.Join(err, os.Remove(path))
	}
	files.used += uint64(len(body))
	return stored{bodyPath: path, bodyLength: uint64(len(body)), bodyDigest: sha256.Sum256(body)}, nil
}

func readFixtureStoredBody(value stored, maximum uint32) contract.ReadResult {
	if value.bodyPath == "" || value.Body != nil {
		if uint64(len(value.Body)) > uint64(maximum) {
			return contract.ReadResult{Status: contract.ReadInvalid}
		}
		return contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(value.Body), Token: value.Token}
	}
	if value.bodyLength > uint64(maximum) {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	file, err := os.Open(value.bodyPath)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
	}
	if info.Size() < 0 || uint64(info.Size()) != value.bodyLength {
		_ = file.Close()
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
	}
	body := make([]byte, int(value.bodyLength))
	_, readErr := io.ReadFull(file, body)
	var extra [1]byte
	var extraCount int
	var extraErr error
	if readErr == nil {
		extraCount, extraErr = file.Read(extra[:])
	}
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || (extraErr != nil && !errors.Is(extraErr, io.EOF)) {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
	}
	if extraCount != 0 {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
	}
	if sha256.Sum256(body) != value.bodyDigest {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
	}
	return contract.ReadResult{Status: contract.ReadOK, Body: body, Token: value.Token}
}

func fixtureBodyWriteFailure() contract.WriteResult {
	return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
}

// useFileBodies moves immutable non-HEAD bodies from the fixture map to files.
// Its directory must be new and owned by the test; copies share these files.
func (m *memoryStore) useFileBodies(directory string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fileBodies != nil {
		return errors.New("fixture body files already enabled")
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return err
	}
	files := &fixtureBodyFiles{directory: directory}
	replacements := make(map[string]stored)
	for key, value := range m.objects {
		if key == m.desc.HeadKey || (value.bodyPath != "" && value.Body == nil) {
			continue
		}
		body, err := files.write(value.Body)
		if err != nil {
			return err
		}
		body.Token = value.Token
		replacements[key] = body
	}
	for key, value := range replacements {
		m.objects[key] = value
	}
	m.fileBodies = files
	return nil
}

func (m *memoryStore) putSelected(key string, body []byte) error {
	if m.fileBodies == nil || key == m.desc.HeadKey {
		m.put(key, body)
		return nil
	}
	value, err := m.fileBodies.write(body)
	if err != nil {
		return err
	}
	m.putValue(key, value)
	return nil
}
