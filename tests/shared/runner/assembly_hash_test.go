package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// full_only: false
func TestAssemblyFileHashReadsFreshBytesWithReusableBuffer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	buffer := bytes.Repeat([]byte{0xa5}, 32*1024)
	// The long digest was derived with Python hashlib.sha256(b'abc'*21846).
	// The other literals are the standard SHA256 empty and "abc" vectors.
	for _, row := range []struct {
		body []byte
		want string
	}{
		{bytes.Repeat([]byte("abc"), 21846), "d591ff05defe75c3c3624a82ef8590da060c0b931c320467c0b7d99078061b2c"},
		{[]byte("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{nil, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	} {
		if err := os.WriteFile(path, row.body, 0600); err != nil {
			t.Fatal(err)
		}
		for _, scratch := range [][]byte{buffer, nil} {
			got, err := assemblyFileSHA256Buffer(path, scratch)
			if err != nil || got != row.want {
				t.Fatalf("fresh hash differs for %d bytes: got %s, error %v", len(row.body), got, err)
			}
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got, err := assemblyFileSHA256Buffer(path, buffer); got != "" || !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing input lost its error", got, err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := assemblyFileSHA256Buffer(path, buffer); got != "" || err == nil {
		t.Fatal("input read failure was accepted", got, err)
	}
}
