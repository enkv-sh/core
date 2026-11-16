package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"

	records "enkv.sh/core/internal/testrecords"
)

var errTelemetryRetention = errors.New("live recovery capture handoff failed; current files retained")

func (s *runState) retainEvidenceBytes(relative, name string, body []byte) (identity os.FileInfo, err error) {
	if s.evidenceDirectories == nil {
		s.evidenceDirectories = map[string]os.FileInfo{}
	}
	if _, err := records.SafePath(s.directory, relative); err != nil || filepath.Base(name) != name || name == "." {
		return nil, errTelemetryRetention
	}
	directories := []string{}
	for directory := relative; directory != "."; directory = filepath.Dir(directory) {
		if directory == "" || filepath.IsAbs(directory) {
			return nil, errTelemetryRetention
		}
		directories = append(directories, directory)
	}
	slices.Reverse(directories)
	if len(directories) < 3 || directories[0] != "evidence" {
		return nil, errTelemetryRetention
	}
	for _, directory := range directories {
		path, err := records.SafePath(s.directory, directory)
		if err != nil {
			return nil, errTelemetryRetention
		}
		owned := s.evidenceDirectories[directory]
		if owned == nil {
			if os.Mkdir(path, 0700) != nil {
				return nil, errTelemetryRetention
			}
			parent, openErr := os.Open(filepath.Dir(path))
			if openErr != nil {
				return nil, errTelemetryRetention
			}
			syncErr, closeErr := parent.Sync(), parent.Close()
			if syncErr != nil || closeErr != nil {
				return nil, errTelemetryRetention
			}
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || owned != nil && !records.SameLocalFile(owned, info) {
			return nil, errTelemetryRetention
		}
		s.evidenceDirectories[directory] = info
	}
	root, err := os.OpenRoot(filepath.Join(s.directory, relative))
	if err != nil {
		return nil, errTelemetryRetention
	}
	defer func() {
		if root.Close() != nil {
			err = errTelemetryRetention
		}
	}()
	info, err := root.Stat(".")
	if err != nil || !records.SameLocalFile(s.evidenceDirectories[relative], info) {
		return nil, errTelemetryRetention
	}
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, errTelemetryRetention
	}
	written, writeErr := file.Write(body)
	if writeErr == nil && written != len(body) {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	identity, statErr := file.Stat()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || statErr != nil || closeErr != nil {
		return nil, errTelemetryRetention
	}
	directory, err := root.Open(".")
	if err != nil {
		return nil, errTelemetryRetention
	}
	syncErr, closeErr = directory.Sync(), directory.Close()
	if syncErr != nil || closeErr != nil || s.privateOwner.verify() != nil {
		return nil, errTelemetryRetention
	}
	current, err := os.Lstat(filepath.Join(s.directory, relative))
	if err != nil || !records.SameLocalFile(s.evidenceDirectories[relative], current) {
		return nil, errTelemetryRetention
	}
	readback, currentFile, readErr := readRetainedEvidenceBytes(s.directory, filepath.ToSlash(filepath.Join(relative, name)), uint64(len(body)))
	if readErr != nil || !records.SameLocalFile(identity, currentFile) || !bytes.Equal(readback, body) {
		return nil, errTelemetryRetention
	}
	return identity, nil
}

func (s *runState) verifyEvidenceDirectories() error {
	for relative, identity := range s.evidenceDirectories {
		path, err := records.SafePath(s.directory, relative)
		if err != nil {
			return errTelemetryRetention
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !records.SameLocalFile(identity, info) {
			return errTelemetryRetention
		}
	}
	return nil
}
