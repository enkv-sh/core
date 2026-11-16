package plugininstallation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"

	"enkv.sh/sdk/artifact"
)

func (c *Coordinator) validate(ctx context.Context, path string, contents artifact.PackageContents, retained bool) error {
	if err := artifact.VerifyExecutable(ctx, filepath.Join(path, "plugin"), contents.Metadata); err != nil {
		return errors.Join(ErrIdentity, err)
	}
	if retained {
		return nil
	}
	settings := make([]debug.BuildSetting, 0, len(contents.Metadata.BuildOptions))
	for _, option := range contents.Metadata.BuildOptions {
		settings = append(settings, debug.BuildSetting{Key: option.Name, Value: option.Value})
	}
	if _, err := artifact.BuildOptions(&debug.BuildInfo{Settings: settings}); err != nil {
		return errors.Join(ErrInvalid, err)
	}
	facts, err := artifact.DecodeDependency(contents.DependencyBytes)
	if err != nil {
		return errors.Join(ErrInvalid, err)
	}
	if !reflect.DeepEqual(facts, contents.Metadata.BuildFacts()) {
		return ErrIdentity
	}
	id, err := artifact.DependencyID(contents.Metadata.Role, contents.DependencyBytes)
	if err != nil {
		return err
	}
	family, err := contents.Metadata.ExecutionFacts()
	if err != nil || family.DependencyManifestID != id {
		return errors.Join(ErrIdentity, err)
	}

	err = c.check(ctx, contents.Metadata, append([]byte(nil), contents.DependencyBytes...))
	if onlyIncompatible(err) {
		return &protocolMismatch{cause: err}
	}
	return err
}

func (c *Coordinator) proofDirectory(selection artifact.Selection) string {
	return filepath.Join(c.store, "proofs", selection.Artifact.String(), selection.Proof.String())
}
func (c *Coordinator) packageDirectory(selection artifact.Selection) string {
	return filepath.Join(c.store, "packages", selection.Artifact.String(), selection.Proof.String())
}

func readPackageDirectory(path string, maximum int) ([]os.DirEntry, error) {
	directory, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(maximum + 1)
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	if err := errors.Join(readErr, directory.Close()); err != nil {
		return nil, err
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return entries, nil
}

func (c *Coordinator) verifyProofFiles(ctx context.Context, path string, selection artifact.Selection) error {
	_, _, _, err := c.readProof(ctx, path, selection)
	return err
}

func (c *Coordinator) readProof(ctx context.Context, path string, selection artifact.Selection) (record artifact.ArchiveRecord, metadataSig, archiveBytes []byte, err error) {
	if err = plainPath(path); err != nil {
		return record, nil, nil, missing(err)
	}
	entries, err := readPackageDirectory(path, 4)
	if err != nil {
		return record, nil, nil, missing(err)
	}
	if len(entries) > 4 {
		return record, nil, nil, ErrInvalid
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "proof.json", "metadata.sig", "archive.json", "archive.sig":
		default:
			return record, nil, nil, ErrInvalid
		}
	}
	proofBytes, err := readFile(ctx, filepath.Join(path, "proof.json"), artifact.MaxProofBytes)
	if err != nil {
		return record, nil, nil, missing(err)
	}
	proof, err := artifact.DecodeOfficialProof(proofBytes)
	if err != nil || artifact.Hash(proofBytes) != selection.Proof || proof.Artifact != selection.Artifact {
		return record, nil, nil, errors.Join(ErrInvalid, err)
	}
	archiveBytes, err = readFile(ctx, filepath.Join(path, "archive.json"), artifact.MaxRecordBytes)
	if err != nil {
		return record, nil, nil, missing(err)
	}
	archiveSig, err := readFile(ctx, filepath.Join(path, "archive.sig"), 64)
	if err != nil {
		return record, nil, nil, missing(err)
	}
	metadataSig, err = readFile(ctx, filepath.Join(path, "metadata.sig"), 64)
	if err != nil {
		return record, nil, nil, missing(err)
	}
	if artifact.Hash(archiveBytes) != proof.ArchiveRecord || artifact.Hash(archiveSig) != proof.ArchiveSignature || artifact.Hash(metadataSig) != proof.MetadataSignature {
		return record, nil, nil, ErrIdentity
	}
	if err = c.verifySignature("plugin-archive", archiveBytes, archiveSig); err != nil {
		return record, nil, nil, err
	}
	record, err = artifact.DecodeArchiveRecord(archiveBytes)
	if err != nil || record.Artifact != selection.Artifact || selection.Name != "" && record.Name != selection.Name || selection.Version != "" && record.Version != selection.Version || selection.Platform != "" && record.Platform != selection.Platform {
		return record, nil, nil, errors.Join(ErrIdentity, err)
	}
	return record, metadataSig, archiveBytes, nil
}

func (c *Coordinator) official(ctx context.Context, selection artifact.Selection, retained bool) (*Installed, error) {
	record, sig, _, err := c.readProof(ctx, c.proofDirectory(selection), selection)
	if err != nil {
		return nil, err
	}
	path := c.packageDirectory(selection)
	if err := plainPath(path); err != nil {
		return nil, missing(err)
	}
	contents, err := artifact.ReadPackageBytes(ctx, path, record)
	if err != nil {
		if stateErr := partialPackage(ctx, path, record); stateErr != nil {
			return nil, stateErr
		}
		return nil, errors.Join(ErrIdentity, err)
	}
	packageSig, err := readFile(ctx, filepath.Join(path, "metadata.sig"), 64)
	if err != nil {
		return nil, missing(err)
	}
	if !bytes.Equal(sig, packageSig) {
		return nil, ErrIdentity
	}
	if err := c.verifySignature("plugin-executable", contents.MetadataBytes, sig); err != nil {
		return nil, err
	}
	if err := c.validate(ctx, path, contents, retained); err != nil {
		return nil, err
	}
	proof := selection.Proof
	return &Installed{path: filepath.Join(path, "plugin"), metadata: contents.MetadataBytes, dependency: contents.DependencyBytes, identity: selection.Artifact, proof: &proof, source: "official"}, nil
}

func partialPackage(ctx context.Context, path string, record artifact.ArchiveRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := readPackageDirectory(path, len(record.Members))
	if err != nil {
		return missing(err)
	}
	if len(entries) > len(record.Members) {
		return ErrIdentity
	}
	members := map[string]artifact.ArchiveMember{}
	for _, m := range record.Members {
		members[m.Name] = m
	}
	for _, entry := range entries {
		member, ok := members[entry.Name()]
		if !ok {
			return ErrIdentity
		}
		info, err := os.Lstat(filepath.Join(path, entry.Name()))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) != member.Length {
			return ErrIdentity
		}
		file, err := os.Open(filepath.Join(path, entry.Name()))
		if err != nil {
			return err
		}
		h := sha256.New()
		n, copyErr := io.Copy(h, io.LimitReader(ctxReader{ctx, file}, int64(member.Length)+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
		if uint64(n) != member.Length || !bytes.Equal(h.Sum(nil), member.SHA256[:]) {
			return ErrIdentity
		}
		delete(members, entry.Name())
	}
	if len(members) > 0 {
		return ErrMissing
	}
	return nil
}

func (c *Coordinator) local(ctx context.Context, output string, expected artifact.Selection) (installed *Installed, err error) {
	ctx, call := startCall(ctx, opCapture)
	known := expected
	installed, err = c.captureLocal(ctx, output, expected, &known)
	finishCall(call, err)
	if err != nil {
		return nil, &candidateFailure{selection: known, cause: err}
	}
	return installed, err
}

func (c *Coordinator) captureLocal(ctx context.Context, output string, expected artifact.Selection, known *artifact.Selection) (installed *Installed, err error) {
	output, err = canonicalDirectory(output)
	if err != nil {
		return nil, errors.Join(ErrMissing, err)
	}
	if err := plainPath(output); err != nil {
		return nil, err
	}
	markerBytes, err := readFile(ctx, filepath.Join(output, "build.json"), artifact.MaxMarkerBytes)
	if err != nil {
		return nil, errors.Join(ErrMissing, err)
	}
	marker, err := artifact.DecodeBuildMarker(markerBytes)
	if err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	known.Artifact = marker.Artifact
	source := filepath.Join(output, filepath.FromSlash(marker.Directory))
	body, err := readFile(ctx, filepath.Join(source, "metadata.json"), artifact.MaxMetadataBytes)
	if err != nil {
		return nil, err
	}
	metadata, err := artifact.DecodeMetadata(body)
	if err != nil || artifact.Hash(body) != marker.Artifact {
		return nil, errors.Join(ErrIdentity, err)
	}
	if metadata.Name != expected.Name || metadata.Platform != expected.Platform {
		return nil, ErrIdentity
	}
	known.Version = metadata.Version
	if _, err := artifact.VerifyBuild(ctx, output); err != nil {
		return nil, errors.Join(ErrIdentity, err)
	}
	dependency, err := readFile(ctx, filepath.Join(source, "dependencies.bin"), artifact.MaxDependencyBytes)
	if err != nil {
		return nil, err
	}
	stage, err := makeStage(filepath.Join(c.store, "builds"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := stage.finish(); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
		if err != nil {
			installed = nil
		}
	}()
	if err := stage.writeBytes(ctx, "metadata.json", body); err != nil {
		return nil, err
	}
	if err := stage.writeBytes(ctx, "dependencies.bin", dependency); err != nil {
		return nil, err
	}
	file, err := os.Open(filepath.Join(source, "plugin"))
	if err != nil {
		return nil, err
	}
	copyErr := stage.write(ctx, "plugin", file, int64(metadata.Executable.Length), 0500)
	if err := errors.Join(copyErr, file.Close()); err != nil {
		return nil, err
	}
	verify := func(path string) error {
		actual, err := localContents(ctx, path, marker.Artifact)
		if err != nil {
			return err
		}
		return c.validate(ctx, path, actual, false)
	}
	if err := verify(stage.path); err != nil {
		return nil, err
	}
	after, err := readFile(ctx, filepath.Join(output, "build.json"), artifact.MaxMarkerBytes)
	if err != nil || !bytes.Equal(markerBytes, after) {
		return nil, errors.Join(ErrSourceChanged, err)
	}
	if err := publishStage(ctx, stage, marker.Artifact.String(), verify); err != nil {
		return nil, err
	}
	after, err = readFile(ctx, filepath.Join(output, "build.json"), artifact.MaxMarkerBytes)
	if err != nil || !bytes.Equal(markerBytes, after) {
		return nil, errors.Join(ErrSourceChanged, err)
	}
	return &Installed{path: filepath.Join(c.store, "builds", marker.Artifact.String(), "plugin"), metadata: body, dependency: dependency, identity: marker.Artifact, source: "local"}, nil
}

func localContents(ctx context.Context, path string, identity artifact.Digest) (artifact.PackageContents, error) {
	if err := plainPath(path); err != nil {
		return artifact.PackageContents{}, missing(err)
	}
	body, err := readFile(ctx, filepath.Join(path, "metadata.json"), artifact.MaxMetadataBytes)
	if err != nil {
		return artifact.PackageContents{}, missing(err)
	}
	metadata, err := artifact.DecodeMetadata(body)
	if err != nil || artifact.Hash(body) != identity {
		return artifact.PackageContents{}, errors.Join(ErrIdentity, err)
	}
	want := 3
	entries, err := readPackageDirectory(path, want)
	if err != nil {
		return artifact.PackageContents{}, err
	}
	if len(entries) != want {
		return artifact.PackageContents{}, ErrInvalid
	}
	for _, e := range entries {
		if e.Name() != "metadata.json" && e.Name() != "plugin" && e.Name() != "dependencies.bin" {
			return artifact.PackageContents{}, ErrInvalid
		}
	}
	dependency, err := readFile(ctx, filepath.Join(path, "dependencies.bin"), artifact.MaxDependencyBytes)
	if err != nil {
		return artifact.PackageContents{}, missing(err)
	}
	if artifact.Hash(dependency) != metadata.Family.Dependency.SHA256 || uint64(len(dependency)) != metadata.Family.Dependency.Length {
		return artifact.PackageContents{}, ErrIdentity
	}
	return artifact.PackageContents{Metadata: metadata, MetadataBytes: body, DependencyBytes: dependency}, nil
}
