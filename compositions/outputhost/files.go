package outputhost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"

	artifactrecord "enkv.sh/sdk/artifact"
	protocol "enkv.sh/sdk/protocols/output"
	"golang.org/x/sys/unix"
)

func ownedPrivate(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Uid) == uint64(os.Geteuid()) && info.Mode().Perm()&0077 == 0
}

func stageArtifact(ctx context.Context, path string, artifact Artifact) (stage *artifactStage, cleanupErr, resultErr error) {
	length := artifact.Length
	if length == 0 || length > artifactrecord.MaxExecutableBytes {
		return nil, nil, ErrAdmission
	}
	source, cleanupErr, err := acquireRegularFile(ctx, path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = errors.Join(ErrArtifactMissing, err)
		}
		return nil, cleanupErr, errors.Join(ErrAdmission, err)
	}
	defer func() {
		if err := source.close(); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			resultErr = errors.Join(resultErr, ErrArtifactUnavailable, err)
		}
		if resultErr != nil {
			if err := stage.close(); err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
				resultErr = errors.Join(resultErr, ErrArtifactUnavailable, err)
			}
			stage = nil
		}
	}()
	if source.info.Mode().Perm()&0022 != 0 || uint64(source.info.Size()) != length {
		return nil, nil, errors.Join(ErrAdmission, ErrArtifactIdentity)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, nil, errors.Join(ErrAdmission, err)
	}
	stage, cleanupErr, err = newTemporaryArtifactStage(ctx, ".launch-"+hex.EncodeToString(random[:]), "output")
	if err != nil {
		return nil, cleanupErr, err
	}
	copyFile, err := openNativeAt(ctx, stage.directory, "output", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		return stage, nil, errors.Join(ErrAdmission, err)
	}
	defer func() {
		if copyFile != nil {
			closeErr := copyFile.Close()
			cleanupErr = errors.Join(cleanupErr, closeErr)
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(copyFile, hash), io.LimitReader(artifactFileReader{ctx, source.file}, int64(length)+1))
	if ctx != nil && ctx.Err() != nil {
		return stage, cleanupErr, errors.Join(copyErr, ctx.Err())
	}
	modeErr := copyFile.Chmod(0500)
	if ctx != nil && ctx.Err() != nil {
		return stage, cleanupErr, errors.Join(copyErr, modeErr, ctx.Err())
	}
	syncErr := copyFile.Sync()
	closeErr := copyFile.Close()
	cleanupErr = errors.Join(cleanupErr, closeErr)
	copyFile = nil
	if ctx != nil && ctx.Err() != nil {
		return stage, cleanupErr, errors.Join(copyErr, modeErr, syncErr, closeErr, ctx.Err())
	}
	if copyErr != nil || modeErr != nil || syncErr != nil || closeErr != nil || uint64(written) != length {
		return stage, cleanupErr, errors.Join(ErrAdmission, copyErr, modeErr, syncErr, closeErr)
	}
	var digest protocol.ID
	copy(digest[:], hash.Sum(nil))
	if digest != artifact.SHA256 {
		return stage, cleanupErr, errors.Join(ErrAdmission, ErrArtifactIdentity)
	}
	if err := source.unchanged(ctx); err != nil {
		return stage, cleanupErr, err
	}
	if err := stage.authenticate(ctx, artifact.SHA256, length); err != nil {
		return stage, cleanupErr, err
	}
	if ctx != nil && ctx.Err() != nil {
		return stage, cleanupErr, ctx.Err()
	}
	if err := stage.directory.Sync(); err != nil {
		return stage, cleanupErr, err
	}
	if ctx != nil && ctx.Err() != nil {
		return stage, cleanupErr, ctx.Err()
	}
	if err := stage.rootFile.Sync(); err != nil {
		return stage, cleanupErr, err
	}
	if ctx != nil && ctx.Err() != nil {
		return stage, cleanupErr, ctx.Err()
	}
	return stage, cleanupErr, nil
}
