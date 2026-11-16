package configuration

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var ErrCapture = errors.New("configuration capture refused")

// ErrSourceImageMissing identifies absence observed at an exact selected source
// image or its required parent. Temporary storage failures do not carry it.
var ErrSourceImageMissing = errors.New("selected configuration image missing")

type Image struct {
	file          *os.File
	size          int64
	digest        [32]byte
	path          string
	sourceInfo    os.FileInfo
	temporaryName string
	temporary     diskIdentity
	named         bool
}

func (i *Image) ReadAt(p []byte, off int64) (int, error) {
	if i == nil || i.file == nil {
		return 0, ErrCapture
	}
	return i.file.ReadAt(p, off)
}
func (i *Image) Size() int64          { return i.size }
func (i *Image) Digest() [32]byte     { return i.digest }
func (i *Image) OriginalPath() string { return i.path }
func (i *Image) CopyTo(w io.Writer) (int64, error) {
	if i == nil || i.file == nil {
		return 0, ErrCapture
	}
	return io.CopyBuffer(w, io.NewSectionReader(i, 0, i.size), make([]byte, WindowBytes))
}
func (i *Image) Close() error {
	if i == nil || i.file == nil && !i.named {
		return nil
	}
	f := i.file
	err := i.removeName()
	if f != nil {
		err = errors.Join(err, f.Close())
	}
	i.file = nil
	if err != nil {
		return captureFailure{cause: err}
	}
	return nil
}

type Pair struct {
	Editable, Generated *Image
	Format              Format
	generatedDirectory  os.FileInfo
	sourceDirectory     os.FileInfo
	captured            *capturedPair
	ownedLocks          *pathLocks
	aliasParent         string
	aliasDirectory      os.FileInfo
}

type capturedSourceError struct {
	cause error
	path  string
}

func (e *capturedSourceError) Error() string              { return e.cause.Error() }
func (e *capturedSourceError) Unwrap() error              { return e.cause }
func (e *capturedSourceError) CapturedSourcePath() string { return e.path }

func bindCapturedSourceError(err error, image *Image) error {
	var diagnostic *Diagnostic
	var captured interface{ CapturedSourcePath() string }
	if err == nil || errors.As(err, &captured) || !errors.As(err, &diagnostic) || image == nil || image.sourceInfo == nil || !localPathValid(image.path) {
		return err
	}
	return &capturedSourceError{cause: err, path: image.path}
}

func generatedCaptureDiagnostic(model *Model, err error) error {
	reason := "read-failed"
	switch {
	case errors.Is(err, ErrSourceImageMissing):
		reason = "restore-exact-generated-file"
	case errors.Is(err, ErrSourceInvalid):
		reason = "invalid-generated-path"
	}
	return spanDiagnostic(model, model.GeneratedSpan, "generated", reason, err)
}

func (p *Pair) Close() error {
	if p == nil {
		return nil
	}
	return errors.Join(p.Editable.Close(), p.Generated.Close())
}
func capturePair(ctx context.Context, path string, format Format) (pair *Pair, resultErr error) {
	if ctx == nil || !localPathValid(path) || format != JSON && format != YAML {
		return nil, ErrCapture
	}
	temporary, valid := temporaryDirectory()
	if !valid {
		return nil, ErrCapture
	}
	originalParent := strings.Clone(filepath.Dir(path))
	if err := checkEditableParent(filepath.Dir(path)); err != nil {
		return nil, captureCause(err)
	}
	path, err := canonicalDestination(path)
	if err != nil {
		return nil, captureCause(err)
	}
	if err := refusePending([]string{path}); err != nil {
		return nil, err
	}
	// Discover only the bounded editable image. It is released before the
	// complete recapture, so discovery adds no second complete pair owner.
	discovery, err := captureInDirectory(ctx, path, MaxPairBytes, temporary)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = bindCapturedSourceError(resultErr, discovery) }()
	model, parseErr := parseEditableMode(ctx, discovery, format, true, nil)
	if err := errors.Join(parseErr, discovery.Close()); err != nil {
		return nil, err
	}
	paths := []string{path}
	if model.Generated != "" {
		paths = append(paths, filepath.Join(filepath.Dir(path), model.Generated))
	}
	if model.Generated != "" {
		directory, err := os.Lstat(filepath.Dir(paths[1]))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				err = errors.Join(ErrSourceImageMissing, err)
			}
			return nil, generatedCaptureDiagnostic(model, err)
		}
		if !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 {
			return nil, spanDiagnostic(model, model.GeneratedSpan, "generated", "invalid-generated-path", errors.Join(ErrCapture, ErrSourceInvalid))
		}
	}
	locks, err := openPathLocks(paths, true, false)
	if err != nil {
		return nil, captureCause(err)
	}
	if err := locks.pinAlias(originalParent, filepath.Dir(path)); err != nil {
		return nil, errors.Join(captureCause(err), locks.close())
	}
	defer func() {
		resultErr = errors.Join(resultErr, locks.close())
		if resultErr != nil && pair != nil {
			resultErr = errors.Join(resultErr, pair.Close())
			pair = nil
		}
	}()
	if err := refusePending(paths); err != nil {
		return nil, err
	}
	var current editableNames
	pair, current, err = capturePairOwned(ctx, path, format, locks, temporary)
	if err != nil {
		return nil, err
	}
	pair.aliasParent = originalParent
	pair.aliasDirectory = locks.aliases[originalParent]
	err = ctx.Err()
	if err != nil {
		err = &Diagnostic{Line: 1, Column: 1, Reason: "cancelled", cause: err}
	}
	if err != nil || current.generated != model.Generated || current.domainName != model.DomainName {
		return pair, captureCause(errors.Join(ErrCapture, err))
	}
	if err := pair.checkExact(ctx); err != nil {
		return pair, err
	}
	if err := refusePending(paths); err != nil {
		return pair, err
	}
	// Lock absence is the final acceptance check, including completed writers.
	if err := locks.check(true); err != nil {
		return pair, captureCause(err)
	}
	return pair, nil
}

type editableNames struct {
	domainName, generated string
}

func capturePairOwned(ctx context.Context, path string, format Format, locks *pathLocks, temporary string) (pair *Pair, names editableNames, err error) {
	if locks == nil || locks.check(false) != nil {
		return nil, editableNames{}, ErrCapture
	}
	p := &Pair{Format: format}
	complete := false
	defer func() {
		if !complete {
			err = errors.Join(err, p.Close())
		}
	}()
	p.sourceDirectory, err = os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, editableNames{}, captureCause(err)
	}
	p.Editable, err = captureInDirectory(ctx, path, MaxPairBytes, temporary)
	if err != nil {
		return nil, editableNames{}, err
	}
	m, e := parseEditableMode(ctx, p.Editable, format, true, nil)
	if e != nil {
		return nil, editableNames{}, e
	}
	if m.Generated != "" {
		dir := filepath.Join(filepath.Dir(path), ".enkv")
		before, e := os.Lstat(dir)
		if e != nil {
			if errors.Is(e, os.ErrNotExist) {
				e = errors.Join(ErrSourceImageMissing, e)
			}
			return nil, editableNames{}, generatedCaptureDiagnostic(m, e)
		}
		if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return nil, editableNames{}, spanDiagnostic(m, m.GeneratedSpan, "generated", "invalid-generated-path", errors.Join(ErrCapture, ErrSourceInvalid))
		}
		p.Generated, e = captureInDirectory(ctx, filepath.Join(filepath.Dir(path), m.Generated), MaxPairBytes-p.Editable.size, temporary)
		if e != nil {
			return nil, editableNames{}, generatedCaptureDiagnostic(m, e)
		}
		after, e := os.Lstat(dir)
		if e != nil || !os.SameFile(before, after) || !sameMetadata(before, after) || after.Mode()&os.ModeSymlink != 0 {
			return nil, editableNames{}, spanDiagnostic(m, m.GeneratedSpan, "generated", "changed-generated-path", errors.Join(ErrCapture, e))
		}
		p.generatedDirectory = before
	}
	if err := sealPair(p); err != nil {
		return nil, editableNames{}, err
	}
	// Open descriptors retain frozen bytes; unlink snapshots once the pair is
	// complete so process exit cannot strand predecessor files.
	for _, image := range []*Image{p.Editable, p.Generated} {
		if image != nil {
			if err := image.removeName(); err != nil {
				return nil, editableNames{}, captureCause(err)
			}
		}
	}
	complete = true
	return p, editableNames{domainName: m.DomainName, generated: m.Generated}, nil
}
func capture(ctx context.Context, path string, limit int64) (*Image, error) {
	temporary, valid := temporaryDirectory()
	if !valid {
		return nil, ErrCapture
	}
	return captureInDirectory(ctx, path, limit, temporary)
}

func captureInDirectory(ctx context.Context, path string, limit int64, temporary string) (image *Image, err error) {
	if ctx == nil || !localDirectoryPathValid(temporary) || len(temporary)+64 > 4096 || !localPathValid(path) {
		return nil, ErrCapture
	}
	before, e := os.Lstat(path)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			e = errors.Join(ErrSourceImageMissing, e)
		}
		return nil, captureCause(e)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(ErrCapture, ErrSourceInvalid)
	}
	if nativeChange(before) == "" {
		return nil, ErrCapture
	}
	if !singleLink(before) {
		return nil, errors.Join(ErrCapture, ErrSourceInvalid)
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, captureCause(e)
	}
	complete := false
	var owned *Image
	defer func() {
		err = errors.Join(err, f.Close())
		if (!complete || err != nil) && owned != nil {
			err = errors.Join(err, owned.Close())
			image = nil
		}
	}()
	opened, e := f.Stat()
	if e != nil {
		return nil, captureCause(e)
	}
	if !os.SameFile(before, opened) || !sameMetadata(before, opened) || nativeChange(opened) == "" {
		return nil, ErrCapture
	}
	if opened.Size() < 0 || opened.Size() > limit {
		return nil, errors.Join(ErrCapture, ErrSourceInvalid)
	}
	tmp, e := os.CreateTemp(temporary, "enkv-configuration-*")
	if e != nil {
		return nil, captureCause(e)
	}
	image = &Image{file: tmp, path: path, sourceInfo: opened}
	owned = image
	if err := image.acquireName(); err != nil {
		return image, captureCause(err)
	}
	buffer := make([]byte, WindowBytes)
	h := sha256.New()
	remaining := limit + 1
	for remaining > 0 {
		if e = ctx.Err(); e != nil {
			return image, captureCause(e)
		}
		n, readErr := f.Read(buffer[:min(int64(len(buffer)), remaining)])
		if n > 0 {
			remaining -= int64(n)
			image.size += int64(n)
			if image.size > limit {
				return image, ErrCapture
			}
			written, writeErr := tmp.Write(buffer[:n])
			if writeErr != nil {
				return image, captureCause(writeErr)
			}
			if written != n {
				return image, captureCause(io.ErrShortWrite)
			}
			_, _ = h.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return image, captureCause(readErr)
		}
		if n == 0 {
			return image, captureCause(io.ErrNoProgress)
		}
	}
	if image.size != opened.Size() {
		return image, ErrCapture
	}
	copy(image.digest[:], h.Sum(nil))
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return image, captureCause(e)
	}
	h.Reset()
	var reread int64
	for {
		if e = ctx.Err(); e != nil {
			return image, captureCause(e)
		}
		n, readErr := f.Read(buffer)
		if n > 0 {
			reread += int64(n)
			if reread > image.size {
				return image, ErrCapture
			}
			_, _ = h.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return image, captureCause(readErr)
		}
		if n == 0 {
			return image, captureCause(io.ErrNoProgress)
		}
	}
	after, e := f.Stat()
	if e != nil {
		return image, captureCause(e)
	}
	pathAfter, e := os.Lstat(path)
	if e != nil {
		return image, captureCause(e)
	}
	if !os.SameFile(opened, pathAfter) || !sameMetadata(opened, after) || !sameMetadata(opened, pathAfter) || reread != image.size || !equalDigest(image.digest, h.Sum(nil)) {
		return image, ErrCapture
	}
	if e = tmp.Sync(); e != nil {
		return image, captureCause(e)
	}
	if e = ctx.Err(); e != nil {
		return image, captureCause(e)
	}
	complete = true
	return image, nil
}
func sameMetadata(a, b os.FileInfo) bool {
	return a.Size() == b.Size() && a.Mode() == b.Mode() && a.ModTime().Equal(b.ModTime()) && nativeChange(a) == nativeChange(b)
}
func equalDigest(a [32]byte, b []byte) bool {
	if len(b) != 32 {
		return false
	}
	var c byte
	for i := range a {
		c |= a[i] ^ b[i]
	}
	return c == 0
}
func captureCause(cause error) error { return captureFailure{cause: errors.Join(ErrCapture, cause)} }
