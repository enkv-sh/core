package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

func sourceIdentity(ctx context.Context, root string) (records.Source, error) {
	source, err := sourceRevision(ctx, root)
	if err != nil || source.ObservationIncomplete {
		return source, err
	}
	status, err := sourceGitCommand(ctx, root, "status", "--porcelain=v1", "-z")
	if err != nil {
		if ctx.Err() != nil || !sourceCommandsJoined(err) {
			return source, errors.Join(ctx.Err(), err)
		}
		source.ObservationIncomplete = true
		return source, nil
	}
	source.Dirty = len(status) != 0
	if source.Dirty {
		diff, err := sourceGitCommand(ctx, root, "diff", "--no-ext-diff", "--binary", "HEAD")
		if err != nil {
			if ctx.Err() != nil || !sourceCommandsJoined(err) {
				return source, errors.Join(ctx.Err(), err)
			}
			source.ObservationIncomplete = true
		}
		digest := sha256.New()
		_, _ = digest.Write(status)
		_, _ = digest.Write(diff)
		names, err := sourceGitCommand(ctx, root, "ls-files", "--others", "--exclude-standard", "-z")
		if err != nil {
			if ctx.Err() != nil || !sourceCommandsJoined(err) {
				return source, errors.Join(ctx.Err(), err)
			}
			source.ObservationIncomplete = true
		}
		for _, name := range bytes.Split(names, []byte{0}) {
			if len(name) == 0 {
				continue
			}
			info, err := os.Lstat(filepath.Join(root, string(name)))
			if err != nil {
				source.ObservationIncomplete = true
				_, _ = digest.Write(name)
				continue
			}
			_ = binary.Write(digest, binary.BigEndian, uint64(len(name)))
			_, _ = digest.Write(name)
			_ = binary.Write(digest, binary.BigEndian, info.Size())
			_ = binary.Write(digest, binary.BigEndian, info.ModTime().UnixNano())
		}
		value := hex.EncodeToString(digest.Sum(nil))
		source.DirtyDiffSHA256 = &value
	}
	return source, nil
}
func sourceRevision(ctx context.Context, root string) (records.Source, error) {
	if err := ctx.Err(); err != nil {
		return records.Source{}, err
	}
	body, err := sourceGitCommand(ctx, root, "rev-parse", "HEAD")
	if ctx.Err() != nil || !sourceCommandsJoined(err) {
		return records.Source{}, errors.Join(ctx.Err(), err)
	}
	if err != nil {
		return records.Source{ObservationIncomplete: true}, nil
	}
	revision := strings.TrimSpace(string(body))
	if !hexString(revision, gitRevisionHexLength) {
		return records.Source{ObservationIncomplete: true}, nil
	}
	return records.Source{Revision: revision}, nil
}
func sourceForRecovery(ctx context.Context, root string, original records.Source) (records.Source, error) {
	if original.Algorithm == "" && hasRawSourceFields(original) || original.Algorithm != "" && !rawSourceValid(original) {
		return records.Source{}, errors.New("retained source algorithm refused")
	}
	return sourceIdentity(ctx, root)
}
func sameSource(first, second records.Source) bool {
	if first.Algorithm == "" && hasRawSourceFields(first) || second.Algorithm == "" && hasRawSourceFields(second) {
		return false
	}
	if first.Algorithm != "" || second.Algorithm != "" {
		return sameRawSource(first, second)
	}
	if first.Revision != second.Revision || first.Dirty != second.Dirty || first.PublicSourcesSHA256 != second.PublicSourcesSHA256 {
		return false
	}
	if first.DirtyDiffSHA256 == nil || second.DirtyDiffSHA256 == nil {
		return first.DirtyDiffSHA256 == nil && second.DirtyDiffSHA256 == nil
	}
	return *first.DirtyDiffSHA256 == *second.DirtyDiffSHA256
}

func hasRawSourceFields(value records.Source) bool {
	return value.Tree != "" || value.PublicRepository != "" || value.PublicRevision != "" || value.PublicTree != "" || len(value.PublicPaths) != 0
}

type sourceObservationContextKey struct{}

func sourceObservation(ctx context.Context, root string) (records.Source, bool, error) {
	if source, ok := ctx.Value(sourceObservationContextKey{}).(records.Source); ok {
		return source, false, nil
	}
	source, err := sourceIdentity(ctx, root)
	return source, true, err
}
func finishSourceObservation(ctx context.Context, root string, source records.Source, output io.Writer) (bool, error) {
	tail, release := finalizationContext(ctx)
	after, err := sourceIdentity(tail, root)
	release()
	if err != nil && !sourceCommandsJoined(err) {
		return false, err
	}
	if err != nil || source.ObservationIncomplete || after.ObservationIncomplete {
		_, printErr := fmt.Fprintln(output, "Source observation incomplete; prepared builds remain in use")
		return false, printErr
	}
	changed := !sameSource(source, after)
	if changed {
		_, err = fmt.Fprintln(output, "Source changed during execution; prepared builds remain in use")
	}
	return changed, err
}
