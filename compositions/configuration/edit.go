package configuration

import (
	"context"
	"errors"
	"io"
)

// Edit replaces one explicitly selected range. Ranges must be ordered and
// disjoint. The caller owns syntax and the meaning of the selected changes.
type Edit struct {
	Offset, Length int64
	Replacement    []byte
	Emit           func(io.Writer) error
}

// CopyEdits copies every byte outside the selected ranges without decoding it.
// Its bounded window does not retain comments or a second encoded document.
func CopyEdits(ctx context.Context, dst io.Writer, image *Image, edits []Edit) error {
	if ctx == nil || dst == nil || image == nil || image.file == nil || len(edits) > MaxSpans {
		return ErrEdit
	}
	end := int64(0)
	for _, edit := range edits {
		if edit.Offset < end || edit.Length < 0 || edit.Offset > image.size || edit.Length > image.size-edit.Offset || edit.Emit != nil && edit.Replacement != nil {
			return ErrEdit
		}
		end = edit.Offset + edit.Length
	}
	buffer := make([]byte, WindowBytes)
	end = 0
	for _, edit := range edits {
		if err := copyEditRange(ctx, dst, image, end, edit.Offset-end, buffer); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrEdit, err)
		}
		if edit.Emit != nil {
			if err := edit.Emit(dst); err != nil {
				return errors.Join(ErrEdit, err)
			}
		} else if n, err := dst.Write(edit.Replacement); err != nil || n != len(edit.Replacement) {
			return errors.Join(ErrEdit, err, io.ErrShortWrite)
		}
		end = edit.Offset + edit.Length
	}
	return copyEditRange(ctx, dst, image, end, image.size-end, buffer)
}

func copyEditRange(ctx context.Context, dst io.Writer, image *Image, offset, length int64, buffer []byte) error {
	for length > 0 {
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrEdit, err)
		}
		n := int(min(length, int64(len(buffer))))
		if _, err := io.ReadFull(io.NewSectionReader(image, offset, int64(n)), buffer[:n]); err != nil {
			return errors.Join(ErrEdit, err)
		}
		if written, err := dst.Write(buffer[:n]); err != nil || written != n {
			return errors.Join(ErrEdit, err, io.ErrShortWrite)
		}
		offset += int64(n)
		length -= int64(n)
	}
	return nil
}
