package configuration

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// full_only: false
func TestEditSplices(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "image-*")
	if err != nil {
		t.Fatal(err)
	}
	const original = "# first\nentry: {value: old} # adjacent\n# last\n"
	if _, err := f.WriteString(original); err != nil {
		t.Fatal(err)
	}
	image := &Image{file: f, size: int64(len(original))}
	t.Cleanup(func() {
		if err := image.Close(); err != nil {
			t.Error(err)
		}
	})
	var out bytes.Buffer
	offset := int64(strings.Index(original, "old"))
	if err := CopyEdits(context.Background(), &out, image, []Edit{{Offset: offset, Length: 3, Replacement: []byte("new")}}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "# first\nentry: {value: new} # adjacent\n# last\n" {
		t.Fatal("unselected bytes changed")
	}
	for _, edits := range [][]Edit{
		{{Offset: -1}}, {{Offset: 0, Length: -1}}, {{Offset: int64(len(original)), Length: 1}},
		{{Offset: 4, Length: 4}, {Offset: 5, Length: 1}},
	} {
		out.Reset()
		if err := CopyEdits(context.Background(), &out, image, edits); !errors.Is(err, ErrEdit) || out.Len() != 0 {
			t.Fatal("invalid edits emitted bytes")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CopyEdits(ctx, &out, image, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
}
