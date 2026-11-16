package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

// full_only: false
func TestResultJSONLayoutCountsAndWritesFragments(t *testing.T) {
	const compact = `{"empty":{},"rows":[[],{"text":"quote\" slash\\ newline\n","base64":"AAECAw=="}]}`
	const want = `{
  "empty": {},
  "rows": [
    [],
    {
      "text": "quote\" slash\\ newline\n",
      "base64": "AAECAw=="
    }
  ]
}
`
	refusal := errors.New("owning result refused")
	for _, width := range []int{1, 2, 3, 7, len(compact)} {
		body, err := renderReadableResultJSON(uint64(len(compact)), refusal, func(w *resultStreamWriter) {
			for start := 0; start < len(compact); start += width {
				w.text(compact[start:min(start+width, len(compact))])
			}
		})
		if err != nil || string(body) != want || len(body) != cap(body) {
			t.Fatalf("fragment width %d changed layout or allocation: %v; %q", width, err, body)
		}
	}
	for _, limit := range []uint64{0, uint64(len(compact) - 1), math.MaxUint64} {
		body, err := renderReadableResultJSON(limit, refusal, func(w *resultStreamWriter) { w.text(compact) })
		if body != nil || err != refusal {
			t.Fatal("invalid compact ceiling escaped its owner", limit, err)
		}
	}
}

// full_only: false
func TestResultJSONLayoutDepthAndDeliveryFailures(t *testing.T) {
	refusal := errors.New("owning result refused")
	for _, depth := range []int{32, 33} {
		compact := strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth)
		body, err := renderReadableResultJSON(uint64(len(compact)), refusal, func(w *resultStreamWriter) { w.text(compact) })
		if depth == 32 && (err != nil || len(body) == 0) || depth == 33 && (err != refusal || body != nil) {
			t.Fatal("structural workspace bound differs", depth, err)
		}
	}
	for _, compact := range []string{"", "{", `{"x":"unfinished}`, "[]{}", "{]"} {
		body, err := renderReadableResultJSON(uint64(len(compact)+1), refusal, func(w *resultStreamWriter) { w.text(compact) })
		if body != nil || err != refusal {
			t.Fatal("incomplete structure escaped", compact, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out bytes.Buffer
	w := &resultStreamWriter{ctx: ctx, out: &out, limit: 1024, limitError: refusal, layout: &resultJSONLayout{compactLimit: 128}}
	w.text(`{"x":[]}`)
	w.finishJSON()
	if !errors.Is(w.err, context.Canceled) || out.Len() != 0 {
		t.Fatal("cancelled layout delivered bytes", w.err)
	}
	w = &resultStreamWriter{ctx: t.Context(), out: resultLayoutShortWriter{}, limit: 1024, limitError: refusal, layout: &resultJSONLayout{compactLimit: 128}}
	w.text(`{"x":[]}`)
	w.finishJSON()
	if !errors.Is(w.err, io.ErrShortWrite) {
		t.Fatal("short layout write was ignored", w.err)
	}
}

type resultLayoutShortWriter struct{}

func (resultLayoutShortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }
