package configuration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

func yamlPlainString(s string, key, flow bool) bool {
	if s == "" || !utf8.ValidString(s) || typedPlain([]byte(s)) || key && s == "<<" {
		return false
	}
	separated := func(i int) bool {
		if i == len(s) {
			return !key
		}
		return s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n' || flow && strings.ContainsRune(",[]{}", rune(s[i]))
	}
	if s[0] <= ' ' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || strings.ContainsRune("\"'!&*%@`{}[]|>#", rune(s[0])) || strings.ContainsRune("?:-", rune(s[0])) && separated(1) {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 && b != '\t' || flow && strings.ContainsRune(",[]{}", rune(b)) || b == ':' && separated(i+1) || b == '#' && i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
			return false
		}
	}
	return true
}

func yamlStringLength(s string, key, flow bool) int64 {
	if yamlPlainString(s, key, flow) {
		return int64(len(s))
	}
	n := int64(len(s) + 2)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			n++
		default:
			if s[i] < 0x20 {
				n += 5
			}
		}
	}
	return n
}

func (w *generatedWriter) yamlString(s string, limit int, key, flow bool) {
	if len(s) > limit || !utf8.ValidString(s) {
		w.err = ErrCapture
		return
	}
	if yamlPlainString(s, key, flow) {
		w.raw(s)
	} else {
		w.quote(s, limit)
	}
}

func editableStringBytes(s string, format Format, span Span, key bool) ([]byte, error) {
	if format == JSON {
		return json.Marshal(s)
	}
	if format != YAML {
		return nil, ErrEdit
	}
	var out bytes.Buffer
	w := &generatedWriter{out: &out}
	w.yamlString(s, len(s), key, span.Flow)
	return out.Bytes(), w.err
}

func (w *generatedWriter) yamlBlob(body []byte, limit int) {
	if len(body) > limit {
		w.err = ErrCapture
		return
	}
	var encoded [4096]byte
	var prefix [32]byte
	number := plainBase64Number(0)
	count := 0
	for remaining := body; len(remaining) > 0; {
		n := min(len(remaining), len(encoded)/4*3)
		width := base64.StdEncoding.EncodedLen(n)
		base64.StdEncoding.Encode(encoded[:width], remaining[:n])
		for _, b := range encoded[:width] {
			if count < len(prefix) {
				prefix[count] = b
			}
			count++
			number = number.next(b)
		}
		remaining = remaining[n:]
	}
	if count == 0 || number.complete() || count <= len(prefix) && typedPlain(prefix[:count]) {
		w.blob(body, limit)
		return
	}
	encoder := base64.NewEncoder(base64.StdEncoding, writerAdapter{w})
	_, writeErr := encoder.Write(body)
	closeErr := encoder.Close()
	if writeErr != nil {
		w.err = writeErr
	} else if closeErr != nil {
		w.err = closeErr
	}
}
