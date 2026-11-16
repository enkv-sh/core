package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type countedCaptureReader struct {
	io.Reader
	bytes int
}

func (r *countedCaptureReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytes += n
	return n, err
}

// full_only: false
func TestNativeCaptureDigestOwnsExactBoundedImage(t *testing.T) {
	footer := []byte("{\"kind\":\"footer\",\"code\":0}\n")
	path := filepath.Join(t.TempDir(), "capture.jsonl")
	if err := os.WriteFile(path, footer, 0600); err != nil {
		t.Fatal(err)
	}
	capture, digest, err := ReadCaptureWithDigest(path)
	if err != nil || len(capture.Events) != 1 || digest != sha256.Sum256(footer) {
		t.Fatal("capture facts and digest do not share one exact image", err)
	}
	if err := os.WriteFile(path, []byte("not-json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadCaptureWithDigest(path); err == nil {
		t.Fatal("invalid image received a complete capture digest")
	}
	if capture.Events[0].Kind != "footer" || digest != sha256.Sum256(footer) {
		t.Fatal("later path replacement changed returned facts")
	}
	row := []byte("{\"kind\":\"source-kind\",\"source_kind\":\"aws-sso\",\"count\":1,\"matched\":true}\n")
	row = append(bytes.Clone(row[:len(row)-1]), bytes.Repeat([]byte{' '}, 1024-len(row))...)
	row = append(row, '\n')
	maximum := bytes.Repeat(row, (MaxCaptureBytes-len(footer))/len(row))
	maximum = append(maximum, bytes.Repeat([]byte{' '}, MaxCaptureBytes-len(maximum)-len(footer))...)
	maximum = append(maximum, footer...)
	if err := os.WriteFile(path, maximum, 0600); err != nil {
		t.Fatal(err)
	}
	if _, digest, err := ReadCaptureWithDigest(path); err != nil || digest != sha256.Sum256(maximum) {
		t.Fatal("exact total capture bound refused", err)
	}
	for _, row := range []struct {
		name        string
		declared    int64
		body        []byte
		maximumRead int
	}{
		{"declared-over-bound", MaxCaptureBytes + 1, footer, 0},
		{"grew-past-declared", int64(len(footer)), append(bytes.Clone(footer), ' '), len(footer) + 1},
		{"grew-past-total-bound", MaxCaptureBytes, append(bytes.Clone(maximum), '\n'), MaxCaptureBytes + 1},
		{"truncated", int64(len(footer)), footer[:len(footer)-1], len(footer)},
	} {
		t.Run(row.name, func(t *testing.T) {
			reader := &countedCaptureReader{Reader: bytes.NewReader(row.body)}
			if body, err := readCaptureBody(reader, row.declared); err == nil || body != nil || reader.bytes > row.maximumRead {
				t.Fatal("changed or oversized capture exceeded bounded intake")
			}
		})
	}
	link := filepath.Join(t.TempDir(), "capture-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadCaptureWithDigest(link); err == nil {
		t.Fatal("capture evidence followed a symlink")
	}
}

// full_only: false
func TestNativeCaptureRejectsFIFOWithoutWriterBeforeIntake(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "regular.jsonl")
	if err := os.WriteFile(regular, []byte("{\"kind\":\"footer\",\"code\":0}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if capture, err := ReadCapture(regular); err != nil || len(capture.Events) != 1 {
		t.Fatal("regular capture control refused", err)
	}
	path := filepath.Join(t.TempDir(), "capture.fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadCapture(path); done <- err }()
	blocked := false
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("nonregular capture was accepted")
		}
		return
	case <-time.After(500 * time.Millisecond):
		blocked = true
	}
	// Release the old blocking Open before reporting the retained failure. Every
	// started goroutine is joined; this test leaves no FIFO reader behind.
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0600)
		if err == nil {
			if err := syscall.Close(fd); err != nil {
				t.Error("FIFO release writer close failed", err)
			}
			break
		}
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("nonregular capture was accepted")
			}
			t.Fatal("capture intake required a FIFO writer before regular-file refusal")
		case <-deadline.C:
			t.Fatal("controlled FIFO reader did not reach its release")
		case <-ticker.C:
		}
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("nonregular capture was accepted")
		}
	case <-deadline.C:
		t.Fatal("controlled FIFO reader did not join after release")
	}
	if blocked {
		t.Fatal("capture intake opened a FIFO before its regular-file gate")
	}
}

// full_only: false
func TestNativePlaintextCaptureIdentityIsClosed(t *testing.T) {
	normal := Event{Kind: "plaintext", Count: 1, Matched: true, EntrySHA256: strings.Repeat("a", 64)}
	inspect := func(events []Event) error {
		var body bytes.Buffer
		for _, event := range events {
			if err := json.NewEncoder(&body).Encode(event); err != nil {
				return err
			}
		}
		_, err := inspectCaptureImage(body.Bytes(), true)
		return err
	}
	footer := Event{Kind: "footer"}
	// A repeated observation is valid capture syntax. Complete-set consumers own
	// distinctness for their specific invocation.
	if err := inspect([]Event{normal, normal, footer}); err != nil {
		t.Fatal("repeated named observation refused", err)
	}
	for _, hash := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), "raw public name"} {
		row := normal
		row.EntrySHA256 = hash
		if inspect([]Event{row, footer}) == nil {
			t.Fatal("malformed plaintext entry digest accepted")
		}
	}
	for _, damage := range []string{"count-zero", "count-many", "role", "operation", "object-key", "sequence", "sent", "status", "denied", "quota", "code"} {
		row := normal
		switch damage {
		case "count-zero":
			row.Count = 0
		case "count-many":
			row.Count = 2
		case "role":
			row.Role = "authority"
		case "operation":
			row.Operation = "kms-decrypt"
		case "object-key":
			row.ObjectKeySHA256 = strings.Repeat("b", 64)
		case "sequence":
			row.Sequence = 1
		case "sent":
			row.Sent = true
		case "status":
			row.Status = 200
		case "denied":
			row.PermissionDenied = true
		case "quota":
			row.QuotaMatched = true
		case "code":
			row.Code = 2
		}
		if inspect([]Event{row, footer}) == nil {
			t.Fatal("plaintext entry identity admitted unrelated fields", damage)
		}
	}
	for _, row := range []Event{
		footer,
		{Kind: "recovery-plaintext", Count: 1, Matched: true},
		{Kind: "recipient-plaintext", Count: 1, Matched: true, Role: "recipient-private"},
		{Kind: "construction", Count: 1, Operation: "key-access", Role: "authority"},
		{Kind: "source-kind", Count: 1, SourceKind: "aws-shared-credentials", Matched: true},
		{Kind: "local-edit-fault", Count: 1},
		{Kind: "store-result", Operation: "store-write", ObjectKeySHA256: strings.Repeat("b", 64), WriteStatus: 4, NotSent: true, LogicalConditionKind: "absent"},
		{Kind: "generator-refused", GeneratorAttempt: strings.Repeat("b", 64), GeneratorAccount: strings.Repeat("a", 32), GeneratorAction: 1},
	} {
		events := []Event{row}
		if row.Kind != "footer" {
			events = append(events, footer)
		}
		if err := inspect(events); err != nil {
			t.Fatal("unrelated event control refused", row.Kind, err)
		}
		for _, hash := range []string{normal.EntrySHA256, "invalid"} {
			events[0].EntrySHA256 = hash
			if inspect(events) == nil {
				t.Fatal("entry digest escaped its normal plaintext owner", row.Kind)
			}
		}
	}
	joined := []Event{{Kind: "http-start", Operation: "head-read", Sequence: 1, Sent: true}, {Kind: "http-return", Operation: "head-read", Sequence: 1, Sent: true, Status: 200}, footer}
	if err := inspect(joined); err != nil {
		t.Fatal("HTTP control refused", err)
	}
	for i := 0; i < 2; i++ {
		rows := append([]Event(nil), joined...)
		rows[i].EntrySHA256 = normal.EntrySHA256
		if inspect(rows) == nil {
			t.Fatal("HTTP event admitted entry digest")
		}
	}
}
