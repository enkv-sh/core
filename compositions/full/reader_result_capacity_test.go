package compositionfull

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestReaderResultWriterBoundAndLateDiscard(t *testing.T) {
	// This independent account includes both sides, added/removed leaf fields,
	// complete values and the closed readable wrapper grammar.
	const fields = 2*512*18 + 2*256*8 + 2*64*3 + 2*1024*12 + 2*513*2 + 2*32 + 2
	const diagnosticCount = 160060
	const semanticImage = 121158832
	const typedImage = 119531256
	const values = 2 * (semanticImage + typedImage)
	const maximum = 656719904 + 12*semanticImage + diagnosticCount*(512+1024)
	const controlled = 2146794448 + values + (maximum - 656719904)
	if fields != 49606 || fields > diagnosticCount || values != 481380176 || maximum != 2356478048 || controlled != 4327932768 {
		t.Fatal("independent comparison value/readable account changed")
	}
	if diagnosticCount != contract.MaxPublicDiagnostics || maximum != contract.MaxComparisonResultJSONBytes || values != comparisonValueBackingLimit || semanticImage != contract.MaxPublicConfigurationBytes || typedImage != contract.MaxPublicTypedConfigurationBytes {
		t.Fatal("comparison contract differs from independent output account")
	}
	// Exercise exact J and J+1 without allocating a speculative maximum body.
	w := readerResultWriter{at: maximum - 1}
	w.literal("x")
	if w.failed || w.at != maximum || w.body != nil {
		t.Fatal("exact J counting boundary refused or allocated")
	}
	w.literal("x")
	if !w.failed || w.at != maximum {
		t.Fatal("J+1 counting escaped")
	}
	for _, name := range []string{"malformed-second-traversal", "length-second-traversal"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			var provisional []byte
			body, err := renderReaderResult(func(w *readerResultWriter) {
				calls++
				if calls == 1 && w.body != nil {
					t.Fatal("counting allocated output")
				}
				if calls == 2 {
					provisional = w.body
				}
				w.literal("prefix")
				if calls == 2 && name == "malformed-second-traversal" {
					w.json(func() {}, 128)
				} else if calls == 2 {
					w.literal("longer")
				} else {
					w.json("x", 128)
				}
			})
			if body != nil || err != ErrReaderResult || calls != 2 || len(provisional) != 9 || cap(provisional) != 9 {
				t.Fatal("late writer failure escaped with partial output", err)
			}
			for _, b := range provisional {
				if b != 0 {
					t.Fatal("late writer failure retained provisional bytes")
				}
			}
		})
	}
	var provisional []byte
	got, err := renderReaderResult(func(w *readerResultWriter) {
		if w.body != nil {
			provisional = w.body
		}
		w.literal("literal")
	})
	if err != nil || string(got) != "literal" || len(got) != cap(got) || unsafe.SliceData(got) != unsafe.SliceData(provisional) {
		t.Fatal("successful writer did not transfer its one exact owner", err)
	}
}

// full_only: true
// Proves the conservative D diagnostic vector through both result codecs.
// This repeated legal descriptor vector is not a reachable-operation claim.
// Small semantic/escaping refusals are in TestReaderDiagnosticRenderingBoundsAndLateRefusal.
func TestReaderResultMaximumDiagnosticVector(t *testing.T) {
	name := strings.Repeat("\x00", 256)
	path := []contract.DiagnosticField{contract.FieldConsumerPolicy}
	source := &contract.SourceLocation{SourceID: strings.Repeat("s", 64), Line: math.MaxUint64, Column: math.MaxUint64}
	d := contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, Name: name, DestinationID: name}, Path: path, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable, SourceLocation: source}
	r := ConfigurationComparisonResult{PublicComparisonResult: core.PublicComparisonResult{Context: core.ReaderOperationContext{Operation: contract.ReaderCompareOperation}, StateResult: contract.ReaderPositiveDefect, ComparisonPayload: contract.ComparisonPayload{Verdict: contract.ComparisonUnable, DiagnosticsComplete: true, EvidenceLimit: contract.ComparisonEvidenceLimit, Diagnostics: make([]contract.Diagnostic, contract.MaxPublicDiagnostics)}}, InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
	for i := range r.Diagnostics {
		r.Diagnostics[i] = d
	}
	// One shared name backing, path backing and source owner; the D-sized row
	// vector is complete. No D independent copies of the shared text are claimed.
	owned := uintptr(cap(r.Diagnostics))*unsafe.Sizeof(contract.Diagnostic{}) + uintptr(cap(path))*unsafe.Sizeof(contract.DiagnosticField("")) + unsafe.Sizeof(*source) + uintptr(len(name)+len(source.SourceID))
	// The subject owns three 16-byte strings, one 32-byte recipient ID and
	// a routing key (one padded selector word plus a 16-byte entry-name string).
	// The row adds a 24-byte path slice, two strings and one 8-byte pointer.
	const routingKey = 8 + 16
	const subject = 3*16 + 32 + routingKey
	const row = subject + 24 + 2*16 + 8
	const shared = 16 + 32 + 256 + 64
	const fixture = 160060*row + shared
	if row != 168 || fixture != 26890448 {
		t.Fatal("independent diagnostic layout account changed")
	}
	if len(r.Diagnostics) != 160060 || cap(r.Diagnostics) != len(r.Diagnostics) || unsafe.Sizeof(contract.PublicRoutingKey{}) != routingKey || unsafe.Sizeof(contract.DiagnosticSubject{}) != subject || unsafe.Sizeof(contract.Diagnostic{}) != row || owned != fixture {
		t.Fatal("diagnostic fixture backing account changed", owned)
	}
	// Map keys have fixed lexicographic JSON order. Each NUL expands to six
	// bytes; all remaining facts below are independent closed grammar literals.
	record := `{"subject":{"destination_id":"` + strings.Repeat(`\u0000`, 256) + `","kind":"output_target","name":"` + strings.Repeat(`\u0000`, 256) + `"},"path":[{"field":"consumer_policy"}],"outcome":"unable to verify","reason":"required-public-fact-unavailable","source_location":{"source_id":"` + strings.Repeat("s", 64) + `","line":18446744073709551615,"column":18446744073709551615}}`
	humanRecord := `Issue output target "` + strings.Repeat(`\x00`, 256) + `" destination "` + strings.Repeat(`\x00`, 256) + `"; field consumer_policy: unable to verify; required-public-fact-unavailable; source "` + strings.Repeat("s", 64) + `" location 18446744073709551615:18446744073709551615`
	if len(record) > 4096 {
		t.Fatal("independent maximum-width record exceeds its allowance")
	}
	const evidence = "Fixed authenticated public settings and requested generated intent only; future generated content is unavailable and secret-value equality is unchecked. Excludes apply admission or no-op, performed effects or credential validity, remote output contents or IAM, historical application, and continued currentness."
	if evidence != contract.ComparisonEvidenceLimit {
		t.Fatal("comparison evidence literal changed")
	}
	// Only this one bounded record and a small wrapper are formatted by the
	// standard library oracle. The expected D-vector is streamed, never copied.
	var readableRecord bytes.Buffer
	if err := json.Indent(&readableRecord, []byte(record), "      ", "  "); err != nil {
		t.Fatal("independent diagnostic record is malformed", err)
	}
	machineRecord := "      " + readableRecord.String()
	const compactPrefix = `{"schema":"ProductResult/v1","operation_kind":"compare-public-configuration","state_result":"positive-defect","effect_summary":"not-applicable","output_summary":"not-applicable","context":{"operation":"compare-public-configuration"},"payload":{"schema":"ComparisonPayload/v1","verdict":"unable to verify","diagnostics_complete":true,"evidence_limit":"`
	const compactMiddle = `","checked_scope":[],"diagnostics":[0],"changes":[],"recipient_labels":{"before":[],"after":[]},"generated_entries":[]},"installation_requirements":{"complete":false,"differences":[]}}`
	var readableWrapper bytes.Buffer
	if err := json.Indent(&readableWrapper, []byte(compactPrefix+evidence+compactMiddle), "", "  "); err != nil {
		t.Fatal("independent diagnostic wrapper is malformed", err)
	}
	machinePrefix, machineSuffix, found := strings.Cut(readableWrapper.String(), "      0")
	if !found {
		t.Fatal("independent diagnostic slot is absent")
	}
	for _, form := range []struct {
		name      string
		render    func(ConfigurationComparisonResult) ([]byte, error)
		prefix    string
		before    string
		after     string
		suffix    string
		record    string
		separator string
	}{
		{"machine", RenderComparisonJSON, machinePrefix, "", "", machineSuffix + "\n", machineRecord, ",\n"},
		{"human", RenderComparisonHuman, "Plan incomplete: positive-defect\nPublic configuration: not fully checked.\nVerdict: unable to verify\nDiagnostics complete: true; issues: 160060\nEvidence: " + evidence + "\nSupplied secret equality: unchecked.\n", "", "\n", "No changes were applied or published.\nLocal plugin selection comparison: incomplete; 0 differences.\n", humanRecord, ""},
	} {
		t.Run(form.name, func(t *testing.T) {
			want := sha256.New()
			length := 0
			expect := func(s string) { length += len(s); _, _ = io.WriteString(want, s) }
			expect(form.prefix)
			for i := range r.Diagnostics {
				if i > 0 {
					expect(form.separator)
				}
				expect(form.before)
				expect(form.record)
				expect(form.after)
			}
			expect(form.suffix)
			if length > contract.MaxComparisonResultJSONBytes || len(form.prefix)+len(form.suffix) > 65536 {
				t.Fatal("independent diagnostic output exceeds J")
			}
			got, err := form.render(r)
			if err != nil || len(got) != length || cap(got) != length {
				t.Fatal("complete maximum diagnostic output differs", err, len(got), cap(got), length)
			}
			digest := sha256.Sum256(got)
			if !bytes.Equal(digest[:], want.Sum(nil)) {
				t.Fatal("maximum output digest differs from independent records")
			}
			// Check every exact semantic record without decoding or retaining a
			// second whole output. Count and order cannot hide behind a hash.
			at := len(form.prefix)
			consume := func(s string) {
				if at > len(got)-len(s) || !bytes.Equal(got[at:at+len(s)], []byte(s)) {
					t.Fatalf("record grammar differs at byte %d", at)
				}
				at += len(s)
			}
			for i := range r.Diagnostics {
				if i > 0 {
					consume(form.separator)
				}
				consume(form.before)
				consume(form.record)
				consume(form.after)
			}
			consume(form.suffix)
			if at != len(got) || !bytes.Equal(got[:len(form.prefix)], []byte(form.prefix)) {
				t.Fatal("maximum result has omitted/trailing records or changed header")
			}
			t.Logf("format=%s emitted_bytes=%d record_bytes=%d diagnostics=%d fixture_owned_bytes=%d digest=%x", form.name, len(got), len(form.record), len(r.Diagnostics), owned, digest)
		})
		// The result has left the subtest scope. Reclaim it before the next
		// maximum representation; this is not an RSS or Go arena measurement.
		runtime.GC()
	}
	for _, name := range []string{"malformed-final-record", "overlong-final-name", "one-over-count"} {
		t.Run(name, func(t *testing.T) {
			original := r.Diagnostics
			defer func() {
				r.Diagnostics = original
				r.Diagnostics[len(r.Diagnostics)-1] = d
			}()
			switch name {
			case "malformed-final-record":
				r.Diagnostics[len(r.Diagnostics)-1].Reason = "raw-error-sentinel"
			case "overlong-final-name":
				r.Diagnostics[len(r.Diagnostics)-1].Subject.Name = strings.Repeat("x", 257)
			case "one-over-count":
				r.Diagnostics = make([]contract.Diagnostic, contract.MaxPublicDiagnostics+1)
				copy(r.Diagnostics, original)
				r.Diagnostics[len(r.Diagnostics)-1] = d
			}
			for _, render := range []func(ConfigurationComparisonResult) ([]byte, error){RenderComparisonJSON, RenderComparisonHuman} {
				got, err := render(r)
				if got != nil || err != ErrReaderResult {
					t.Fatal("maximum invalid vector returned partial result", err)
				}
			}
		})
	}
}

// full_only: false
func TestConfigurationSourceFailureFitsFramingAllowance(t *testing.T) {
	// The source singleton cannot accompany a subject-name diagnostic vector.
	// Its independent bound includes all declared ASCII text maxima and headers.
	const backing = 80 + 64 + 512 + 64 + 7 + 4096
	const framing = 4096 + 12*256 + 4096 + 26634 + 1024
	if unsafe.Sizeof(ConfigurationSourceFailure{}) != 96 || backing != 4823 || framing != 38922 || framing > 65536 {
		t.Fatal("source failure backing or fixed framing account changed")
	}
	f := &ConfigurationSourceFailure{SourceID: "candidate.generated", Path: "/" + strings.Repeat("\x01", 4095), Field: strings.Repeat("store_configuration.", 15) + "store_configuration", Reason: "flow-indicator-in-plain-scalar", Line: math.MaxUint64, Column: math.MaxUint64, Precision: "context"}
	if !validConfigurationSourceFailure(f) {
		t.Fatal("maximum-width safe source fact refused")
	}
	const prefix = `{"source_id":"candidate.generated","path":"/`
	want := prefix + strings.Repeat(`\u0001`, 4095) + `","field":"` + strings.Repeat("store_configuration.", 15) + `store_configuration","reason":"flow-indicator-in-plain-scalar","line":18446744073709551615,"column":18446744073709551615,"precision":"context"}`
	body, err := renderReaderResult(func(w *readerResultWriter) { w.json(f, configurationSourceFailureJSONBytes) })
	if err != nil || string(body) != want || len(want) > 26634 {
		t.Fatal("safe singleton differs from independent bounded literal", err)
	}
}
