// Package nativeprocess contains local test orchestration for public executable
// joins. Its overlays observe installed paths; they cannot supply admission.
package nativeprocess

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Two provider runtimes can share the file. Each admitted request can emit a
// source, start, return and Store result. Additional slots cover publication
// sources, plaintext, generator pairs, constructors, local edits and the footer.
// Repeated or refused hooks still stop at this finite byte boundary.
const MaxCaptureBytes = (2*4096*4 + 1024 + 512 + 2*(3+8) + 14 + 3 + 1) * 1024

// Policy is private test input. Selector values and synthetic byte expectations
// never enter the capture record. A local responder is allowed only on loopback.
type Policy struct {
	Version               int               `json:"version"`
	RecordPath            string            `json:"record_path"`
	Bucket                string            `json:"bucket,omitempty"`
	Prefix                string            `json:"prefix,omitempty"`
	ListPrefix            string            `json:"list_prefix,omitempty"`
	MaxRequests           uint64            `json:"max_requests"`
	MaxBytes              uint64            `json:"max_bytes"`
	MaxStoreWrites        uint64            `json:"max_store_writes,omitempty"`
	MaxStoreWriteBytes    uint64            `json:"max_store_write_bytes,omitempty"`
	NormalSigner          string            `json:"normal_signer,omitempty"`
	SuccessorSigner       string            `json:"successor_signer,omitempty"`
	SuccessorKEK          string            `json:"successor_kek,omitempty"`
	AuthorityKEK          string            `json:"authority_kek,omitempty"`
	RecoverySigner        string            `json:"recovery_signer,omitempty"`
	RecoveryKEK           string            `json:"recovery_kek,omitempty"`
	QuotaProject          string            `json:"quota_project,omitempty"`
	Fault                 string            `json:"fault,omitempty"`
	FaultOrdinal          uint64            `json:"fault_ordinal,omitempty"`
	NoKMS                 bool              `json:"no_kms,omitempty"`
	StoreReadOnly         bool              `json:"store_read_only,omitempty"`
	LocalAddress          string            `json:"local_address,omitempty"`
	RootCAPEM             string            `json:"root_ca_pem,omitempty"`
	ExpectedSHA256        map[string]string `json:"expected_sha256,omitempty"`
	RecoveryOracle        bool              `json:"recovery_oracle,omitempty"`
	RecoveryBinding       []byte            `json:"recovery_binding,omitempty"`
	RecipientOracle       bool              `json:"recipient_oracle,omitempty"`
	RecipientBinding      []byte            `json:"recipient_binding,omitempty"`
	RecipientKEK          string            `json:"recipient_kek,omitempty"`
	ExpectedSourceKind    string            `json:"expected_source_kind,omitempty"`
	RequireStandardSource bool              `json:"require_standard_source,omitempty"`
	HeadBarrier           string            `json:"head_barrier,omitempty"`
	ManifestBarrier       string            `json:"manifest_barrier,omitempty"`
	GeneratorLedgerPath   string            `json:"generator_ledger_path,omitempty"`
	GeneratorRunID        string            `json:"generator_run_id,omitempty"`
	GeneratorAccount      string            `json:"generator_account,omitempty"`
	GeneratorCreates      uint64            `json:"generator_creates,omitempty"`
	GeneratorRetires      uint64            `json:"generator_retires,omitempty"`
}

type Event struct {
	Kind                  string           `json:"kind"`
	Count                 uint32           `json:"count,omitempty"`
	ObjectKeySHA256       string           `json:"object_key_sha256,omitempty"`
	EntrySHA256           string           `json:"entry_sha256,omitempty"`
	Operation             string           `json:"operation,omitempty"`
	Role                  string           `json:"role,omitempty"`
	Sequence              uint64           `json:"sequence,omitempty"`
	Sent                  bool             `json:"sent,omitempty"`
	Status                int              `json:"status,omitempty"`
	TransportFailure      string           `json:"transport_failure,omitempty"`
	TransportTrace        *TransportTrace  `json:"transport_trace,omitempty"`
	PermissionDenied      bool             `json:"permission_denied,omitempty"`
	QuotaMatched          bool             `json:"quota_matched,omitempty"`
	Matched               bool             `json:"matched,omitempty"`
	Code                  int              `json:"code,omitempty"`
	SourceKind            string           `json:"source_kind,omitempty"`
	WrapAbsent            bool             `json:"wrap_absent,omitempty"`
	WriteStatus           uint8            `json:"write_status,omitempty"`
	StoreReason           uint8            `json:"store_reason,omitempty"`
	NotSent               bool             `json:"not_sent,omitempty"`
	LogicalConditionKind  string           `json:"logical_condition_kind,omitempty"`
	LogicalConditionValue []byte           `json:"logical_condition_value,omitempty"`
	WireConditionKind     string           `json:"wire_condition_kind,omitempty"`
	WireConditionValue    []byte           `json:"wire_condition_value,omitempty"`
	GeneratorAttempt      string           `json:"generator_attempt,omitempty"`
	GeneratorAccount      string           `json:"generator_account,omitempty"`
	GeneratorAction       uint8            `json:"generator_action,omitempty"`
	GeneratorTarget       string           `json:"generator_target,omitempty"`
	GeneratorQualified    bool             `json:"generator_qualified,omitempty"`
	GeneratorReturn       *GeneratorReturn `json:"generator_return,omitempty"`
}

// GeneratorReturn records closed producer observations, not cleanup authority.
// Absence in a historical capture means the return was not observed in detail.
type GeneratorReturn struct {
	Code                uint16                `json:"code"`
	CommonFacts         *GeneratorCommonFacts `json:"common_facts,omitempty"`
	ExpectedResultValid bool                  `json:"expected_result_valid"`
	Qualification       string                `json:"qualification"`
}

type GeneratorCommonFacts struct {
	Disposition uint8 `json:"disposition"`
	Reason      uint8 `json:"reason"`
}

// TransportTrace records first callback observations, relative to the delegated
// RoundTrip. Unobserved callbacks are unknown; completion does not imply success.
// Completion outcomes report only whether that first callback supplied an error.
// Missing historical outcomes and later callback outcomes remain unknown. No
// callback outcome proves that a request was not sent or accepted by a provider.
// All elapsed observations saturate at ten minutes.
type TransportTrace struct {
	ElapsedMS         uint32        `json:"elapsed_ms"`
	DNSStart          TraceCallback `json:"dns_start"`
	DNSDone           TraceCallback `json:"dns_done"`
	ConnectStart      TraceCallback `json:"connect_start"`
	ConnectDone       TraceCallback `json:"connect_done"`
	TLSStart          TraceCallback `json:"tls_start"`
	TLSDone           TraceCallback `json:"tls_done"`
	WroteHeaders      TraceCallback `json:"wrote_headers"`
	WroteRequest      TraceCallback `json:"wrote_request"`
	FirstResponseByte TraceCallback `json:"first_response_byte"`
}

type TraceCallback struct {
	Observed  bool   `json:"observed"`
	ElapsedMS uint32 `json:"elapsed_ms"`
	Outcome   string `json:"outcome,omitempty"`
}

type Capture struct{ Events []Event }

// ReadCapture requires one normal-return footer and exact paired HTTP events.
// This proves process and HTTP joins, not typed Store settlement: consumers
// must require a store-result for each physical write they intend to settle.
func ReadCapture(path string) (Capture, error) { return readCapture(path, true) }

// InspectCapture validates the same bounded bytes that an evidence owner has
// already hashed. It does not reopen a path or infer provider settlement.
func InspectCapture(body []byte) (Capture, error) { return inspectCaptureImage(body, true) }

// ReadCaptureWithDigest returns the digest of the same bounded image that was
// validated. Receipt and cleanup owners must not reopen the path to hash it.
func ReadCaptureWithDigest(path string) (Capture, [32]byte, error) {
	return readCaptureImage(path, true)
}

// ReadProgress checks completed native operations before a local preparation step.
// It never qualifies normal process completion; ReadCapture requires its footer.
func ReadProgress(path string) (Capture, error) { return readCapture(path, false) }

func readCapture(path string, requireFooter bool) (Capture, error) {
	result, _, err := readCaptureImage(path, requireFooter)
	return result, err
}

func readCaptureBody(reader io.Reader, size int64) ([]byte, error) {
	if size < 0 || size > MaxCaptureBytes {
		return nil, errors.New("native capture refused")
	}
	// One sentinel detects growth without consuming an unbounded stream.
	body := make([]byte, int(size)+1)
	n, err := io.ReadFull(reader, body)
	if n != int(size) || err != io.ErrUnexpectedEOF && (size != 0 || err != io.EOF) {
		clear(body)
		return nil, errors.New("native capture changed or exceeded its bound")
	}
	return body[:n], nil
}

func readCaptureImage(path string, requireFooter bool) (result Capture, digest [32]byte, resultErr error) {
	if !filepath.IsAbs(path) {
		return result, digest, errors.New("native capture refused")
	}
	// Nonblocking open reaches the descriptor gate even for an accidental FIFO.
	// No-follow keeps this local evidence owner on the nominated regular file.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return result, digest, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			result, digest = Capture{}, [32]byte{}
			resultErr = errors.Join(resultErr, err)
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return result, digest, errors.New("native capture refused")
	}
	body, err := readCaptureBody(f, info.Size())
	if err != nil {
		return result, digest, err
	}
	defer clear(body[:cap(body)])
	after, err := f.Stat()
	if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return result, digest, errors.New("native capture changed")
	}
	result, err = inspectCaptureImage(body, requireFooter)
	if err != nil {
		return Capture{}, digest, err
	}
	return result, sha256.Sum256(body), nil
}

func inspectCaptureImage(body []byte, requireFooter bool) (Capture, error) {
	var result Capture
	if len(body) > MaxCaptureBytes {
		return result, errors.New("native capture refused")
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), 4096)
	pending := map[uint64]bool{}
	generators := map[string]Event{}
	seen := map[uint64]Event{}
	storeResults := map[uint64]bool{}
	footer := false
	for scanner.Scan() {
		if !jsontext.Value(scanner.Bytes()).IsValid() {
			return Capture{}, errors.New("native capture refused")
		}
		var event Event
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&event) != nil || decoder.Decode(new(any)) != io.EOF {
			return Capture{}, errors.New("native capture refused")
		}
		if footer {
			return Capture{}, errors.New("native capture after footer")
		}
		if event.Kind != "plaintext" && event.EntrySHA256 != "" {
			return Capture{}, errors.New("native plaintext identity owner refused")
		}
		if event.Kind != "source-kind" && event.SourceKind != "" {
			return Capture{}, errors.New("native capture source kind refused")
		}
		if event.Kind != "recipient-plaintext" && event.WrapAbsent {
			return Capture{}, errors.New("native capture wrap absence refused")
		}
		if event.Kind != "store-result" && (event.WriteStatus != 0 || event.StoreReason != 0 || event.NotSent) {
			return Capture{}, errors.New("native capture Store status refused")
		}
		if !strings.HasPrefix(event.Kind, "generator-") && (event.GeneratorAttempt != "" || event.GeneratorAccount != "" || event.GeneratorAction != 0 || event.GeneratorTarget != "" || event.GeneratorQualified) {
			return Capture{}, errors.New("native generator field owner refused")
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(scanner.Bytes(), &fields) != nil {
			return Capture{}, errors.New("native capture refused")
		}
		if _, present := fields["transport_failure"]; present {
			if event.Kind != "http-return" || !event.Sent || event.Status != 0 || event.PermissionDenied || event.QuotaMatched {
				return Capture{}, errors.New("native transport failure owner refused")
			}
			switch event.TransportFailure {
			case "cancelled", "deadline", "dns", "timeout", "tls", "connection", "eof", "other":
			default:
				return Capture{}, errors.New("native transport failure class refused")
			}
		}
		// encoding/json folds field names; trace admission requires exact spelling.
		for name := range fields {
			if name != "transport_trace" && strings.EqualFold(name, "transport_trace") {
				return Capture{}, errors.New("native transport trace field refused")
			}
			if name != "generator_return" && strings.EqualFold(name, "generator_return") {
				return Capture{}, errors.New("native generator return field refused")
			}
		}
		if raw, present := fields["generator_return"]; present {
			if event.Kind != "generator-return" || !nativeGeneratorReturnValid(raw, event) {
				return Capture{}, errors.New("native generator return refused")
			}
		}
		if raw, present := fields["transport_trace"]; present {
			if event.Kind != "http-return" || !event.Sent || !nativeTransportTraceValid(raw, event.TransportTrace) {
				return Capture{}, errors.New("native transport trace refused")
			}
		}
		hasCondition := false
		for _, field := range []string{"logical_condition_kind", "logical_condition_value", "wire_condition_kind", "wire_condition_value"} {
			if _, present := fields[field]; present {
				hasCondition = true
			}
		}
		if hasCondition && (event.Kind != "http-start" && event.Kind != "store-result" || event.Operation != "head-write" && event.Operation != "store-write" && event.Operation != "store-delete") {
			return Capture{}, errors.New("native capture condition owner refused")
		}
		if event.Kind == "store-result" || hasCondition {
			if !nativeStoreConditionValid(event) {
				return Capture{}, errors.New("native capture original condition refused")
			}
		}
		switch event.Kind {
		case "generator-entry", "generator-return", "generator-refused":
			if !nativeGeneratorEventValid(event) {
				return Capture{}, errors.New("native generator event refused")
			}
			switch event.Kind {
			case "generator-entry":
				if _, exists := generators[event.GeneratorAttempt]; exists {
					return Capture{}, errors.New("native generator duplicate entry")
				}
				generators[event.GeneratorAttempt] = event
			case "generator-return":
				entry, exists := generators[event.GeneratorAttempt]
				if !exists || entry.GeneratorAccount != event.GeneratorAccount || entry.GeneratorAction != event.GeneratorAction || entry.GeneratorAction == 2 && entry.GeneratorTarget != event.GeneratorTarget {
					return Capture{}, errors.New("native generator result join refused")
				}
				delete(generators, event.GeneratorAttempt)
			}
		case "local-edit-fault", "local-edit-unknown", "local-edit-disposed":
			wantCount := uint32(1)
			if event.Kind == "local-edit-disposed" {
				wantCount = 4
			}
			if event.Count != wantCount || event.Kind != "local-edit-disposed" && event.Matched || event.ObjectKeySHA256 != "" || event.Operation != "" || event.Role != "" || event.Sequence != 0 || event.Sent || event.Status != 0 || event.PermissionDenied || event.QuotaMatched || event.Code != 0 {
				return Capture{}, errors.New("native local edit observation refused")
			}
		case "construction":
			switch event.Operation {
			case "signing-metadata", "encryption-metadata", "signer", "key-access", "public-qualifier":
			default:
				return Capture{}, errors.New("native constructor purpose refused")
			}
			switch event.Role {
			case "normal", "successor", "successor-private", "authority", "recovery-signing", "recovery-private", "recipient-private", "ordinary":
			default:
				return Capture{}, errors.New("native constructor role refused")
			}
			if event.Count != 1 || event.ObjectKeySHA256 != "" || event.Sequence != 0 || event.Sent || event.Status != 0 || event.PermissionDenied || event.QuotaMatched || event.Matched || event.Code != 0 {
				return Capture{}, errors.New("native constructor event refused")
			}
		case "source-kind":
			if (event.SourceKind != "aws-sso" && event.SourceKind != "aws-assume-role" && event.SourceKind != "aws-shared-credentials" && event.SourceKind != "gcp-user-adc" && event.SourceKind != "gcp-impersonated-adc" && event.SourceKind != "gcp-service-account-adc") || event.Count != 1 ||
				event.ObjectKeySHA256 != "" || event.Operation != "" || event.Role != "" || event.Sequence != 0 ||
				event.Sent || event.Status != 0 || event.PermissionDenied || event.QuotaMatched || event.Code != 0 {
				return Capture{}, errors.New("native capture source kind refused")
			}
		case "http-start":
			if _, exists := seen[event.Sequence]; event.Sequence == 0 || exists {
				return Capture{}, errors.New("native capture sequence refused")
			}
			pending[event.Sequence] = true
			seen[event.Sequence] = event
		case "http-return":
			start := seen[event.Sequence]
			if !pending[event.Sequence] || event.Operation != start.Operation || event.ObjectKeySHA256 != start.ObjectKeySHA256 || event.Role != start.Role || event.Sent != start.Sent {
				return Capture{}, errors.New("native capture return refused")
			}
			delete(pending, event.Sequence)
		case "store-result":
			if event.Operation != "head-write" && event.Operation != "store-write" && event.Operation != "store-delete" ||
				event.Count != 0 || event.Role != "" || event.Status != 0 || event.PermissionDenied || event.QuotaMatched || event.Matched || event.Code != 0 ||
				len(event.ObjectKeySHA256) != sha256.Size*2 {
				return Capture{}, errors.New("native capture Store result refused")
			}
			for _, digit := range event.ObjectKeySHA256 {
				if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
					return Capture{}, errors.New("native capture Store key refused")
				}
			}
			if event.WriteStatus < 1 || event.WriteStatus > 5 {
				return Capture{}, errors.New("native capture Store status refused")
			}
			if event.StoreReason > 7 || event.NotSent && (event.Sent || event.WriteStatus != 4 && event.WriteStatus != 5) {
				return Capture{}, errors.New("native capture Store transmission result refused")
			}
			if event.Sequence == 0 {
				if event.Sent {
					return Capture{}, errors.New("native capture unsent Store result refused")
				}
				break
			}
			start, exists := seen[event.Sequence]
			if !exists || pending[event.Sequence] || storeResults[event.Sequence] || event.Operation != start.Operation || event.ObjectKeySHA256 != start.ObjectKeySHA256 || event.Sent != start.Sent || event.LogicalConditionKind != start.LogicalConditionKind || !bytes.Equal(event.LogicalConditionValue, start.LogicalConditionValue) || event.WireConditionKind != start.WireConditionKind || !bytes.Equal(event.WireConditionValue, start.WireConditionValue) {
				return Capture{}, fmt.Errorf("native capture Store result join refused: sequence=%d events=%d start_seen=%t http_pending=%t duplicate=%t operation_equal=%t key_equal=%t sent_equal=%t logical_kind_equal=%t logical_value_equal=%t wire_kind_equal=%t wire_value_equal=%t", event.Sequence, len(result.Events), exists, pending[event.Sequence], storeResults[event.Sequence], event.Operation == start.Operation, event.ObjectKeySHA256 == start.ObjectKeySHA256, event.Sent == start.Sent, event.LogicalConditionKind == start.LogicalConditionKind, bytes.Equal(event.LogicalConditionValue, start.LogicalConditionValue), event.WireConditionKind == start.WireConditionKind, bytes.Equal(event.WireConditionValue, start.WireConditionValue))
			}
			storeResults[event.Sequence] = true
		case "plaintext":
			if len(event.EntrySHA256) != sha256.Size*2 || event.Count != 1 || event.ObjectKeySHA256 != "" || event.Operation != "" || event.Role != "" || event.Sequence != 0 || event.Sent || event.Status != 0 || event.PermissionDenied || event.QuotaMatched || event.Code != 0 {
				return Capture{}, errors.New("native plaintext identity refused")
			}
			for _, digit := range event.EntrySHA256 {
				if digit < '0' || digit > '9' && digit < 'a' || digit > 'f' {
					return Capture{}, errors.New("native plaintext identity refused")
				}
			}
		case "recovery-plaintext":
		case "recipient-plaintext":
			if event.Role != "recipient-private" || event.Count > 1 || event.Matched && event.Count != 1 ||
				event.WrapAbsent && (event.Count != 0 || event.Matched || event.PermissionDenied) || event.PermissionDenied && event.Count != 0 ||
				event.ObjectKeySHA256 != "" || event.Operation != "" || event.Sequence != 0 || event.Sent || event.Status != 0 || event.QuotaMatched || event.Code != 0 {
				return Capture{}, errors.New("native capture recipient observation refused")
			}
		case "footer":
			footer = true
		default:
			return Capture{}, errors.New("native capture event refused")
		}
		result.Events = append(result.Events, event)
	}
	if scanner.Err() != nil || requireFooter && !footer || len(pending) != 0 || requireFooter && len(generators) != 0 {
		return Capture{}, errors.New("native capture incomplete")
	}
	return result, nil
}

func nativeGeneratorReturnValid(raw json.RawMessage, e Event) bool {
	r := e.GeneratorReturn
	var fields map[string]json.RawMessage
	if r == nil || json.Unmarshal(raw, &fields) != nil || len(fields) != 3 && len(fields) != 4 ||
		(r.Code < 1 || r.Code > 12) || len(fields["code"]) == 0 ||
		!bytes.Equal(fields["expected_result_valid"], []byte("true")) && !bytes.Equal(fields["expected_result_valid"], []byte("false")) ||
		len(fields["qualification"]) == 0 {
		return false
	}
	if facts, present := fields["common_facts"]; present {
		var common map[string]json.RawMessage
		if r.CommonFacts == nil || json.Unmarshal(facts, &common) != nil || len(common) != 2 ||
			len(common["disposition"]) == 0 || len(common["reason"]) == 0 || bytes.Equal(common["reason"], []byte("null")) ||
			r.CommonFacts.Disposition < 1 || r.CommonFacts.Disposition > 8 ||
			r.CommonFacts.Reason > 10 ||
			r.CommonFacts.Disposition >= 6 && r.CommonFacts.Reason != 0 {
			return false
		}
		switch r.CommonFacts.Disposition {
		case 1, 4:
			if r.CommonFacts.Reason != 0 {
				return false
			}
		case 2:
			if r.CommonFacts.Reason < 1 || r.CommonFacts.Reason > 4 {
				return false
			}
		case 5:
			if r.CommonFacts.Reason < 5 {
				return false
			}
		}
	} else if len(fields) != 3 || r.CommonFacts != nil {
		return false
	}
	if r.ExpectedResultValid && r.CommonFacts == nil || e.GeneratorQualified != (r.Qualification == "qualified") {
		return false
	}
	if r.ExpectedResultValid {
		d := r.CommonFacts.Disposition
		if e.GeneratorAction == 1 && d > 3 ||
			e.GeneratorAction == 2 && d != 4 && d < 6 {
			return false
		}
	}
	if r.Code != 1 {
		return r.Qualification == "producer-failed"
	}
	if !r.ExpectedResultValid {
		return r.Qualification == "facts-refused"
	}
	switch r.Qualification {
	case "resource-unavailable":
		return e.GeneratorAction == 1 && e.GeneratorTarget == ""
	case "disposition-refused":
		return e.GeneratorAction == 2 && r.CommonFacts.Disposition >= 6
	case "ledger-unavailable", "qualified":
		return e.GeneratorTarget != "" && (e.GeneratorAction == 1 &&
			(r.CommonFacts.Disposition == 1 || r.CommonFacts.Disposition == 2) ||
			e.GeneratorAction == 2 && r.CommonFacts.Disposition == 4)
	default:
		return false
	}
}

func nativeTransportTraceValid(raw json.RawMessage, trace *TransportTrace) bool {
	var fields map[string]json.RawMessage
	if trace == nil || trace.ElapsedMS > 600000 || json.Unmarshal(raw, &fields) != nil || len(fields) != 10 || bytes.Equal(fields["elapsed_ms"], []byte("null")) || len(fields["elapsed_ms"]) == 0 {
		return false
	}
	for _, callback := range []struct {
		name  string
		value TraceCallback
	}{
		{"dns_start", trace.DNSStart}, {"dns_done", trace.DNSDone},
		{"connect_start", trace.ConnectStart}, {"connect_done", trace.ConnectDone},
		{"tls_start", trace.TLSStart}, {"tls_done", trace.TLSDone},
		{"wrote_headers", trace.WroteHeaders}, {"wrote_request", trace.WroteRequest},
		{"first_response_byte", trace.FirstResponseByte},
	} {
		var observation map[string]json.RawMessage
		if json.Unmarshal(fields[callback.name], &observation) != nil || len(observation) != 2 && len(observation) != 3 ||
			!bytes.Equal(observation["observed"], []byte("true")) && !bytes.Equal(observation["observed"], []byte("false")) ||
			len(observation["elapsed_ms"]) == 0 || bytes.Equal(observation["elapsed_ms"], []byte("null")) ||
			callback.value.ElapsedMS > trace.ElapsedMS || !callback.value.Observed && callback.value.ElapsedMS != 0 {
			return false
		}
		outcome, present := observation["outcome"]
		if !present {
			if len(observation) != 2 || callback.value.Outcome != "" {
				return false
			}
			continue
		}
		if len(observation) != 3 || !callback.value.Observed ||
			callback.name != "dns_done" && callback.name != "connect_done" && callback.name != "tls_done" && callback.name != "wrote_request" ||
			!bytes.Equal(outcome, []byte(`"no-error"`)) && !bytes.Equal(outcome, []byte(`"error"`)) {
			return false
		}
	}
	return true
}

// nativeStoreConditionValid checks the typed input and, only after a physical
// send, the exact permitted SDK precondition. Raw HTTP alone proves no input.
func nativeStoreConditionValid(event Event) bool {
	if event.Operation == "store-delete" && event.LogicalConditionKind != "match" {
		return false
	}
	switch event.LogicalConditionKind {
	case "absent":
		if len(event.LogicalConditionValue) != 0 {
			return false
		}
	case "match":
		if !nativeAWSConditionTokenValid(event.LogicalConditionValue) && !nativeGCPConditionTokenValid(event.LogicalConditionValue) {
			return false
		}
	default:
		return false
	}
	if !event.Sent {
		return event.WireConditionKind == "" && len(event.WireConditionValue) == 0
	}
	switch event.WireConditionKind {
	case "aws-if-none-match":
		return event.LogicalConditionKind == "absent" && bytes.Equal(event.WireConditionValue, []byte("*"))
	case "aws-if-match":
		return event.LogicalConditionKind == "match" && nativeAWSConditionTokenValid(event.LogicalConditionValue) && bytes.Equal(event.LogicalConditionValue, event.WireConditionValue)
	case "gcp-generation-match":
		if event.LogicalConditionKind == "absent" {
			return bytes.Equal(event.WireConditionValue, []byte("0"))
		}
		return nativeGCPConditionTokenValid(event.LogicalConditionValue) && bytes.Equal(event.LogicalConditionValue, event.WireConditionValue)
	}
	return false
}

// Capture syntax stays standard-library-only. Actual provider token admission
// remains with its contract owner; this observer grants no call authority.
func nativeAWSConditionTokenValid(value []byte) bool {
	if len(value) < 2 || len(value) > 256 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	for _, b := range value[1 : len(value)-1] {
		if b != 0x21 && (b < 0x23 || b > 0x7e) && b < 0x80 {
			return false
		}
	}
	return true
}

func nativeGCPConditionTokenValid(value []byte) bool {
	if len(value) == 0 || len(value) > 19 {
		return false
	}
	text := string(value)
	n, err := strconv.ParseInt(text, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == text
}

// Exact accepted identities are test evidence only. No event grants dispatch.
func nativeGeneratorEventValid(e Event) bool {
	hexID := func(s string, n int) bool {
		if len(s) != n {
			return false
		}
		for _, b := range s {
			if b < '0' || b > '9' && b < 'a' || b > 'f' {
				return false
			}
		}
		return true
	}
	return hexID(e.GeneratorAttempt, 64) && hexID(e.GeneratorAccount, 32) &&
		(e.GeneratorAction == 1 && (e.GeneratorTarget == "" && !e.GeneratorQualified || e.Kind == "generator-return" && hexID(e.GeneratorTarget, 32)) || e.GeneratorAction == 2 && hexID(e.GeneratorTarget, 32)) &&
		(e.Kind == "generator-return" || !e.GeneratorQualified) && e.Count == 0 && e.ObjectKeySHA256 == "" && e.Operation == "" && e.Role == "" && e.Sequence == 0 && !e.Sent && e.Status == 0 && !e.PermissionDenied && !e.QuotaMatched && !e.Matched && e.Code == 0 && e.SourceKind == "" && !e.WrapAbsent && e.WriteStatus == 0
}
