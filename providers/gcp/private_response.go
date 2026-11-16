package gcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
)

const maximumPrivateErrorHTTPStatus = 599

const (
	maximumPrivateSuccessResponseBytes = 4096
	maximumPrivateSuccessNodes         = 32
	maximumPrivateErrorDepth           = 16
	maximumPrivateErrorNodes           = 4096
)

// Only AsymmetricDecrypt installs this state. Public metadata, Trust and Store
// retain their existing response profiles and do not enter this guard.
type privateDecrypt struct {
	packetLength uint16
	protection   string
	raw          []byte
	observed     enkvcrypto.KeyUses
}

func (p *privateDecrypt) clear() { clear(p.raw[:cap(p.raw)]); p.raw = nil }

type privateFailure uint8

const (
	privateTransportFailure privateFailure = iota + 1
	privateMalformed
	privateLimit
	privateUnknownCode
	privateProviderFailure
)

type privateResponseError struct {
	kind       privateFailure
	status     enkvcrypto.KeyStatus
	httpStatus int
}

func (e *privateResponseError) Error() string {
	switch e.kind {
	case privateMalformed:
		return "GCP private response malformed"
	case privateLimit:
		return "GCP private response limit exceeded"
	case privateUnknownCode:
		return "GCP private response code unknown"
	case privateProviderFailure:
		return "GCP private operation refused"
	default:
		return "GCP private transport incomplete"
	}
}
func privateStatus(err error) enkvcrypto.KeyStatus {
	var safe *privateResponseError
	if errors.As(err, &safe) {
		return safe.status
	}
	return enkvcrypto.KeyUnavailable
}

func (p *privateDecrypt) response(resp *http.Response) (*http.Response, error) {
	success := resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices
	status := enkvcrypto.KeyUnknown
	fail := func(kind privateFailure) (*http.Response, error) {
		p.observed.Record(1, status)
		if kind == privateProviderFailure && status == enkvcrypto.KeyUnavailable {
			p.observed = enkvcrypto.KeyUses{Failed: 1}
		}
		p.clear()
		return nil, &privateResponseError{kind: kind, status: status, httpStatus: resp.StatusCode}
	}
	limit := int64(maxJSON)
	if success {
		limit = maximumPrivateSuccessResponseBytes
	}
	if resp.Uncompressed || (resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity") {
		_ = resp.Body.Close()
		return fail(privateMalformed)
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	closeErr := resp.Body.Close()
	p.raw = raw
	if readErr != nil || closeErr != nil {
		status = enkvcrypto.KeyUnavailable
		return fail(privateTransportFailure)
	}
	if int64(len(raw)) > limit {
		return fail(privateLimit)
	}
	if resp.ContentLength >= 0 && int64(len(raw)) != resp.ContentLength {
		status = enkvcrypto.KeyUnavailable
		return fail(privateTransportFailure)
	}
	if !utf8.Valid(raw) {
		return fail(privateMalformed)
	}
	if success {
		if resp.StatusCode != http.StatusOK || !p.success(raw) {
			return fail(privateMalformed)
		}
		p.observed = enkvcrypto.KeyUses{Completed: 1}
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		return resp, nil
	}
	code, httpCode, kind := inspectPrivateError(raw)
	if kind != 0 {
		return fail(kind)
	}
	if httpCode != resp.StatusCode {
		return fail(privateMalformed)
	}
	status = code.outcome(httpCode)
	if status == enkvcrypto.KeyUnknown {
		return fail(privateUnknownCode)
	}
	return fail(privateProviderFailure)
}

func (p *privateDecrypt) success(raw []byte) bool {
	if p.packetLength != contract.SingleKeyMaterialPacketLength && p.packetLength != contract.ValueMaterialPacketLength {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	var seen uint8
	nodes := 1
	var scratch [102]byte
	var encoded [136]byte
	defer clear(encoded[:])
	defer clear(scratch[:])
	var packetCRC, expectedCRC uint32
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return false
		}
		nodes++
		value, e := d.Token()
		if e != nil {
			return false
		}
		nodes++
		if nodes > maximumPrivateSuccessNodes {
			return false
		}
		var bit uint8
		switch key {
		case "plaintext":
			bit = 1
			text, ok := value.(string)
			if !ok || len(text) != base64.StdEncoding.EncodedLen(int(p.packetLength)) || strings.ContainsAny(text, "\r\n") {
				return false
			}
			n, e := base64.StdEncoding.Strict().Decode(scratch[:], encoded[:copy(encoded[:], text)])
			if e != nil || n != int(p.packetLength) {
				return false
			}
			packetCRC = crc(scratch[:n])
		case "plaintextCrc32c":
			bit = 2
			text, ok := value.(string)
			if !ok {
				return false
			}
			n, e := strconv.ParseUint(text, 10, 32)
			if e != nil || strconv.FormatUint(n, 10) != text {
				return false
			}
			expectedCRC = uint32(n)
		case "verifiedCiphertextCrc32c":
			bit = 4
			verified, ok := value.(bool)
			if !ok || !verified {
				return false
			}
		case "protectionLevel":
			bit = 8
			level, ok := value.(string)
			if !ok || level != p.protection {
				return false
			}
		default:
			return false
		}
		if seen&bit != 0 {
			return false
		}
		seen |= bit
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') || seen != 15 || packetCRC != expectedCRC {
		return false
	}
	_, e = d.Token()
	return e == io.EOF
}

type privateProviderCode uint8

const (
	codeDenied privateProviderCode = iota + 1
	codeUnauthenticated
	codeInvalid
	codeMissing
	codeState
	codeTimeout
	codeUnavailable
	codeInternal
	codeExhausted
)

func privateCode(s string) privateProviderCode {
	switch s {
	case "PERMISSION_DENIED":
		return codeDenied
	case "UNAUTHENTICATED":
		return codeUnauthenticated
	case "INVALID_ARGUMENT":
		return codeInvalid
	case "NOT_FOUND":
		return codeMissing
	case "FAILED_PRECONDITION":
		return codeState
	case "DEADLINE_EXCEEDED":
		return codeTimeout
	case "UNAVAILABLE":
		return codeUnavailable
	case "INTERNAL":
		return codeInternal
	case "RESOURCE_EXHAUSTED":
		return codeExhausted
	default:
		return 0
	}
}
func (c privateProviderCode) outcome(status int) enkvcrypto.KeyStatus {
	switch c {
	case codeDenied:
		if status == http.StatusForbidden {
			return enkvcrypto.KeyDenied
		}
	case codeUnauthenticated:
		if status == http.StatusUnauthorized {
			return enkvcrypto.KeyDenied
		}
	case codeInvalid:
		if status == http.StatusBadRequest {
			return enkvcrypto.KeyInvalid
		}
	case codeMissing:
		if status == http.StatusNotFound {
			return enkvcrypto.KeyUnavailable
		}
	case codeState:
		if status == http.StatusBadRequest {
			return enkvcrypto.KeyUnavailable
		}
	case codeTimeout:
		if status == http.StatusGatewayTimeout {
			return enkvcrypto.KeyUnavailable
		}
	case codeUnavailable:
		if status == http.StatusServiceUnavailable {
			return enkvcrypto.KeyUnavailable
		}
	case codeInternal:
		if status == http.StatusInternalServerError {
			return enkvcrypto.KeyUnavailable
		}
	case codeExhausted:
		if status == http.StatusTooManyRequests {
			return enkvcrypto.KeyUnavailable
		}
	}
	return enkvcrypto.KeyUnknown
}

// The fixed envelope fields are checked in place. Arbitrary Details tokens are
// counted and discarded; no provider message or Details graph is retained.
func inspectPrivateError(raw []byte) (privateProviderCode, int, privateFailure) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return 0, 0, privateMalformed
	}
	type frame struct {
		kind     json.Delim
		key      bool
		field    uint8
		envelope bool
	}
	var stack [maximumPrivateErrorDepth]frame
	stack[0] = frame{kind: '{', key: true}
	depth, nodes := 1, 1
	var seen uint8
	var code privateProviderCode
	var httpCode int
	for depth > 0 {
		token, err = d.Token()
		if err != nil {
			return 0, 0, privateMalformed
		}
		f := &stack[depth-1]
		if delim, ok := token.(json.Delim); ok && (delim == '}' || delim == ']') {
			if (delim == '}' && (f.kind != '{' || !f.key)) || (delim == ']' && f.kind != '[') {
				return 0, 0, privateMalformed
			}
			depth--
			continue
		}
		nodes++
		if nodes > maximumPrivateErrorNodes {
			return 0, 0, privateLimit
		}
		if f.kind == '{' && f.key {
			name, ok := token.(string)
			if !ok {
				return 0, 0, privateMalformed
			}
			f.key = false
			f.field = 0
			if depth == 1 && name == "error" {
				f.field = 1
			}
			if f.envelope {
				switch name {
				case "code":
					f.field = 2
				case "status":
					f.field = 4
				case "message":
					f.field = 8
				case "details":
					f.field = 16
				}
			}
			if f.field != 0 {
				if seen&f.field != 0 {
					return 0, 0, privateMalformed
				}
				seen |= f.field
			}
			continue
		}
		field := f.field
		f.field = 0
		if f.kind == '{' {
			f.key = true
		}
		if delim, ok := token.(json.Delim); ok {
			if (delim != '{' && delim != '[') || (field == 1 && delim != '{') || (field == 16 && delim != '[') || (field != 0 && field != 1 && field != 16) {
				return 0, 0, privateMalformed
			}
			if depth == len(stack) {
				return 0, 0, privateLimit
			}
			stack[depth] = frame{kind: delim, key: delim == '{', envelope: field == 1}
			depth++
			continue
		}
		switch field {
		case 1, 16:
			return 0, 0, privateMalformed
		case 2:
			number, ok := token.(json.Number)
			if !ok {
				return 0, 0, privateMalformed
			}
			n, e := strconv.Atoi(string(number))
			if e != nil || n < http.StatusBadRequest || n > maximumPrivateErrorHTTPStatus || strconv.Itoa(n) != string(number) {
				return 0, 0, privateMalformed
			}
			httpCode = n
		case 4:
			text, ok := token.(string)
			if !ok {
				return 0, 0, privateMalformed
			}
			code = privateCode(text)
		case 8:
			if _, ok := token.(string); !ok {
				return 0, 0, privateMalformed
			}
		}
	}
	_, err = d.Token()
	if err != io.EOF {
		return 0, 0, privateMalformed
	}
	if seen&7 != 7 || code == 0 {
		return 0, 0, privateUnknownCode
	}
	return code, httpCode, 0
}
