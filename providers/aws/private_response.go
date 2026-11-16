package awsprovider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/restjson"
)

const (
	maximumPrivateSuccessResponseBytes = 4096
	maximumPrivateSuccessNodes         = 32
	maximumPrivateErrorDepth           = 16
	maximumPrivateErrorNodes           = 4096
)

// This state is installed only by the RSA Decrypt adapter. It is never attached
// to Store, signing or metadata operations. Raw bytes stay here until SDK return.
type privateDecrypt struct {
	selector     string
	packetLength uint16
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

// No arbitrary provider string can become an error field or formatted message.
type privateResponseError struct {
	kind       privateFailure
	status     enkvcrypto.KeyStatus
	httpStatus int
}

func (e *privateResponseError) Error() string {
	switch e.kind {
	case privateMalformed:
		return "AWS private response malformed"
	case privateLimit:
		return "AWS private response limit exceeded"
	case privateUnknownCode:
		return "AWS private response code unknown"
	case privateProviderFailure:
		return "AWS private operation refused"
	default:
		return "AWS private transport incomplete"
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
	limit := int64(maxErrorResponse)
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
		// The generated success decoder receives exactly the checked bytes.
		p.observed = enkvcrypto.KeyUses{Completed: 1}
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		return resp, nil
	}
	code, kind := inspectPrivateError(raw)
	if kind != 0 {
		return fail(kind)
	}
	if header := resp.Header.Get("X-Amzn-ErrorType"); header != "" {
		headerCode := privateCode(header)
		if headerCode == 0 || headerCode != code {
			return fail(privateUnknownCode)
		}
	}
	status = code.outcome(resp.StatusCode)
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
		text, ok := value.(string)
		if !ok {
			return false
		}
		var bit uint8
		switch key {
		case "KeyId":
			bit = 1
			if text != p.selector {
				return false
			}
		case "EncryptionAlgorithm":
			bit = 2
			if text != "RSAES_OAEP_SHA_256" {
				return false
			}
		case "KeyOrigin":
			bit = 8
			if text != "AWS_KMS" && text != "EXTERNAL" {
				return false
			}
		case "Plaintext":
			bit = 4
			if len(text) != base64.StdEncoding.EncodedLen(int(p.packetLength)) || strings.ContainsAny(text, "\r\n") {
				return false
			}
			n, e := base64.StdEncoding.Strict().Decode(scratch[:], encoded[:copy(encoded[:], text)])
			if e != nil || n != int(p.packetLength) {
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
	if e != nil || end != json.Delim('}') || seen&7 != 7 {
		return false
	}
	_, e = d.Token()
	return e == io.EOF
}

type privateProviderCode uint8

const (
	codeDenied privateProviderCode = iota + 1
	codeUnauthenticated
	codeCorrupt
	codeWrongKey
	codeInvalidUsage
	codeDisabled
	codeMissing
	codeState
	codeTimeout
	codeUnavailable
	codeInternal
	codeThrottled
)

func privateCode(s string) privateProviderCode {
	s = restjson.SanitizeErrorCode(s)
	switch s {
	case "AccessDeniedException":
		return codeDenied
	case "UnrecognizedClientException", "InvalidClientTokenId", "ExpiredTokenException":
		return codeUnauthenticated
	case "InvalidCiphertextException":
		return codeCorrupt
	case "IncorrectKeyException":
		return codeWrongKey
	case "InvalidKeyUsageException":
		return codeInvalidUsage
	case "DisabledException":
		return codeDisabled
	case "NotFoundException":
		return codeMissing
	case "KMSInvalidStateException":
		return codeState
	case "DependencyTimeoutException":
		return codeTimeout
	case "KeyUnavailableException":
		return codeUnavailable
	case "KMSInternalException":
		return codeInternal
	case "ThrottlingException":
		return codeThrottled
	default:
		return 0
	}
}
func (c privateProviderCode) outcome(status int) enkvcrypto.KeyStatus {
	switch c {
	case codeDenied, codeUnauthenticated:
		if status == http.StatusBadRequest || status == http.StatusUnauthorized || status == http.StatusForbidden {
			return enkvcrypto.KeyDenied
		}
	case codeCorrupt, codeWrongKey:
		if status == http.StatusBadRequest {
			return enkvcrypto.KeyAuthenticationFailed
		}
	case codeInvalidUsage:
		if status == http.StatusBadRequest {
			return enkvcrypto.KeyInvalid
		}
	case codeDisabled, codeMissing, codeState:
		if status == http.StatusBadRequest {
			return enkvcrypto.KeyUnavailable
		}
	case codeTimeout, codeUnavailable, codeInternal:
		if status == http.StatusInternalServerError {
			return enkvcrypto.KeyUnavailable
		}
	case codeThrottled:
		if status == http.StatusBadRequest || status == http.StatusTooManyRequests {
			return enkvcrypto.KeyUnavailable
		}
	}
	return enkvcrypto.KeyUnknown
}

// Error details are traversed as tokens and discarded. The fixed stack is the
// only nested representation; selected fields become closed facts immediately.
func inspectPrivateError(raw []byte) (privateProviderCode, privateFailure) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return 0, privateMalformed
	}
	type frame struct {
		kind  json.Delim
		key   bool
		field uint8
	}
	var stack [maximumPrivateErrorDepth]frame
	stack[0] = frame{kind: '{', key: true}
	depth, nodes := 1, 1
	var seen uint8
	var code privateProviderCode
	for depth > 0 {
		token, err = d.Token()
		if err != nil {
			return 0, privateMalformed
		}
		f := &stack[depth-1]
		if delim, ok := token.(json.Delim); ok && (delim == '}' || delim == ']') {
			if (delim == '}' && (f.kind != '{' || !f.key)) || (delim == ']' && f.kind != '[') {
				return 0, privateMalformed
			}
			depth--
			continue
		}
		nodes++
		if nodes > maximumPrivateErrorNodes {
			return 0, privateLimit
		}
		if f.kind == '{' && f.key {
			name, ok := token.(string)
			if !ok {
				return 0, privateMalformed
			}
			f.key = false
			f.field = 0
			if depth == 1 {
				switch name {
				case "__type":
					f.field = 1
				case "message", "Message":
					f.field = 2
				}
			}
			if f.field != 0 {
				if seen&f.field != 0 {
					return 0, privateMalformed
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
			if field != 0 || (delim != '{' && delim != '[') {
				return 0, privateMalformed
			}
			if depth == len(stack) {
				return 0, privateLimit
			}
			stack[depth] = frame{kind: delim, key: delim == '{'}
			depth++
			continue
		}
		if field != 0 {
			text, ok := token.(string)
			if !ok {
				return 0, privateMalformed
			}
			if field == 1 {
				code = privateCode(text)
			}
		}
	}
	_, err = d.Token()
	if err != io.EOF {
		return 0, privateMalformed
	}
	if seen&1 == 0 || code == 0 {
		return 0, privateUnknownCode
	}
	return code, 0
}
