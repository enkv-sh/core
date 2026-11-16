package core

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

var ErrReaderInputs = errors.New("local Reader input refused")

// readLocalReaderPublicBasis retains existing public basis meanings with an
// exact tagged schema. No branch-inapplicable fields or null values are needed.
// The encoded input account owns body until return. Base64 decoding owns only its exact decoded
// allocation: it borrows encoded spans instead of making another full string.
// Enrollment vectors and strings fit the existing 8 MiB decoded-input allowance;
// Per-field text and key decoding remain bounded by the fixed public-basis limits.
func readLocalReaderPublicBasis(path string) (localBasisImage, error) {
	body, err := readLocalProtected(path, localBasisLimit)
	if err != nil {
		return localBasisImage{}, ErrReaderInputs
	}
	p := readerInputJSON{body: body, failed: !utf8.Valid(body)}
	var out localBasisImage
	fields := p.object([]string{"schema", "kind", "descriptor", "control", "selection", "enrollment", "anchor", "store_configuration", "head", "root", "recipient_pages"}, func(field int) {
		switch field {
		case 0:
			if p.unsigned() != 3 {
				p.failed = true
			}
			out.Schema = 3
		case 1:
			out.Kind = p.text(11)
		case 2:
			out.Descriptor = p.binary(contract.GenesisDescriptorLimit)
		case 3:
			out.Control = p.binary(contract.ControlCoreMaxLength)
		case 4:
			out.Selection = p.binary(contract.MaxHeadLength)
		case 5:
			out.Enrollment = p.enrollment()
		case 6:
			out.SigningAnchor = p.binary(contract.PublicSigningBindingMaxLength)
		case 7:
			out.StoreConfiguration = p.binary(contract.MaxStoreConfigurationLength)
		case 8:
			out.HEAD = p.binary(contract.MaxHeadLength)
		case 9:
			out.Root = p.binary(contract.MaxRootLength)
		case 10:
			out.RecipientPages = p.recipientPages()
		}
	})
	valid := out.Kind == "genesis" && fields == 7 && len(out.Descriptor) != 0 || out.Kind == "successor" && fields == 59 && len(out.Control) != 0 && len(out.Selection) != 0 && len(out.Enrollment) != 0 || out.Kind == "observation" && fields == 1987 && len(out.SigningAnchor) != 0 && len(out.StoreConfiguration) != 0 && len(out.HEAD) != 0 && len(out.Root) != 0 && len(out.RecipientPages) != 0
	if !valid || !p.complete() {
		return localBasisImage{}, ErrReaderInputs
	}
	return out, nil
}

// readerInputJSON is a cursor for the retained public basis record only. Object
// fields are matched after Unicode decoding, so escaped aliases share one bit.
// There is no recursive value decoder: each field has one fixed kind and bound.
type readerInputJSON struct {
	body   []byte
	at     int
	failed bool
}

func (p *readerInputJSON) space() {
	for p.at < len(p.body) {
		switch p.body[p.at] {
		case ' ', '\n', '\r', '\t':
			p.at++
		default:
			return
		}
	}
}
func (p *readerInputJSON) take(c byte) bool {
	p.space()
	if p.failed || p.at == len(p.body) || p.body[p.at] != c {
		p.failed = true
		return false
	}
	p.at++
	return true
}
func (p *readerInputJSON) next(c byte) bool {
	p.space()
	return !p.failed && p.at < len(p.body) && p.body[p.at] == c
}
func (p *readerInputJSON) complete() bool { p.space(); return !p.failed && p.at == len(p.body) }

func (p *readerInputJSON) object(keys []string, field func(int)) uint64 {
	if !p.take('{') {
		return 0
	}
	var seen uint64
	if p.next('}') {
		p.at++
		return seen
	}
	for !p.failed {
		key := p.text(32)
		index := slices.Index(keys, key)
		if index < 0 || seen&(uint64(1)<<index) != 0 || !p.take(':') {
			p.failed = true
			break
		}
		seen |= uint64(1) << index
		field(index)
		if p.next('}') {
			p.at++
			break
		}
		if !p.take(',') {
			break
		}
	}
	return seen
}

func (p *readerInputJSON) unsigned() uint64 {
	p.space()
	start := p.at
	for p.at < len(p.body) && p.body[p.at] >= '0' && p.body[p.at] <= '9' {
		p.at++
	}
	n := p.at - start
	if p.failed || n == 0 || n > 20 || n > 1 && p.body[start] == '0' {
		p.failed = true
		return 0
	}
	v, err := strconv.ParseUint(string(p.body[start:p.at]), 10, 64)
	if err != nil {
		p.failed = true
	}
	return v
}

// readerInputRune reads one already bounded JSON string character. It rejects
// lone UTF-16 surrogates before encoding/json can replace them with U+FFFD.
func readerInputRune(body []byte, at *int) (rune, bool) {
	if *at >= len(body) {
		return 0, false
	}
	c := body[*at]
	*at++
	if c < 0x20 {
		return 0, false
	}
	if c != '\\' {
		if c < utf8.RuneSelf {
			return rune(c), true
		}
		r, n := utf8.DecodeRune(body[*at-1:])
		*at += n - 1
		return r, r != utf8.RuneError || n != 1
	}
	if *at >= len(body) {
		return 0, false
	}
	c = body[*at]
	*at++
	switch c {
	case '"', '\\', '/':
		return rune(c), true
	case 'b':
		return '\b', true
	case 'f':
		return '\f', true
	case 'n':
		return '\n', true
	case 'r':
		return '\r', true
	case 't':
		return '\t', true
	case 'u':
		first, ok := readerInputHex(body, at)
		if !ok {
			return 0, false
		}
		if first >= 0xdc00 && first <= 0xdfff {
			return 0, false
		}
		if first < 0xd800 || first > 0xdbff {
			return rune(first), true
		}
		if len(body)-*at < 2 || body[*at] != '\\' || body[*at+1] != 'u' {
			return 0, false
		}
		*at += 2
		second, ok := readerInputHex(body, at)
		if !ok || second < 0xdc00 || second > 0xdfff {
			return 0, false
		}
		return utf16.DecodeRune(rune(first), rune(second)), true
	default:
		return 0, false
	}
}
func readerInputHex(body []byte, at *int) (uint16, bool) {
	if len(body)-*at < 4 {
		return 0, false
	}
	var v uint16
	for range 4 {
		c := body[*at]
		*at++
		var digit byte
		switch {
		case c >= '0' && c <= '9':
			digit = c - '0'
		case c >= 'a' && c <= 'f':
			digit = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			digit = c - 'A' + 10
		default:
			return 0, false
		}
		v = v<<4 | uint16(digit)
	}
	return v, true
}

// stringSpan includes quotes and borrows body. The byte count is the decoded
// UTF-8 length and is checked before any proportional string allocation.
func (p *readerInputJSON) stringSpan(limit int) ([]byte, int) {
	p.space()
	start := p.at
	if !p.take('"') {
		return nil, 0
	}
	count := 0
	for !p.failed && p.at < len(p.body) {
		if p.body[p.at] == '"' {
			p.at++
			return p.body[start:p.at], count
		}
		r, ok := readerInputRune(p.body, &p.at)
		if !ok {
			p.failed = true
			break
		}
		count += utf8.RuneLen(r)
		if count > limit {
			p.failed = true
			break
		}
	}
	p.failed = true
	return nil, 0
}
func (p *readerInputJSON) text(limit int) string {
	span, _ := p.stringSpan(limit)
	if p.failed {
		return ""
	}
	var text string
	if json.Unmarshal(span, &text) != nil {
		p.failed = true
	}
	return text
}
func (p *readerInputJSON) binary(limit int) []byte {
	span, n := p.stringSpan(4 * ((limit + 2) / 3))
	if p.failed {
		return nil
	}
	span = span[1 : len(span)-1]
	if n%4 != 0 {
		p.failed = true
		return nil
	}
	// Validate every decoded character and padding position before allocation.
	padding := 0
	for at, pos := 0, 0; at < len(span); pos++ {
		r, ok := readerInputRune(span, &at)
		if !ok || (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '+' && r != '/' && r != '=' {
			p.failed = true
			return nil
		}
		if r == '=' {
			padding++
			if pos < n-2 || padding > 2 {
				p.failed = true
				return nil
			}
		} else if padding != 0 {
			p.failed = true
			return nil
		}
	}
	size := n/4*3 - padding
	if size > limit || size < 0 {
		p.failed = true
		return nil
	}
	out := make([]byte, size)
	var quartet [4]byte
	for at, offset := 0, 0; at < len(span); {
		for i := range quartet {
			r, _ := readerInputRune(span, &at)
			quartet[i] = byte(r)
		}
		decoded, err := base64.StdEncoding.Strict().Decode(out[offset:], quartet[:])
		if err != nil {
			p.failed = true
			return nil
		}
		offset += decoded
	}
	return out
}

func (p *readerInputJSON) enrollment() []localEnrollmentImage {
	if !p.take('[') {
		return nil
	}
	out := make([]localEnrollmentImage, 0, contract.CryptoMaxRecipients)
	if p.next(']') {
		p.at++
		return out
	}
	for !p.failed {
		if len(out) == contract.CryptoMaxRecipients {
			p.failed = true
			break
		}
		var row localEnrollmentImage
		fields := p.object([]string{"id", "status", "display_name"}, func(field int) {
			switch field {
			case 0:
				row.ID = p.text(64)
				if _, err := localID(row.ID); err != nil {
					p.failed = true
				}
			case 1:
				switch p.text(7) {
				case "current":
					row.Status = contract.CurrentRecipient
				case "retired":
					row.Status = contract.RetiredRecipient
				default:
					p.failed = true
				}
			case 2:
				row.Name = p.text(contract.CryptoMaxName)
			}
		})
		if fields != 7 {
			p.failed = true
			break
		}
		for _, before := range out {
			if before.ID == row.ID {
				p.failed = true
				break
			}
		}
		out = append(out, row)
		if p.next(']') {
			p.at++
			break
		}
		if !p.take(',') {
			break
		}
	}
	return out
}

func (p *readerInputJSON) recipientPages() [][]byte {
	if !p.take('[') {
		return nil
	}
	out := make([][]byte, 0, contract.MaxRecipientPages)
	if p.next(']') {
		p.at++
		return out
	}
	for !p.failed {
		if len(out) == contract.MaxRecipientPages {
			p.failed = true
			break
		}
		body := p.binary(format.MaxRecipientPage)
		if len(body) == 0 {
			p.failed = true
			break
		}
		out = append(out, body)
		if p.next(']') {
			p.at++
			break
		}
		if !p.take(',') {
			break
		}
	}
	return out
}

func (row localEnrollmentImage) MarshalJSON() ([]byte, error) {
	var status string
	switch row.Status {
	case contract.CurrentRecipient:
		status = "current"
	case contract.RetiredRecipient:
		status = "retired"
	default:
		return nil, ErrReaderInputs
	}
	return json.Marshal(struct {
		ID          string `json:"id"`
		Status      string `json:"status"`
		DisplayName string `json:"display_name"`
	}{row.ID, status, row.Name})
}
