package configuration

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

type generatedWriter struct {
	out                        io.Writer
	err                        error
	count                      int64
	multiline, quoted, escaped bool
	depth, baseDepth           int
	empty                      [MaxDepth]bool
}

func (w *generatedWriter) write(s string) {
	if !w.multiline {
		w.raw(s)
		return
	}
	for len(s) > 0 && w.err == nil {
		if w.quoted {
			n := 0
			for n < len(s) {
				c := s[n]
				n++
				if w.escaped {
					w.escaped = false
				} else if c == '\\' {
					w.escaped = true
				} else if c == '"' {
					w.quoted = false
					break
				}
			}
			w.raw(s[:n])
			s = s[n:]
			continue
		}
		c := s[0]
		s = s[1:]
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if w.depth > 0 && w.empty[w.depth-1] && c != '}' && c != ']' {
			w.newline(w.depth)
			w.empty[w.depth-1] = false
		}
		switch c {
		case '{', '[':
			if w.depth == len(w.empty) {
				w.err = ErrCapture
				return
			}
			w.raw(string(c))
			w.empty[w.depth] = true
			w.depth++
		case '}', ']':
			if w.depth == 0 {
				w.err = ErrCapture
				return
			}
			w.depth--
			if !w.empty[w.depth] {
				w.newline(w.depth)
			}
			w.raw(string(c))
		case ',':
			w.raw(",")
			w.newline(w.depth)
		case ':':
			w.raw(": ")
		case '"':
			w.raw(`"`)
			w.quoted = true
		default:
			n := 0
			for n < len(s) && (s[n] >= 'a' && s[n] <= 'z' || s[n] >= '0' && s[n] <= '9') {
				n++
			}
			w.raw(string(c) + s[:n])
			s = s[n:]
		}
	}
}
func (w *generatedWriter) newline(depth int) {
	w.raw("\n" + strings.Repeat("  ", w.baseDepth+depth))
}
func (w *generatedWriter) raw(s string) {
	if w.err != nil {
		return
	}
	if int64(len(s)) > MaxPairBytes-w.count {
		w.err = ErrCapture
		return
	}
	n, e := io.WriteString(w.out, s)
	w.count += int64(n)
	if e != nil {
		w.err = e
	} else if n != len(s) {
		w.err = io.ErrShortWrite
	}
}
func (w *generatedWriter) quote(s string, limit int) {
	if len(s) > limit || !utf8.ValidString(s) {
		w.err = ErrCapture
		return
	}
	w.write(`"`)
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		w.write(s[start:i])
		switch c {
		case '"', '\\':
			w.write("\\" + string(c))
		case '\b':
			w.write(`\b`)
		case '\f':
			w.write(`\f`)
		case '\n':
			w.write(`\n`)
		case '\r':
			w.write(`\r`)
		case '\t':
			w.write(`\t`)
		default:
			const hex = "0123456789abcdef"
			w.write(`\u00` + string([]byte{hex[c>>4], hex[c&15]}))
		}
		start = i + 1
	}
	w.write(s[start:])
	w.write(`"`)
}
func (w *generatedWriter) id(id contract.ID) {
	if id.IsZero() {
		w.err = ErrCapture
		return
	}
	w.quote(hex.EncodeToString(id[:]), 64)
}
func (w *generatedWriter) blob(b []byte, limit int) {
	if len(b) > limit {
		w.err = ErrCapture
		return
	}
	w.write(`"`)
	if w.err != nil {
		return
	}
	encoder := base64.NewEncoder(base64.StdEncoding, writerAdapter{w})
	_, e := encoder.Write(b)
	closeErr := encoder.Close()
	if e != nil {
		w.err = e
	} else if closeErr != nil {
		w.err = closeErr
	}
	w.write(`"`)
}

type writerAdapter struct{ w *generatedWriter }

func (a writerAdapter) Write(b []byte) (int, error) {
	if a.w.err != nil {
		return 0, a.w.err
	}
	a.w.write(string(b))
	if a.w.err != nil {
		return 0, a.w.err
	}
	return len(b), nil
}
func (w *generatedWriter) key(k Key, selector string, signing bool) {
	if selector == "" {
		w.err = ErrCapture
		return
	}
	w.write(`{"selector":`)
	w.quote(selector, 1024)
	w.write(`,"public_key":`)
	limit := contract.KMSPublicKeyLength
	if signing {
		limit = contract.MaxPublicKey
	}
	w.blob(k.PublicKey, limit)
	if !signing {
		w.write(`,"binding":{"id":`)
		w.id(k.Binding.ID)
		w.write(`,"incarnation":`)
		w.id(k.Binding.Incarnation)
		w.write(`,"serial":`)
		if k.Binding.Serial == 0 {
			w.err = ErrCapture
		}
		w.write(strconv.FormatUint(k.Binding.Serial, 10))
		w.write(`,"protection":`)
		switch k.Binding.Protection {
		case contract.HardwareProtection:
			w.quote("hardware", 8)
		case contract.SoftwareProtection:
			w.quote("software", 8)
		default:
			w.err = ErrCapture
		}
		w.write(`}`)
	}
	w.write(`}`)
}

// EmitGenerated streams one generated image. The file transaction must validate
// the completed pair and establish its exact native readback before commit.
func EmitGenerated(out io.Writer, m *Model) error {
	if out == nil || m == nil || len(m.Recipients) > 255 || len(m.Entries) > 512 {
		return ErrCapture
	}
	w := &generatedWriter{out: out, multiline: true}
	w.write(`{"schema":"enkv/generated/v2","file_id":`)
	w.id(m.FileID)
	w.write(`,"domain":{"id":`)
	w.id(m.DomainID)
	w.write(`,"authority":{"id":`)
	w.id(m.Authority.ID)
	w.write(`,"signing":`)
	w.key(m.Authority.Signing, m.Authority.SigningSelector, true)
	w.write(`,"encryption":`)
	w.key(m.Authority.Encryption, m.Authority.EncryptionSelector, false)
	w.write(`},"recovery":{"enabled":`)
	w.write(strconv.FormatBool(m.RecoveryEnabled))
	if m.RecoveryEnabled {
		w.write(`,"signing":`)
		w.key(m.Recovery.Signing, m.Recovery.SigningSelector, true)
		w.write(`,"encryption":`)
		w.key(m.Recovery.Encryption, m.Recovery.EncryptionSelector, false)
	}
	w.write(`}},"recipients":{`)
	order := make([]int, len(m.Recipients))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool { return m.Recipients[order[i]].Reference < m.Recipients[order[j]].Reference })
	for j, i := range order {
		r := m.Recipients[i]
		if j > 0 {
			w.write(`,`)
		}
		if r.Reference == "" {
			w.err = ErrCapture
		}
		w.quote(r.Reference, 256)
		w.write(`:{"id":`)
		w.id(r.ID)
		w.write(`,"encryption":`)
		w.key(r.Encryption, r.Selector, false)
		if r.Creation != nil {
			w.write(`,"creation":{"snapshot":`)
			w.id(r.Creation.Snapshot)
			w.write(`,"nonce":`)
			w.id(r.Creation.Nonce)
			w.write(`}`)
		}
		w.write(`}`)
	}
	w.write(`},"secrets":{`)
	order = make([]int, len(m.Entries))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool { return m.Entries[order[i]].Name < m.Entries[order[j]].Name })
	first := true
	for _, i := range order {
		e := m.Entries[i]
		if !e.Secret || e.Generated != nil {
			continue
		}
		if e.Retained == nil && len(e.Sealed) == 0 && m.preparation {
			if _, missing := slices.BinarySearch(m.MissingInputs, e.Name); missing {
				continue
			}
		}
		if !first {
			w.write(`,`)
		}
		first = false
		w.quote(e.Name, 256)
		if e.Retained != nil && len(e.Sealed) == 0 {
			w.write(`:{"retained":{"incarnation":`)
			w.id(e.Retained.Incarnation)
			w.write(`,"material":`)
			w.id(e.Retained.Material)
			w.write(`}}`)
		} else if e.Retained == nil && len(e.Sealed) > 0 {
			w.write(`:{"sealed":`)
			w.blob(e.Sealed, contract.CryptoMaxSealedInputLength)
			w.write(`}`)
		} else {
			w.err = ErrCapture
		}
	}
	w.write(`},"public_basis":`)
	w.basis(m.Basis)
	if m.Observation != nil {
		w.write(`,"observation":{"kind":"selected-closure/v1","store_configuration":`)
		w.blob(m.Observation.StoreConfiguration, 4096)
		w.write(`,"head":`)
		w.blob(m.Observation.Head, 65536)
		w.write(`}`)
	}
	if m.Maintenance != nil {
		w.write(`,"maintenance":`)
		w.maintenance(m.Maintenance)
	}
	if m.Replacement != nil {
		w.write(`,"replacement":`)
		w.replacement(m.Replacement)
	}
	w.canonicalRecords(m)
	w.write("}")
	w.raw("\n")
	if w.err != nil {
		return captureCause(w.err)
	}
	return nil
}

func (w *generatedWriter) basis(b Basis) {
	observationEmpty := len(b.SigningAnchor) == 0 && len(b.StoreConfiguration) == 0 && len(b.HEAD) == 0 && len(b.Root) == 0 && len(b.RecipientPages) == 0
	if observationEmpty && len(b.Descriptor) > 0 && len(b.Control) == 0 && len(b.Selection) == 0 && len(b.Enrollment) == 0 {
		w.write(`{"kind":"genesis","descriptor":`)
		w.blob(b.Descriptor, contract.GenesisDescriptorLimit)
		w.write(`}`)
	} else if observationEmpty && len(b.Descriptor) == 0 && len(b.Control) > 0 && len(b.Selection) > 0 && len(b.Enrollment) > 0 && len(b.Enrollment) <= 256 {
		w.write(`{"kind":"successor","control":`)
		w.blob(b.Control, contract.ControlCoreMaxLength)
		w.write(`,"selection":`)
		w.blob(b.Selection, contract.MaxHeadLength)
		w.write(`,"enrollment":[`)
		order := make([]int, len(b.Enrollment))
		for i := range order {
			order[i] = i
		}
		sort.Slice(order, func(i, j int) bool {
			return string(b.Enrollment[order[i]].ID[:]) < string(b.Enrollment[order[j]].ID[:])
		})
		for position, i := range order {
			r := b.Enrollment[i]
			if position > 0 {
				w.write(`,`)
			}
			w.write(`{"id":`)
			w.id(r.ID)
			w.write(`,"status":`)
			switch r.Status {
			case contract.CurrentRecipient:
				w.quote("current", 7)
			case contract.RetiredRecipient:
				w.quote("retired", 7)
			default:
				w.err = ErrCapture
			}
			w.write(`,"display_name":`)
			w.quote(r.DisplayName, 256)
			w.write(`}`)
		}
		w.write(`]}`)
	} else if len(b.Descriptor) == 0 && len(b.Control) == 0 && len(b.Selection) == 0 && len(b.Enrollment) == 0 &&
		len(b.SigningAnchor) > 0 && len(b.StoreConfiguration) > 0 && len(b.HEAD) > 0 && len(b.Root) > 0 && len(b.RecipientPages) > 0 && len(b.RecipientPages) <= contract.MaxRecipientPages {
		w.write(`{"kind":"observation","anchor":`)
		w.blob(b.SigningAnchor, contract.PublicSigningBindingMaxLength)
		w.write(`,"store_configuration":`)
		w.blob(b.StoreConfiguration, contract.MaxStoreConfigurationLength)
		w.write(`,"head":`)
		w.blob(b.HEAD, contract.MaxHeadLength)
		w.write(`,"root":`)
		w.blob(b.Root, contract.MaxRootLength)
		w.write(`,"recipient_pages":[`)
		for i, page := range b.RecipientPages {
			if len(page) == 0 {
				w.err = ErrCapture
				return
			}
			if i > 0 {
				w.write(`,`)
			}
			w.blob(page, contract.MaxRecipientPageLength)
		}
		w.write(`]}`)
	} else {
		w.err = ErrCapture
	}
}
