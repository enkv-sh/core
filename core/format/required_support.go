package format

import (
	"bytes"

	"enkv.sh/core/contract"
)

const MaxRequiredSupportPage = contract.MaxRequiredSupportPageLength

type RequiredSupportPage struct {
	Domain, Object ID
	Index          uint16
	Records        []contract.SupportRecord
}

// RequiredSupportPageView borrows complete record bodies from one immutable
// page. The selected closure retains the page backing until inspection ends.
type RequiredSupportPageView struct {
	Domain, Object ID
	Index          uint16
	Records        []contract.SupportRecordView
}

func supportPageWriter(domain, object ID, index uint16, count uint16) (writer, error) {
	if !idsValid(domain, object) || index >= contract.MaxChildPages || count == 0 || int(count) > (MaxRequiredSupportPage-contract.RequiredSupportPageHeaderLength)/contract.SupportRecordMinLength {
		return writer{}, ErrFormat
	}
	w := start(byte(contract.RequiredSupportKind))
	w.id(domain)
	w.id(object)
	w.u16(index)
	w.u16(count)
	return w, nil
}

func EncodeRequiredSupportPage(p RequiredSupportPage) ([]byte, error) {
	return encodeRequiredSupportPage(p, nil)
}

type supportRecordPlan struct {
	kind         uint8
	domainID, id ID
	body, framed []byte
}

func newReceiptSupportPlan(v contract.CompactMutationReceiptPlan) (*supportRecordPlan, error) {
	framed, err := contract.AppendMutationReceiptSupportPlan(nil, v)
	if err != nil {
		return nil, ErrFormat
	}
	return &supportRecordPlan{kind: contract.MutationReceiptSupportKind, domainID: v.DomainID, id: v.OperationID, body: framed[contract.SupportRecordOverhead:], framed: framed}, nil
}

func newGeneratedParentSupportPlan(v contract.GeneratedParentPlan) (*supportRecordPlan, error) {
	framed, err := contract.AppendGeneratedParentSupportPlan(nil, v)
	if err != nil {
		return nil, ErrFormat
	}
	return &supportRecordPlan{kind: contract.GeneratedParentSupportKind, domainID: v.DomainID, id: v.OperationID, body: framed[contract.SupportRecordOverhead:], framed: framed}, nil
}

func (p *supportRecordPlan) matches(row contract.SupportRecord) bool {
	return p != nil && row.Kind == p.kind && row.RecordID == p.id
}

func (p *supportRecordPlan) domain(row contract.SupportRecord) (ID, error) {
	if p.matches(row) {
		if !bytes.Equal(row.Body, p.body) {
			return ID{}, ErrFormat
		}
		return p.domainID, nil
	}
	return contract.SupportRecordDomain(row)
}

// EncodeRequiredSupportReceiptPlan differs from actual encoding only at the
// single named receipt. Actual readers cannot accept its request-identity hole.
func EncodeRequiredSupportReceiptPlan(p RequiredSupportPage, v contract.CompactMutationReceiptPlan) ([]byte, error) {
	plan, err := newReceiptSupportPlan(v)
	if err != nil || p.Domain != v.DomainID {
		return nil, ErrFormat
	}
	return encodeRequiredSupportPage(p, plan)
}

// EncodeRequiredSupportParentPlan admits only the initial parent's named
// request-identity hole. Every other record uses its complete stored encoding.
func EncodeRequiredSupportParentPlan(p RequiredSupportPage, v contract.GeneratedParentPlan) ([]byte, error) {
	plan, err := newGeneratedParentSupportPlan(v)
	if err != nil || p.Domain != v.DomainID {
		return nil, ErrFormat
	}
	return encodeRequiredSupportPage(p, plan)
}

func encodeRequiredSupportPage(p RequiredSupportPage, plan *supportRecordPlan) ([]byte, error) {
	if len(p.Records) == 0 || len(p.Records) > (MaxRequiredSupportPage-contract.RequiredSupportPageHeaderLength)/contract.SupportRecordMinLength {
		return nil, ErrFormat
	}
	total, fragments, planned := contract.RequiredSupportPageHeaderLength, 0, 0
	seen := make(map[supportRecordKey]bool, len(p.Records))
	for _, row := range p.Records {
		domain, err := plan.domain(row)
		if err != nil || !domain.IsZero() && domain != p.Domain || seen[supportRecordKey{row.Kind, row.RecordID}] {
			return nil, ErrFormat
		}
		seen[supportRecordKey{row.Kind, row.RecordID}] = true
		total += contract.SupportRecordOverhead + len(row.Body)
		if total > MaxRequiredSupportPage {
			return nil, ErrFormat
		}
		if row.Kind == contract.GeneratedFragmentSupportKind {
			fragments++
		}
		if plan.matches(row) {
			planned++
		}
	}
	if plan != nil && planned != 1 || fragments != 0 && (fragments != len(p.Records) || fragments > 2) {
		return nil, ErrFormat
	}
	w, err := supportPageWriter(p.Domain, p.Object, p.Index, uint16(len(p.Records)))
	if err != nil {
		return nil, err
	}
	header := w.b
	w.b = make([]byte, len(header), total)
	copy(w.b, header)
	for _, record := range p.Records {
		if plan.matches(record) {
			w.b = append(w.b, plan.framed...)
		} else {
			w.b, err = contract.AppendSupportRecord(w.b, record)
		}
		if err != nil || len(w.b) > MaxRequiredSupportPage {
			return nil, ErrFormat
		}
	}
	if len(w.b) != total {
		return nil, ErrFormat
	}
	return w.result()
}

func InspectRequiredSupportPage(body []byte) (RequiredSupportPageView, error) {
	r := begin(body, byte(contract.RequiredSupportKind), MaxRequiredSupportPage)
	p := RequiredSupportPageView{Domain: r.id(), Object: r.id(), Index: r.u16()}
	count := int(r.u16())
	if r.bad || !idsValid(p.Domain, p.Object) || p.Index >= contract.MaxChildPages || count < 1 || count > (len(body)-contract.RequiredSupportPageHeaderLength)/contract.SupportRecordMinLength {
		return RequiredSupportPageView{}, ErrFormat
	}
	p.Records = make([]contract.SupportRecordView, 0, count)
	seen := make(map[supportRecordKey]bool, count)
	fragments := 0
	for i := 0; i < count; i++ {
		row, n, err := contract.ParseSupportRecord(r.b[r.off:])
		if err != nil {
			return RequiredSupportPageView{}, ErrFormat
		}
		domain, err := contract.SupportRecordDomain(contract.SupportRecord(row))
		if err != nil || !domain.IsZero() && domain != p.Domain {
			return RequiredSupportPageView{}, ErrFormat
		}
		key := supportRecordKey{row.Kind, row.RecordID}
		if seen[key] {
			return RequiredSupportPageView{}, ErrFormat
		}
		seen[key] = true
		if row.Kind == contract.GeneratedFragmentSupportKind {
			fragments++
		}
		r.off += n
		p.Records = append(p.Records, row)
	}
	if !r.end() || fragments != 0 && (fragments != count || fragments > 2) {
		return RequiredSupportPageView{}, ErrFormat
	}
	return p, nil
}

type supportRecordKey struct {
	kind uint8
	id   contract.ID
}
