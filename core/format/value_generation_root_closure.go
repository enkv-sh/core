package format

import (
	"bytes"
	"crypto/sha256"

	"enkv.sh/core/contract"
)

const fragmentLocationLength = 32 + 2 + 2 + 1

type FragmentLocation struct {
	BlobID                          ID
	FragmentIndex, SupportPageIndex uint16
	RowSlot                         uint8
}

type GeneratedClosure struct {
	ActiveOwner, ActivePhase, ActiveGraph                                                      ID
	GeneratedCurrent, Retiring, Attempts, Duties, Hazards, Results, Materials, PendingReleases uint32
	Graphs, LiveOwners, SuccessWindow, FailureWindow, ReceiptOrder, Slices                     contract.GeneratorDescriptor
	Fragments                                                                                  []FragmentLocation
}

func EmptyGeneratedClosure() GeneratedClosure {
	d := contract.EmptyGeneratorIndexes()
	return GeneratedClosure{Graphs: d[0], LiveOwners: d[1], SuccessWindow: d[2], FailureWindow: d[3], ReceiptOrder: d[4], Slices: contract.EmptyGeneratorVector(contract.GeneratorVectorSlices)}
}

func generatedClosureShapeValid(v GeneratedClosure) bool {
	if v.ActiveOwner.IsZero() != v.ActivePhase.IsZero() || v.ActiveOwner.IsZero() != v.ActiveGraph.IsZero() || v.GeneratedCurrent > contract.GeneratedCurrentEntryLimit || len(v.Fragments) > contract.GeneratedFragmentLocationLimit ||
		!contract.GeneratorVectorShapeValid(contract.GeneratorVectorSlices, v.Slices) {
		return false
	}
	for i, d := range []contract.GeneratorDescriptor{v.Graphs, v.LiveOwners, v.SuccessWindow, v.FailureWindow, v.ReceiptOrder} {
		if !contract.GeneratorIndexShapeValid(contract.GeneratorIndexKind(i+1), d) {
			return false
		}
	}
	if v.ReceiptOrder.Count != v.SuccessWindow.Count+v.FailureWindow.Count {
		return false
	}
	for i, row := range v.Fragments {
		if row.BlobID.IsZero() || row.FragmentIndex >= contract.GeneratedFragmentLocationLimit || row.SupportPageIndex >= contract.MaxChildPages || row.RowSlot > 1 {
			return false
		}
		if i > 0 {
			before := v.Fragments[i-1]
			order := bytes.Compare(before.BlobID[:], row.BlobID[:])
			if order > 0 || order == 0 && before.FragmentIndex >= row.FragmentIndex {
				return false
			}
		}
	}
	return true
}

func writeGeneratedClosure(w *writer, v GeneratedClosure) error {
	if !generatedClosureShapeValid(v) {
		return ErrFormat
	}
	if v.ActiveOwner.IsZero() {
		w.u8(0)
	} else {
		w.u8(1)
		w.id(v.ActiveOwner)
	}
	w.id(v.ActivePhase)
	w.id(v.ActiveGraph)
	for _, n := range []uint32{v.GeneratedCurrent, v.Retiring, v.Attempts, v.Duties, v.Hazards, v.Results, v.Materials, v.PendingReleases} {
		w.u32(n)
	}
	for _, d := range []contract.GeneratorDescriptor{v.Graphs, v.LiveOwners, v.SuccessWindow, v.FailureWindow, v.ReceiptOrder, v.Slices} {
		var err error
		w.b, err = contract.AppendGeneratorDescriptor(w.b, d)
		if err != nil {
			return ErrFormat
		}
	}
	w.u16(uint16(len(v.Fragments)))
	for _, row := range v.Fragments {
		w.id(row.BlobID)
		w.u16(row.FragmentIndex)
		w.u16(row.SupportPageIndex)
		w.u8(row.RowSlot)
	}
	return nil
}

// EncodeGeneratedClosure supplies the exact root-owned work commitment to
// preservation projections that cannot read disposable support pages.
func EncodeGeneratedClosure(v GeneratedClosure) ([]byte, error) {
	w := writer{}
	if err := writeGeneratedClosure(&w, v); err != nil {
		return nil, err
	}
	return w.b, nil
}

func readGeneratedClosure(r *reader) GeneratedClosure {
	var v GeneratedClosure
	switch r.u8() {
	case 0:
	case 1:
		v.ActiveOwner = r.id()
		if v.ActiveOwner.IsZero() {
			r.bad = true
		}
	default:
		r.bad = true
	}
	v.ActivePhase, v.ActiveGraph = r.id(), r.id()
	for _, n := range []*uint32{&v.GeneratedCurrent, &v.Retiring, &v.Attempts, &v.Duties, &v.Hazards, &v.Results, &v.Materials, &v.PendingReleases} {
		*n = r.u32()
	}
	for _, d := range []*contract.GeneratorDescriptor{&v.Graphs, &v.LiveOwners, &v.SuccessWindow, &v.FailureWindow, &v.ReceiptOrder, &v.Slices} {
		b := r.take(contract.GeneratorDescriptorLength)
		var err error
		*d, err = contract.DecodeGeneratorDescriptor(b)
		if err != nil {
			r.bad = true
		}
	}
	count := int(r.u16())
	if r.bad || count > contract.GeneratedFragmentLocationLimit || count > (len(r.b)-r.off)/fragmentLocationLength {
		r.bad = true
		return GeneratedClosure{}
	}
	if count != 0 {
		v.Fragments = make([]FragmentLocation, count)
	}
	for i := range v.Fragments {
		v.Fragments[i] = FragmentLocation{BlobID: r.id(), FragmentIndex: r.u16(), SupportPageIndex: r.u16(), RowSlot: r.u8()}
	}
	if !generatedClosureShapeValid(v) {
		r.bad = true
	}
	return v
}

func generatedRootValid(p Root) bool {
	v := p.Generated
	if !generatedClosureShapeValid(v) || v.GeneratedCurrent > p.ValueEntryCount {
		return false
	}
	for _, n := range []uint32{v.Attempts, v.Duties, v.Hazards, v.Results, v.Materials, v.PendingReleases, v.Slices.Count} {
		if n > p.RequiredSupportRecordCount {
			return false
		}
	}
	for _, row := range v.Fragments {
		found := false
		for _, ref := range p.RequiredSupport {
			if ref.Index == row.SupportPageIndex {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ValidateFragmentDirectory checks every selected fragment and its whole blob
// without joining the payloads into a second large allocation.
func ValidateFragmentDirectory(directory []FragmentLocation, pages []RequiredSupportPageView) error {
	shape := EmptyGeneratedClosure()
	shape.Fragments = directory
	if !generatedClosureShapeValid(shape) {
		return ErrFormat
	}
	var byIndex [contract.MaxChildPages]*RequiredSupportPageView
	fragments := 0
	for i := range pages {
		p := &pages[i]
		if p.Index >= contract.MaxChildPages || byIndex[p.Index] != nil {
			return ErrFormat
		}
		byIndex[p.Index] = p
		pageFragments := 0
		for _, row := range p.Records {
			if row.Kind == contract.GeneratedFragmentSupportKind {
				pageFragments++
			}
		}
		if pageFragments != 0 && (pageFragments != len(p.Records) || pageFragments > 2) {
			return ErrFormat
		}
		fragments += pageFragments
	}
	if fragments != len(directory) {
		return ErrFormat
	}
	var previous contract.GeneratedFragmentView
	whole := sha256.New()
	var length uint64
	for i, location := range directory {
		page := byIndex[location.SupportPageIndex]
		if page == nil || int(location.RowSlot) >= len(page.Records) {
			return ErrFormat
		}
		row := page.Records[location.RowSlot]
		fragment, err := contract.InspectGeneratedFragment(row.Body)
		if err != nil || row.Kind != contract.GeneratedFragmentSupportKind || fragment.BlobID != location.BlobID || fragment.Index != location.FragmentIndex {
			return ErrFormat
		}
		id, err := contract.GeneratorFragmentID(fragment.BlobID, fragment.Index)
		if err != nil || row.RecordID != id {
			return ErrFormat
		}
		if fragment.Index == 0 {
			if i > 0 && previous.Index+1 != previous.Count {
				return ErrFormat
			}
			whole.Reset()
			length = 0
		} else if i == 0 || previous.BlobID != fragment.BlobID || previous.Index+1 != fragment.Index ||
			previous.Count != fragment.Count || previous.TotalLength != fragment.TotalLength || previous.WholeDigest != fragment.WholeDigest {
			return ErrFormat
		}
		_, _ = whole.Write(fragment.Payload)
		length += uint64(len(fragment.Payload))
		if fragment.Index+1 == fragment.Count {
			if length != fragment.TotalLength || !bytes.Equal(whole.Sum(nil), fragment.WholeDigest[:]) {
				return ErrFormat
			}
		}
		previous = fragment
	}
	if len(directory) > 0 && previous.Index+1 != previous.Count {
		return ErrFormat
	}
	return nil
}
