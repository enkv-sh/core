package format

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"slices"

	"enkv.sh/core/contract"
)

// ResolveGeneratedSliceLocations authenticates the snapshot carrier vector
// without reading the blob pages named by its locations. An administrative
// reader uses it when an optional blob page is unavailable.
func ResolveGeneratedSliceLocations(domain, snapshot ID, descriptor contract.GeneratorDescriptor, pages []RequiredSupportPageView) ([]contract.GeneratorSliceLocation, error) {
	if domain.IsZero() || snapshot.IsZero() || !contract.GeneratorVectorShapeValid(contract.GeneratorVectorSlices, descriptor) {
		return nil, ErrFormat
	}
	var carriers []contract.GeneratorVectorCarrier
	for _, page := range pages {
		for _, row := range page.Records {
			if row.Kind != contract.GeneratorVectorSupportKind {
				continue
			}
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return nil, ErrFormat
			}
			if v.VectorKind != contract.GeneratorVectorSlices {
				continue
			}
			if v.DomainID != domain || v.OwnerKind != contract.GeneratorSnapshotOwner || v.OwnerID != snapshot ||
				v.Vector != descriptor || len(carriers) >= int(descriptor.Count) {
				return nil, ErrFormat
			}
			id, err := contract.GeneratorVectorCarrierID(v)
			if err != nil || id != row.RecordID {
				return nil, ErrFormat
			}
			carriers = append(carriers, v)
		}
	}
	if len(carriers) != int(descriptor.Count) {
		return nil, ErrFormat
	}
	slices.SortFunc(carriers, func(a, b contract.GeneratorVectorCarrier) int { return cmp.Compare(a.Ordinal, b.Ordinal) })
	rows := make([][]byte, len(carriers))
	for i, v := range carriers {
		if v.Ordinal != uint32(i) {
			return nil, ErrFormat
		}
		rows[i] = v.Row
	}
	d, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, rows)
	if err != nil || d != descriptor {
		return nil, ErrFormat
	}
	if len(rows) == 0 {
		return nil, nil
	}
	out := make([]contract.GeneratorSliceLocation, len(rows))
	for i, row := range rows {
		v, err := contract.InspectGeneratorSliceLocation(row)
		if err != nil {
			return nil, ErrFormat
		}
		out[i] = v
	}
	return out, nil
}

// ResolveGeneratedSlices validates the selected physical mapping and hashes
// each exact byte slice without copying its blob. Core must separately derive
// the required logical contents from live consumers and reject unused mappings.
func ResolveGeneratedSlices(domain, snapshot ID, closure GeneratedClosure, pages []RequiredSupportPageView) ([]contract.GeneratorSliceLocation, error) {
	if !generatedClosureShapeValid(closure) || ValidateFragmentDirectory(closure.Fragments, pages) != nil {
		return nil, ErrFormat
	}
	locations, err := ResolveGeneratedSliceLocations(domain, snapshot, closure.Slices, pages)
	if err != nil {
		return nil, err
	}
	if len(locations) == 0 {
		return nil, nil
	}
	var byIndex [contract.MaxChildPages]*RequiredSupportPageView
	for i := range pages {
		byIndex[pages[i].Index] = &pages[i]
	}
	fragments := make(map[ID][]contract.GeneratedFragmentView)
	for _, loc := range closure.Fragments {
		page := byIndex[loc.SupportPageIndex]
		v, err := contract.InspectGeneratedFragment(page.Records[loc.RowSlot].Body)
		if err != nil {
			return nil, ErrFormat
		}
		fragments[v.BlobID] = append(fragments[v.BlobID], v)
	}
	for _, v := range locations {
		blob := fragments[v.BlobID]
		end := v.Offset + uint64(v.Length)
		if len(blob) == 0 || end > blob[0].TotalLength {
			return nil, ErrFormat
		}
		hash := sha256.New()
		var read uint64
		for _, fragment := range blob {
			start, stop := uint64(fragment.Offset), uint64(fragment.Offset)+uint64(len(fragment.Payload))
			if start >= end || stop <= v.Offset {
				continue
			}
			part := fragment.Payload[max(start, v.Offset)-start : min(stop, end)-start]
			_, _ = hash.Write(part)
			read += uint64(len(part))
		}
		if read != uint64(v.Length) || !bytes.Equal(hash.Sum(nil), v.Digest[:]) {
			return nil, ErrFormat
		}
	}
	return locations, nil
}
