package format

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"slices"

	"enkv.sh/core/contract"
)

const GrantWrapLength = 4 + contract.WrapRowWireLength
const MaxGrantPages = contract.MaxHeadLength / GrantWrapLength

// GrantHeadFits reserves the final authorization signature at its maximum DER
// length. The token and setup proofs are already known on an ordinary grant.
// A generated reservation supplies the maximum sizes still possible at Final.
func GrantHeadFits(rows, tokenBytes, k1Bytes, k3Bytes int, generated bool) bool {
	if rows <= 0 || rows > contract.MaxHeadLength/GrantWrapLength ||
		tokenBytes < 1 || tokenBytes > contract.SuccessorHeadCoreMaxLength-contract.SuccessorHeadCoreMinLength+1 ||
		k1Bytes <= 0 || k1Bytes > contract.MaxSignature || k3Bytes < 0 || k3Bytes > contract.MaxSignature {
		return false
	}
	subjectBytes := contract.LifecycleSubjectLength
	if generated {
		subjectBytes = contract.GeneratorAuthoritySubjectLength
	}
	// Seven prefix bytes, one authorization tag, and five blob lengths.
	const framing = 7 + 1 + 5*4
	coreBytes := contract.SuccessorHeadCoreMinLength - 1 + tokenBytes + len(ID{})
	return framing+coreBytes+k1Bytes+k3Bytes+subjectBytes+contract.MaxSignature+rows*GrantWrapLength <= contract.MaxHeadLength
}

// Grant rows follow the order of the selected access pages, records and
// recipient IDs. Their coordinates locate the omitted rows in those pages.
func validGrantWraps(body []byte) bool {
	if len(body) == 0 || len(body) > contract.MaxHeadLength || len(body)%GrantWrapLength != 0 {
		return false
	}
	var previousPosition uint32
	var previousSubject ID
	for offset := 0; offset < len(body); offset += GrantWrapLength {
		row := body[offset : offset+GrantWrapLength]
		position := binary.BigEndian.Uint32(row)
		page, record := position>>16, uint16(position)
		wrap, err := contract.InspectWrapRow(row[4:])
		if page >= contract.MaxChildPages || record >= contract.AccessPageRecordLimit || err != nil ||
			wrap.SubjectKind != contract.OrdinaryWrapSubject || wrap.PublicBindingDigest.IsZero() ||
			offset != 0 && (position < previousPosition || position == previousPosition && bytes.Compare(wrap.SubjectID[:], previousSubject[:]) <= 0) {
			return false
		}
		previousPosition, previousSubject = position, wrap.SubjectID
	}
	return true
}

func grantHeadAllowed(h Head) bool {
	switch h.AuthKind {
	case LifecycleAuth:
		return h.Subject.OperationKind == contract.OperationApplyDeclaration && h.Subject.Grant.Grants.Count != 0
	case GeneratorAuth:
		return h.Generator != nil && h.Generator.Purpose == contract.GeneratorAuthorityFinal &&
			h.Generator.RequiredAuthoritySet&contract.GeneratorAuthorityGrant != 0
	default:
		return false
	}
}

func grantBodyMatches(core HeadCore, body []byte) bool {
	if len(body) == 0 {
		return core.GrantDigest.IsZero()
	}
	return !core.GrantDigest.IsZero() && validGrantWraps(body) && contract.Hash(body) == core.GrantDigest
}

// SplitGrantPage leaves existing protection on the staged page and transfers
// only new recipient rows to HEAD. The signed full page reference commits to
// the exact original ordering and every byte needed at selection.
func SplitGrantPage(page AccessPage, grants map[ID][]ID) (AccessPage, []byte, error) {
	base := page
	base.Records = slices.Clone(page.Records)
	var rows []byte
	for i, record := range page.Records {
		wanted := grants[record.MaterialID]
		if record.MaterialKind != contract.ValueMaterialKind || len(wanted) == 0 {
			continue
		}
		base.Records[i].Wraps = slices.Clone(record.Wraps)
		count := 0
		for j, wrap := range record.Wraps {
			if wrap.SubjectKind != contract.OrdinaryWrapSubject || !slices.Contains(wanted, wrap.SubjectID) {
				continue
			}
			if len(rows) > contract.MaxHeadLength-GrantWrapLength {
				return AccessPage{}, nil, contract.ErrRecordCapacity
			}
			rows = binary.BigEndian.AppendUint16(rows, page.Index)
			rows = binary.BigEndian.AppendUint16(rows, uint16(i))
			var err error
			rows, err = contract.AppendWrapRow(rows, wrap)
			if err != nil {
				return AccessPage{}, nil, err
			}
			// The immutable slot commits to the complete row, including its
			// binding and ciphertext. No ciphertext bytes enter the slot.
			base.Records[i].Wraps[j].PublicBindingDigest = contract.Hash(rows[len(rows)-contract.WrapRowWireLength:])
			base.Records[i].Wraps[j].RSACiphertext = make([]byte, contract.RSACiphertextLength)
			count++
		}
		if count != len(wanted) {
			return AccessPage{}, nil, ErrFormat
		}
	}
	if len(rows) != 0 {
		base.Object = grantBaseObject(page.Domain, page.Object)
	}
	return base, rows, nil
}

func grantBaseObject(domain, logical ID) ID {
	body := append([]byte("ENKV/access-page/grant-base/v1\x00"), domain[:]...)
	return contract.Hash(append(body, logical[:]...))
}

type GrantPageSource struct {
	Base Ref
	Rows []byte
}

func (r Root) GrantSources(head Head) (map[Ref]GrantPageSource, error) {
	if len(r.GrantPages) == 0 && len(head.GrantWraps) == 0 && head.Core.GrantDigest.IsZero() {
		return nil, nil
	}
	if !grantHeadAllowed(head) || !grantBodyMatches(head.Core, head.GrantWraps) ||
		len(r.GrantPages) == 0 || head.Core.Domain != r.Domain || head.Core.Root.Object != r.Snapshot {
		return nil, ErrFormat
	}
	rows := head.GrantWraps
	sources := make(map[Ref]GrantPageSource, len(r.GrantPages))
	for _, base := range r.GrantPages {
		i, ok := slices.BinarySearchFunc(r.CurrentAccess.Core.AccessPageRefs, base.Index, func(ref Ref, index uint16) int {
			return cmp.Compare(ref.Index, index)
		})
		if !ok {
			return nil, ErrFormat
		}
		ref := r.CurrentAccess.Core.AccessPageRefs[i]
		n := 0
		for n < len(rows) && binary.BigEndian.Uint16(rows[n:n+2]) == base.Index {
			n += GrantWrapLength
		}
		if n == 0 || base.Object != grantBaseObject(ref.Domain, ref.Object) || base.Length != ref.Length {
			return nil, ErrFormat
		}
		sources[ref] = GrantPageSource{Base: base, Rows: rows[:n:n]}
		rows = rows[n:]
	}
	if len(rows) != 0 {
		return nil, ErrFormat
	}
	return sources, nil
}

// RestoreGrantPage consumes an owned base page. Its output must match the
// signed logical reference before any caller uses a recipient row.
func RestoreGrantPage(ref Ref, base AccessPage, rows []byte) (AccessPage, []byte, error) {
	if base.Object != grantBaseObject(ref.Domain, ref.Object) || base.Domain != ref.Domain || base.Index != ref.Index ||
		ref.Kind != AccessKind || !validGrantWraps(rows) {
		return AccessPage{}, nil, ErrFormat
	}
	for offset := 0; offset < len(rows); offset += GrantWrapLength {
		row := rows[offset : offset+GrantWrapLength]
		index := int(binary.BigEndian.Uint16(row[2:4]))
		if binary.BigEndian.Uint16(row[:2]) != ref.Index || index >= len(base.Records) ||
			base.Records[index].MaterialKind != contract.ValueMaterialKind {
			return AccessPage{}, nil, ErrFormat
		}
		wrap, err := contract.DecodeWrapRow(row[4:])
		if err != nil {
			return AccessPage{}, nil, err
		}
		wraps := base.Records[index].Wraps
		j, ok := slices.BinarySearchFunc(wraps, wrap, func(a, b contract.WrapRow) int {
			if order := cmp.Compare(a.SubjectKind, b.SubjectKind); order != 0 {
				return order
			}
			return bytes.Compare(a.SubjectID[:], b.SubjectID[:])
		})
		var empty [contract.RSACiphertextLength]byte
		if !ok || wraps[j].BindingID != wrap.BindingID || wraps[j].BindingSerial != wrap.BindingSerial ||
			wraps[j].PublicBindingDigest != contract.Hash(row[4:]) || !bytes.Equal(wraps[j].RSACiphertext, empty[:]) {
			return AccessPage{}, nil, ErrFormat
		}
		wraps[j] = wrap
	}
	base.Object = ref.Object
	body, err := EncodeAccessPage(base)
	if err != nil || uint64(len(body)) != uint64(ref.Length) || contract.Hash(body) != ref.Digest {
		return AccessPage{}, nil, ErrFormat
	}
	return base, body, nil
}
