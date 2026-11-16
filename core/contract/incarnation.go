package contract

import "math"

const accessIncarnationPrefix = "ENKV/CORE/v1/access-incarnation\x00"

// IncarnationCounterStep validates one local ordering step. A counter can
// restart only under a different authenticated incarnation at its last value.
func IncarnationCounterStep(beforeID ID, before uint64, afterID ID, after uint64) bool {
	if beforeID.IsZero() || afterID.IsZero() || before == 0 || after == 0 {
		return false
	}
	if before == math.MaxUint64 {
		return after == 1 && afterID != beforeID
	}
	return afterID == beforeID && after == before+1
}

// DeriveAccessIncarnationID binds a fresh identity to this domain and purpose.
// The caller must establish freshness for the exact predecessor before
// selecting a successor. Genesis can use its fresh qualified signer identity.
func DeriveAccessIncarnationID(domain, seed ID) ID {
	if domain.IsZero() || seed.IsZero() {
		return ID{}
	}
	b := make([]byte, 0, len(accessIncarnationPrefix)+2*len(ID{}))
	b = append(b, accessIncarnationPrefix...)
	b = append(b, domain[:]...)
	b = append(b, seed[:]...)
	return Hash(b)
}

// AdvanceAccessGeneration mutates only the current access ordering pair.
func AdvanceAccessGeneration(core *CurrentAccessCore, seed ID) error {
	if core == nil || core.AccessIncarnationID.IsZero() || core.AccessGeneration == 0 {
		return ErrRecord
	}
	if core.AccessGeneration != math.MaxUint64 {
		core.AccessGeneration++
		return nil
	}
	next := DeriveAccessIncarnationID(core.DomainID, seed)
	if next.IsZero() || next == core.AccessIncarnationID {
		return ErrRecord
	}
	core.AccessIncarnationID = next
	core.AccessGeneration = 1
	return nil
}
