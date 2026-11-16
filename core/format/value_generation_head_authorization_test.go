package format

import (
	"bytes"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func generatedHeadFixture(t testing.TB, maximum bool) Head {
	t.Helper()
	h := headFixture(t)
	if maximum {
		h.Core.PreviousToken.Value = `"` + strings.Repeat("a", 254) + `"`
		// Two positive 256-bit integers require a sign byte each in DER.
		sig := []byte{0x30, 0x46, 0x02, 0x21, 0, 0x80}
		sig = append(sig, make([]byte, 31)...)
		sig = append(sig, 0x02, 0x21, 0, 0x80)
		sig = append(sig, make([]byte, 31)...)
		h.K1, h.AuthorizationSignature, h.K3 = bytes.Clone(sig), bytes.Clone(sig), bytes.Clone(sig)
	}
	core, err := EncodeHeadCore(h.Core)
	if err != nil {
		t.Fatal(err)
	}
	condition := conditionFixture(h.Core.PreviousToken)
	conditionDigest, err := contract.CryptoConditionDigest(condition)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := EncodeConditionalPlan(ConditionalPlan{Family: h.Core.PreviousToken.Family, Store: h.Core.Store,
		Coordinate: h.Core.Coordinate, NonBody: h.Core.NonBody, Condition: condition, HeadCore: contract.Hash(core), HeadCoreLength: uint32(len(core))})
	if err != nil {
		t.Fatal(err)
	}
	d := contract.GeneratorDescriptor{Digest: fid(50), Length: 4}
	s := contract.GeneratorAuthoritySubject{Schema: contract.GeneratorAuthoritySubjectSchema, Purpose: contract.GeneratorAuthorityFinal, RequiredAuthoritySet: 1,
		DomainID: h.Core.Domain, OperationID: fid(51), RequestIdentityDigest: fid(52), PlanGraphID: fid(53), UsePlanDigest: fid(54), PhaseID: fid(55),
		PreviousHEADDigest: h.Core.PreviousDigest, PreviousRevisionID: h.Core.PreviousRevision, ConditionDigest: conditionDigest,
		BeforeRootDigest: fid(56), AfterRootDigest: h.Core.Root.Digest, BeforeAccessDigest: fid(57), AfterAccessDigest: fid(58), OwnerID: fid(59),
		HeadCoreDigest: contract.Hash(core), ConditionalPlanDigest: contract.Hash(plan), Intent: d, IdentityPlan: d, ValueEntryUnion: d,
		MembershipChanges: d, BeforeWork: d, AfterWork: d, ResultVector: d, CapacityReservation: d,
		BeforePhase: 1, AfterPhase: 2, HeadCoreLength: uint32(len(core)), ConditionalLength: uint32(len(plan))}
	h.AuthKind, h.Subject, h.Generator = GeneratorAuth, contract.LifecycleSubject{}, &s
	return h
}

// full_only: false
func TestGeneratedHEADExactAuthorityAndBound(t *testing.T) {
	for _, maximum := range []bool{false, true} {
		h := generatedHeadFixture(t, maximum)
		b, err := EncodeHead(h)
		if err != nil {
			t.Fatal(err)
		}
		// Independently derived: seven envelope bytes; four length words for
		// core/K1/K3/subject, one tag, then signature B; max core 674, subject
		// 1140 and three 72-byte signatures.
		if maximum && len(b) != 2058 {
			t.Fatal("maximum generated HEAD size", len(b))
		}
		got, err := DecodeHead(b)
		if err != nil || got.Core != h.Core || got.Generator == nil || *got.Generator != *h.Generator || got.AuthKind != GeneratorAuth {
			t.Fatal("generated HEAD traversal", err)
		}
		for n := range b {
			if _, err := DecodeHead(b[:n]); err == nil {
				t.Fatal("accepted truncation", n)
			}
		}
		if _, err := DecodeHead(append(bytes.Clone(b), 0)); err == nil {
			t.Fatal("accepted suffix")
		}
	}
	h := generatedHeadFixture(t, false)
	for name, change := range map[string]func(*Head){
		"missing condition":    func(v *Head) { v.Core.PreviousToken = contract.Token{} },
		"changed head token":   func(v *Head) { v.Core.PreviousToken.Value = `"another-token"` },
		"changed head digest":  func(v *Head) { v.Core.PreviousDigest = fid(80) },
		"changed head root":    func(v *Head) { v.Core.Root.Digest = fid(80) },
		"genesis head":         func(v *Head) { v.Core.Form = GenesisHead },
		"domain":               func(v *Head) { v.Generator.DomainID = fid(80) },
		"predecessor revision": func(v *Head) { v.Generator.PreviousRevisionID = fid(80) },
		"predecessor digest":   func(v *Head) { v.Generator.PreviousHEADDigest = fid(80) },
		"condition":            func(v *Head) { v.Generator.ConditionDigest = fid(80) },
		"selected root":        func(v *Head) { v.Generator.AfterRootDigest = fid(80) },
		"head digest":          func(v *Head) { v.Generator.HeadCoreDigest = fid(80) },
		"plan digest":          func(v *Head) { v.Generator.ConditionalPlanDigest = fid(80) },
		"plan length":          func(v *Head) { v.Generator.ConditionalLength++ },
		"head length":          func(v *Head) { v.Generator.HeadCoreLength++ },
		"missing subject":      func(v *Head) { v.Generator = nil },
		"other tag":            func(v *Head) { v.AuthKind = LifecycleAuth },
		"mixed authority":      func(v *Head) { v.Subject.Operation = fid(80) },
		"genesis authority":    func(v *Head) { v.Genesis = &GenesisProof{} },
		"succession authority": func(v *Head) { v.Succession = &SuccessionProof{} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := h
			subject := *h.Generator
			bad.Generator = &subject
			change(&bad)
			if _, err := EncodeHead(bad); err == nil {
				t.Fatal("changed authority relation accepted")
			}
		})
	}
	ordinary := headFixture(t)
	ordinary.Generator = h.Generator
	if _, err := EncodeHead(ordinary); err == nil {
		t.Fatal("inactive generated authority accepted")
	}
}
