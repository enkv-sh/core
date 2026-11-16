package format

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestSuccessionHeadPlanHasOnlyRootDigestHole(t *testing.T) {
	_, core, _, _ := successionWireFixture(t)
	actual := core
	core.Root.Digest = ID{}
	want := successionHeadCoreBytes(core)
	got, err := EncodeHeadPlan(HeadPlan(core))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("HEAD plan differs from independent traversal", err)
	}
	if _, err := EncodeHeadCore(core); err == nil {
		t.Fatal("stored HEAD core accepted plan")
	}
	if _, err := DecodeHeadCore(got); err == nil {
		t.Fatal("stored HEAD decoder accepted plan")
	}
	if _, err := EncodeHeadPlan(HeadPlan(actual)); err == nil {
		t.Fatal("plan accepted filled root digest")
	}
	if _, err := contract.DecodeRef(got[72+64+5+len(core.PreviousToken.Value):][:contract.RefLength], Version); err == nil {
		t.Fatal("stored Ref decoder accepted root digest hole")
	}
	for name, change := range map[string]func(*HeadCore){
		"root kind":            func(p *HeadCore) { p.Root.Kind = ValueEntryPageKind },
		"root format":          func(p *HeadCore) { p.Root.Format = 3 },
		"root index":           func(p *HeadCore) { p.Root.Index = 1 },
		"root length zero":     func(p *HeadCore) { p.Root.Length = 0 },
		"root length excess":   func(p *HeadCore) { p.Root.Length = MaxRoot + 1 },
		"root domain zero":     func(p *HeadCore) { p.Root.Domain = ID{} },
		"root object zero":     func(p *HeadCore) { p.Root.Object = ID{} },
		"root domain mismatch": func(p *HeadCore) { p.Root.Domain = fid(99) },
		"revision":             func(p *HeadCore) { p.Revision = ID{} },
		"previous revision":    func(p *HeadCore) { p.PreviousRevision = ID{} },
		"previous digest":      func(p *HeadCore) { p.PreviousDigest = ID{} },
		"token":                func(p *HeadCore) { p.PreviousToken = contract.Token{} },
		"store":                func(p *HeadCore) { p.Store = ID{} },
		"trust":                func(p *HeadCore) { p.Trust = ID{} },
		"coordinate":           func(p *HeadCore) { p.Coordinate = ID{} },
		"nonbody":              func(p *HeadCore) { p.NonBody = ID{} },
		"interpretation":       func(p *HeadCore) { p.Interpretation = ID{} },
		"epoch":                func(p *HeadCore) { p.Epoch = 0 },
		"unsupported":          func(p *HeadCore) { p.Unsupported = 1 },
		"genesis": func(p *HeadCore) {
			p.Form = GenesisHead
			p.Epoch = 1
			p.PreviousRevision = ID{}
			p.PreviousDigest = ID{}
			p.PreviousToken = contract.Token{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := core
			change(&p)
			if _, err := EncodeHeadPlan(HeadPlan(p)); err == nil {
				t.Fatal("accepted a second hole or invalid root shape")
			}
		})
	}
	for _, change := range []func(*HeadCore){
		func(p *HeadCore) { p.Domain = fid(99); p.Root.Domain = p.Domain }, func(p *HeadCore) { p.Revision = fid(99) },
		func(p *HeadCore) { p.PreviousRevision = fid(99) }, func(p *HeadCore) { p.PreviousDigest = fid(99) },
		func(p *HeadCore) { p.PreviousToken.Value = `"other"` }, func(p *HeadCore) { p.Root.Object = fid(99) },
		func(p *HeadCore) { p.Root.Length = MaxRoot }, func(p *HeadCore) { p.Store = fid(99) }, func(p *HeadCore) { p.Trust = fid(99) },
		func(p *HeadCore) { p.Coordinate = fid(99) }, func(p *HeadCore) { p.NonBody = fid(99) }, func(p *HeadCore) { p.Interpretation = fid(99) }, func(p *HeadCore) { p.Epoch++ },
	} {
		p := core
		change(&p)
		changed, err := EncodeHeadPlan(HeadPlan(p))
		if err != nil || bytes.Equal(changed, got) || !bytes.Equal(changed, successionHeadCoreBytes(p)) {
			t.Fatal("HEAD plan omitted a non-hole field", err)
		}
	}
}

// full_only: false
func TestSuccessionConditionalPlanHasOnlyHeadDigestHole(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		_, head, _, _ := successionWireFixture(t)
		head.PreviousToken.Family = family
		if family == contract.GCP {
			head.PreviousToken.Value = "42"
		}
		length := uint32(len(successionHeadCoreBytes(head)))
		plan := ConditionalPlan{Family: family, Store: head.Store, Coordinate: head.Coordinate, NonBody: head.NonBody, Condition: conditionFixture(head.PreviousToken), HeadCoreLength: length}
		got, err := EncodeConditionalRequestPlan(ConditionalRequestPlan(plan))
		if err != nil || !bytes.Equal(got, successionConditionalBytes(head, ID{}, length)) {
			t.Fatal("conditional plan differs from independent traversal", err)
		}
		if _, err := EncodeConditionalPlan(plan); err == nil {
			t.Fatal("actual condition accepted head digest hole")
		}
		if _, err := DecodeConditionalPlan(got); err == nil {
			t.Fatal("actual decoder accepted conditional plan")
		}
		for name, change := range map[string]func(*ConditionalPlan){
			"filled digest":      func(p *ConditionalPlan) { p.HeadCore = fid(99) },
			"missing store":      func(p *ConditionalPlan) { p.Store = ID{} },
			"missing coordinate": func(p *ConditionalPlan) { p.Coordinate = ID{} },
			"missing nonbody":    func(p *ConditionalPlan) { p.NonBody = ID{} },
			"invalid family":     func(p *ConditionalPlan) { p.Family = 0 },
			"short head":         func(p *ConditionalPlan) { p.HeadCoreLength = 418 },
			"long head":          func(p *ConditionalPlan) { p.HeadCoreLength = 675 },
			"absent":             func(p *ConditionalPlan) { p.Condition = contract.AbsentHeadCondition(); p.HeadCoreLength = 349 },
			"wrong family":       func(p *ConditionalPlan) { p.Family = contract.AWS + contract.GCP - p.Family },
		} {
			t.Run(name, func(t *testing.T) {
				p := plan
				change(&p)
				if _, err := EncodeConditionalRequestPlan(ConditionalRequestPlan(p)); err == nil {
					t.Fatal("invalid conditional plan accepted")
				}
			})
		}
		for _, change := range []func(*ConditionalPlan){
			func(p *ConditionalPlan) { p.Store = fid(99) }, func(p *ConditionalPlan) { p.Coordinate = fid(99) }, func(p *ConditionalPlan) { p.NonBody = fid(99) }, func(p *ConditionalPlan) { p.HeadCoreLength++ },
			func(p *ConditionalPlan) {
				v := head.PreviousToken
				if v.Family == contract.GCP {
					v.Value = "43"
				} else {
					v.Value = `"other"`
				}
				p.Condition = conditionFixture(v)
			},
		} {
			p := plan
			change(&p)
			changed, err := EncodeConditionalRequestPlan(ConditionalRequestPlan(p))
			if err != nil || bytes.Equal(changed, got) {
				t.Fatal("conditional plan omitted non-hole field", err)
			}
		}
	}
}
