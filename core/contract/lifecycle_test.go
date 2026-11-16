package contract

import (
	"bytes"
	"reflect"
	"testing"
)

func lifecycleFixture() LifecycleSubject {
	id := Hash([]byte("lifecycle"))
	return LifecycleSubject{
		OperationKind: OperationApplyDeclaration, Operation: id, Request: id, Recipient: id, KeyBinding: id, Fingerprint: id, BindingVersion: 1,
		IdentityPlan: DigestLength{id, 331}, HeadCore: id, HeadCoreLength: 426, ConditionalPlan: id,
		BeforeValueEntryCount: 1, AfterValueEntryCount: 1, BeforeRawBytes: 1, AfterRawBytes: 1,
		BeforeAccessRoot: Hash([]byte("before access")), AfterAccessRoot: Hash([]byte("after access")),
		BeforeMembershipCount: 1, AfterMembershipCount: 1,
		Normal:    NormalSection{Intent: DigestLength{id, 882}, PublicState: DigestLength{id, 181}, Union: DescriptorVector{id, 276, 1}, Changed: 1},
		Grant:     GrantSection{Grants: DescriptorVector{id, 61, 0}},
		Exclusion: ExclusionSection{Exclusions: DescriptorVector{id, 65, 0}, Retirements: DescriptorVector{id, 66, 0}},
	}
}

// full_only: false
func TestLifecycleOutputOnly(t *testing.T) {
	// One unchanged entry, one membership and zero name bytes: ordinary intent
	// 70 + 119 + 0 + 32 = 221. Complete framing adds at least 661.
	// A page-only plan is 162 + 35 = 197.
	fixture := lifecycleFixture()
	fixture.Normal.Changed = 0
	fixture.AfterAccessRoot = fixture.BeforeAccessRoot
	fixture.IdentityPlan.Length = 197
	for _, pages := range []uint64{1, MaxChildPages} {
		s := fixture
		s.IdentityPlan.Length = 162 + 35*pages
		body, err := LifecycleBytes(s)
		if err != nil || len(body) != 715 {
			t.Fatal("output-only lifecycle refused", err)
		}
		decoded, err := InspectLifecycleSubject(body)
		if err != nil || decoded != s {
			t.Fatal("output-only subject changed", err)
		}
		request, err := NewLifecycleRequest(s)
		if err != nil || !request.Valid() || request.Purpose() != LifecyclePurpose {
			t.Fatal("output-only signing refused", err)
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*LifecycleSubject)
	}{
		{"zero access", func(s *LifecycleSubject) { s.BeforeAccessRoot, s.AfterAccessRoot = ID{}, ID{} }},
		{"changed entry count", func(s *LifecycleSubject) { s.AfterValueEntryCount = 0 }},
		{"changed secret count", func(s *LifecycleSubject) { s.AfterSecretCount = 1 }},
		{"changed raw count", func(s *LifecycleSubject) { s.AfterRawBytes++ }},
		{"changed membership count", func(s *LifecycleSubject) { s.AfterMembershipCount++ }},
		{"changed union cardinality", func(s *LifecycleSubject) { s.Normal.Union.Count++ }},
		{"grant count", func(s *LifecycleSubject) { s.Grant.Grants.Count++ }},
		{"exclusion count", func(s *LifecycleSubject) { s.Exclusion.Exclusions.Count++ }},
		{"noncanonical empty grants", func(s *LifecycleSubject) { s.Grant.Grants.Length++ }},
		{"noncanonical empty exclusions", func(s *LifecycleSubject) { s.Exclusion.Exclusions.Length++ }},
		{"short intent", func(s *LifecycleSubject) { s.Normal.Intent.Length-- }},
		{"long intent", func(s *LifecycleSubject) { s.Normal.Intent.Length = 221 + 491604 + 1 }},
		{"replacement intent with unchanged access", func(s *LifecycleSubject) {
			s.OperationKind = OperationRotateRecipientKeyBinding
			s.Normal.Intent.Length = uint64(recipientReplacementIntentMinLength)
		}},
		{"noncanonical name framing", func(s *LifecycleSubject) { s.Normal.PublicState.Length++ }},
		{"noncanonical union framing", func(s *LifecycleSubject) { s.Normal.Union.Length++ }},
		{"empty page plan", func(s *LifecycleSubject) { s.IdentityPlan.Length = 162 }},
		{"short page plan", func(s *LifecycleSubject) { s.IdentityPlan.Length-- }},
		{"long page plan", func(s *LifecycleSubject) { s.IdentityPlan.Length++ }},
		{"value row plan", func(s *LifecycleSubject) { s.IdentityPlan.Length = 162 + 390 + 35 }},
		{"page capacity", func(s *LifecycleSubject) { s.IdentityPlan.Length = 162 + 35*(MaxChildPages+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture
			tc.change(&s)
			if _, err := LifecycleBytes(s); err != ErrSubject {
				t.Fatal("invalid output-only lifecycle admitted", err)
			}
			if request, err := NewLifecycleRequest(s); err != ErrSubject || request.Valid() {
				t.Fatal("invalid output-only signing admitted", err)
			}
		})
	}
}

// full_only: false
func TestLifecycleZeroChangeRecipientReplacement(t *testing.T) {
	s := lifecycleFixture()
	s.Normal.Changed = 0
	s.OperationKind = OperationRotateRecipientKeyBinding
	s.IdentityPlan.Length = 197
	for _, length := range []uint64{uint64(recipientReplacementIntentMinLength), uint64(recipientReplacementIntentMaxLength)} {
		s.Normal.Intent.Length = length
		if _, err := LifecycleBytes(s); err != nil {
			t.Fatal("recipient replacement refused", err)
		}
		if request, err := NewLifecycleRequest(s); err != nil || !request.Valid() {
			t.Fatal("recipient replacement signing refused", err)
		}
	}
	s.Normal.Intent.Length = 215
	if _, err := LifecycleBytes(s); err != ErrSubject {
		t.Fatal("ordinary intent changed recipient access", err)
	}
}

// full_only: false
func TestLifecycleAdditionRemovalAndReplacementBounds(t *testing.T) {
	for _, tc := range []struct {
		name                                   string
		before, after, added, removed, updated uint32
	}{
		{"first addition", 0, 1, 1, 0, 0},
		{"last removal", 1, 0, 0, 1, 0},
		{"retained update", 1, 1, 0, 0, 1},
		{"retained removal", 2, 1, 0, 1, 0},
		{"mixed transition", 3, 3, 1, 1, 1},
		{"maximum single membership replacement", 512, 512, 512, 512, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := lifecycleFixture()
			s.BeforeValueEntryCount, s.AfterValueEntryCount = tc.before, tc.after
			s.BeforeMembershipCount, s.AfterMembershipCount = tc.before, tc.after
			s.BeforeRawBytes = min(uint64(tc.before)*65536, 8<<20)
			s.AfterRawBytes = min(uint64(tc.after)*65536, 8<<20)
			s.Normal.Intent.Length = 731 + 407*uint64(tc.after)
			s.Normal.PublicState.Length = 143 + 294*uint64(tc.after)
			s.Normal.Union.Count = tc.before + tc.added
			s.Normal.Union.Length = 70 + 262*uint64(s.Normal.Union.Count) + 100*uint64(tc.before+tc.after)
			s.Normal.Changed = tc.added + tc.removed + tc.updated
			s.Grant.Grants.Count, s.Grant.Grants.Length = tc.added, 61+360*uint64(tc.added)
			s.Exclusion.Exclusions.Count, s.Exclusion.Exclusions.Length = tc.removed, 65+392*uint64(tc.removed)
			pages := (uint64(tc.added+tc.updated) + 15) / 16
			s.IdentityPlan.Length = 162 + 390*uint64(tc.added+tc.updated) + 35*pages
			if b, err := LifecycleBytes(s); err != nil || len(b) != 715 {
				t.Fatal("bounded lifecycle refused", err)
			}
			request, err := NewLifecycleRequest(s)
			if err != nil || !request.Valid() || request.Purpose() != LifecyclePurpose {
				t.Fatal("lifecycle signing refused", err)
			}
			if tc.name == "maximum single membership replacement" {
				if s.Normal.Intent.Length != 209115 || s.Normal.PublicState.Length != 150671 || s.Normal.Union.Length != 370758 ||
					s.Grant.Grants.Length != 184381 || s.Exclusion.Exclusions.Length != 200769 || s.IdentityPlan.Length != 200962 {
					t.Fatal("maximum vector bounds differ")
				}
			}
		})
	}
}

// full_only: false
func TestLifecycleClosedCountsAndLengths(t *testing.T) {
	tests := []struct {
		name   string
		change func(*LifecycleSubject)
	}{
		{"zero binding version", func(s *LifecycleSubject) { s.BindingVersion = 0 }},
		{"replacement with value changes", func(s *LifecycleSubject) { s.OperationKind = OperationRotateRecipientKeyBinding }},
		{"excess changes", func(s *LifecycleSubject) { s.Normal.Changed = 2 }},
		{"count overflow", func(s *LifecycleSubject) { s.BeforeValueEntryCount = ^uint32(0) }},
		{"before capacity", func(s *LifecycleSubject) { s.BeforeValueEntryCount = 513 }},
		{"after capacity", func(s *LifecycleSubject) { s.AfterValueEntryCount = 513 }},
		{"before memberships below members", func(s *LifecycleSubject) { s.BeforeMembershipCount = 0 }},
		{"after memberships below members", func(s *LifecycleSubject) { s.AfterMembershipCount = 0 }},
		{"before memberships exceed per member limit", func(s *LifecycleSubject) { s.BeforeMembershipCount = 65 }},
		{"after memberships exceed per member limit", func(s *LifecycleSubject) { s.AfterMembershipCount = 65 }},
		{"before secret count exceeds members", func(s *LifecycleSubject) { s.BeforeSecretCount = 2 }},
		{"after secret count exceeds members", func(s *LifecycleSubject) { s.AfterSecretCount = 2 }},
		{"before raw capacity", func(s *LifecycleSubject) { s.BeforeRawBytes = 8<<20 + 1 }},
		{"after raw capacity", func(s *LifecycleSubject) { s.AfterRawBytes = 8<<20 + 1 }},
		{"before per-member raw", func(s *LifecycleSubject) { s.BeforeRawBytes = 65537 }},
		{"after per-member raw", func(s *LifecycleSubject) { s.AfterRawBytes = 65537 }},
		{"grant exceeds after", func(s *LifecycleSubject) { s.Grant.Grants.Count = 2 }},
		{"exclusion exceeds before", func(s *LifecycleSubject) { s.Exclusion.Exclusions.Count = 2 }},
		{"grant count without rows", func(s *LifecycleSubject) { s.Grant.Grants.Count = 1 }},
		{"union count", func(s *LifecycleSubject) { s.Normal.Union.Count = 2 }},
		{"changed underflow", func(s *LifecycleSubject) {
			s.Grant.Grants.Count = 1
			s.Exclusion.Exclusions.Count = 1
			s.Normal.Union.Count = 2
		}},
		{"retirement count", func(s *LifecycleSubject) { s.Exclusion.Retirements.Count = 1 }},
		{"retirement length", func(s *LifecycleSubject) { s.Exclusion.Retirements.Length++ }},
		{"empty grant length", func(s *LifecycleSubject) { s.Grant.Grants.Length++ }},
		{"empty exclusion length", func(s *LifecycleSubject) { s.Exclusion.Exclusions.Length++ }},
		{"intent length", func(s *LifecycleSubject) { s.Normal.Intent.Length = 221 + 491604 + 1 }},
		{"public-state below minimum", func(s *LifecycleSubject) { s.Normal.PublicState.Length = 180 }},
		{"public-state above maximum", func(s *LifecycleSubject) { s.Normal.PublicState.Length = 438 }},
		{"union length", func(s *LifecycleSubject) { s.Normal.Union.Length++ }},
		{"identity plan below minimum", func(s *LifecycleSubject) { s.IdentityPlan.Length = 161 }},
		{"identity plan above maximum", func(s *LifecycleSubject) { s.IdentityPlan.Length = 208803 }},
		{"length overflow", func(s *LifecycleSubject) { s.IdentityPlan.Length = ^uint64(0) }},
		{"short head core", func(s *LifecycleSubject) { s.HeadCoreLength = 418 }},
		{"long head core", func(s *LifecycleSubject) { s.HeadCoreLength = 675 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := lifecycleFixture()
			tc.change(&s)
			if _, err := LifecycleBytes(s); err != ErrSubject {
				t.Fatalf("invalid subject: %v", err)
			}
			if request, err := NewLifecycleRequest(s); err != ErrSubject || request.Valid() {
				t.Fatalf("invalid signing request: %v", err)
			}
		})
	}
}

// full_only: false
func TestLifecycleBindsEveryIdentity(t *testing.T) {
	s := lifecycleFixture()
	canonical, err := LifecycleBytes(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(canonical) != 715 {
		t.Fatalf("subject length %d", len(canonical))
	}
	var visit func(reflect.Value)
	visit = func(v reflect.Value) {
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			if field.Type() == reflect.TypeOf(ID{}) {
				old := field.Interface().(ID)
				field.Set(reflect.ValueOf(ID{}))
				name := v.Type().Field(i).Name
				encoded, err := LifecycleBytes(s)
				if name == "BeforeAccessRoot" || name == "AfterAccessRoot" {
					if err != nil || bytes.Equal(encoded, canonical) {
						t.Fatal("opaque access digest omitted or refused", err)
					}
				} else if err != ErrSubject {
					t.Fatal("zero required identity accepted")
				}
				field.Set(reflect.ValueOf(Hash([]byte("other"))))
				encoded, err = LifecycleBytes(s)
				if err != nil || bytes.Equal(encoded, canonical) {
					t.Fatal("identity omitted", err)
				}
				field.Set(reflect.ValueOf(old))
			} else if field.Kind() == reflect.Struct {
				visit(field)
			}
		}
	}
	visit(reflect.ValueOf(&s).Elem())
}
