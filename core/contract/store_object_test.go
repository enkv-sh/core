package contract

import (
	"fmt"
	"strings"
	"testing"
)

// full_only: false
func TestStoreObjectKeysHaveOneCanonicalTypedGrammar(t *testing.T) {
	domain, object := gcTestID(1), gcTestID(2)
	prefix := strings.Repeat("p", 512)
	rows := []struct {
		name   string
		object StoreObjectIdentity
		length int
		limit  uint32
	}{
		{"member", StoreObjectIdentity{Namespace: StorePageObject, Kind: ValueEntryPageKind, Index: 31, ObjectID: object}, 652, 2 << 20},
		{"recipient", StoreObjectIdentity{Namespace: StorePageObject, Kind: RecipientKind, Index: 31, ObjectID: object}, 655, 96 << 10},
		{"root", StoreObjectIdentity{Namespace: StorePageObject, Kind: RootKind, ObjectID: object}, 649, 256 << 10},
		{"access", StoreObjectIdentity{Namespace: StorePageObject, Kind: AccessKind, Index: 255, ObjectID: object}, 653, 2 << 20},
		{"support", StoreObjectIdentity{Namespace: StorePageObject, Kind: RequiredSupportKind, Index: 255, ObjectID: object}, 654, 2 << 20},
		{"admin-index", StoreObjectIdentity{Namespace: StorePageObject, Kind: AdministrativeIndexKind, Index: 255, ObjectID: object}, 658, 2 << 20},
		{"result", StoreObjectIdentity{Namespace: StoreResultObject, ObjectID: object}, 649, 92637},
		{"configuration", StoreObjectIdentity{Namespace: StoreConfigurationObject, ObjectID: object}, 656, 4096},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			key, err := StoreObjectKey(prefix, domain, row.object)
			if err != nil || len(key) != row.length || StoreObjectLimit(row.object) != row.limit {
				t.Fatal("exact namespace bound", len(key), StoreObjectLimit(row.object), err)
			}
			want := prefix + "/" + strings.Repeat("01", 32) + "/" + row.name + "/"
			if row.object.Namespace == StorePageObject {
				want += fmt.Sprint(row.object.Index) + "/"
			}
			want += strings.Repeat("02", 32)
			if key != want {
				t.Fatal("typed key bytes changed")
			}
			got, err := ParseStoreObjectKey(prefix, domain, key)
			if err != nil || got != row.object {
				t.Fatal("typed key round trip", got, err)
			}
		})
	}
	if MaxStoreObjectKeyLength != 658 {
		t.Fatal("global immutable key bound changed", MaxStoreObjectKeyLength)
	}
}

// full_only: false
func TestStoreObjectKeysRejectForeignAndAmbiguousCoordinates(t *testing.T) {
	domain, object := gcTestID(1), gcTestID(2)
	identity := StoreObjectIdentity{Namespace: StorePageObject, Kind: ValueEntryPageKind, Index: 2, ObjectID: object}
	valid := "p/" + strings.Repeat("01", 32) + "/member/2/" + strings.Repeat("02", 32)
	for name, key := range map[string]string{
		"head":                   "p/HEAD",
		"domain-head":            "p/" + strings.Repeat("01", 32) + "/HEAD",
		"foreign-prefix":         "other" + strings.TrimPrefix(valid, "p"),
		"foreign-domain":         strings.Replace(valid, strings.Repeat("01", 32), strings.Repeat("03", 32), 1),
		"uppercase-object":       strings.TrimSuffix(valid, strings.Repeat("02", 32)) + strings.Repeat("AB", 32),
		"zero-object":            strings.TrimSuffix(valid, strings.Repeat("02", 32)) + strings.Repeat("00", 32),
		"short-object":           valid[:len(valid)-1],
		"leading-zero-index":     strings.Replace(valid, "/member/2/", "/member/02/", 1),
		"signed-index":           strings.Replace(valid, "/member/2/", "/member/+2/", 1),
		"negative-index":         strings.Replace(valid, "/member/2/", "/member/-2/", 1),
		"member-index-overflow":  strings.Replace(valid, "/member/2/", "/member/32/", 1),
		"root-index":             strings.Replace(valid, "/member/2/", "/root/1/", 1),
		"support-index-overflow": strings.Replace(valid, "/member/2/", "/support/256/", 1),
		"unknown-kind":           strings.Replace(valid, "/member/", "/unknown/", 1),
		"missing-index":          strings.Replace(valid, "/member/2/", "/member/", 1),
		"result-with-index":      strings.Replace(valid, "/member/2/", "/result/2/", 1),
		"escaped-separator":      strings.Replace(valid, "/member/2/", "/member%2F2/", 1),
		"trailing-segment":       valid + "/more",
		"query":                  valid + "?x=y",
		"overlong":               strings.Repeat("p", 659),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseStoreObjectKey("p", domain, key); err == nil {
				t.Fatal("foreign or ambiguous key accepted")
			}
		})
	}
	for _, prefix := range []string{"", "/p", "p/", "p//q", ".", "p/../q", `p\q`, "p?x", "p#x", "p\x00q", string([]byte{0xff}), strings.Repeat("p", 513)} {
		if _, err := StoreObjectKey(prefix, domain, identity); err == nil {
			t.Fatal("invalid prefix entered key construction")
		}
		if _, err := ParseStoreObjectKey(prefix, domain, valid); err == nil {
			t.Fatal("invalid prefix entered key recognition")
		}
	}
	if _, err := StoreObjectKey("p", ID{}, identity); err == nil {
		t.Fatal("zero domain accepted")
	}
	if _, err := ParseStoreObjectKey("p", ID{}, valid); err == nil {
		t.Fatal("zero expected domain accepted")
	}
	for name, v := range map[string]StoreObjectIdentity{
		"zero-object":         {Namespace: StorePageObject, Kind: RootKind},
		"head-kind":           {Namespace: StorePageObject, Kind: HeadKind, ObjectID: object},
		"unknown-namespace":   {Namespace: 4, ObjectID: object},
		"root-index":          {Namespace: StorePageObject, Kind: RootKind, Index: 1, ObjectID: object},
		"result-kind":         {Namespace: StoreResultObject, Kind: RootKind, ObjectID: object},
		"result-index":        {Namespace: StoreResultObject, Index: 1, ObjectID: object},
		"configuration-kind":  {Namespace: StoreConfigurationObject, Kind: RootKind, ObjectID: object},
		"configuration-index": {Namespace: StoreConfigurationObject, Index: 1, ObjectID: object},
	} {
		t.Run(name, func(t *testing.T) {
			if StoreObjectLimit(v) != 0 {
				t.Fatal("invalid identity has an object byte allowance")
			}
			if _, err := StoreObjectKey("p", domain, v); err == nil {
				t.Fatal("invalid identity constructed a key")
			}
		})
	}
}
