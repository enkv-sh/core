package core

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicObservationOwnsCompleteBranchAndRefusesMixedEvidence(t *testing.T) {
	original := PublicBasis{SigningAnchor: []byte{1}, StoreConfiguration: []byte{2}, HEAD: []byte{3}, Root: []byte{4}, RecipientPages: [][]byte{{5}, {6}}}
	owned, err := original.OwnedCopy()
	if err != nil {
		t.Fatal(err)
	}
	original.SigningAnchor[0]++
	original.StoreConfiguration[0]++
	original.HEAD[0]++
	original.Root[0]++
	original.RecipientPages[0][0]++
	original.RecipientPages[1] = nil
	if !bytes.Equal(owned.SigningAnchor, []byte{1}) || !bytes.Equal(owned.StoreConfiguration, []byte{2}) || !bytes.Equal(owned.HEAD, []byte{3}) || !bytes.Equal(owned.Root, []byte{4}) || !reflect.DeepEqual(owned.RecipientPages, [][]byte{{5}, {6}}) {
		t.Fatal("observation retained caller backing")
	}
	for _, kind := range []string{"descriptor", "control", "selection", "enrollment", "missing-anchor", "missing-helper", "missing-head", "missing-root", "missing-pages", "nil-page"} {
		t.Run(kind, func(t *testing.T) {
			offered, _ := owned.OwnedCopy()
			switch kind {
			case "descriptor":
				offered.Descriptor = []byte{1}
			case "control":
				offered.Control = []byte{1}
			case "selection":
				offered.Selection = []byte{1}
			case "enrollment":
				offered.Enrollment = []PublicEnrollment{{RecipientID: contract.ID{1}, Status: 1}}
			case "missing-anchor":
				offered.SigningAnchor = nil
			case "missing-helper":
				offered.StoreConfiguration = nil
			case "missing-head":
				offered.HEAD = nil
			case "missing-root":
				offered.Root = nil
			case "missing-pages":
				offered.RecipientPages = nil
			case "nil-page":
				offered.RecipientPages[0] = nil
			}
			if _, err := offered.OwnedCopy(); err == nil {
				t.Fatal("incomplete or mixed branch accepted")
			}
		})
	}
	owned.clear()
	if !reflect.DeepEqual(owned, PublicBasis{}) {
		t.Fatal("cleared branch retained fields")
	}
}

// full_only: false
func TestReaderObservationClosedSchemaAndFields(t *testing.T) {
	record := `{"schema":3,"kind":"observation","anchor":"AQ==","store_configuration":"Ag==","head":"Aw==","root":"BA==","recipient_pages":["BQ=="]}`
	parsed, err := readLocalReaderPublicBasis(localAdmissionPath(t, "observation", []byte(record)))
	if err != nil || parsed.Kind != "observation" || !bytes.Equal(parsed.SigningAnchor, []byte{1}) || !reflect.DeepEqual(parsed.RecipientPages, [][]byte{{5}}) {
		t.Fatal("observation schema refused", err)
	}
	for _, body := range []string{
		strings.Replace(record, `"schema":3`, `"schema":2`, 1),
		strings.Replace(record, `"anchor":"AQ=="`, `"anchor":null`, 1),
		strings.Replace(record, `"root":"BA=="`, `"root":""`, 1),
		strings.Replace(record, `["BQ=="]`, `[]`, 1),
		strings.Replace(record, `["BQ=="]`, `[null]`, 1),
		strings.Replace(record, `["BQ=="]`, `[""]`, 1),
		strings.Replace(record, `"schema":3`, `"schema":3,"selection":"AA=="`, 1),
		strings.Replace(record, `"anchor":"AQ=="`, `"anchor":"AQ==","\u0061nchor":"AQ=="`, 1),
	} {
		if got, err := readLocalReaderPublicBasis(localAdmissionPath(t, "refused", []byte(body))); err == nil || !reflect.DeepEqual(got, localBasisImage{}) {
			t.Fatal("malformed observation accepted", body, err)
		}
	}
	writer, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readLocalReaderPublicBasis(localAdmissionPath(t, "writer", writer))
	if err != nil || !reflect.DeepEqual(got, parsed) {
		t.Fatal("standalone writer lost observation", err)
	}
}

// full_only: true
func TestPublicObservationExactIndependentBackingLimits(t *testing.T) {
	limits := []int{1613, 4096, 65536, 262144, 98304}
	if contract.PublicSigningBindingMaxLength != limits[0] || contract.MaxRecipientPages != 32 {
		t.Fatal("observation owner limits changed")
	}
	basis := PublicBasis{SigningAnchor: make([]byte, limits[0]), StoreConfiguration: make([]byte, limits[1]), HEAD: make([]byte, limits[2]), Root: make([]byte, limits[3]), RecipientPages: make([][]byte, 32)}
	for i := range basis.RecipientPages {
		basis.RecipientPages[i] = make([]byte, limits[4])
	}
	owned, err := basis.OwnedCopy()
	if err != nil {
		t.Fatal("exact maxima", err)
	}
	total := cap(owned.SigningAnchor) + cap(owned.StoreConfiguration) + cap(owned.HEAD) + cap(owned.Root)
	for _, page := range owned.RecipientPages {
		total += cap(page)
	}
	encoded, err := json.Marshal(localBasisImage{Schema: 3, Kind: "observation", SigningAnchor: basis.SigningAnchor, StoreConfiguration: basis.StoreConfiguration, HEAD: basis.HEAD, Root: basis.Root, RecipientPages: basis.RecipientPages})
	if err != nil || len(encoded) != 4639038 {
		t.Fatal("exact standalone framing/base64 account", len(encoded), err)
	}
	parsed, err := readLocalReaderPublicBasis(localAdmissionPath(t, "maximum-observation", encoded))
	if err != nil || len(parsed.RecipientPages) != 32 || len(parsed.SigningAnchor) != 1613 || len(parsed.StoreConfiguration) != 4096 || len(parsed.HEAD) != 65536 || len(parsed.Root) != 262144 || len(parsed.RecipientPages[31]) != 98304 {
		t.Fatal("maximum standalone observation refused", err)
	}
	if total != 3479117 {
		t.Fatal("observation decoded backing", total)
	}
	for field := range 6 {
		t.Run(string(rune('a'+field)), func(t *testing.T) {
			excess := basis
			switch field {
			case 0:
				excess.SigningAnchor = make([]byte, 1614)
			case 1:
				excess.StoreConfiguration = make([]byte, 4097)
			case 2:
				excess.HEAD = make([]byte, 65537)
			case 3:
				excess.Root = make([]byte, 262145)
			case 4:
				excess.RecipientPages = append([][]byte(nil), basis.RecipientPages...)
				excess.RecipientPages[31] = make([]byte, 98305)
			case 5:
				excess.RecipientPages = append(append([][]byte(nil), basis.RecipientPages...), []byte{1})
			}
			if _, err := excess.OwnedCopy(); err == nil {
				t.Fatal("first excess accepted")
			}
			encoded, err := json.Marshal(localBasisImage{Schema: 3, Kind: "observation", SigningAnchor: excess.SigningAnchor, StoreConfiguration: excess.StoreConfiguration, HEAD: excess.HEAD, Root: excess.Root, RecipientPages: excess.RecipientPages})
			if err != nil {
				t.Fatal(err)
			}
			if got, err := readLocalReaderPublicBasis(localAdmissionPath(t, "excess", encoded)); err == nil || !reflect.DeepEqual(got, localBasisImage{}) {
				t.Fatal("standalone first excess accepted", err)
			}
		})
	}
}
