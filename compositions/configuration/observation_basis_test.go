package configuration

import (
	"bytes"
	"context"
	"encoding/base64"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

const observationBasisJSON = `{"kind":"observation","anchor":"AP8B","store_configuration":"AgA=","head":"AwQ=","root":"BQ==","recipient_pages":["Bgc=","CA=="]}`

func observationBasisFixture() Basis {
	return Basis{SigningAnchor: []byte{0, 255, 1}, StoreConfiguration: []byte{2, 0}, HEAD: []byte{3, 4}, Root: []byte{5}, RecipientPages: [][]byte{{6, 7}, {8}}}
}

// These bytes test source representation only. Authentication belongs to the
// composition round trip through a real committed reconstruction.
// full_only: false
func TestObservationBasisPreservesExactBytesAcrossPairForms(t *testing.T) {
	generated := strings.Replace(sourceGeneratedJSON, `{"kind":"genesis","descriptor":"AQ=="}`, observationBasisJSON, 1)
	model, err := Parse(context.Background(), writePair(t, sourceSetupJSON, generated, JSON))
	if err != nil || !reflect.DeepEqual(model.Basis, observationBasisFixture()) {
		t.Fatal("complete observation source changed bytes", err)
	}
	for _, format := range []Format{JSON, YAML} {
		var editable, satellite bytes.Buffer
		if err := EmitEditable(&editable, model, format); err != nil {
			t.Fatal(err)
		}
		if err := EmitGenerated(&satellite, model); err != nil {
			t.Fatal(err)
		}
		again, err := Parse(context.Background(), captureEditableEmission(t, editable.Bytes(), satellite.Bytes(), format, model.Generated))
		if err != nil || !reflect.DeepEqual(again.Basis, observationBasisFixture()) {
			t.Fatal("pair emission changed observation bytes", err)
		}
	}
	_, basis := model.TakePublic()
	if !reflect.DeepEqual(*model, Model{}) || !reflect.DeepEqual(basis, observationBasisFixture()) {
		t.Fatal("public transfer lost observation ownership")
	}
}

// full_only: false
func TestObservationBasisRefusesIncompleteMixedAndUnknownFields(t *testing.T) {
	for _, body := range []string{
		strings.Replace(observationBasisJSON, `"observation"`, `"unknown"`, 1),
		strings.Replace(observationBasisJSON, `"anchor":"AP8B",`, ``, 1),
		strings.Replace(observationBasisJSON, `"anchor":"AP8B"`, `"anchor":""`, 1),
		strings.Replace(observationBasisJSON, `"anchor":"AP8B"`, `"anchor":null`, 1),
		strings.Replace(observationBasisJSON, `"anchor":"AP8B"`, `"anchor":"AP8B","anchor":"AP8B"`, 1),
		strings.Replace(observationBasisJSON, `"recipient_pages":["Bgc=","CA=="]`, `"recipient_pages":[]`, 1),
		strings.Replace(observationBasisJSON, `"recipient_pages":["Bgc=","CA=="]`, `"recipient_pages":[""]`, 1),
		strings.Replace(observationBasisJSON, `"recipient_pages":["Bgc=","CA=="]`, `"recipient_pages":[null]`, 1),
		strings.Replace(observationBasisJSON, `"kind":"observation"`, `"kind":"observation","descriptor":"AQ=="`, 1),
		strings.Replace(observationBasisJSON, `"kind":"observation"`, `"kind":"observation","enrollment":[]`, 1),
		strings.Replace(observationBasisJSON, `"root":"BQ=="`, `"root":"BQ==","foreign":"AQ=="`, 1),
		`{"kind":"genesis","descriptor":"AQ==","anchor":"AQ=="}`,
		`{"kind":"successor","control":"AQ==","selection":"AQ==","enrollment":[],"root":"AQ=="}`,
	} {
		p := newParser(context.Background(), strings.NewReader(body), JSON)
		var basis Basis
		parseBasis(p, &basis)
		if p.done() == nil {
			t.Fatal("invalid observation basis accepted")
		}
	}
}

// full_only: false
func TestObservationBasisIndependentDecodedBounds(t *testing.T) {
	maximum := Basis{SigningAnchor: make([]byte, 1613), StoreConfiguration: make([]byte, 4096), HEAD: make([]byte, 65536), Root: make([]byte, 262144)}
	for range 32 {
		maximum.RecipientPages = append(maximum.RecipientPages, make([]byte, 98304))
	}
	if contract.PublicSigningBindingMaxLength != 1613 || contract.MaxStoreConfigurationLength != 4096 || contract.MaxHeadLength != 65536 || contract.MaxRootLength != 262144 || contract.MaxRecipientPages != 32 || contract.MaxRecipientPageLength != 98304 {
		t.Fatal("observation owner bounds differ from independent contract values")
	}
	body, err := generatedBasisBytes(maximum)
	if err != nil {
		t.Fatal("exact independent limits refused", err)
	}
	p := newParser(context.Background(), bytes.NewReader(body), JSON)
	var decoded Basis
	parseBasis(p, &decoded)
	if p.done() != nil || !reflect.DeepEqual(decoded, maximum) {
		t.Fatal("exact independent owner limits did not round trip", p.err)
	}
	for _, field := range []string{"anchor", "store_configuration", "head", "root", "recipient_pages"} {
		t.Run(field, func(t *testing.T) {
			basis := observationBasisFixture()
			var excessive []byte
			switch field {
			case "anchor":
				excessive = make([]byte, 1614)
				basis.SigningAnchor = excessive
			case "store_configuration":
				excessive = make([]byte, 4097)
				basis.StoreConfiguration = excessive
			case "head":
				excessive = make([]byte, 65537)
				basis.HEAD = excessive
			case "root":
				excessive = make([]byte, 262145)
				basis.Root = excessive
			case "recipient_pages":
				excessive = make([]byte, 98305)
				basis.RecipientPages = [][]byte{excessive}
			}
			if _, err := generatedBasisBytes(basis); err == nil {
				t.Fatal("emitter accepted first excess")
			}
			literal := `{"kind":"observation","anchor":"AQ==","store_configuration":"AQ==","head":"AQ==","root":"AQ==","recipient_pages":["AQ=="]}`
			value := `"` + base64.StdEncoding.EncodeToString(excessive) + `"`
			if field == "recipient_pages" {
				literal = strings.Replace(literal, `["AQ=="]`, `[`+value+`]`, 1)
			} else {
				literal = strings.Replace(literal, `"`+field+`":"AQ=="`, `"`+field+`":`+value, 1)
			}
			p := newParser(context.Background(), strings.NewReader(literal), JSON)
			var decoded Basis
			parseBasis(p, &decoded)
			if p.done() == nil {
				t.Fatal("parser accepted first excess")
			}
		})
	}
	t.Run("page count", func(t *testing.T) {
		basis := observationBasisFixture()
		basis.RecipientPages = make([][]byte, 33)
		for i := range basis.RecipientPages {
			basis.RecipientPages[i] = []byte{1}
		}
		if _, err := generatedBasisBytes(basis); err == nil {
			t.Fatal("emitter accepted 33rd page")
		}
		body := strings.Replace(observationBasisJSON, `["Bgc=","CA=="]`, `[`+strings.TrimSuffix(strings.Repeat(`"AQ==",`, 33), ",")+`]`, 1)
		p := newParser(context.Background(), strings.NewReader(body), JSON)
		var decoded Basis
		parseBasis(p, &decoded)
		if p.done() == nil || len(decoded.RecipientPages) > 32 {
			t.Fatal("parser retained excess recipient page")
		}
	})
}

// full_only: false
func TestMaintenanceKeepsObservationBytesAfterSourceBasisRelease(t *testing.T) {
	for _, encoding := range []Format{JSON, YAML} {
		original, request, material := maintenanceFileFixture(t, encoding, contract.OperationRetireRecipientIdentity)
		editable := maintenanceImageBytes(t, original.Editable)
		generated := bytes.Replace(maintenanceImageBytes(t, original.Generated), []byte(`{"kind":"genesis","descriptor":"AQ=="}`), []byte(observationBasisJSON), 1)
		pair := captureEditableEmission(t, editable, generated, encoding, ".enkv/prod.generated.json")
		path := filepath.Join(t.TempDir(), "successor")
		output, err := PrepareMaintenanceOutput(t.Context(), pair, path, request)
		if err != nil {
			t.Fatal(err)
		}
		defer closeSourceOwner(t, output)
		if !reflect.DeepEqual(output.model.Basis, Basis{}) || output.model.BasisSpan == 0 {
			t.Fatal("output retained decoded source proof or lost its edit span")
		}
		readback, err := output.Publish(t.Context(), material)
		if err != nil || !reflect.DeepEqual(readback.Model.Basis, observationBasisFixture()) || !bytes.Contains(maintenanceImageBytes(t, readback.Pair.Generated), []byte(observationBasisJSON)) {
			t.Fatal("maintenance changed preserved observation proof bytes", err)
		}
		if !bytes.Equal(maintenanceImageBytes(t, pair.Generated), generated) {
			t.Fatal("maintenance changed source proof bytes")
		}
		if err := output.Close(); err != nil {
			t.Fatal(err)
		}
		existing, err := PrepareMaintenanceOutput(t.Context(), pair, path, request)
		if err != nil {
			t.Fatal(err)
		}
		defer closeSourceOwner(t, existing)
		if existing.Existing() == nil || !reflect.DeepEqual(existing.Existing().Basis, observationBasisFixture()) {
			t.Fatal("existing output lost proof needed for later admission")
		}
	}
}
