package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

const readerInputID = "0101010101010101010101010101010101010101010101010101010101010101"

// full_only: false
func TestReaderPublicBasisClosedGrammarAndBounds(t *testing.T) {
	genesis := `{"schema":3,"kind":"genesis","descriptor":"AAEC/w=="}`
	successor := `{"schema":3,"kind":"successor","control":"AQ==","selection":"Ag==","enrollment":[{"id":"` + readerInputID + `","status":"current","display_name":"name"}]}`
	for _, body := range []string{genesis, successor, strings.Replace(genesis, `AAEC/w==`, `\u0041AEC\/w==`, 1)} {
		got, err := readLocalReaderPublicBasis(localAdmissionPath(t, "basis", []byte(body)))
		if err != nil {
			t.Fatal("valid basis refused", err)
		}
		if got.Kind == "genesis" && (!bytes.Equal(got.Descriptor, []byte{0, 1, 2, 255}) || cap(got.Descriptor) != len(got.Descriptor)) {
			t.Fatalf("base64 bytes: %x", got.Descriptor)
		}
		if got.Kind == "successor" && (!bytes.Equal(got.Control, []byte{1}) || !bytes.Equal(got.Selection, []byte{2}) || len(got.Enrollment) != 1 || got.Enrollment[0].Status != 1) {
			t.Fatal("successor meaning changed")
		}
	}
	onePad, err := readLocalReaderPublicBasis(localAdmissionPath(t, "one-padding", []byte(strings.Replace(genesis, `AAEC/w==`, `AQI=`, 1))))
	if err != nil || !bytes.Equal(onePad.Descriptor, []byte{1, 2}) || cap(onePad.Descriptor) != 2 {
		t.Fatal("one padding binary meaning", err)
	}
	cases := map[string]string{
		"one padding unused bits": strings.Replace(genesis, `AAEC/w==`, `AQJ=`, 1),
		"missing descriptor":      `{"schema":3,"kind":"genesis"}`,
		"empty descriptor":        strings.Replace(genesis, `AAEC/w==`, ``, 1),
		"null descriptor":         strings.Replace(genesis, `"AAEC/w=="`, `null`, 1),
		"unpadded":                strings.Replace(genesis, `AAEC/w==`, `AAEC/w`, 1),
		"pad bits":                strings.Replace(genesis, `AAEC/w==`, `AAEC/x==`, 1),
		"newline":                 strings.Replace(genesis, `AAEC/w==`, `AAEC/\nw==`, 1),
		"unknown field":           strings.Replace(genesis, `"schema":3`, `"schema":3,"other":true`, 1),
		"duplicate escaped key":   strings.Replace(genesis, `"schema":3`, `"schema":3,"\u0073chema":1`, 1),
		"wrong case":              strings.Replace(genesis, `"descriptor":`, `"Descriptor":`, 1),
		"branch overlap":          strings.Replace(genesis, `"schema":3`, `"schema":3,"control":"AQ=="`, 1),
		"missing enrollment":      strings.Replace(successor, `,"enrollment":[{"id":"`+readerInputID+`","status":"current","display_name":"name"}]`, ``, 1),
		"empty enrollment":        strings.Replace(successor, `[{"id":"`+readerInputID+`","status":"current","display_name":"name"}]`, `[]`, 1),
		"obsolete caller field":   strings.Replace(successor, `"display_name":"name"`, `"display_name":"name","callers":[]`, 1),
		"bad status":              strings.Replace(successor, `"status":"current"`, `"status":"unknown"`, 1),
		"name overflow":           strings.Replace(successor, `"display_name":"name"`, `"display_name":"`+strings.Repeat("n", 257)+`"`, 1),
		"unpaired name":           strings.Replace(successor, `"display_name":"name"`, `"display_name":"\udc00"`, 1),
		"missing row field":       strings.Replace(successor, `,"display_name":"name"`, ``, 1),
		"old basis schema":        strings.Replace(successor, `"schema":3`, `"schema":1`, 1),

		"trailing": genesis + ` true`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := readLocalReaderPublicBasis(localAdmissionPath(t, "basis", []byte(body))); err == nil || !reflect.DeepEqual(got, localBasisImage{}) {
				t.Fatal("invalid basis accepted or partial result returned", err)
			}
		})
	}
	atBounds := strings.Replace(successor, `"display_name":"name"`, `"display_name":"`+strings.Repeat("é", 128)+`"`, 1)
	bounded, err := readLocalReaderPublicBasis(localAdmissionPath(t, "basis", []byte(atBounds)))
	if err != nil || len(bounded.Enrollment) != 1 || len(bounded.Enrollment[0].Name) != 256 {
		t.Fatal("exact name boundary refused", err)
	}
	row := `{"id":"` + readerInputID + `","status":"current","display_name":"name"}`
	var rows []string
	for i := 1; i <= 257; i++ {
		rows = append(rows, fmt.Sprintf(`{"id":"%064x","status":"retired","display_name":""}`, i))
	}
	atRecipientBound := strings.Replace(successor, "["+row+"]", "["+strings.Join(rows[:256], ",")+"]", 1)
	if got, err := readLocalReaderPublicBasis(localAdmissionPath(t, "basis", []byte(atRecipientBound))); err != nil || len(got.Enrollment) != 256 {
		t.Fatal("exact enrollment count refused", err)
	}
	for name, rows := range map[string]string{
		"duplicate enrollment":      row + "," + row,
		"enrollment count overflow": strings.Join(rows, ","),
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(successor, "["+row+"]", "["+rows+"]", 1)
			if _, err := readLocalReaderPublicBasis(localAdmissionPath(t, "basis", []byte(body))); err == nil {
				t.Fatal("invalid enrollment accepted")
			}
		})
	}
	// Exercise the per-field limit without a maximum descriptor fixture.
	control := strings.Repeat("AAAA", 2232) + "AA==" // 6,697 zero bytes.
	boundedControl := strings.Replace(successor, `"control":"AQ=="`, `"control":"`+control+`"`, 1)
	if got, err := readLocalReaderPublicBasis(localAdmissionPath(t, "basis", []byte(boundedControl))); err != nil || len(got.Control) != 6697 {
		t.Fatal("exact control byte bound refused", err)
	}
	control = strings.Repeat("AAAA", 2232) + "AAA=" // 6,698 zero bytes.
	body := strings.Replace(successor, `"control":"AQ=="`, `"control":"`+control+`"`, 1)
	if _, err := readLocalReaderPublicBasis(localAdmissionPath(t, "basis", []byte(body))); err == nil {
		t.Fatal("control decoded-byte overflow accepted")
	}
}

// full_only: false
func TestReaderAcceptsSharedPublicBasisWriter(t *testing.T) {
	for _, image := range []localBasisImage{
		{Schema: 3, Kind: "genesis", Descriptor: []byte{1}},
		{Schema: 3, Kind: "successor", Control: []byte{1}, Selection: []byte{2}, Enrollment: []localEnrollmentImage{{ID: readerInputID, Status: 1, Name: ""}}},
	} {
		body, err := json.Marshal(image)
		if err != nil {
			t.Fatal(err)
		}
		got, err := readLocalReaderPublicBasis(localAdmissionPath(t, "shared-basis", body))
		if err != nil || !reflect.DeepEqual(got, image) {
			t.Fatal("shared public basis writer is incompatible", image.Kind, err)
		}
	}
	b := &qualifiedCurrentBasis{issued: true, control: []byte{1}, selection: []byte{2}, enrollment: []recipientEnrollment{{id: contract.ID{1}, status: 1}}}
	image, err := testSuccessorPublicBasisImage(b)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(image)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalReaderPublicBasis(localAdmissionPath(t, "native-successor-basis", body)); err != nil {
		t.Fatal("native successor basis refused", err)
	}

}

func testSuccessorPublicBasisImage(b *qualifiedCurrentBasis) (localBasisImage, error) {
	if b == nil || !b.issued {
		return localBasisImage{}, ErrLocalAuthorityAdmission
	}
	identifier := func(id contract.ID) string { return hex.EncodeToString(id[:]) }
	image := localBasisImage{Schema: 3, Kind: "successor", Control: bytes.Clone(b.control),
		Selection: bytes.Clone(b.selection)}
	for _, row := range b.enrollment {
		image.Enrollment = append(image.Enrollment, localEnrollmentImage{ID: identifier(row.id), Status: row.status, Name: row.name})
	}
	if _, err := localEnrollment(image.Enrollment); err != nil {
		return localBasisImage{}, err
	}
	return image, nil
}

// full_only: false
func TestReaderStandaloneSuccessorUsesSharedEnrollmentGrammar(t *testing.T) {
	current := `{"schema":3,"kind":"successor","control":"AQ==","selection":"Ag==","enrollment":[{"id":"` + readerInputID + `","status":"current","display_name":"recipient"}]}`
	for _, tc := range []struct {
		status string
		want   uint8
	}{{"current", contract.CurrentRecipient}, {"retired", contract.RetiredRecipient}} {
		t.Run(tc.status, func(t *testing.T) {
			body := strings.Replace(current, `"status":"current"`, `"status":"`+tc.status+`"`, 1)
			got, err := readLocalReaderPublicBasis(localAdmissionPath(t, "successor-enrollment", []byte(body)))
			if err != nil || len(got.Enrollment) != 1 || got.Enrollment[0].Status != tc.want || got.Enrollment[0].Name != "recipient" {
				t.Fatal("shared successor enrollment grammar refused", err)
			}
		})
	}
	for _, body := range []string{
		strings.Replace(current, `"display_name":"recipient"`, `"name":"recipient"`, 1),
		strings.Replace(current, `"status":"current"`, `"status":1`, 1),
		strings.Replace(strings.Replace(current, `"display_name":"recipient"`, `"name":"recipient"`, 1), `"status":"current"`, `"status":1`, 1),
	} {
		if got, err := readLocalReaderPublicBasis(localAdmissionPath(t, "obsolete-enrollment", []byte(body))); err == nil || !reflect.DeepEqual(got, localBasisImage{}) {
			t.Fatal("obsolete standalone enrollment grammar accepted", err)
		}
	}
}
