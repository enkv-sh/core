package core

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

// full_only: true
func TestReaderPublicBasisMaximumBacking(t *testing.T) {
	// These are native input records. Their arbitrary binary bodies establish
	// parsing and ownership only, not a trusted descriptor, control or HEAD.
	const basisJSON = 5592920
	const decodedAllowance = 11939958
	if localBasisLimit != basisJSON || contract.GenesisDescriptorLimit != 4194304 || contract.ControlCoreMaxLength != 6697 || contract.MaxHeadLength != 65536 {
		t.Fatal("native encoded-input account changed")
	}
	t.Run("descriptor", func(t *testing.T) {
		for _, size := range []int{4194304, 4194305} {
			body := make([]byte, size)
			for i := range body {
				body[i] = byte(i)
			}
			record := []byte(`{"schema":3,"kind":"genesis","descriptor":"` + base64.StdEncoding.EncodeToString(body) + `"}`)
			path := localAdmissionPath(t, fmt.Sprintf("descriptor-%d", size), record)
			got, err := readLocalReaderPublicBasis(path)
			if size > 4194304 {
				if err == nil || !reflect.DeepEqual(got, localBasisImage{}) {
					t.Fatal("one-over descriptor returned a partial basis")
				}
				continue
			}
			if err != nil || len(got.Descriptor) != size || cap(got.Descriptor) != size || !bytes.Equal(got.Descriptor, body) {
				t.Fatal("maximum descriptor bytes or exact decoded backing", err)
			}
			if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Descriptor, body) {
				t.Fatal("decoded descriptor borrows the protected file")
			}
		}
	})
	t.Run("encoded-file-account", func(t *testing.T) {
		basis := []byte(`{"schema":3,"kind":"genesis","descriptor":"AQ=="}`)
		basis = append(basis, bytes.Repeat([]byte{' '}, basisJSON-len(basis))...)
		basisPath := localAdmissionPath(t, "basis-file-account", basis)
		basisOwner, err := readLocalProtected(basisPath, localBasisLimit)
		if err != nil || len(basisOwner) != basisJSON || cap(basisOwner) != basisJSON {
			t.Fatal("basis file backing", err)
		}
		if _, err := readLocalReaderPublicBasis(basisPath); err != nil {
			t.Fatal("legal whitespace at the basis file ceiling", err)
		}
		if err := os.WriteFile(basisPath, append(basis, ' '), 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := readLocalReaderPublicBasis(basisPath); err == nil || !reflect.DeepEqual(got, localBasisImage{}) {
			t.Fatal("one-over basis file accepted")
		}
		if !bytes.Equal(basisOwner, basis) {
			t.Fatal("file replacement changed a returned exact file owner")
		}
	})
	t.Run("joint-successor", func(t *testing.T) {
		control, head := bytes.Repeat([]byte{17}, 6697), bytes.Repeat([]byte{23}, 65536)
		var record strings.Builder
		fmt.Fprintf(&record, `{"schema":3,"kind":"successor","control":%q,"selection":%q,"enrollment":[`, base64.StdEncoding.EncodeToString(control), base64.StdEncoding.EncodeToString(head))
		for row := range 256 {
			if row != 0 {
				record.WriteByte(',')
			}
			// Escaping every name byte also exercises the declared JSON expansion.
			fmt.Fprintf(&record, `{"id":"%064x","status":"current","display_name":"%s"}`, row+1, strings.Repeat(`\u006e`, 256))
		}

		record.WriteString(`]}`)
		path := localAdmissionPath(t, "joint-successor", []byte(record.String()))
		got, err := readLocalReaderPublicBasis(path)
		if err != nil || !bytes.Equal(got.Control, control) || !bytes.Equal(got.Selection, head) || cap(got.Control) != 6697 || cap(got.Selection) != 65536 || len(got.Enrollment) != 256 || cap(got.Enrollment) != 256 {
			t.Fatal("joint maximum successor input", err)
		}
		if unsafe.Sizeof(localEnrollmentImage{}) != 40 || unsafe.Sizeof("") != 16 {
			t.Fatal("decoded account requires the declared 64-bit layout")
		}
		backing := cap(got.Control) + cap(got.Selection) + cap(got.Enrollment)*40
		for row, enrollment := range got.Enrollment {
			if enrollment.ID != fmt.Sprintf("%064x", row+1) || enrollment.Name != strings.Repeat("n", 256) || enrollment.Status != 1 {
				t.Fatalf("enrollment row %d changed", row)
			}
			backing += len(enrollment.ID) + len(enrollment.Name)
		}
		if backing != 164393 {
			t.Fatalf("decoded successor collection/body backing=%d want=164393", backing)
		}
		// Include the fixed image and kind, and conservatively retain the complete
		// public-basis record. No retired connection owner is charged.
		backing += int(unsafe.Sizeof(got)) + len(got.Kind)
		if backing > decodedAllowance {
			t.Fatalf("decoded native account=%d ceiling=%d", backing, decodedAllowance)
		}
		if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Control, control) || !bytes.Equal(got.Selection, head) || got.Enrollment[255].ID != fmt.Sprintf("%064x", 256) {
			t.Fatal("decoded successor borrows replaced file storage")
		}
	})
}
