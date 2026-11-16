package contract

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"testing"
)

type valueAccessVector struct {
	Name, Schema, Hex string
	Accept            bool
	Value             json.RawMessage
}

func checkValueAccessVector[T any](t *testing.T, vector valueAccessVector, decode func([]byte) (T, error), encode func(T) ([]byte, error)) {
	t.Helper()
	wire, err := hex.DecodeString(vector.Hex)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decode(wire)
	if !vector.Accept {
		if err == nil {
			t.Fatal("invalid fixed wire image was accepted")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	var want T
	if err := json.Unmarshal(vector.Value, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("decoded fields differ from independent fields")
	}
	encoded, err := encode(want)
	if err != nil || !bytes.Equal(encoded, wire) {
		t.Fatal("encoded fields differ from independent wire image")
	}
	for n := 0; n < len(wire); n++ {
		if _, err := decode(wire[:n]); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
	if _, err := decode(append(bytes.Clone(wire), 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
	clear(wire)
	owned, err := encode(got)
	if err != nil || !bytes.Equal(owned, encoded) {
		t.Fatal("decoded fields retain caller-owned wire bytes")
	}
}

func checkUnassignedWrapSubjects[T any](t *testing.T, vector valueAccessVector, offset int, decode func([]byte) (T, error), encode func(T) ([]byte, error), changeSubject func(T, uint8) T) {
	t.Helper()
	if !vector.Accept {
		return
	}
	wire, err := hex.DecodeString(vector.Hex)
	if err != nil || offset >= len(wire) {
		t.Fatal("invalid independent subject offset", err)
	}
	for _, subject := range []uint8{0, 3, 255} {
		t.Run("subject_"+strconv.Itoa(int(subject)), func(t *testing.T) {
			bad := bytes.Clone(wire)
			bad[offset] = subject
			if _, err := decode(bad); err != ErrRecord {
				t.Fatal("unassigned wire subject refusal", err)
			}
			var fields T
			if err := json.Unmarshal(vector.Value, &fields); err != nil {
				t.Fatal(err)
			}
			encoded, err := encode(changeSubject(fields, subject))
			if err != ErrRecord || encoded != nil {
				t.Fatal("unassigned field subject refusal", err)
			}
		})
	}
}

// full_only: false
func TestValueAccessIndependentWireVectors(t *testing.T) {
	data, err := os.ReadFile("../../tests/shared/testdata/value-access-wire-schema11.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []valueAccessVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("empty wire fixture")
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			switch vector.Schema {
			case "ValueCore":
				checkValueAccessVector(t, vector, DecodeValueCore, EncodeValueCore)
			case "CanonicalPayload":
				checkValueAccessVector(t, vector, DecodeCanonicalPayload, EncodeCanonicalPayload)
			case "Member":
				checkValueAccessVector(t, vector, DecodeValueEntry, EncodeValueEntry)
			case "WrapCore":
				checkValueAccessVector(t, vector, DecodeWrapCore, EncodeWrapCore)
				// Schema/profile, three IDs, material kind and two IDs precede the subject.
				checkUnassignedWrapSubjects(t, vector, 166, DecodeWrapCore, EncodeWrapCore, func(v WrapCore, subject uint8) WrapCore {
					v.SubjectKind = subject
					return v
				})
			case "WrapRow":
				checkValueAccessVector(t, vector, DecodeWrapRow, EncodeWrapRow)
				checkUnassignedWrapSubjects(t, vector, 0, DecodeWrapRow, EncodeWrapRow, func(v WrapRow, subject uint8) WrapRow {
					v.SubjectKind = subject
					return v
				})
			case "AccessRecord":
				checkValueAccessVector(t, vector, DecodeAccessRecord, EncodeAccessRecord)
				// Schema/material kind, three IDs and wrap count precede the first wrap.
				checkUnassignedWrapSubjects(t, vector, 102, DecodeAccessRecord, EncodeAccessRecord, func(v AccessRecord, subject uint8) AccessRecord {
					v.Wraps[0].SubjectKind = subject
					return v
				})
			default:
				t.Fatal("unknown wire schema")
			}
		})
	}
}
