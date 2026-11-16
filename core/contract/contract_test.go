package contract

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// full_only: false
func TestRetiredSigningPurposeRefuses(t *testing.T) {
	if (SignRequest{purpose: Purpose(2), digest: Hash([]byte("retired subject"))}).Valid() {
		t.Fatal("retired purpose 2 accepted")
	}
}

// full_only: false
func TestTokenValidation(t *testing.T) {
	for _, s := range []string{"", "0", "-1", "+1", "01", "9223372036854775808"} {
		if (Token{Family: GCP, Value: s}).Valid() || (TokenView{Family: GCP, Value: []byte(s)}).Valid() {
			t.Fatalf("accepted generation %q", s)
		}
	}
	if !(Token{Family: GCP, Value: "9223372036854775807"}).Valid() || !(TokenView{Family: GCP, Value: []byte("9223372036854775807")}).Valid() {
		t.Fatal("rejected maximum generation")
	}

	valid := []string{
		`""`,
		`"opaque-etag"`,
		`"a,b"`,
		`"*"`,
		string([]byte{'"', 0x21, 0x23, 0x7e, 0x80, 0xff, '"'}),
		`"` + strings.Repeat("a", maxTokenValue-2) + `"`,
	}
	for _, value := range valid {
		t.Run("valid", func(t *testing.T) {
			token := Token{Family: AWS, Value: value}
			view := TokenView{Family: AWS, Value: []byte(value)}
			if !token.Valid() || !view.Valid() {
				t.Fatalf("rejected strong ETag %q", value)
			}
			owned, err := view.Own()
			if err != nil || owned != token {
				t.Fatalf("owned token differs: %+v, %v", owned, err)
			}
			wire, err := AppendToken(nil, token)
			if err != nil {
				t.Fatal(err)
			}
			parsed, n, err := ParseToken(wire)
			if err != nil || n != len(wire) || parsed != token {
				t.Fatalf("wire token differs: %+v, %d, %v", parsed, n, err)
			}
		})
	}

	invalid := []string{
		"",
		"*",
		"bare",
		`W/"weak"`,
		`"one", "two"`,
		` "outer"`,
		`"outer" `,
		"\t\"outer\"",
		"\"outer\"\t",
		`"has space"`,
		"\"has\tcontrol\"",
		"\"has\x00control\"",
		"\"has\x7fdelete\"",
		`"has"quote"`,
		`"unterminated`,
		`"` + strings.Repeat("a", maxTokenValue-1) + `"`,
	}
	for _, value := range invalid {
		t.Run("invalid", func(t *testing.T) {
			if (Token{Family: AWS, Value: value}).Valid() || (TokenView{Family: AWS, Value: []byte(value)}).Valid() {
				t.Fatalf("accepted invalid strong ETag %q", value)
			}
			wire := make([]byte, 5+len(value))
			wire[0] = byte(AWS)
			binary.BigEndian.PutUint32(wire[1:5], uint32(len(value)))
			copy(wire[5:], value)
			if _, _, err := ParseToken(wire); err == nil {
				t.Fatalf("parsed invalid strong ETag %q", value)
			}
		})
	}
}

// full_only: false
func TestClosedSigningSubjects(t *testing.T) {
	id := Hash([]byte("id"))
	b := BindingSubject{Domain: id, Coordinate: id, Store: id, Trust: id, PublicKey: id, Interpretation: id, ControlIncarnationID: id, Epoch: 1}
	r, err := NewBindingRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	n := lifecycleFixture()
	s, err := NewLifecycleRequest(n)
	if err != nil {
		t.Fatal(err)
	}
	if r.Digest() == s.Digest() || r.Purpose() == s.Purpose() {
		t.Fatal("signing purposes collapsed")
	}
	if _, err := NewLifecycleRequest(LifecycleSubject{}); err == nil {
		t.Fatal("accepted empty subject")
	}
	if (SignRequest{}).Valid() {
		t.Fatal("zero request became signing authority")
	}
}

// full_only: false
func TestSigningRolePolicyCommitsAllAllowedPurposes(t *testing.T) {
	// These finite sets come from the Product purpose contracts. In particular,
	// normal generation, EndWork, publication and GC purposes are not optional.
	for role := uint8(0); role < 5; role++ {
		for purpose := 0; purpose < 256; purpose++ {
			want := false
			if role == 1 {
				want = purpose == 1 || purpose == 3 || purpose == 4 || purpose == 7 || purpose == 10 || purpose == 12 || purpose == 13 || purpose == 14 || purpose == 15 || purpose == 16 || purpose == 17
			}
			if role == 2 {
				want = purpose == 5 || purpose == 7 || purpose == 8 || purpose == 11 || purpose == 14
			}
			if SigningPurposeAllowed(role, Purpose(purpose)) != want {
				t.Fatalf("role=%d purpose=%d", role, purpose)
			}
		}
	}
	// SHA256 of the v9 domain, exact numeric purpose lists and the unchanged
	// finite support metadata. Derived with Python hashlib, not this owner.
	// The independent calculation reproduces the prior hash before adding
	// normal purpose 17. Recovery retains its exact finite purpose list.
	decoded, err := hex.DecodeString("7277bcc1bc65d1b2222d6706ffc8152114d61664a8e000abd7465ca21d5c4577")
	if err != nil {
		t.Fatal(err)
	}
	var want ID
	copy(want[:], decoded)
	if TrustInterpretationID() != want {
		t.Fatalf("trust interpretation=%x want=%x", TrustInterpretationID(), want)
	}
}
