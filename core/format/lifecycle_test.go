package format

import (
	"bytes"
	"encoding/hex"
	"enkv.sh/core/contract"
	"testing"
)

// full_only: false
func TestLifecycleRequiresEveryFixedSection(t *testing.T) {
	_, _, subject := projectionFixture(t)
	body, err := contract.LifecycleBytes(subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []int{0, 19, 20, 21, 399, 415, 416, 545, 560, 561, 606, 625, 626} {
		broken := bytes.Clone(body)
		broken[at] ^= 1
		if _, err := DecodeLifecycleSubject(broken); err != ErrFormat {
			t.Fatalf("changed section tag at %d accepted: %v", at, err)
		}
	}
	for _, b := range [][]byte{body[:399], body[:545], body[:606], append(bytes.Clone(body), 0)} {
		if _, err := DecodeLifecycleSubject(b); err != ErrFormat {
			t.Fatal("incomplete or excessive lifecycle accepted", err)
		}
	}
}

func setMaximumLifecycle(s *contract.LifecycleSubject) {
	s.BeforeValueEntryCount, s.AfterValueEntryCount = 512, 512
	s.BeforeRawBytes, s.AfterRawBytes = 8<<20, 8<<20
	s.IdentityPlan.Length = 200962
	s.BeforeMembershipCount, s.AfterMembershipCount = 512, 512
	s.Normal.Intent.Length, s.Normal.PublicState.Length = 209115, 150671
	s.Normal.Union.Length, s.Normal.Union.Count, s.Normal.Changed = 370758, 1024, 1024
	s.Grant.Grants.Length, s.Grant.Grants.Count = 184381, 512
	s.Exclusion.Exclusions.Length, s.Exclusion.Exclusions.Count = 200769, 512
}

// Literal retired bytes remain independent of the active encoder.
func retiredVectors(t testing.TB) [][]byte {
	t.Helper()
	literals := []string{
		// HeadCore
		"454e4b56050001010100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000010000000822657461672d31220300010100000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000007b00000700000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000b00000000000000000000000000000000000000000000000000000000000000000000000000000c00000000",
		// ConditionalPlan
		"454e4b560600010100000003505554070000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000010000000822657461672d312289e3b0fd5b889e5d80ef69e94cb7399ee0eac8d740bc8ce30b43f64c2d9487bf000001aa",
		// Retired authority subject
		"454e4b562f4b322d4e4f524d414c2f76310014000000000000000000000000000000000000000000000000000000000000001500000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000017000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000000000000000000419000000000000000000000000000000000000000000000000000000000000000000000189e3b0fd5b889e5d80ef69e94cb7399ee0eac8d740bc8ce30b43f64c2d9487bf000001aa4cead1475fa054b370d238df2f04fa9fdc1e7c936ec0536e2af3b9a8f24d52fb",
	}
	var values [][]byte
	for _, literal := range literals {
		b, err := hex.DecodeString(literal)
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, b)
	}
	return values
}

// full_only: false
func TestRetiredInterpretationsRefuse(t *testing.T) {
	for _, b := range retiredVectors(t) {
		if _, err := DecodeHeadCore(b); err == nil {
			t.Fatal("retired core accepted")
		}
		if _, err := DecodeLifecycleSubject(b); err == nil {
			t.Fatal("retired subject accepted")
		}
		if _, err := DecodeHead(b); err == nil {
			t.Fatal("retired HEAD accepted")
		}
	}
}

// full_only: false
func TestEveryRecordRefusesRetiredBinaryVersion(t *testing.T) {
	tests := []struct {
		name   string
		encode func() ([]byte, error)
		decode func([]byte) error
	}{
		{"member", func() ([]byte, error) { return EncodeValueEntryPage(valueEntryPageFixture()) }, func(b []byte) error { _, err := DecodeValueEntryPage(b); return err }},
		{"recipient", func() ([]byte, error) { return EncodeRecipientPage(recipientFixture(t)) }, func(b []byte) error { _, err := DecodeRecipientPage(b); return err }},
		{"root", func() ([]byte, error) { return EncodeRoot(rootFixture(t)) }, func(b []byte) error { _, err := DecodeRoot(b); return err }},
		{"head core", func() ([]byte, error) { return EncodeHeadCore(headFixture(t).Core) }, func(b []byte) error { _, err := DecodeHeadCore(b); return err }},
		{"head", func() ([]byte, error) { return EncodeHead(headFixture(t)) }, func(b []byte) error { _, err := DecodeHead(b); return err }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := tc.encode()
			if err != nil {
				t.Fatal(err)
			}
			version := byte(11)
			retiredVersions := []byte{1, 4, 6, 7, 8, 9, 10}
			if tc.name == "head" {
				version = 12
				retiredVersions = append(retiredVersions, 11)
			}
			if body[5] != 0 || body[6] != version {
				t.Fatal("current version differs")
			}
			for _, retired := range retiredVersions {
				body[6] = retired
				if err := tc.decode(body); err != ErrFormat {
					t.Fatalf("retired binary version %d accepted: %v", retired, err)
				}
			}
		})
	}
}
