package installedarchive

import (
	"encoding/hex"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestRecoveryLocationsKeepExactOwnedTargets(t *testing.T) {
	current, prior, object := contract.Hash([]byte("current")), contract.Hash([]byte("prior")), contract.Hash([]byte("object"))
	id := func(v contract.ID) string { return hex.EncodeToString(v[:]) }
	for _, row := range []struct {
		condition  string
		locations  RecoveryLocations
		target     string
		wantDomain contract.ID
		wantPrefix string
	}{
		{"new-domain-no-pin", RecoveryLocations{PriorDomain: prior}, "fixture/" + id(prior) + "/member/0/" + id(object), prior, "fixture"},
		{"copied-location", RecoveryLocations{CopiedPrefix: "fixture/copied"}, "fixture/copied/" + id(current) + "/configuration/" + id(object), current, "fixture/copied"},
	} {
		t.Run(row.condition, func(t *testing.T) {
			if !row.locations.Valid(row.condition, "fixture", current) {
				t.Fatal("exact setup facts refused")
			}
			prefix, domain, ok := row.locations.Target(contract.AWS, "fixture", current, row.target)
			if !ok || prefix != row.wantPrefix || domain != row.wantDomain {
				t.Fatal("recorded target refused")
			}
			for _, target := range []string{strings.Replace(row.target, id(row.wantDomain), id(contract.Hash([]byte("unknown"))), 1), "fixture-sibling/" + strings.TrimPrefix(row.target, "fixture/"), strings.Replace(row.target, "fixture/", "fixture/%2F/", 1), row.target + "/extra", strings.Replace(row.target, id(object), strings.ToUpper(id(object)), 1)} {
				if _, _, ok := row.locations.Target(contract.AWS, "fixture", current, target); ok {
					t.Fatal("forged target admitted")
				}
			}
			if row.locations.Valid("complete", "fixture", current) {
				t.Fatal("historical location admitted for unrelated case")
			}
		})
	}
	for _, facts := range []RecoveryLocations{{PriorDomain: current}, {PriorDomain: prior, CopiedPrefix: "fixture/copied"}, {CopiedPrefix: "fixture-sibling/copied"}, {CopiedPrefix: "fixture/%2Fcopied"}} {
		if facts.Valid("new-domain-no-pin", "fixture", current) || facts.Valid("copied-location", "fixture", current) {
			t.Fatal("forged setup facts admitted")
		}
		if _, _, ok := facts.Target(contract.AWS, "fixture", current, "fixture/HEAD"); ok {
			t.Fatal("forged setup facts admitted before target lookup")
		}
	}
}
