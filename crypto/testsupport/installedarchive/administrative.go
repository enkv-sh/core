package installedarchive

import (
	"bytes"
	"embed"
	"encoding/json"
	"testing"

	"enkv.sh/core/contract"
)

// AdministrativeFixture contains only independently exported public state.
// Before owns selected work; After owns its real retained EndWork receipt.
type AdministrativeFixture struct {
	Before, After        RecoveryFixture
	Basis                []byte
	GroupID, OperationID contract.ID
	PreviewIdentity      contract.ID
	Receipt              []byte
}

//go:embed testdata/admin-aws.json testdata/admin-gcp.json
var administrativeArchives embed.FS

func LoadAdministrative(t testing.TB, family string) AdministrativeFixture {
	t.Helper()
	if family != "aws" && family != "gcp" {
		t.Fatal("unknown administrative archive")
	}
	body, err := administrativeArchives.ReadFile("testdata/admin-" + family + ".json")
	if err != nil {
		t.Fatal("administrative archive unavailable")
	}
	var out AdministrativeFixture
	if err := json.Unmarshal(body, &out); err != nil || out.GroupID.IsZero() || out.OperationID.IsZero() || out.PreviewIdentity.IsZero() || len(out.Basis) == 0 {
		t.Fatal("administrative archive facts refused", err)
	}
	for _, fixture := range []*RecoveryFixture{&out.Before, &out.After} {
		encoded, err := json.Marshal(fixture)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeRecoveryFixture(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal("administrative archive state refused", err)
		}
		// Token is not a JSON field. Keep the validated fixture whose objects
		// own the decoded TokenWire values required by native GET responses.
		*fixture = decoded
	}
	receipt, err := contract.InspectCompactMutationReceipt(out.Receipt)
	if err != nil || receipt.OperationKind != contract.OperationEndSelectedWork || receipt.OperationID != out.OperationID || receipt.AdministrativeGroupID != out.GroupID || out.Before.Archive.Family != out.After.Archive.Family || out.Before.Archive.Domain != out.After.Archive.Domain || out.Before.Archive.Location != out.After.Archive.Location || out.After.Archive.Revision == out.Before.Archive.Revision {
		t.Fatal("administrative archive receipt or state relation refused", err)
	}
	return out
}
