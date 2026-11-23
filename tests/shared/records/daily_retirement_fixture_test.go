package records

import (
	"encoding/json"
	"reflect"
	"testing"
)

// full_only: false
func TestDailyRetirementFixtureRetainsExactBrowserRolePrefix(t *testing.T) {
	good := StockPluginFixture{Schema: 1, Purpose: StockRetirementProofPurpose, FixtureID: "0123456789abcdef0123456789abcdef",
		Provider: "aws", Account: "123456789012", Region: "ap-southeast-2",
		Bucket: "enkv-123456789012-pa-0123456789abcdef0123456789abcdef", DailyRolePrefix: "enkv-orders-r01-public"}
	if good.Validate() != nil {
		t.Fatal("daily versioned fixture refused")
	}
	body, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	var retained StockPluginFixture
	if json.Unmarshal(body, &retained) != nil || !reflect.DeepEqual(retained, good) {
		t.Fatal("retained fixture lost its browser authentication binding")
	}
	for _, prefix := range []string{"enkv-orders-r01-public*", "enkv-orders-R01-public", "enkv-orders-1-public", "enkv-orders-abcdefghijklmn-public", "enkv-other-r01-public"} {
		bad := good
		bad.DailyRolePrefix = prefix
		if bad.Validate() == nil {
			t.Fatal("invalid daily role prefix accepted", prefix)
		}
	}
	for _, purpose := range []string{"stock-plugin-acceptance", "other"} {
		bad := good
		bad.Purpose = purpose
		if bad.Validate() == nil {
			t.Fatal("daily authentication admitted outside retirement proof")
		}
	}
	bad := stockFixtureLiteral("gcp")
	bad.DailyRolePrefix = good.DailyRolePrefix
	if bad.Validate() == nil {
		t.Fatal("daily AWS source admitted for GCP")
	}
	good.DailyRolePrefix = ""
	if good.Validate() != nil {
		t.Fatal("ordinary SSO retirement fixture refused")
	}
}
