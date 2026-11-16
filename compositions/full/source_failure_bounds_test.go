package compositionfull

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func sourceFailureComparisonFixture(t testing.TB) ConfigurationComparisonResult {
	t.Helper()
	r, err := NewComparisonRefusal(configuration.YAML)
	if err != nil {
		t.Fatal(err)
	}
	r.PreAdmission.Stage = "parse"
	r.SourceFailure = &ConfigurationSourceFailure{SourceID: "source", Path: "/" + strings.Repeat("\x01", 4095), Field: "schema", Reason: "unsupported-schema", Line: 1, Column: 1, Precision: "exact"}
	return r
}

// full_only: false
func TestSourceFailurePathBoundsAndOperationRelations(t *testing.T) {
	base := sourceFailureComparisonFixture(t)
	for _, human := range []bool{false, true} {
		var body []byte
		var err error
		if human {
			body, err = RenderComparisonHuman(base)
		} else {
			body, err = RenderComparisonJSON(base)
		}
		if err != nil || len(body) > 65536 {
			t.Fatal("maximum escaped source path exceeded its unchanged branch account", err, len(body))
		}
	}
	for _, path := range []string{"/" + strings.Repeat("x", 4096), "/", "relative", "/tmp/../source", "/tmp/\x00source", "/tmp/\xff"} {
		r := base
		f := *base.SourceFailure
		f.Path = path
		r.SourceFailure = &f
		for _, render := range []func(ConfigurationComparisonResult) ([]byte, error){RenderComparisonJSON, RenderComparisonHuman} {
			if body, err := render(r); err == nil || body != nil {
				t.Fatal("invalid or one-over source path reached output")
			}
		}
	}
	for _, fact := range []string{"commit", "evidence", "requested", "observed", "snapshot", "before-label", "generated-row"} {
		t.Run(fact, func(t *testing.T) {
			r := sourceFailureComparisonFixture(t)
			switch fact {
			case "commit":
				r.Result.CommitMayHaveOccurred = true
			case "evidence":
				r.Result.Evidence = core.AuthenticatedClosure
			case "requested":
				r.Result.RequestedRevision = contract.ID{1}
			case "observed":
				r.Result.ObservedRevision = contract.ID{1}
			case "snapshot":
				r.Result.ObservedSnapshotID = contract.ID{1}
			case "before-label":
				r.BeforeRecipients = []contract.ComparisonRecipientLabel{{RecipientID: contract.ID{1}}}
			case "generated-row":
				r.GeneratedEntries = []contract.GeneratedPlanningEntry{{Name: "entry"}}
			}
			for _, render := range []func(ConfigurationComparisonResult) ([]byte, error){RenderComparisonJSON, RenderComparisonHuman} {
				if body, err := render(r); err == nil || body != nil {
					t.Fatal("source refusal accepted incompatible operation facts")
				}
			}
			planning := configurationPlanningResult(r)
			for _, render := range []func(ConfigurationPlanningResult) ([]byte, error){RenderPlanningJSON, RenderPlanningHuman} {
				if body, err := render(planning); err == nil || body != nil {
					t.Fatal("private planning accepted incompatible source-refusal facts")
				}
			}
		})
	}
}

// full_only: false
func TestSourceFailureFitsPrepareAndManifestFieldAccounts(t *testing.T) {
	f := sourceFailureComparisonFixture(t).SourceFailure
	prepare, err := NewPrepareRefusal()
	if err != nil {
		t.Fatal(err)
	}
	prepare.facts.SourceFailure = f
	prepare.facts.Diagnostics = []prepareDiagnostic{{Subject: "source", Reason: "source-invalid"}}
	for _, render := range []func(*PrepareResult) ([]byte, error){RenderPrepareJSON, RenderPrepareHuman} {
		if body, err := render(prepare); err != nil || len(body) > 65536 {
			t.Fatal("maximum source singleton failed prepare branch", err, len(body))
		}
	}
	issuance, err := NewManifestRefusal(configuration.YAML)
	if err != nil {
		t.Fatal(err)
	}
	issuance.PreAdmission.Stage = "parse"
	manifest := NewManifestFileResult(issuance)
	manifest.SourceFailure = f
	manifest.Delivery.TargetPath = "/" + strings.Repeat("\x02", 4095)
	for _, render := range []func(ManifestFileResult) ([]byte, error){RenderManifestFileJSON, RenderManifestFileHuman} {
		if body, err := render(manifest); err != nil || len(body) > 65536 {
			t.Fatal("maximum source and requested target paths failed manifest branch", err, len(body))
		}
	}
	bad := *f
	bad.Path += "x"
	prepare.facts.SourceFailure = &bad
	manifest.SourceFailure = &bad
	if body, err := RenderPrepareJSON(prepare); err == nil || body != nil {
		t.Fatal("prepare accepted one-over path")
	}
	if body, err := RenderManifestFileJSON(manifest); err == nil || body != nil {
		t.Fatal("manifest accepted one-over path")
	}
}

// full_only: false
func TestSourceRefusalCannotClaimGCArtifactDelivery(t *testing.T) {
	for _, flag := range []string{"created", "synced", "readback"} {
		t.Run(flag, func(t *testing.T) {
			r, err := NewGCPlanRefusal(configuration.YAML)
			if err != nil {
				t.Fatal(err)
			}
			r.Operation.PreAdmission.Stage = "parse"
			r.SourceFailure = sourceFailureComparisonFixture(t).SourceFailure
			var valid bytes.Buffer
			if err := WriteGCPlanJSON(t.Context(), &valid, r); err != nil {
				t.Fatal("valid source-only GC fixture refused", err)
			}
			switch flag {
			case "created":
				r.Delivery.PlanCreated = true
			case "synced":
				r.Delivery.PlanCreated, r.Delivery.PlanSynced = true, true
			case "readback":
				r.Delivery.PlanCreated, r.Delivery.PlanSynced, r.Delivery.PlanReadback = true, true, true
			}
			for _, human := range []bool{false, true} {
				var out bytes.Buffer
				var err error
				if human {
					err = WriteGCPlanHuman(t.Context(), &out, r)
				} else {
					err = WriteGCPlanJSON(t.Context(), &out, r)
				}
				if err == nil || out.Len() != 0 {
					t.Fatal("source refusal claimed plan delivery", err)
				}
			}
		})
	}
}

// full_only: false
func TestInitializationSourceRefusalRetainsIndependentLocalDelivery(t *testing.T) {
	r, err := NewInitializationRefusal(configuration.YAML)
	if err != nil {
		t.Fatal(err)
	}
	r.PreAdmission.Stage = "parse"
	r.EditablePath, r.GeneratedPath, r.DeliveryAttempted = "/tmp/editable.yaml", "/tmp/.enkv/domain.generated.json", true
	cause := &configuration.Diagnostic{Field: "domain", Reason: "missing-required-field"}
	body, err := RenderInitializationJSON(r, cause)
	var wire struct {
		Delivery struct {
			Outcome string `json:"outcome"`
			Path    string `json:"editable_path"`
		} `json:"local_delivery"`
	}
	if err != nil || json.Unmarshal(body, &wire) != nil || wire.Delivery.Outcome != "failed" || wire.Delivery.Path != r.EditablePath {
		t.Fatal("source refusal erased independently attempted local delivery", err)
	}
	r.ManifestPath = "/tmp/init.manifest"
	if body, err := RenderInitializationJSON(r, cause); err == nil || body != nil {
		t.Fatal("source refusal accepted an initialization manifest")
	}
}
