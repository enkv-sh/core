package compositionfull

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/installedarchive"
	testtrust "enkv.sh/crypto/testsupport/trust"
	gcpprovider "enkv.sh/providers/gcp"
)

func administrativeHTTPObjects(a installedarchive.Archive) []testtrust.AdministrativeReadObject {
	out := make([]testtrust.AdministrativeReadObject, len(a.Objects))
	for i, o := range a.Objects {
		out[i] = testtrust.AdministrativeReadObject{Key: o.Key, Token: o.Token, Body: bytes.Clone(o.Body)}
	}
	return out
}
func administrativeSourceCall(t *testing.T, path string, q AbandonmentRequest, transport *http.Transport) AbandonmentResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	nonce := contract.Hash([]byte(string(q.Operation) + path + q.ArtifactPath + time.Now().String()))
	return abandonConfigurationFile(ctx, nonce, path, configuration.JSON, q, func(ctx context.Context, m *configuration.Model, s abandonmentSource, mutation bool) (abandonmentResources, error) {
		return nativeAbandonmentResources(ctx, m, s, mutation, transport, func(ctx context.Context, m *configuration.Model, s abandonmentSource, mutation bool, transport *http.Transport, out abandonmentResources) (abandonmentResources, error) {
			if m.Provider == contract.GCP {
				return openGCPNativeAbandonmentResources(ctx, m, s, mutation, transport, out, gcpprovider.NewLocalResponderClient)
			}
			return openNativeAbandonmentResources(ctx, m, s, mutation, transport, out)
		})
	}, nativeAbandonPlanIO())
}

// full_only: false
func TestLocalAdministrativeAWSGCPReadsUseOnlyNativeGETConstruction(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			f := installedarchive.LoadAdministrative(t, family)
			dir := protectedConfigurationTestDirectory(t)
			path := WriteAdministrativeFixtureSource(t, f, dir)
			testtrust.AdministrativeNativeCredentials(t, dir, family, "first")
			h, transport := testtrust.NewAdministrativeReadHTTP(t, f.Before.Archive.Location, administrativeHTTPObjects(f.Before.Archive))
			list := administrativeSourceCall(t, path, AbandonmentRequest{Operation: core.AdministrativeList}, transport)
			if list.Operation.Result.Outcome != core.ObservedCurrent || list.Operation.List == nil || len(list.Operation.List.Groups) != 1 || list.Operation.List.Groups[0].GroupID != f.GroupID {
				t.Fatal("source-based native list lost exact selected target", list.Operation.Result)
			}
			plan := administrativeSourceCall(t, path, AbandonmentRequest{Operation: core.AdministrativePlan, TargetGroupID: f.GroupID, ArtifactPath: filepath.Join(dir, "plan-one.json")}, transport)
			if AbandonmentExitCode(plan) != 0 || plan.Operation.Plan == nil || plan.Operation.Plan.Preview.Identity != f.PreviewIdentity || !plan.Delivery.PlanReadback {
				t.Fatal("source-based native plan lost complete disposition", plan.Operation.Result)
			}
			var planWire struct {
				OperationPayload string                        `json:"operation_payload"`
				Payload          struct{ Schema, View string } `json:"payload"`
			}
			var renderedPlan bytes.Buffer
			if err := WriteAdministrativeJSON(t.Context(), &renderedPlan, plan); err != nil || json.Unmarshal(renderedPlan.Bytes(), &planWire) != nil || planWire.OperationPayload != "InspectionPayload/v1" || planWire.Payload.Schema != "InspectionPayload/v1" || planWire.Payload.View != "administrative-plan" {
				t.Error("administrative plan writer did not emit its maintained v1 inspection schema")
			}
			testtrust.AdministrativeNativeCredentials(t, dir, family, "second")
			again := administrativeSourceCall(t, path, AbandonmentRequest{Operation: core.AdministrativePlan, TargetGroupID: f.GroupID, ArtifactPath: filepath.Join(dir, "plan-two.json")}, transport)
			if again.Operation.Plan == nil || again.Operation.Plan.Preview.Identity != plan.Operation.Plan.Preview.Identity {
				t.Fatal("fresh credentials changed authenticated plan")
			}
			h.SetObjects(administrativeHTTPObjects(f.After.Archive))
			receipt := administrativeSourceCall(t, path, AbandonmentRequest{Operation: core.AdministrativeReceipt, OperationID: f.OperationID}, transport)
			if receipt.Operation.Result.Outcome != core.ObservedCurrent || receipt.Operation.Receipt == nil || !bytes.Equal(receipt.Operation.Receipt.ReceiptBytes, f.Receipt) {
				t.Fatal("native receipt lookup changed original bytes", receipt.Operation.Result)
			}
			unknown := administrativeSourceCall(t, path, AbandonmentRequest{Operation: core.AdministrativeReceipt, OperationID: contract.Hash([]byte("not retained operation"))}, transport)
			if unknown.Operation.Result.Outcome != core.EvidenceUnavailable || unknown.Operation.Receipt != nil || unknown.Operation.Query == nil || unknown.Operation.Query.RequiredStoredKind != contract.OperationEndSelectedWork {
				t.Fatal("missing receipt claimed original noncommit or lost exact lookup context", unknown.Operation.Result)
			}
			reads, forbidden, principals := h.Counts()
			if reads == 0 || forbidden != 0 || principals < 2 {
				t.Fatal("read paths used private calls or lost credential separation", reads, forbidden, principals)
			}
		})
	}
}

// full_only: false
func TestLocalAdministrativeAWSGCPMandatoryProofFailuresKeepExactRefusals(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			f := installedarchive.LoadAdministrative(t, family)
			dir := protectedConfigurationTestDirectory(t)
			path := WriteAdministrativeFixtureSource(t, f, dir)
			testtrust.AdministrativeNativeCredentials(t, dir, family, "proof")
			h, transport := testtrust.NewAdministrativeReadHTTP(t, f.Before.Archive.Location, administrativeHTTPObjects(f.Before.Archive))
			object, ok := f.Before.Archive.Object(f.Before.Archive.Location.PrefixBeforeHEAD + "/HEAD")
			if !ok {
				t.Fatal("fixture HEAD missing")
			}
			head, err := format.DecodeHead(object.Body)
			if err != nil {
				t.Fatal(err)
			}
			key, err := format.Key(f.Before.Archive.Location.PrefixBeforeHEAD, head.Core.Root)
			if err != nil {
				t.Fatal(err)
			}
			for _, cut := range []struct {
				name     string
				outcome  core.Outcome
				reason   core.Reason
				provider contract.Reason
			}{{"missing", core.EvidenceUnavailable, core.MissingSelectedObject, contract.ReasonNone}, {"denied", core.EvidenceUnavailable, core.ReadUnavailable, contract.ReasonAccess}, {"corrupt", core.IntegrityFailure, core.InvalidReference, contract.ReasonNone}} {
				t.Run(cut.name, func(t *testing.T) {
					h.Fail(cut.name, key)
					for _, op := range []core.AdministrativeOperation{core.AdministrativeList, core.AdministrativePlan, core.AdministrativeReceipt} {
						r := administrativeSourceCall(t, path, AbandonmentRequest{Operation: op, TargetGroupID: f.GroupID, OperationID: f.OperationID, ArtifactPath: filepath.Join(dir, "damaged-plan.json")}, transport)
						if r.Operation.Result.Outcome != cut.outcome || r.Operation.Result.Reason != cut.reason || r.Operation.Result.StoreReason != cut.provider || r.Operation.Query == nil {
							t.Fatal("mandatory selected damage lost exact refusal", op, r.Operation.Result)
						}
					}
					if reads, forbidden, _ := h.Counts(); reads == 0 || forbidden != 0 {
						t.Fatal("mandatory damage attempted fallback or effects", reads, forbidden)
					}
				})
			}
		})
	}
}

// full_only: false
func TestLocalAdministrativeAWSGCPRefusesAbsentOrMismatchedIndependentBasis(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, axis := range []string{"missing-generated", "domain", "store", "damaged-trust"} {
			t.Run(family+"/"+axis, func(t *testing.T) {
				f := installedarchive.LoadAdministrative(t, family)
				dir := protectedConfigurationTestDirectory(t)
				path := WriteAdministrativeFixtureSource(t, f, dir)
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var editable map[string]any
				if json.Unmarshal(body, &editable) != nil {
					t.Fatal("source fixture")
				}
				generatedPath := filepath.Join(dir, editable["generated"].(string))
				if axis == "missing-generated" {
					if err := os.Remove(generatedPath); err != nil {
						t.Fatal(err)
					}
				} else {
					body, err := os.ReadFile(generatedPath)
					if err != nil {
						t.Fatal(err)
					}
					var generated map[string]any
					if json.Unmarshal(body, &generated) != nil {
						t.Fatal("generated fixture")
					}
					switch axis {
					case "domain":
						generated["domain"].(map[string]any)["id"] = readerID(contract.Hash([]byte("wrong domain")))
					case "store":
						editable["domain"].(map[string]any)["store"].(map[string]any)["bucket"] = "wrong-fixture-bucket"
					case "damaged-trust":
						basis := generated["public_basis"].(map[string]any)
						descriptor, err := base64.StdEncoding.DecodeString(basis["descriptor"].(string))
						if err != nil {
							t.Fatal(err)
						}
						descriptor[0] ^= 1
						basis["descriptor"] = descriptor
					}
					body, err = json.Marshal(generated)
					if err != nil {
						t.Fatal(err)
					}
					reference := editable["generated"].(string)
					if err := os.WriteFile(filepath.Join(dir, reference), body, 0600); err != nil {
						t.Fatal(err)
					}
					editable["generated"] = reference
					body, err = json.Marshal(editable)
					if err != nil || os.WriteFile(path, body, 0600) != nil {
						t.Fatal("damaged source fixture delivery", err)
					}
				}
				calls := 0
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				r := abandonConfigurationFile(ctx, contract.Hash([]byte("source refusal nonce")), path, configuration.JSON, AbandonmentRequest{Operation: core.AdministrativeList}, func(context.Context, *configuration.Model, abandonmentSource, bool) (abandonmentResources, error) {
					calls++
					return abandonmentResources{}, ErrAbandonmentPlan
				}, nativeAbandonPlanIO())
				if calls != 0 || r.Operation.Result.Outcome != core.AdmissionRefused || r.Operation.PreAdmission == nil {
					t.Fatal("untrusted source reached provider construction", calls, r.Operation.Result)
				}
			})
		}
	}
}
