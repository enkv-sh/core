package compositionfull

import (
	"bytes"
	"encoding/json"
	"enkv.sh/compositions/configuration"
	"io"
	"reflect"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func readableExpectedJSON(t *testing.T, compact string) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := json.Indent(&out, []byte(compact), "", "  "); err != nil {
		t.Fatal(err)
	}
	out.WriteByte('\n')
	return out.Bytes()
}

func resultJSONFactsEqual(left, right []byte) bool {
	if !json.Valid(left) || !json.Valid(right) {
		return false
	}
	decode := func(body []byte) (any, error) {
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		var value any
		err := decoder.Decode(&value)
		return value, err
	}
	a, aerr := decode(left)
	b, berr := decode(right)
	return aerr == nil && berr == nil && reflect.DeepEqual(a, b)
}

// full_only: false
func TestOrdinaryResultJSONLayout(t *testing.T) {
	for _, row := range []struct {
		name   string
		prefix string
		render func(*testing.T) ([]byte, error)
	}{
		{"initialization", "{\n  \"schema\": \"ProductResult/v1\",\n", func(t *testing.T) ([]byte, error) {
			r, err := NewInitializationRefusal(0)
			if err != nil {
				return nil, err
			}
			return RenderInitializationJSON(r, nil)
		}},
		{"apply", "{\n  \"schema\": \"ProductResult/v1\",\n", func(t *testing.T) ([]byte, error) {
			r, err := NewApplyRefusal(0)
			if err != nil {
				return nil, err
			}
			return RenderApplyJSON(r)
		}},
		{"recipient-retirement", "{\n  \"schema\": \"ProductResult/v1\",\n", func(t *testing.T) ([]byte, error) {
			r, err := NewRecipientRetirementRefusal(0)
			if err != nil {
				return nil, err
			}
			return RenderRecipientRetirementJSON(r)
		}},
		{"rekey", "{\n  \"schema\": \"ProductResult/v1\",\n", func(t *testing.T) ([]byte, error) {
			r, err := NewEnvelopeRekeyRefusal(0)
			if err != nil {
				return nil, err
			}
			return RenderEnvelopeRekeyJSON(r)
		}},
		{"publication", "{\n  \"schema\": \"ProductResult/v1\",\n", func(t *testing.T) ([]byte, error) {
			return RenderPublicationJSON(core.PublicPublicationResult{RequestID: contract.ID{1}, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}})
		}},
		{"combined-apply-publication", "{\n  \"schema\": \"ApplyPublicationResult/v1\",\n", func(t *testing.T) ([]byte, error) {
			r, err := NewApplyRefusal(0)
			if err != nil {
				return nil, err
			}
			return resultLayoutOutput(func(w io.Writer) error {
				return WriteApplyPublicationJSON(w, core.PublicApplyPublicationResult{Apply: r, Publication: core.ApplyPublicationStage{Stage: "unstarted", Reason: "apply-incomplete"}})
			})
		}},
		{"prepare", "{\n  \"schema\": \"enkv/prepare-result/v2\",\n", func(t *testing.T) ([]byte, error) {
			r, err := NewPrepareRefusal()
			if err != nil {
				return nil, err
			}
			return RenderPrepareJSON(r)
		}},
		{"materialization", "{\n  \"schema\": \"ProductResult/v1\",\n", func(t *testing.T) ([]byte, error) {
			r, err := NewMaterializationRefusal(0)
			if err != nil {
				return nil, err
			}
			return resultLayoutOutput(func(w io.Writer) error { return WriteMaterializationJSON(t.Context(), w, r) })
		}},
		{"gc-execution", "{\n  \"schema\": \"ProductResult/v1\",\n", func(t *testing.T) ([]byte, error) {
			r, err := NewGCApplyRefusal(0)
			if err != nil {
				return nil, err
			}
			return resultLayoutOutput(func(w io.Writer) error { return WriteGCApplyJSON(t.Context(), w, r) })
		}},
		{"abandonment", "{\n  \"schema\": \"ProductResult/v1\",\n", func(t *testing.T) ([]byte, error) {
			r, err := NewAbandonmentRefusal(core.AdministrativeList, 0)
			if err != nil {
				return nil, err
			}
			return resultLayoutOutput(func(w io.Writer) error { return WriteAdministrativeJSON(t.Context(), w, r) })
		}},
		{"replacement", "{\n  \"operation_payload\": \"none\",\n", func(t *testing.T) ([]byte, error) {
			r, err := NewReplacementCommandRefusal(configuration.ReplaceAuthority, contract.ID{1}, 0)
			if err != nil {
				return nil, err
			}
			return resultLayoutOutput(func(w io.Writer) error { return WriteReplacementJSON(t.Context(), w, r) })
		}},
		{"maintenance", "{\n  \"schema\": \"ProductResult/v1\",\n", func(t *testing.T) ([]byte, error) {
			r, err := NewEnvelopeRekeyRefusal(0)
			if err != nil {
				return nil, err
			}
			return RenderMaintenanceCommandJSON(contract.OperationEnvelopeRekey, MaintenanceCommandResult{PublicApplyResult: r, Delivery: ReplacementCommandDelivery{Status: "not-attempted"}, SourceUsability: "unchecked"})
		}},
		{"local", "{\n  \"schema\": \"LocalEditResult/v1\",\n", func(t *testing.T) ([]byte, error) {
			r, err := NewLocalEditRefusal("domain-rename")
			if err != nil {
				return nil, err
			}
			return RenderLocalEditJSON(r, nil)
		}},
		{"set", "{\n  \"local_edit\": \"plain\",\n", func(t *testing.T) ([]byte, error) {
			return RenderSetJSON(&SetResult{StateResult: SetRefused}, nil)
		}},
		{"generated", "{\n  \"schema\": \"ProductResult/v1\",\n", func(t *testing.T) ([]byte, error) {
			return RenderGeneratedListJSON(core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: contract.ID{1}}, StateResult: contract.ReaderUnavailable, Result: core.Result{Outcome: core.EvidenceUnavailable}})
		}},
		{"query", "{\n  \"schema\": \"ProductResult/v1\",\n", func(t *testing.T) ([]byte, error) {
			var out bytes.Buffer
			r, err := NewDomainInspectionRefusal(0)
			if err != nil {
				return nil, err
			}
			err = WriteInspectionJSON(t.Context(), &out, r)
			return out.Bytes(), err
		}},
		{"native-manifest", "{\n  \"schema\": \"ManifestFileResult/v2\",\n", func(t *testing.T) ([]byte, error) {
			return RenderManifestFileJSON(manifestFileResultFixture())
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			body, err := row.render(t)
			if err != nil || !json.Valid(body) || !bytes.HasPrefix(body, []byte(row.prefix)) || !bytes.HasSuffix(body, []byte("\n}\n")) || bytes.HasSuffix(body, []byte("\n\n")) {
				t.Fatalf("ordinary JSON layout differs: %v; got %q", err, body)
			}
		})
	}
}

func resultLayoutOutput(write func(io.Writer) error) ([]byte, error) {
	var out bytes.Buffer
	err := write(&out)
	return out.Bytes(), err
}
