package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicInspectionEnforcesPerEntryRecipientLimitBeforeOutput(t *testing.T) {
	for _, count := range []int{64, 65} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r := publicQueryRendererDomain(t)
			entry := core.InspectionEntry{Name: "entry", IncarnationID: contract.ID{200}, ValueStateID: contract.ID{201}, ValueSource: contract.Supplied}
			for i := range count {
				id := contract.ID{byte(i + 1)}
				entry.RecipientIDs = append(entry.RecipientIDs, id)
				r.View.Recipients = append(r.View.Recipients, core.InspectionRecipient{RecipientID: id, Status: contract.CurrentRecipient, BindingID: id, BindingSerial: 1, BindingFingerprint: id})
			}
			r.View.Entries = []core.InspectionEntry{entry}
			if err := r.ValidateMetadataWorkOutput(); (err == nil) != (count == 64) {
				t.Error("per-entry recipient limit", count, err)
			}
			for _, human := range []bool{false, true} {
				var out bytes.Buffer
				write := WriteInspectionJSON
				if human {
					write = WriteInspectionHuman
				}
				err := write(t.Context(), &out, r)
				if count == 64 {
					if err != nil || out.Len() == 0 || !human && !json.Valid(out.Bytes()) {
						t.Fatal("valid maximum refused", human, err, out.Len())
					}
				} else if err == nil || out.Len() != 0 {
					t.Error("over-limit entry crossed output boundary", human, err, out.Len())
				}
			}
		})
	}
}

type finalQueryWrite struct {
	interrupt      func()
	final          bool
	written, total int
}

func (w *finalQueryWrite) Write(p []byte) (int, error) {
	w.written += len(p)
	if w.written == w.total {
		w.final = true
		w.interrupt()
	}
	return len(p), nil
}

// full_only: false
func TestPublicQueryFinalWriteInterruptionReturnsError(t *testing.T) {
	domain := publicQueryRendererDomain(t)
	base, basis, digest := publicQueryRendererBasis(t, core.InspectRecipientOperation)
	recipient := core.PublicRecipientInspectionResult{PublicQueryResult: base, Query: &core.RecipientInspectionQueryIdentity{PublicQueryBasis: basis, RecipientID: contract.ID{11}, Digest: digest}, View: &core.RecipientInspection{Observation: *basis.Observation, RecipientID: contract.ID{11}}}
	list, detail := publicQueryRendererList(t), publicQueryRendererDetail(t)
	administrative := administrativeListResult(2)
	for _, form := range []string{"domain", "recipient", "list", "detail", "administrative"} {
		for _, human := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/human=%t", form, human), func(t *testing.T) {
				render := func(ctx context.Context, out io.Writer) error {
					var err error
					switch form {
					case "domain":
						err = writeInspection(ctx, out, domain, human, nil)
					case "recipient":
						err = writeRecipientInspection(ctx, out, recipient, human, nil)
					case "list":
						err = writeReceiptList(ctx, out, list, human, nil)
					case "detail":
						err = writeReceiptDetail(ctx, out, detail, human, nil)
					case "administrative":
						if human {
							err = WriteAdministrativeHuman(ctx, out, administrative)
						} else {
							err = WriteAdministrativeJSON(ctx, out, administrative)
						}
					}
					return err
				}
				var complete bytes.Buffer
				if err := render(t.Context(), &complete); err != nil || complete.Len() == 0 || !bytes.HasSuffix(complete.Bytes(), []byte("\n")) {
					t.Fatal("complete output control", err, complete.Len())
				}
				if !human && (form == "domain" || form == "recipient") {
					var wire struct {
						OperationPayload string                        `json:"operation_payload"`
						Payload          struct{ Schema, Form string } `json:"payload"`
					}
					if json.Unmarshal(complete.Bytes(), &wire) != nil || wire.OperationPayload != "InspectionPayload/v1" || wire.Payload.Schema != "InspectionPayload/v1" || wire.Payload.Form != form {
						t.Error("inspection writer did not emit the maintained v1 schema for its selected form")
					}
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				out := &finalQueryWrite{interrupt: cancel, total: complete.Len()}
				err := render(ctx, out)
				if !out.final || !errors.Is(err, context.Canceled) {
					t.Fatal("final-write cancellation lost", out.final, err)
				}
			})
		}
	}
	t.Run("deadline", func(t *testing.T) {
		var complete bytes.Buffer
		if err := WriteReceiptListJSON(t.Context(), &complete, list); err != nil || complete.Len() == 0 {
			t.Fatal("complete output control", err, complete.Len())
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		out := &finalQueryWrite{interrupt: func() { <-ctx.Done() }, total: complete.Len()}
		if err := WriteReceiptListJSON(ctx, out, list); !out.final || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("final-write deadline lost", out.final, err)
		}
	})
}
