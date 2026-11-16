package core

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGCObservationRejectsMalformedStoreTuples(t *testing.T) {
	s := generatedEmptyPredecessorForFamily(t, contract.GCP)
	page := *s.recipients[0]
	page.Object = gcTestID("observation-target")
	body, err := format.EncodeRecipientPage(page)
	if err != nil {
		t.Fatal(err)
	}
	target := contract.GCTarget{Object: contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RecipientKind, ObjectID: page.Object}, Length: uint32(len(body)), Digest: contract.Hash(body), Token: contract.Token{Family: contract.GCP, Value: "1"}}
	for _, name := range []string{"missing-body", "missing-token", "missing-reason", "ok-reason", "ok-token", "ok-family", "ok-empty", "ok-oversized", "ok-framing", "ok-domain", "ok-object", "ok-index", "valid-exact", "valid-changed-token", "valid-changed-body", "valid-missing"} {
		t.Run(name, func(t *testing.T) {
			read := contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(body), Token: target.Token}
			want, reason := contract.GCTargetUnknown, contract.ReasonMalformed
			switch name {
			case "missing-body":
				read = contract.ReadResult{Status: contract.ReadMissing, Body: []byte{1}}
			case "missing-token":
				read = contract.ReadResult{Status: contract.ReadMissing, Token: target.Token}
			case "missing-reason":
				read = contract.ReadResult{Status: contract.ReadMissing, Reason: contract.ReasonAccess}
			case "ok-reason":
				read.Reason = contract.ReasonAccess
			case "ok-token":
				read.Token = contract.Token{}
			case "ok-family":
				read.Token = contract.Token{Family: contract.AWS, Value: "\"etag\""}
			case "ok-empty":
				read.Body = nil
			case "ok-oversized":
				read.Body = make([]byte, contract.MaxRecipientPageLength+1)
			case "ok-framing":
				read.Body = append(read.Body, 0)
			case "ok-domain", "ok-object", "ok-index":
				wrong := page
				if name == "ok-domain" {
					wrong.Domain = gcTestID("foreign-domain")
				}
				if name == "ok-object" {
					wrong.Object = gcTestID("other-object")
				}
				if name == "ok-index" {
					wrong.Index = 1
				}
				read.Body, err = format.EncodeRecipientPage(wrong)
				if err != nil {
					t.Fatal(err)
				}
			case "valid-exact":
				want, reason = contract.GCTargetPending, contract.ReasonNone
			case "valid-changed-token":
				read.Token.Value = "999"
				want, reason = contract.GCTargetChanged, contract.ReasonCondition
			case "valid-changed-body":
				changed := page
				row := *page.Slots[0]
				row.DisplayName = "Changed"
				changed.Slots[0] = &row
				read.Body, err = format.EncodeRecipientPage(changed)
				if err != nil {
					t.Fatal(err)
				}
				want, reason = contract.GCTargetChanged, contract.ReasonCondition
			case "valid-missing":
				read = contract.ReadResult{Status: contract.ReadMissing}
				want, reason = contract.GCTargetAbsent, contract.ReasonNone
			}
			ctx := gcReadContext(t)
			probe := &gcReadProbe{store: s.admission.store, read: func(context.Context, string, uint32) contract.ReadResult { return read }}
			physical, err := newGCPhysicalReader(ctx, probe)
			if err != nil {
				t.Fatal(err)
			}
			got, why := gcObservation(ctx, physical, s.admission.store, s.root.Domain, target)
			if got != want || why != reason {
				t.Fatalf("tuple %s: got disposition=%d reason=%d; want %d %d", name, got, why, want, reason)
			}
			if len(probe.keys) != 1 {
				t.Fatal("observation expanded its fixed logical read", probe.keys)
			}
		})
	}
}
