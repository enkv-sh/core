package contract

import "testing"

// full_only: false
func TestGeneratedPreparationBoundsCurrentAndRetainedMembership(t *testing.T) {
	request := generatedSuppliedCryptoFixture(t)
	body, err := EncodeCryptoGeneratedSuppliedRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	view, err := InspectCryptoGeneratedSuppliedRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CryptoGeneratedSuppliedResultBound(view)
	// Complete body:10 framing;14 prepared row framing;2 names of256;
	// entry154;64 IDs;canonical215+87384;metadata envelope460;
	// access102;256 ordinary +1 recovery wraps,489 bytes each.
	const want = 10 + 14 + 512 + 154 + 2048 + 215 + 87384 + 460 + 102 + 257*489
	if err != nil || got != want {
		t.Fatal("generated membership body exceeds independent pre-private bound", got, want, err)
	}
	if CryptoGeneratedResponseLimit != 4<<20 {
		t.Fatal("response ceiling changed")
	}
}

// full_only: false
func TestGeneratedPreparationCarriesCurrentCanonicalIdentity(t *testing.T) {
	_, _, results := generatedCryptoValueEntryBatchFixture(t, 1)
	current := results[0]
	request := generatedSuppliedCryptoFixture(t)
	request.IdentityPlan = generatedSuppliedIdentityBody(t, []IdentityRow{{Name: current.Entry.Name, Slot: current.Slot,
		Incarnation: current.Entry.Incarnation, ValueState: current.Entry.ValueState, OriginSnapshot: current.Entry.OriginSnapshot, OriginTransition: current.Entry.OriginTransition}})
	entry, err := EncodeValueEntry(current.Entry)
	if err != nil {
		t.Fatal(err)
	}
	access, err := EncodeAccessRecord(current.Access)
	if err != nil {
		t.Fatal(err)
	}
	response, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: request.Final, Rows: []CryptoPreparedSecret{
		{Name: current.Entry.Name, Slot: current.Slot, EntryBytes: entry, AccessRecord: access},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"current_identity", "sealed_source", "wrong_identity"} {
		t.Run(mode, func(t *testing.T) {
			candidate := request
			if mode == "sealed_source" {
				candidate.SealedInputs = []CryptoSealedInput{generatedSuppliedSourceFixture(t, candidate, current.Entry.Name)}
			}
			if mode == "wrong_identity" {
				candidate.IdentityPlan = generatedSuppliedIdentityBody(t, []IdentityRow{{Name: current.Entry.Name, Slot: current.Slot,
					Incarnation: current.Entry.Incarnation, ValueState: generatedRecordID(211), OriginSnapshot: current.Entry.OriginSnapshot, OriginTransition: current.Entry.OriginTransition}})
			}
			body, err := EncodeCryptoGeneratedSuppliedRequest(candidate)
			if err != nil {
				t.Fatal(err)
			}
			q := CryptoRequest{Schema: CryptoSchema, Kind: CryptoPrepare, RequestID: generatedRecordID(93), CustodyInstanceID: generatedRecordID(94), Body: body}
			p := CryptoResponse{Schema: q.Schema, Kind: q.Kind, RequestID: q.RequestID, CustodyInstanceID: q.CustodyInstanceID, ResultCode: CryptoSuccess, Body: response}
			err = ValidateCryptoExchange(q, p)
			if mode == "current_identity" && err != nil || mode != "current_identity" && err != ErrCryptoMessage {
				t.Fatal("prepared current identity/source binding", mode, err)
			}
		})
	}
}
