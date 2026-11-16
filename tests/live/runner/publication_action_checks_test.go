package core

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestLivePublicationPhysicalActionReservations(t *testing.T) {
	// Columns are the six action tags in Formats, including both delete forms.
	rows := []struct {
		profile string
		counts  [6]uint64
	}{
		{"AWS-SECRETS-MANAGER", [6]uint64{2, 0, 1, 0, 1, 2}},
		{"GCP-SECRET-MANAGER", [6]uint64{2, 0, 2, 0, 3, 3}},
		{"GITHUB-REPOSITORY", [6]uint64{0, 2, 2, 0, 1, 1}},
		{"GITHUB-ORGANIZATION", [6]uint64{0, 2, 2, 2, 1, 1}},
		{"GITHUB-ENVIRONMENT", [6]uint64{0, 2, 2, 0, 1, 1}},
	}
	for _, row := range rows {
		t.Run(row.profile, func(t *testing.T) {
			profile := "ENKV/OUTPUT/" + row.profile + "/v3"
			for i, expected := range row.counts {
				count, ok := livePublicationRequests(profile, uint8(i+1))
				if ok != (expected != 0) || ok && count != expected {
					t.Fatalf("action=%d requests=%d supported=%v expected=%d", i+1, count, ok, expected)
				}
			}
			for _, action := range []uint8{0, 7, 255} {
				if _, ok := livePublicationRequests(profile, action); ok {
					t.Fatal("undefined action admitted")
				}
			}
		})
	}
	if _, ok := livePublicationRequests("ENKV/OUTPUT/TEST-PROFILE/v3", 1); ok {
		t.Fatal("test profile admitted to live native budget")
	}
}

type livePublicationCheckOwner struct {
	publicationPrivateOwner
	send        func() (contract.PublicationResult, contract.CryptoResultCode)
	armCalls    int
	sendCalls   int
	retireCalls int
}

func (o *livePublicationCheckOwner) Arm(context.Context, contract.ID, contract.PublicationDispatch) error {
	o.armCalls++
	return nil
}
func (o *livePublicationCheckOwner) Send(context.Context, contract.ID) (contract.PublicationResult, contract.CryptoResultCode) {
	o.sendCalls++
	return o.send()
}
func (o *livePublicationCheckOwner) Retire(context.Context) error { o.retireCalls++; return nil }

func livePublicationActionCheck(t *testing.T) (*livePublicationRecorder, *livePublicationOwner, *livePublicationCheckOwner, contract.PublicationDispatch, contract.PublicationResult) {
	t.Helper()
	id := func(label string) contract.ID { return contract.Hash([]byte("live action control " + label)) }
	domain := id("domain")
	scope := records.OutputFixtureScope{RunID: strings.Repeat("1", 32), Scenario: "publication.aws-secrets-manager.plain-secret-lifecycle/plain1_secret1_create_value_delete", DomainID: hex.EncodeToString(domain[:]), WriterID: "writer-0"}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0700) != nil {
		t.Fatal("control private directory refused")
	}
	path := filepath.Join(directory, "output-inventory.json")
	profile, slot := "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3", "arn:aws:secretsmanager:us-east-1:123456789012:secret:fixture"
	premise := id("namespace")
	if records.NewOutputFixtureInventory(path, scope, []records.OutputFixtureRow{{ProfileID: profile, PlannedSlot: slot, ExclusiveNamespaceDigest: hex.EncodeToString(premise[:])}}) != nil ||
		records.SetOutputFixtureActors(path, scope, records.OutputFixtureActors{ProfileID: profile, Writer: "writer", ReaderA: "consumer-a", ReaderB: "consumer-b"}) != nil {
		t.Fatal("control inventory setup refused")
	}
	r := &livePublicationRecorder{scope: scope, inventoryPath: path, budget: &runBudget{limits: liveLimits{Requests: 8, BodyBytes: 8 * operationBodyAllowance}, keys: make(map[string]bool)}}
	projection := contract.PublicationProjection{Schema: 4, DomainID: domain, ConfigurationDigest: id("configuration"), CoordinateID: id("coordinate"), BindingIncarnationID: id("binding"), EntryIncarnationID: id("entry"), TargetRowDigest: id("row"), Action: contract.PublicationCreateEmpty, PolicyDigest: id("policy"), RequestContractDigest: id("request"), ActingRecipientID: id("recipient")}
	commitment, err := contract.PublicationProjectionCommitment(projection)
	if err != nil {
		t.Fatal("control projection refused")
	}
	dispatch := contract.PublicationDispatch{Schema: 5, DomainID: domain, OperationID: id("operation"), AttemptID: id("attempt"), CoordinateID: projection.CoordinateID, Projection: projection, ProjectionCommitment: commitment, AuthoritySubjectDigest: id("authority"), ExecutorID: "executor", CredentialRouteID: "route", ResponseContractDigest: id("response")}
	contextDigest, err := contract.PublicationDispatchContextDigest(dispatch)
	if err != nil {
		t.Fatal("control dispatch refused")
	}
	result := contract.PublicationResult{Schema: 2, DomainID: domain, OperationID: dispatch.OperationID, AttemptID: dispatch.AttemptID, CoordinateID: dispatch.CoordinateID, ProjectionCommitment: commitment, DispatchContextDigest: contextDigest,
		Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationRequestAcknowledged, ResponseContractDigest: dispatch.ResponseContractDigest, NormalizedStatus: 200, SafeResourceID: slot + "-ABC123", ConsumerLocator: slot + "-ABC123?stage=AWSCURRENT"}}
	if contract.ValidatePublicationResult(dispatch, result) != nil {
		t.Fatal("control result refused")
	}
	inner := &livePublicationCheckOwner{}
	owner := r.observe(inner, publicationOwnerInput{Projection: projection, Target: contract.OutputTarget{CanonicalTarget: slot}}, 0).(*livePublicationOwner)
	return r, owner, inner, dispatch, result
}

// full_only: false
func TestLivePublicationActionPersistsIntentAndQualifiedBirth(t *testing.T) {
	r, owner, inner, dispatch, result := livePublicationActionCheck(t)
	inner.send = func() (contract.PublicationResult, contract.CryptoResultCode) {
		inventory, err := records.ReadOutputFixtureInventory(r.inventoryPath, r.scope)
		// AWS create reserves one STS qualification and one mutation.
		if err != nil || len(inventory.Rows[0].Attempts) != 1 || inventory.Rows[0].Attempts[0].Outcome != "pending" || inventory.Rows[0].BirthAttemptID != "" || r.budget.snapshot().Requests != 2 {
			t.Fatal("native entry preceded durable intent or budget")
		}
		return result, contract.CryptoSuccess
	}
	id := contract.Hash([]byte("owner admission"))
	if owner.Arm(t.Context(), id, dispatch) != nil {
		t.Fatal("arm refused")
	}
	got, code := owner.Send(t.Context(), id)
	if got != result || code != contract.CryptoSuccess {
		t.Fatal("actual response changed")
	}
	if _, code := owner.Send(t.Context(), id); code != contract.CryptoInvalidAdmission || inner.sendCalls != 1 {
		t.Fatal("same owner entered twice")
	}
	inventory, err := records.ReadOutputFixtureInventory(r.inventoryPath, r.scope)
	if err != nil || inventory.Rows[0].OwnedInstance != result.Evidence.SafeResourceID || inventory.Rows[0].BirthAttemptID != hex.EncodeToString(dispatch.AttemptID[:]) || inventory.Rows[0].Attempts[0].Outcome != "acknowledged" {
		t.Fatal("qualified birth not retained")
	}
	if owner.Retire(t.Context()) != nil || owner.Retire(t.Context()) != nil || inner.retireCalls != 1 {
		t.Fatal("retirement not joined once")
	}
	if owners, retired, sends, err := r.state(); owners != 1 || retired != 1 || sends != 1 || err != nil {
		t.Fatal("owner lifecycle facts differ")
	}
}

// full_only: false
func TestLivePublicationActionRefusesBeforeEntry(t *testing.T) {
	for _, condition := range []string{"budget", "missing_inventory", "wrong_row", "unarmed", "different_admission", "retired"} {
		t.Run(condition, func(t *testing.T) {
			r, owner, inner, dispatch, _ := livePublicationActionCheck(t)
			id := contract.Hash([]byte("owner admission"))
			if condition != "unarmed" && owner.Arm(t.Context(), id, dispatch) != nil {
				t.Fatal("control arm refused")
			}
			switch condition {
			case "budget":
				r.budget.limits.Requests = 0
			case "missing_inventory":
				if os.Remove(r.inventoryPath) != nil {
					t.Fatal("remove control inventory")
				}
			case "wrong_row":
				owner.index = 1
			case "different_admission":
				id = contract.Hash([]byte("different admission"))
			case "retired":
				if owner.Retire(t.Context()) != nil {
					t.Fatal("retire control owner")
				}
			}
			if _, code := owner.Send(t.Context(), id); code != contract.CryptoInvalidAdmission || inner.sendCalls != 0 {
				t.Fatal("refused action reached native entry")
			}
		})
	}
}

// full_only: false
func TestLivePublicationActionUnqualifiedResponseKeepsUnknown(t *testing.T) {
	for _, condition := range []string{"different_attempt", "different_context", "different_response_contract", "failed_code", "save_failure"} {
		t.Run(condition, func(t *testing.T) {
			r, owner, inner, dispatch, response := livePublicationActionCheck(t)
			code := contract.CryptoSuccess
			switch condition {
			case "different_attempt":
				response.AttemptID = contract.Hash([]byte("other attempt"))
			case "different_context":
				response.DispatchContextDigest = contract.Hash([]byte("other context"))
			case "different_response_contract":
				response.Evidence.ResponseContractDigest = contract.Hash([]byte("other response"))
			case "failed_code":
				code = contract.CryptoResponseUnknown
			}
			inner.send = func() (contract.PublicationResult, contract.CryptoResultCode) {
				if condition == "save_failure" && os.Chmod(r.inventoryPath, 0400) != nil {
					t.Fatal("control inventory mode")
				}
				return response, code
			}
			id := contract.Hash([]byte("owner admission"))
			if owner.Arm(t.Context(), id, dispatch) != nil {
				t.Fatal("control arm refused")
			}
			got, gotCode := owner.Send(t.Context(), id)
			if got != response || gotCode != code || inner.sendCalls != 1 {
				t.Fatal("private response changed or repeated")
			}
			if condition == "save_failure" {
				if _, _, _, err := r.state(); err == nil {
					t.Fatal("failed persistence lost its signal")
				}
				if os.Chmod(r.inventoryPath, 0600) != nil {
					t.Fatal("restore control inventory mode")
				}
			}
			inventory, err := records.ReadOutputFixtureInventory(r.inventoryPath, r.scope)
			expected := "unknown"
			if condition == "save_failure" {
				expected = "pending"
			}
			if err != nil || inventory.Rows[0].BirthAttemptID != "" || inventory.Rows[0].OwnedInstance != "" || inventory.Rows[0].Attempts[0].Outcome != expected {
				t.Fatal("unqualified response acquired birth or lost uncertainty")
			}
		})
	}
}
