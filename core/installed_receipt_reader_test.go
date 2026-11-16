package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestReceiptReadersRefuseWithoutPublicInstallationAndCompleteTelemetry(t *testing.T) {
	var reader *InstalledReceiptReader
	for _, operation := range []telemetry.Operation{telemetry.OpCoreReceiptList, telemetry.OpCoreReceiptDetail} {
		t.Run(string(operation), func(t *testing.T) {
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			var result PublicQueryResult
			if operation == telemetry.OpCoreReceiptList {
				got := reader.List(ctx, ReceiptListRequest{contract.ID{1}})
				if got.Payload != nil || got.Query != nil {
					t.Fatal("refusal disclosed a list")
				}
				result = got.PublicQueryResult
			} else {
				got := reader.Detail(ctx, ReceiptDetailRequest{contract.ID{1}, contract.ID{2}})
				if got.Payload != nil || got.Query != nil {
					t.Fatal("refusal disclosed a receipt")
				}
				result = got.PublicQueryResult
			}
			if result.StateResult != PublicQueryRefused || result.Result != refused(AdmissionInvalid) || result.RequestID != (contract.ID{1}) || result.FailureReason != contract.ReasonInvalidInput {
				t.Fatal("unsafe refusal", result)
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3))
			if len(records) != 3 || records[2].Operation != operation || records[2].Result != telemetry.ResultAdmissionRefused {
				t.Fatal("incomplete refusal telemetry", records)
			}
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// full_only: false
func TestPublicQueriesBindSourceFormSelectorAndCompleteObservation(t *testing.T) {
	q := PublicQueryBasis{Schema: "QueryRequestIdentity/v1", Operation: ReceiptDetailOperation, SemanticOperation: 16,
		ExpectedDomain: contract.ID{1}, StoreID: contract.ID{2}, CoordinateID: contract.ID{3}, NonBodyID: contract.ID{4},
		StoreDescriptorDigest: contract.ID{5}, PublicBasisDigest: contract.ID{6}, SourcePins: installedAdministrativeTestPins(), RequestNonce: contract.ID{7},
		Observation: &PublicObservation{contract.ID{1}, contract.ID{8}, contract.ID{9}, contract.ID{10}}}
	want, ok := q.digest(contract.ID{11})
	if !ok {
		t.Fatal("valid exact query refused")
	}
	for _, change := range []func(*PublicQueryBasis){
		func(q *PublicQueryBasis) { q.StoreID[0]++ }, func(q *PublicQueryBasis) { q.CoordinateID[0]++ }, func(q *PublicQueryBasis) { q.NonBodyID[0]++ },
		func(q *PublicQueryBasis) { q.StoreDescriptorDigest[0]++ }, func(q *PublicQueryBasis) { q.PublicBasisDigest[0]++ }, func(q *PublicQueryBasis) { q.RequestNonce[0]++ },
		func(q *PublicQueryBasis) { q.SourcePins.EditableDigest[0]++ }, func(q *PublicQueryBasis) { q.SourcePins.GeneratedDigest[0]++ }, func(q *PublicQueryBasis) { q.SourcePins.Format = 2 },
		func(q *PublicQueryBasis) { q.SourcePins.EditableLength++ }, func(q *PublicQueryBasis) { q.SourcePins.GeneratedLength++ }, func(q *PublicQueryBasis) { q.SourcePins.FileID[0]++ },
		func(q *PublicQueryBasis) { q.Observation.HeadRevisionID[0]++ }, func(q *PublicQueryBasis) { q.Observation.SnapshotID[0]++ }, func(q *PublicQueryBasis) { q.Observation.RootDigest[0]++ },
		func(q *PublicQueryBasis) { q.Operation = InspectRecipientOperation; q.SemanticOperation = 15 },
	} {
		changed := q
		observation := *q.Observation
		changed.Observation = &observation
		change(&changed)
		got, ok := changed.digest(contract.ID{11})
		if !ok || got == want {
			t.Fatal("query omitted a bound fact")
		}
	}
	if got, ok := q.digest(contract.ID{12}); !ok || got == want {
		t.Fatal("query omitted exact operation selector")
	}
	if _, ok := q.digest(contract.ID{}); ok {
		t.Fatal("detail admitted missing operation selector")
	}
	q.Operation = ReceiptListOperation
	if _, ok := q.digest(contract.ID{11}); ok {
		t.Fatal("list admitted a detail selector")
	}
	if _, ok := q.digest(contract.ID{}); !ok {
		t.Fatal("closed list query refused")
	}
}

// full_only: false
func TestReceiptListProjectionRequiresCompleteMandatoryEvidence(t *testing.T) {
	state, receipt, _ := receiptStateFixture(t)
	rows, err := projectReceiptList(state)
	if err != nil || len(rows) != 1 || rows[0] != (ReceiptSummary{receipt.OperationID, receipt.OperationKind, receipt.CanonicalOutcome, receipt.StateResult, receipt.ObservedRevisionID, receipt.RequestedRevisionID, receipt.WarningBits, receipt.EvidenceCeiling}) {
		t.Fatal("original receipt scalars changed", err, rows)
	}
	state.support[0].Records = nil
	if rows, err := projectReceiptList(state); err == nil || rows != nil {
		t.Fatal("mandatory loss disclosed a partial list")
	}
}

// full_only: false
func TestReceiptReadValidationRefusesPayloadsAndImpossibleReadTuples(t *testing.T) {
	var reader *InstalledReceiptReader
	list := reader.List(context.Background(), ReceiptListRequest{contract.ID{1}})
	detail := reader.Detail(context.Background(), ReceiptDetailRequest{contract.ID{1}, contract.ID{2}})
	if err := list.Validate(); err != nil {
		t.Fatal("closed unbound list refusal rejected", err)
	}
	if err := detail.Validate(); err != nil {
		t.Fatal("closed unbound detail refusal rejected", err)
	}
	list.Payload = &ReceiptListPayload{}
	if list.Validate() == nil {
		t.Fatal("failed list carried success payload")
	}
	detail.Payload = &ReceiptDetailPayload{}
	if detail.Validate() == nil {
		t.Fatal("failed detail carried success payload")
	}
	for _, change := range []func(*PublicQueryResult){
		func(r *PublicQueryResult) { r.Result.CommitMayHaveOccurred = true },
		func(r *PublicQueryResult) { r.Result.RequestedRevision = contract.ID{1} },
		func(r *PublicQueryResult) { r.Result.Evidence = AuthenticatedClosure },
		func(r *PublicQueryResult) { r.Result.ObservedRevision = contract.ID{1} },
		func(r *PublicQueryResult) {
			r.FailureReason = contract.ReasonCancelled
			r.Result.Outcome = IntegrityFailure
			r.StateResult = PublicQueryPositiveDefect
		},
		func(r *PublicQueryResult) { r.FailureReason = contract.DiagnosticReason("unreviewed text") },
	} {
		bad := detail.PublicQueryResult
		change(&bad)
		if validatePublicQueryResult(bad) == nil {
			t.Fatal("invalid query tuple accepted", bad)
		}
	}
}

// full_only: false
func TestPublicQueryPreAdmissionRelationPreservesDirectCoreRefusals(t *testing.T) {
	var reader *InstalledReceiptReader
	direct := reader.List(context.Background(), ReceiptListRequest{contract.ID{1}}).PublicQueryResult
	if direct.PreAdmission != nil || validateUnboundPublicQuery(direct) != nil {
		t.Fatal("direct Core unbound refusal changed")
	}
	local := direct
	local.OperationID = contract.ID{2}
	local.PreAdmission = &PreAdmissionRequestIdentity{Stage: "dispatch", Code: string(contract.ReasonInvalidInput), SourceSchema: "enkv/configuration/v1", SourceProfile: "direct-candidate", RequestNonce: local.RequestID}
	if validateUnboundPublicQuery(local) != nil {
		t.Fatal("local refusal relation rejected")
	}
	for _, damage := range []string{"bound-identity", "missing-id", "nonce", "stage", "code", "schema", "profile"} {
		t.Run(damage, func(t *testing.T) {
			bad := local
			q := *local.PreAdmission
			bad.PreAdmission = &q
			switch damage {
			case "bound-identity":
				bad.RequestIdentity = contract.ID{3}
			case "missing-id":
				bad.OperationID = contract.ID{}
			case "nonce":
				q.RequestNonce = contract.ID{4}
			case "stage":
				q.Stage = ""
			case "code":
				q.Code = ""
			case "schema":
				q.SourceSchema = ""
			case "profile":
				q.SourceProfile = ""
			}
			if validatePublicQueryResult(bad) == nil {
				t.Fatal("invalid local query relation accepted", damage)
			}
		})
	}
	q := PublicQueryBasis{Schema: "QueryRequestIdentity/v1", Operation: ReceiptListOperation, SemanticOperation: 16, ExpectedDomain: contract.ID{1}, StoreID: contract.ID{2}, CoordinateID: contract.ID{3}, NonBodyID: contract.ID{4}, StoreDescriptorDigest: contract.ID{5}, PublicBasisDigest: contract.ID{6}, SourcePins: installedAdministrativeTestPins(), RequestNonce: contract.ID{7}, Observation: &PublicObservation{contract.ID{1}, contract.ID{8}, contract.ID{9}, contract.ID{10}}}
	digest, ok := q.digest(contract.ID{})
	if !ok {
		t.Fatal("bound query fixture")
	}
	bound := PublicQueryResult{Operation: ReceiptListOperation, RequestID: q.RequestNonce, OperationID: publicQueryOperationID(digest), RequestIdentity: digest, DomainID: q.ExpectedDomain, Result: Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure, ObservedRevision: contract.ID{8}, ObservedSnapshotID: contract.ID{9}}, StateResult: PublicQuerySuccess}
	if validatePublicQueryBinding(bound, q, digest, contract.ID{}) != nil {
		t.Fatal("bound Core query changed")
	}
	metadata := *local.PreAdmission
	metadata.RequestNonce = bound.RequestID
	bound.PreAdmission = &metadata
	if validatePublicQueryBinding(bound, q, digest, contract.ID{}) == nil {
		t.Fatal("bound query accepted local parser overlay")
	}
}

// full_only: false
func TestPublicQueryAdmissionInterruptionPrecedesOperationFailure(t *testing.T) {
	fallback := readerSelectionFailure(failure(IntegrityFailure, InvalidFormat))
	for _, ctx := range []context.Context{nil, t.Context()} {
		if got := publicQueryFailure(ctx, nil, fallback); got != fallback {
			t.Fatal("pre-admission failure changed without an invocation", got)
		}
	}
	for _, operation := range []string{ReceiptListOperation, ReceiptDetailOperation, InspectOperation, InspectRecipientOperation} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			deadline, _ := ctx.Deadline()
			inv := &readerInvocation{admission: readerAdmission{issued: true, operation: operation, request: contract.ID{1}, domain: contract.ID{2},
				store:          contract.Descriptor{Family: contract.GCP, Identity: contract.ID{3}, Coordinate: contract.ID{4}, NonBody: contract.ID{5}, Prefix: "query", HeadKey: "query/HEAD"},
				interpretation: contract.InterpretationID(), trustInterpretation: contract.TrustInterpretationID(), compatibility: contract.CompatibilityID(), cryptoSupport: contract.CryptoSupportID(), deadline: deadline, done: ctx.Done()}}
			if got := publicQueryFailure(ctx, inv, fallback); got != fallback {
				t.Fatal("current invocation hid a genuine selected-data failure", got)
			}
			if got := publicQueryFailure(ctx, inv, readerFailure{}); got != (readerFailure{}) {
				t.Fatal("current successful invocation was refused", got)
			}
			cancel()
			if got := publicQueryFailure(ctx, inv, fallback); got != readerRefusal(contract.ReasonCancelled) {
				t.Fatal("cancellation lost precedence over selected-data failure", got)
			}
			expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			defer stop()
			inv.admission.deadline, _ = expired.Deadline()
			inv.admission.done = expired.Done()
			if got := publicQueryFailure(expired, inv, fallback); got != readerRefusal(contract.ReasonExpired) {
				t.Fatal("expiry lost precedence over selected-data failure", got)
			}
		})
	}
}
