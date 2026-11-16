package core

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

type publicationKeyUseOwner struct {
	publicationPrivateOwner
	reply func([]contract.KeyUseRow) ([]contract.KeyUseRow, contract.CryptoResultCode)
}

func (owner *publicationKeyUseOwner) Prepare(ctx context.Context, id contract.ID, selection *contract.ConsumerSelection) ([]contract.KeyUseRow, contract.CryptoResultCode) {
	rows, code := owner.publicationPrivateOwner.Prepare(ctx, id, selection)
	if code != contract.CryptoSuccess {
		return rows, code
	}
	return owner.reply(rows)
}

func publicationKeyUseFixture(t *testing.T, secret, metadataFirst bool) (*fixture, publicationInput, *publicationControlledPrivate) {
	t.Helper()
	configureMetadata := func(target *contract.OutputTarget) {
		target.Capabilities &^= contract.OutputCapabilityCreateWithValue
		target.Capabilities |= contract.OutputCapabilityCreateEmpty
		target.CreateValueBounds = contract.OutputPayloadBounds{}
		target.Capabilities &^= contract.OutputCapabilityCreateSetsPolicy
		target.Capabilities &^= contract.OutputCapabilityWriteSetsPolicy
		target.Capabilities |= contract.OutputCapabilityUpdatePolicy
	}
	if !secret {
		f, input, controlled := publicationEngineFixture(t)
		if metadataFirst {
			hermeticPublicationTargetFacts(t, f, configureMetadata)
		}
		return f, input, controlled
	}
	env := memoryScenarioEnvironment(t)
	initial := newEnvironmentFixture(t, t.Context(), env, nil, false)
	entries := []ApplyEntryInput{suppliedSecret(t, env, "secret", "publication source", custody.StandardValue)}
	target := publicationEngineTarget("secret", "publication")
	if metadataFirst {
		configureMetadata(&target.target)
	}
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}}}
	selected := selectAdmittedOutputConfiguration(t, t.Context(), initial.session, env, env.Custody, entries, output)
	selected.admission.publicationNamespaces = []publicationNamespace{{domain: env.Domain, service: "controlled-provider", physical: "publication", premise: fixtureID(env.Domain, "independent namespace")}}
	f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: OpenContext{admission: &selected.admission}, session: selected}
	input := publicationInput{names: []string{"secret"}, acting: selected.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	return f, input, newPublicationControlledPrivate()
}

// full_only: false
func TestPublicationPrepareKeyUses(t *testing.T) {
	for _, name := range []string{
		"secret_completed", "secret_missing", "secret_duplicate", "wrong_binding", "wrong_digest",
		"wrong_subject_kind", "wrong_subject", "wrong_provider", "wrong_purpose", "zero_count", "extra_count",
		"denied_success", "failed_success", "unknown_success", "unknown_result_code", "changed_owner_instance",
		"plain_zero", "plain_extra", "metadata_zero", "metadata_extra",
	} {
		t.Run(name, func(t *testing.T) {
			secret := name != "plain_zero" && name != "plain_extra" && name != "metadata_zero" && name != "metadata_extra"
			f, input, controlled := publicationKeyUseFixture(t, secret, name == "metadata_zero" || name == "metadata_extra")
			if !attachLocalObservation(&input.observation, f.session, true) {
				t.Fatal("publication observation admission")
			}
			private := controlled.callbacks()
			newOwner := private.NewOwner
			private.NewOwner = func(ctx context.Context, in publicationOwnerInput) (publicationPrivateOwner, error) {
				owner, err := newOwner(ctx, in)
				if err != nil {
					return nil, err
				}
				return &publicationKeyUseOwner{publicationPrivateOwner: owner, reply: func(rows []contract.KeyUseRow) ([]contract.KeyUseRow, contract.CryptoResultCode) {
					code := contract.CryptoSuccess
					if name == "plain_extra" || name == "metadata_extra" {
						binding := *f.session.recipientRecord(input.acting).CurrentBinding
						digest, err := contract.PublicBindingDigest(binding)
						if err != nil {
							t.Fatal("expected public binding", err)
						}
						rows = []contract.KeyUseRow{{BindingID: binding.BindingID, PublicBindingDigest: digest, SubjectKind: contract.OrdinaryWrapSubject, SubjectID: input.acting, Provider: binding.Provider, Purpose: contract.KeyUseMaterialOpen, Outcome: contract.KeyUseCompleted, Count: 1}}
					}
					switch name {
					case "secret_missing":
						rows = nil
					case "secret_duplicate":
						rows = append(rows, rows[0])
					case "wrong_binding":
						rows[0].BindingID[0] ^= 1
					case "wrong_digest":
						rows[0].PublicBindingDigest[0] ^= 1
					case "wrong_subject_kind":
						rows[0].SubjectKind = contract.RecoveryWrapSubject
					case "wrong_subject":
						rows[0].SubjectID[0] ^= 1
					case "wrong_provider":
						rows[0].Provider = contract.GCP
						if f.session.admission.store.Family == contract.GCP {
							rows[0].Provider = contract.AWS
						}
					case "wrong_purpose":
						rows[0].Purpose = contract.KeyUseMaterialWrap
					case "zero_count":
						rows[0].Count = 0
					case "extra_count":
						rows[0].Count = 2
					case "denied_success":
						rows[0].Outcome = contract.KeyUseDenied
					case "failed_success":
						rows[0].Outcome = contract.KeyUseFailed
					case "unknown_success":
						rows[0].Outcome = contract.KeyUseUnknown
					case "unknown_result_code":
						code = 0
					case "changed_owner_instance":
						owner.(*publicationControlledOwner).id[0] ^= 1
					}
					return rows, code
				}}, nil
			}
			plan, state := f.session.planPublication(t.Context(), input, private)
			if plan == nil || state.Outcome != ObservedCurrent {
				t.Fatal("publication plan", state)
			}
			beforeCreates, beforeCAS := f.store.creates, f.store.cas
			got := plan.execute(t.Context(), private, publicationEngineCurrent(f))
			accepted := name == "secret_completed" || name == "plain_zero" || name == "metadata_zero"
			if accepted {
				if got.summary != contract.PublicationSummaryComplete {
					t.Fatal("valid preparation refused", got.state)
				}
				for _, owner := range controlled.owners {
					if owner.prepared != 1 || owner.armed != 1 || owner.sent != 1 || owner.retired != 1 {
						t.Fatal("accepted action lifecycle", owner)
					}
				}
				return
			}
			if got.output.Entries[0].Actions[0].Disposition != contract.PublicationNotSent || got.state.Reason == NoReason || len(controlled.owners) != 1 {
				t.Fatal("unchecked preparation accepted", got.state)
			}
			facts, status := input.observation.read()
			if len(facts) != 0 || status.Accepted != 0 {
				t.Fatal("rejected preparation supplied trusted key-use evidence", status)
			}
			owner := controlled.owners[0]
			if owner.prepared != 1 || owner.armed != 0 || owner.sent != 0 || owner.retired != 1 {
				t.Fatal("rejected preparation lifecycle", owner)
			}
			if f.store.creates != beforeCreates || f.store.cas != beforeCAS {
				t.Fatal("rejected preparation reached persistence")
			}
			selected := publicationEngineReopen(t, f)
			if _, exists := selected.markers[plan.targets[0].attempts[0]]; exists {
				t.Fatal("rejected preparation selected a marker")
			}
		})
	}
	t.Run("observation", publicationPrepareObservation)
	t.Run("owner_acquisition", publicationOwnerAcquisition)
}

func publicationPrepareObservation(t *testing.T) {
	for _, name := range []string{"secret", "plain", "metadata", "denied", "failed", "unknown", "completed_then_failed", "failed_before_use", "cancelled_after_use", "persistence_failure", "disabled", "busy", "full", "fresh_invocation"} {
		t.Run(name, func(t *testing.T) {
			f, input, controlled := publicationKeyUseFixture(t, name != "plain", name == "metadata")
			var observation *operationObservation
			if !attachLocalObservation(&observation, f.session, name != "disabled") {
				t.Fatal("publication observation admission")
			}
			input.observation = observation
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if name == "fresh_invocation" {
				controlled.evidence = contract.PublicationUnproved
			}
			private := controlled.callbacks()
			newOwner := private.NewOwner
			var returned [][]contract.KeyUseRow
			private.NewOwner = func(ctx context.Context, in publicationOwnerInput) (publicationPrivateOwner, error) {
				owner, err := newOwner(ctx, in)
				if err != nil {
					return nil, err
				}
				return &publicationKeyUseOwner{publicationPrivateOwner: owner, reply: func(rows []contract.KeyUseRow) ([]contract.KeyUseRow, contract.CryptoResultCode) {
					code := contract.CryptoSuccess
					switch name {
					case "denied":
						rows[0].Outcome, code = contract.KeyUseDenied, contract.CryptoPrivateRouteUnavailable
					case "failed":
						rows[0].Outcome, code = contract.KeyUseFailed, contract.CryptoCustodyUnavailable
					case "unknown":
						rows[0].Outcome, code = contract.KeyUseUnknown, contract.CryptoResponseUnknown
					case "completed_then_failed":
						code = contract.CryptoStoredAuthenticationFailed
					case "failed_before_use":
						rows, code = nil, contract.CryptoInvalidAdmission
					case "cancelled_after_use":
						cancel()
					}
					returned = append(returned, rows)
					return rows, code
				}}, nil
			}
			plan, state := f.session.planPublication(ctx, input, private)
			if plan == nil || state.Outcome != ObservedCurrent {
				t.Fatal("observed publication plan", state)
			}
			if name == "persistence_failure" {
				f.store.createMode = "conflict"
			}
			if name == "busy" {
				observation.collector.mu.Lock()
			}
			if name == "full" {
				observation.collector.storedBytes = observationRetainedLimit()
			}
			beforeCreates, beforeCAS := f.store.creates, f.store.cas
			got := plan.execute(ctx, private, publicationEngineCurrent(f))
			if name == "busy" {
				observation.collector.mu.Unlock()
			}
			failed := name == "denied" || name == "failed" || name == "unknown" || name == "completed_then_failed" || name == "failed_before_use" || name == "cancelled_after_use" || name == "persistence_failure"
			if failed {
				if got.output.Entries[0].Actions[0].Disposition != contract.PublicationNotSent || len(controlled.owners) != 1 || controlled.owners[0].armed != 0 || controlled.owners[0].sent != 0 || controlled.owners[0].retired != 1 || f.store.cas != beforeCAS {
					t.Fatal("failed preparation acquired publication rights", got.state)
				}
				if name != "persistence_failure" && f.store.creates != beforeCreates {
					t.Fatal("failed preparation reached persistence")
				}
			} else {
				wantSummary := uint8(contract.PublicationSummaryComplete)
				if name == "fresh_invocation" {
					wantSummary = contract.PublicationSummaryUnknown
				}
				if got.summary != wantSummary {
					t.Fatal("observation changed publication outcome", got.state)
				}
			}
			facts, status := observation.read()
			if name == "disabled" || name == "busy" || name == "full" {
				if len(facts) != 0 || status.Accepted != 0 || name == "busy" && status.DroppedContention != 1 || name == "full" && status.DroppedFull != 1 {
					t.Fatal("collector loss changed retention policy", status)
				}
				return
			}
			if len(facts) != len(controlled.owners) || status.Accepted != uint64(len(facts)) || status.Rejected != 0 {
				t.Fatal("checked Prepare exchange was lost", status)
			}
			binding := plan.targets[0].selection.Binding
			digest, err := contract.PublicBindingDigest(binding.Binding)
			if err != nil {
				t.Fatal("expected publication binding digest", err)
			}
			for i, fact := range facts {
				attempt := plan.targets[0].attempts[i]
				wantSource := observationSource{Stage: observationExchange, DomainID: f.session.root.Domain, OperationID: plan.operation, AttemptID: attempt}
				var expectedRows []contract.KeyUseRow
				action := controlled.owners[i].input.Projection.Action
				if name != "plain" && name != "failed_before_use" && (action == contract.PublicationCreateWithValue || action == contract.PublicationWriteValue) {
					outcome := uint8(contract.KeyUseCompleted)
					if name == "denied" {
						outcome = contract.KeyUseDenied
					}
					if name == "failed" {
						outcome = contract.KeyUseFailed
					}
					if name == "unknown" {
						outcome = contract.KeyUseUnknown
					}
					expectedRows = []contract.KeyUseRow{{BindingID: binding.Binding.BindingID, PublicBindingDigest: digest, SubjectKind: binding.SubjectKind, SubjectID: binding.SubjectID, Provider: binding.Binding.Provider, Purpose: contract.KeyUseMaterialOpen, Outcome: outcome, Count: 1}}
				}
				wantCode := contract.CryptoSuccess
				switch name {
				case "denied":
					wantCode = contract.CryptoPrivateRouteUnavailable
				case "failed":
					wantCode = contract.CryptoCustodyUnavailable
				case "unknown":
					wantCode = contract.CryptoResponseUnknown
				case "completed_then_failed":
					wantCode = contract.CryptoStoredAuthenticationFailed
				case "failed_before_use":
					wantCode = contract.CryptoInvalidAdmission
				}
				if fact.Change != nil || fact.Exchange == nil || fact.Exchange.Source != wantSource || fact.Exchange.RequestID != attempt || fact.Exchange.CustodyInstanceID != controlled.owners[i].id || fact.Exchange.Kind != contract.CryptoPrepare || fact.Exchange.ResultCode != wantCode || !reflect.DeepEqual(fact.Exchange.Rows, expectedRows) {
					t.Fatal("publication exchange did not retain exact checked facts")
				}
			}
			for _, rows := range returned {
				if len(rows) != 0 {
					rows[0].Count = 99
					rows[0].BindingID[0] ^= 1
				}
			}
			again, _ := observation.read()
			if !reflect.DeepEqual(facts, again) {
				t.Fatal("publication observation borrowed private reply rows")
			}
			if name == "fresh_invocation" {
				publicationEngineReopen(t, f)
				input.observation = nil
				input.republish = map[contract.ID][]contract.ID{plan.targets[0].coordinate: {got.output.Entries[0].Actions[0].AttemptID}}
				controlled.evidence = contract.PublicationRequestAcknowledged
				next, state := f.session.planPublication(t.Context(), input, controlled.callbacks())
				if next == nil {
					t.Fatal("fresh publication plan", state)
				}
				completed := next.execute(t.Context(), controlled.callbacks(), publicationEngineCurrent(f))
				if completed.summary != contract.PublicationSummaryComplete || len(controlled.owners) != 2 {
					t.Fatal("fresh publication did not perform a new action", completed.state)
				}
				last, lastStatus := observation.read()
				if !reflect.DeepEqual(facts, last) || status != lastStatus {
					t.Fatal("returned session reused the earlier publication collector")
				}
			}
		})
	}
}

func publicationOwnerAcquisition(t *testing.T) {
	for _, name := range []string{"owner_error", "zero_instance", "owner_error_retire_failure", "zero_instance_retire_failure", "owner_error_cancelled", "zero_instance_cancelled", "nil_owner_error"} {
		t.Run(name, func(t *testing.T) {
			f, input, controlled := publicationEngineFixture(t)
			if !attachLocalObservation(&input.observation, f.session, true) {
				t.Fatal("publication observation admission")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			retired := make(chan struct{})
			controlled.configureOwner = func(owner *publicationControlledOwner) {
				owner.onRetire = func() { close(retired) }
				if name == "owner_error_retire_failure" || name == "zero_instance_retire_failure" {
					owner.retireError = errors.New("controlled disposal failure")
				}
			}
			private := controlled.callbacks()
			newOwner := private.NewOwner
			private.NewOwner = func(ctx context.Context, in publicationOwnerInput) (publicationPrivateOwner, error) {
				if name == "nil_owner_error" {
					return nil, errors.New("controlled acquisition failure")
				}
				owner, err := newOwner(ctx, in)
				if err != nil {
					t.Fatal("controlled acquisition", err)
				}
				zero := name == "zero_instance" || name == "zero_instance_retire_failure" || name == "zero_instance_cancelled"
				if zero {
					owner.(*publicationControlledOwner).id = contract.ID{}
				}
				if name == "owner_error_cancelled" || name == "zero_instance_cancelled" {
					cancel()
				}
				if !zero {
					return owner, errors.New("controlled acquisition failure")
				}
				return owner, nil
			}
			plan, state := f.session.planPublication(ctx, input, private)
			if plan == nil || state.Outcome != ObservedCurrent {
				t.Fatal("publication acquisition plan", state)
			}
			beforeCreates, beforeCAS := f.store.creates, f.store.cas
			got := plan.execute(ctx, private, publicationEngineCurrent(f))
			if got.state != refused(CustodyUnavailable) || got.output.Entries[0].Actions[0].Disposition != contract.PublicationNotSent {
				t.Fatal("failed owner acquisition gained publication rights", got.state)
			}
			if name == "nil_owner_error" {
				if len(controlled.owners) != 0 {
					t.Fatal("nil owner acquisition created a private lifetime")
				}
				select {
				case <-retired:
					t.Fatal("nil owner was retired")
				default:
				}
			} else {
				if len(controlled.owners) != 1 {
					t.Fatal("failed acquisition did not retain its exact owner")
				}
				owner := controlled.owners[0]
				if owner.prepared != 0 || owner.armed != 0 || owner.sent != 0 || owner.retired != 1 {
					t.Fatalf("failed acquisition lifecycle prepared=%d armed=%d sent=%d retired=%d", owner.prepared, owner.armed, owner.sent, owner.retired)
				}
				select {
				case <-retired:
				default:
					t.Fatal("failed acquisition returned before retirement completed")
				}
			}
			if (name == "owner_error_cancelled" || name == "zero_instance_cancelled") && ctx.Err() == nil {
				t.Fatal("acquisition cancellation did not reach the caller")
			}
			if f.store.creates != beforeCreates || f.store.cas != beforeCAS {
				t.Fatal("failed owner acquisition reached persistence")
			}
			facts, status := input.observation.read()
			if len(facts) != 0 || status.Accepted != 0 {
				t.Fatal("failed owner acquisition supplied checked use evidence", status)
			}
			selected := publicationEngineReopen(t, f)
			if _, exists := selected.markers[plan.targets[0].attempts[0]]; exists {
				t.Fatal("failed owner acquisition selected a marker")
			}
		})
	}
}
