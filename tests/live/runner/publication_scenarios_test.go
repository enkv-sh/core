package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/custody"
)

func livePublicationPolicy(profile records.OutputFixtureProfile, reduced bool) contract.OutputPolicy {
	if profile.Scope != "github-organization" {
		return contract.OutputPolicy{}
	}
	subjects := profile.GitHub.SelectedRepositoryIDs
	if reduced {
		subjects = subjects[:1]
	}
	data := []byte{0, 1, 3}
	data = binary.BigEndian.AppendUint16(data, uint16(len(subjects)))
	for _, subject := range subjects {
		data = binary.BigEndian.AppendUint64(data, subject)
	}
	return contract.OutputPolicy{ContractID: "github-actions/org-visibility/v1", Data: data}
}
func livePublicationProvider(scope string) string {
	switch scope {
	case "aws-secrets-manager":
		return "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1"
	case "gcp-secret-manager":
		return "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1"
	default:
		return "github-actions/service/v1"
	}
}
func livePublicationConfigContract(scope string) string {
	if scope == "aws-secrets-manager" {
		return "ENKV/OUTPUT/AWS-SECRETS-MANAGER/CONFIG/v1"
	}
	if scope == "gcp-secret-manager" {
		return "ENKV/OUTPUT/GCP-SECRET-MANAGER/CONFIG/v1"
	}
	return "github-actions/" + strings.TrimPrefix(scope, "github-") + "-config/v1"
}
func livePublicationCapabilities(scope string) contract.OutputActionCapabilities {
	if scope == "aws-secrets-manager" || scope == "gcp-secret-manager" {
		return (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot)
	}
	caps := (contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot)
	if scope == "github-organization" {
		caps |= contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy
	}
	return caps
}
func livePublicationJSON(value any) []byte {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return body
}

func livePublicationInitialActions(scope string) []uint8 {
	if scope == "aws-secrets-manager" || scope == "gcp-secret-manager" {
		return []uint8{contract.PublicationCreateEmpty, contract.PublicationWriteValue}
	}
	return []uint8{contract.PublicationCreateWithValue}
}

// Response resource identifiers are service-assigned facts. Check their exact
// relation before using the same opaque fact to correlate wire and selected ACK.
func livePublicationResource(profile string, action uint8, slot, owned, resource string, attempt contract.ID) bool {
	switch profile {
	case "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3":
		if action == contract.PublicationWriteValue {
			return resource == hex.EncodeToString(attempt[:])
		}
		if action == contract.PublicationCreateEmpty {
			if !strings.HasPrefix(resource, slot+"-") || len(resource) != len(slot)+7 {
				return false
			}
			for _, c := range resource[len(slot)+1:] {
				if c < '0' || c > '9' && c < 'A' || c > 'Z' && c < 'a' || c > 'z' {
					return false
				}
			}
			return true
		}
		return owned != "" && resource == owned
	case "ENKV/OUTPUT/GCP-SECRET-MANAGER/v3":
		if action == contract.PublicationWriteValue {
			prefix := slot + "/versions/"
			if !strings.HasPrefix(resource, prefix) {
				return false
			}
			version := strings.TrimPrefix(resource, prefix)
			number, err := strconv.ParseInt(version, 10, 64)
			return err == nil && number > 0 && strconv.FormatInt(number, 10) == version
		}
		return resource == slot
	case "ENKV/OUTPUT/GITHUB-REPOSITORY/v3", "ENKV/OUTPUT/GITHUB-ORGANIZATION/v3", "ENKV/OUTPUT/GITHUB-ENVIRONMENT/v3":
		return resource == slot
	}
	return false
}

type livePublicationScenario struct {
	*publicationScenario
	runtime *livePublicationRuntime
	births  map[contract.ID]livePublicationBirth
	markers map[contract.ID]livePublicationActionExpectation
	reduced bool
	changed bool
	removed bool
}

type livePublicationBirth struct {
	attempt, binding, entry, row contract.ID
	instance, locator            string
}

type livePublicationTargetExpectation struct {
	profile records.OutputFixtureProfile
	input   records.OutputFixtureTarget
	target  contract.OutputTarget
	id      contract.ID
	actions []livePublicationActionExpectation
}

type livePublicationActionExpectation struct {
	projection contract.PublicationProjection
	outcome    contract.PublicationOutcome
}

// Validated fixture allocations end in one secret-name component. This name
// is an entry identity; no prefix or slot override is offered to a native profile.
func livePublicationEntryName(target records.OutputFixtureTarget) string {
	return target.PlannedSlot[strings.LastIndexAny(target.PlannedSlot, "/:")+1:]
}

func livePublicationDestination(profile records.OutputFixtureProfile, reduced bool) contract.OutputDestination {
	d := contract.OutputDestination{ConfigContractID: livePublicationConfigContract(profile.Scope), ServiceContractID: livePublicationProvider(profile.Scope), Policy: livePublicationPolicy(profile, reduced), Capabilities: livePublicationCapabilities(profile.Scope)}
	if cloud := profile.Cloud; cloud != nil {
		if profile.Scope == "aws-secrets-manager" {
			d.CanonicalSettings = livePublicationJSON(struct {
				Account string `json:"account"`
				Region  string `json:"region"`
			}{cloud.Account, cloud.Region})
		} else {
			d.CanonicalSettings = livePublicationJSON(struct {
				Project string `json:"project_number"`
			}{cloud.ProjectNumber})
		}
	} else if github := profile.GitHub; github != nil {
		d.CanonicalSettings = livePublicationJSON(struct {
			Owner       string `json:"owner"`
			Repository  string `json:"repository,omitempty"`
			Environment string `json:"environment,omitempty"`
		}{github.Owner, github.Repository, github.Environment})
	}
	return d
}

func (p *livePublicationScenario) output() *outputApplyInput {
	out := &outputApplyInput{}
	routes := make(map[string][]string)
	for _, profile := range p.runtime.input.Profiles {
		binding := outputApplyBinding{destinationID: "publication-" + profile.Scope, destination: livePublicationDestination(profile, p.reduced)}
		for _, target := range profile.Targets {
			name := livePublicationEntryName(target)
			binding.targets = append(binding.targets, outputApplyTarget{entryName: name, target: livePublicationTarget(profile, target, p.reduced)})
			routes[name] = append(routes[name], binding.destinationID)
		}
		out.bindings = append(out.bindings, binding)
	}
	slices.SortFunc(out.bindings, func(a, b outputApplyBinding) int { return strings.Compare(a.destinationID, b.destinationID) })
	for name, destinations := range routes {
		slices.Sort(destinations)
		out.routes = append(out.routes, outputApplyRoute{entryName: name, destinations: destinations})
	}
	slices.SortFunc(out.routes, func(a, b outputApplyRoute) int { return strings.Compare(a.entryName, b.entryName) })
	return out
}

// Both native-source callers use the same private admission and full cold open.
func selectLivePublicationEntries(t testing.TB, ctx context.Context, s *StateSession, env fixtureEnvironment, entries []ApplyEntryInput, output *outputApplyInput) *StateSession {
	t.Helper()
	s.admission.outputInterpreter = nil
	parent := admitSuppliedOutputComparisonWithInstalledProfiles(t, s, env.Custody, entries, output)
	c, result := s.compareWithOutput(ctx, entries, output, parent)
	if c == nil || result.Outcome != ObservedCurrent {
		t.Fatal("live output comparison", result)
	}
	candidate, result := s.Prepare(ctx, c, admit(t, s, c), env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("live output preparation", result)
	}
	env.Custody.RetireApply()
	if result = s.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("live output selection", result)
	}
	return generatedLifecycleReopen(t, ctx, s, env.Store)
}

func (p *livePublicationScenario) selectEntries(entries []ApplyEntryInput, output *outputApplyInput) {
	p.fixture.session = selectLivePublicationEntries(p.run.t, p.run.ctx, p.fixture.session, p.run.env, entries, output)
	p.fixture.admission = OpenContext{admission: &p.fixture.session.admission}
}

func livePublicationTarget(profile records.OutputFixtureProfile, target records.OutputFixtureTarget, reduced bool) contract.OutputTarget {
	t := contract.OutputTarget{ServiceContractID: livePublicationProvider(profile.Scope), CanonicalTarget: target.PlannedSlot, ConsumerLocator: target.ConsumerLocator, PayloadEncoding: contract.OutputEncodingRaw, Capabilities: livePublicationCapabilities(profile.Scope), Policy: livePublicationPolicy(profile, reduced)}
	name := livePublicationEntryName(target)
	switch profile.Scope {
	case "aws-secrets-manager":
		t.TargetContractID = "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1"
		t.TargetData = livePublicationJSON(struct {
			Account string `json:"account"`
			Region  string `json:"region"`
			Name    string `json:"name"`
		}{profile.Cloud.Account, profile.Cloud.Region, name})
		t.ConsumerLocator = ""
		t.LocatorRequiresCreation = true
		t.WriteValueBounds.Minimum = 1
		t.WriteValueBounds.Maximum = 65536
	case "gcp-secret-manager":
		t.TargetContractID = "ENKV/OUTPUT/GCP-SECRET-MANAGER/TARGET/v1"
		t.TargetData = livePublicationJSON(struct {
			Project string `json:"project_number"`
			Name    string `json:"name"`
		}{profile.Cloud.ProjectNumber, name})
		t.WriteValueBounds.Maximum = 65536
	default:
		t.TargetContractID = "github-actions/target/v1"
		scope := uint8(1)
		if profile.Scope == "github-organization" {
			scope = 2
		}
		if profile.Scope == "github-environment" {
			scope = 3
		}
		t.TargetData = livePublicationJSON(struct {
			Scope      uint8  `json:"scope"`
			Coordinate string `json:"coordinate"`
		}{scope, target.PlannedSlot})
		t.CreateValueBounds.Maximum = 48000
		t.WriteValueBounds.Maximum = 48000
	}
	return t
}

// The expected set and action chain come from the selected input and named
// lifecycle. The plan supplies only preallocated, opaque operation identities.
func (p *livePublicationScenario) expectations(plan *publicationPlan, stage string, laterRefusal bool) ([]livePublicationTargetExpectation, contract.PublicationOutcomeVector) {
	t := p.run.t
	var targets []livePublicationTargetExpectation
	for _, profile := range p.runtime.input.Profiles {
		for _, input := range profile.Targets {
			target := livePublicationTarget(profile, input, p.reduced)
			target.EntryIncarnationID = sessionConsumerSelection(t, plan.session, p.input.acting, livePublicationEntryName(input)).Entry.Incarnation
			targets = append(targets, livePublicationTargetExpectation{profile: profile, input: input, target: target, id: publicationExpectedCoordinate(p.run.env.Domain, target.ServiceContractID, target.CanonicalTarget)})
		}
	}
	slices.SortFunc(targets, func(a, b livePublicationTargetExpectation) int { return bytes.Compare(a.id[:], b.id[:]) })
	if len(plan.targets) != len(targets) {
		t.Fatal("publication plan omitted or added a target")
	}
	vector := contract.PublicationOutcomeVector{Schema: 2, DomainID: p.run.env.Domain, OperationID: plan.operation, SnapshotID: plan.session.root.Snapshot, SelectionDigest: sha256.Sum256(plan.session.body)}
	for i := range targets {
		want, actual := &targets[i], plan.targets[i]
		var actions []uint8
		switch stage {
		case "initial":
			actions = livePublicationInitialActions(want.profile.Scope)
		case "value":
			actions = []uint8{contract.PublicationWriteValue}
		case "policy":
			actions = []uint8{contract.PublicationUpdatePolicy}
		case "delete":
			actions = []uint8{contract.PublicationDeleteOwned}
		case "noop":
		default:
			t.Fatal("unknown fixed publication stage")
		}
		if actual.coordinate != want.id || actual.destination != "publication-"+want.profile.Scope || actual.refusal != 0 || len(actual.blockers) != 0 || !slices.Equal(actual.actions, actions) || len(actual.attempts) != len(actions) {
			t.Fatalf("publication planned lifecycle differs at target %d", i)
		}
		entry := contract.PublicationTargetOutcome{CoordinateID: want.id}
		if len(actions) == 0 {
			if !reflect.DeepEqual(actual.target, want.target) {
				t.Fatal("publication no-op changed target meaning")
			}
			entry.Actions = []contract.PublicationOutcome{{Disposition: contract.PublicationNoOp}}
		}
		birth := p.births[want.id]
		if stage == "initial" {
			if !actual.retained.OwnedBirthAttemptID.IsZero() || !birth.attempt.IsZero() {
				t.Fatal("fresh publication inherited ownership")
			}
			birth.attempt = actual.attempts[0]
		} else if birth.attempt.IsZero() || actual.retained.OwnedBirthAttemptID != birth.attempt || actual.binding != birth.binding || want.target.EntryIncarnationID != birth.entry || actual.retained.DeletionTargetRowDigest != birth.row {
			t.Fatal("publication changed its qualified birth or frozen deletion inputs")
		}
		for j, action := range actions {
			projection, commitment, response := publicationExpectedProjection(t, plan, actual, action, want.target, birth.attempt, birth.row)
			status := uint16(200)
			if want.target.ServiceContractID == "github-actions/service/v1" {
				status = 204
				if action == contract.PublicationCreateWithValue {
					status = 201
				}
			}
			outcome := contract.PublicationOutcome{Action: action, ProjectionCommitment: commitment, AttemptID: actual.attempts[j], Disposition: contract.PublicationOutcomeAcknowledged, RemoteValueMayRemain: 1, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationRequestAcknowledged, ResponseContractDigest: response, NormalizedStatus: status}}
			if laterRefusal && i > 0 {
				outcome = contract.PublicationOutcome{Action: action, ProjectionCommitment: commitment, Disposition: contract.PublicationNotSent, CoreReason: uint16(AdmissionInvalid)}
			}
			want.actions = append(want.actions, livePublicationActionExpectation{projection: projection, outcome: outcome})
			entry.Actions = append(entry.Actions, outcome)
		}
		vector.Entries = append(vector.Entries, entry)
	}
	return targets, vector
}

func (p *livePublicationScenario) verifySelected(session *StateSession) {
	t := p.run.t
	selected, err := selectedPublicationRelation(session.selectedImage())
	if err != nil || len(selected.coordinates) != 2*len(p.runtime.input.Profiles) {
		t.Fatal("publication selected coordinate set differs")
	}
	for _, profile := range p.runtime.input.Profiles {
		for _, target := range profile.Targets {
			id := publicationExpectedCoordinate(p.run.env.Domain, livePublicationProvider(profile.Scope), target.PlannedSlot)
			coordinate, present := selected.coordinates[id]
			bindingState := uint8(contract.PublicationBindingActive)
			if p.removed {
				bindingState = contract.PublicationBindingRetired
			}
			if !present || coordinate.ServiceContractID != livePublicationProvider(profile.Scope) || coordinate.CanonicalTarget != target.PlannedSlot || coordinate.BindingState != bindingState {
				t.Fatal("publication coordinate identity or binding state differs")
			}
			if _, owned := p.births[id]; !owned {
				if coordinate.OwnerState != contract.PublicationOwnerNone || !coordinate.OwnedBirthAttemptID.IsZero() || !coordinate.OwnedInstanceDigest.IsZero() || !coordinate.DeletionTargetRowDigest.IsZero() || coordinate.PossibleRemoteObject != 0 || coordinate.LateEffectRisk != 0 || coordinate.LastAdmissionOrdinal != 0 || !coordinate.LatestUnresolvedAttemptID.IsZero() {
					t.Fatal("unsent publication acquired an effect or ownership")
				}
			} else if coordinate.DeletionDestinationID != "publication-"+profile.Scope || coordinate.DeletionConsumerLocator != p.births[id].locator || coordinate.DeletionConfigContractID != livePublicationConfigContract(profile.Scope) || coordinate.DeletionPayloadEncoding != contract.OutputEncodingRaw {
				t.Fatal("publication retained deletion inputs differ")
			}
		}
	}
	for attempt, expected := range p.markers {
		marker, found := selected.markers[attempt]
		if !found || marker.State != contract.PublicationAcknowledged || marker.Projection != expected.projection || marker.ProjectionCommitment != expected.outcome.ProjectionCommitment || marker.Evidence != expected.outcome.Evidence || marker.LateEffectRisk != 0 {
			t.Fatal("publication selected ACK differs from qualified fixed action")
		}
	}
	if len(selected.markers) != len(p.markers) {
		t.Fatal("publication selected an unexpected marker")
	}
	for id, birth := range p.births {
		coordinate := selected.coordinates[id]
		body := make([]byte, 0, 256)
		for _, value := range []contract.ID{p.run.env.Domain, id, birth.binding, birth.entry, birth.row, birth.attempt} {
			body = append(body, value[:]...)
		}
		owned := publicationExpectedHash("ENKV/PUBLICATION/OWNED-INSTANCE/v2", publicationExpectedBlob(body, []byte(birth.instance)))
		if coordinate.OwnerState != contract.PublicationOwnerQualified || coordinate.OwnedBirthAttemptID != birth.attempt || coordinate.OwnedInstanceDigest != owned || coordinate.DeletionTargetRowDigest != birth.row || coordinate.LastBindingIncarnationID != birth.binding || coordinate.LastEntryIncarnationID != birth.entry || coordinate.PossibleRemoteObject != 1 || coordinate.LateEffectRisk != 0 || !coordinate.LatestUnresolvedAttemptID.IsZero() {
			t.Fatal("publication selected ownership or uncertainty differs")
		}
	}
}

func (p *livePublicationScenario) acceptWire(plan *publicationPlan, targets []livePublicationTargetExpectation, vector *contract.PublicationOutcomeVector, start int) {
	t := p.run.t
	p.runtime.recorder.mu.Lock()
	observations := slices.Clone(p.runtime.recorder.observations[start:])
	p.runtime.recorder.mu.Unlock()
	n := 0
	for i, target := range targets {
		birth := p.births[target.id]
		for j, expected := range target.actions {
			if expected.outcome.Disposition != contract.PublicationOutcomeAcknowledged {
				continue
			}
			if n >= len(observations) {
				t.Fatal("publication lacks a required native result")
			}
			observation := observations[n]
			n++
			dispatch, result := observation.Dispatch, observation.Result
			action, attempt := expected.outcome.Action, expected.outcome.AttemptID
			if observation.Index != target.input.Index || observation.Code != contract.CryptoSuccess || contract.ValidatePublicationResult(dispatch, result) != nil || dispatch.Schema != 4 || dispatch.DomainID != p.run.env.Domain || dispatch.OperationID != plan.operation || dispatch.AttemptID != attempt || dispatch.CoordinateID != target.id || dispatch.Projection != expected.projection || dispatch.ProjectionCommitment != expected.outcome.ProjectionCommitment || dispatch.ResponseContractDigest != expected.outcome.Evidence.ResponseContractDigest || dispatch.AuthoritySubjectDigest.IsZero() || dispatch.ExecutorID != hex.EncodeToString(plan.targets[i].facts.ExecutorID[:]) || dispatch.CredentialRouteID != target.profile.Native.CredentialRouteID {
				t.Fatalf("native publication correlation differs at target %d action %d", i, action)
			}
			resource := result.Evidence.SafeResourceID
			if !livePublicationResource(target.profile.ProfileID, action, target.input.PlannedSlot, birth.instance, resource, attempt) {
				t.Fatalf("native publication resource differs at target %d action %d", i, action)
			}
			wantLocator := ""
			if action == contract.PublicationCreateEmpty || action == contract.PublicationCreateWithValue {
				wantLocator = target.target.ConsumerLocator
				if target.target.LocatorRequiresCreation {
					wantLocator = resource + "?stage=AWSCURRENT"
				}
			}
			if result.Evidence.ConsumerLocator != wantLocator {
				t.Fatal("native publication creation locator differs from exact acknowledged birth")
			}
			expected.outcome.Evidence.SafeResourceID = resource
			expected.outcome.Evidence.ConsumerLocator = result.Evidence.ConsumerLocator
			if result.Evidence != expected.outcome.Evidence {
				t.Fatalf("native publication evidence differs at target %d action %d", i, action)
			}
			vector.Entries[i].Actions[j] = expected.outcome
			p.markers[attempt] = expected
			if action == contract.PublicationCreateEmpty || action == contract.PublicationCreateWithValue {
				birth = livePublicationBirth{attempt: attempt, binding: expected.projection.BindingIncarnationID, entry: expected.projection.EntryIncarnationID, row: expected.projection.TargetRowDigest, instance: resource, locator: result.Evidence.ConsumerLocator}
				p.births[target.id] = birth
			}
		}
	}
	if n != len(observations) {
		t.Fatal("publication made an unexpected native send")
	}
	inventory, err := records.ReadOutputFixtureInventory(p.runtime.input.InventoryPath, p.runtime.input.Scope)
	if err != nil {
		t.Fatal("publication durable inventory unavailable")
	}
	for _, target := range targets {
		row, err := inventory.Row(target.input.Index, target.profile.ProfileID, target.input.PlannedSlot)
		birth := p.births[target.id]
		if err != nil || row.OwnedInstance != birth.instance || row.BirthAttemptID != livePublicationIDText(birth.attempt) {
			t.Fatal("publication durable ownership differs from native birth")
		}
		for _, expected := range target.actions {
			if expected.outcome.Disposition != contract.PublicationOutcomeAcknowledged {
				continue
			}
			found := false
			for _, receipt := range row.Attempts {
				if receipt.AttemptID == hex.EncodeToString(expected.outcome.AttemptID[:]) {
					found = receipt.Action == expected.outcome.Action && receipt.Outcome == "acknowledged"
				}
			}
			if !found {
				t.Fatal("publication durable action receipt differs")
			}
		}
	}
}

func livePublicationIDText(id contract.ID) string {
	if id.IsZero() {
		return ""
	}
	return hex.EncodeToString(id[:])
}

func (p *livePublicationScenario) execute(stage string, laterRefusal bool) {
	t := p.run.t
	before := sessionStateImage(t, p.fixture.session)
	owners, retired, start, recorderErr := p.runtime.recorder.state()
	checks, preparations := p.runtime.checks.Load(), p.runtime.preparations.Load()
	calls, privateCalls := p.run.env.Custody.Calls()
	effects := p.run.spy.scenarioEffects
	if recorderErr != nil || owners != retired {
		t.Fatal("previous publication owner has not completed")
	}
	ctx, cancel := context.WithCancel(p.run.ctx)
	defer cancel()
	plan, state := p.fixture.session.planPublication(ctx, p.input, p.runtime.private)
	if plan == nil || state.Outcome != ObservedCurrent {
		t.Fatal("live publication complete plan refused", state)
	}
	targets, want := p.expectations(plan, stage, laterRefusal)
	current := p.current
	stopped := false
	if laterRefusal {
		firstActions := len(targets[0].actions)
		current = func(operationCtx context.Context) (*StateSession, contract.Trust, Result) {
			ownerCount, retiredCount, sends, err := p.runtime.recorder.state()
			if !stopped && err == nil && sends-start == firstActions && ownerCount == retiredCount {
				firstVector := want
				p.acceptWire(plan, targets[:1], &firstVector, start)
				session, _, state := p.current(p.run.ctx)
				if session == nil || state.Outcome != ObservedCurrent {
					t.Fatal("first publication checkpoint unavailable")
				}
				p.verifySelected(session)
				stopped = true
				cancel()
			}
			return p.current(operationCtx)
		}
	}
	got := plan.execute(ctx, p.runtime.private, current)
	p.acceptWire(plan, targets, &want, start)
	summary := uint8(contract.PublicationSummaryComplete)
	if laterRefusal {
		summary = contract.PublicationSummaryMixedTerminal
		if !stopped || got.state != refused(AdmissionInvalid) {
			t.Fatal("later publication admission did not refuse after joined ACK chain")
		}
	} else if stage == "noop" {
		summary = contract.PublicationSummaryNoChange
	}
	assertPublicationScenarioVector(t, got, want, summary)
	p.reopen()
	p.verifySelected(p.fixture.session)
	after := sessionStateImage(t, p.fixture.session)
	if !reflect.DeepEqual(before.Pages, after.Pages) || !reflect.DeepEqual(before.Recipient, after.Recipient) || !reflect.DeepEqual(before.Access, after.Access) || before.Root.OutputConfiguration != after.Root.OutputConfiguration {
		t.Fatal("publication changed selected values, recipients, access or configuration")
	}
	newOwners, newRetired, sends, recorderErr := p.runtime.recorder.state()
	expectedSends := 0
	for _, target := range targets {
		for _, action := range target.actions {
			if action.outcome.Disposition == contract.PublicationOutcomeAcknowledged {
				expectedSends++
			}
		}
	}
	if recorderErr != nil || newOwners-owners != uint64(expectedSends) || newRetired-retired != uint64(expectedSends) || sends-start != expectedSends {
		t.Fatal("publication native owner or send count differs")
	}
	if stage == "noop" {
		afterCalls, afterPrivateCalls := p.run.env.Custody.Calls()
		if calls != afterCalls || privateCalls != afterPrivateCalls || checks != p.runtime.checks.Load() || preparations != p.runtime.preparations.Load() || effects.StoreCreate != p.run.spy.StoreCreate || effects.StoreCAS != p.run.spy.StoreCAS || effects.TrustSign != p.run.spy.TrustSign {
			t.Fatal("publication no-op made private or selected work")
		}
	}
	// The native host returns only after its own staging and child join finish.
	// Other cases can use the same admitted assembly directory concurrently.

}

const liveConsumerObservationCeiling = 10 * time.Minute
const liveConsumerObservationInterval = 5 * time.Second
const liveConsumerObservationRounds = 121

type liveConsumerFailure struct {
	Stage          string             `json:"stage"`
	Row            uint32             `json:"row"`
	Actor          liveOutputConsumer `json:"actor"`
	Attempts       int                `json:"attempts"`
	ElapsedSeconds float64            `json:"elapsed_seconds"`
	HTTPStatus     int                `json:"http_status"`
	AccessRefused  bool               `json:"access_refused"`
	CurrentMatch   bool               `json:"current_match"`
	PriorMatch     bool               `json:"prior_match"`
	Length         int                `json:"length"`
	Cause          string             `json:"cause"`
}

func waitLiveConsumerObservation(ctx context.Context) bool {
	timer := time.NewTimer(liveConsumerObservationInterval)
	defer timer.Stop()
	select {
	case <-timer.C:
		return ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}

func (p *livePublicationScenario) consumers() {
	if failure := p.observeConsumers(waitLiveConsumerObservation); failure != nil {
		path := filepath.Join(filepath.Dir(p.runtime.input.InventoryPath), "output-consumer-failure.json")
		if records.WriteJSON(path, failure, 0600) != nil {
			p.run.t.Fatal("publication consumer failure facts could not be saved")
		}
		p.run.t.Fatal("publication consumer observation failed")
	}
}

// Acknowledged writes and policies do not prove current consumer visibility.
// Recheck the complete set; a prior successful row cannot satisfy a later round.
func (p *livePublicationScenario) observeConsumers(pause func(context.Context) bool) *liveConsumerFailure {
	started := time.Now()
	ctx, cancel := context.WithTimeout(p.run.ctx, liveConsumerObservationCeiling)
	defer cancel()
	values := [][]byte{[]byte("private data"), []byte("enkv first secret test value")}
	var prior [][]byte
	stage := "initial"
	if p.changed {
		prior = values
		values = [][]byte{[]byte("updated plain data"), []byte("enkv other secret test value")}
		stage = "value"
	}
	facts := liveConsumerFailure{Stage: stage}
	stop := func(cause string) *liveConsumerFailure {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			cause = "deadline"
		} else if ctx.Err() != nil {
			cause = "canceled"
		}
		facts.ElapsedSeconds, facts.Cause = time.Since(started).Seconds(), cause
		return &facts
	}
	manifest, err := p.consumerManifest(ctx)
	if err != nil {
		return stop("manifest_failed")
	}
	byName := make(map[string]liveConsumerManifestEntry, len(manifest))
	for _, entry := range manifest {
		byName[entry.Name] = entry
	}
	for _, entry := range p.entries {
		row, present := byName[entry.Name]
		if !present {
			return stop("manifest_incomplete")
		}
		if entry.ConfidentialityClass == contract.Plain && (row.Content.Kind != "plain" || !bytes.Equal(row.Content.Plain, values[0])) {
			return stop("inline_plain_mismatch")
		}
	}
	for round := 1; round <= liveConsumerObservationRounds; round++ {
		if ctx.Err() != nil {
			return stop("canceled")
		}
		var pending *liveConsumerFailure
		for _, profile := range p.runtime.profiles {
			if profile.cloud == nil {
				continue
			}
			for i, target := range profile.input.Targets {
				if i == 0 {
					continue
				}
				row := byName[livePublicationEntryName(target)]
				var locator, encoding string
				for _, destination := range row.Content.Destinations {
					if destination.Destination == "publication-"+profile.input.Scope {
						locator, encoding = destination.Locator, destination.Encoding
					}
				}
				if row.Content.Kind != "secret" || locator == "" || encoding != "raw" {
					return stop("manifest_locator_unusable")
				}
				maximum := len(values[i])
				if prior != nil {
					maximum = max(maximum, len(prior[i]))
				}
				for _, consumer := range []liveOutputConsumer{liveOutputConsumerA, liveOutputConsumerB} {
					if ctx.Err() != nil {
						return stop("canceled")
					}
					read, err := profile.cloud.ReadConsumer(ctx, consumer, locator, uint32(maximum))
					facts = liveConsumerFailure{Stage: stage, Row: target.Index, Actor: consumer, Attempts: round,
						AccessRefused: read.AccessRefused, CurrentMatch: bytes.Equal(read.Bytes, values[i]), Length: len(read.Bytes)}
					if read.HTTPStatus >= 100 && read.HTTPStatus <= 599 {
						facts.HTTPStatus = read.HTTPStatus
					}
					if prior != nil {
						facts.PriorMatch = bytes.Equal(read.Bytes, prior[i])
					}
					clear(read.Bytes)
					if err != nil {
						return stop("read_failed")
					}
					if ctx.Err() != nil {
						return stop("canceled")
					}
					matches := !read.AccessRefused && facts.CurrentMatch
					retry := read.AccessRefused && facts.Length == 0 || !read.AccessRefused && facts.PriorMatch && p.changed
					if !matches && !retry {
						return stop("unexpected_result")
					}
					if !matches && pending == nil {
						copy := facts
						pending = &copy
					}
				}
			}
		}
		if ctx.Err() != nil {
			return stop("canceled")
		}
		if pending == nil {
			return nil
		}
		facts = *pending
		if round == liveConsumerObservationRounds {
			return stop("round_limit")
		}
		if !pause(ctx) {
			return stop("observation_stopped")
		}
	}
	return stop("round_limit")
}

func (p *livePublicationScenario) refuseInheritedPolicy() {
	t := p.run.t
	profile := p.runtime.input.Profiles[0]
	for _, target := range profile.Targets {
		invalid := livePublicationTarget(profile, target, false)
		invalid.Policy = contract.OutputPolicy{ContractID: "unsupported-policy/v1", Data: []byte{1}}
		before := p.run.spy.scenarioEffects
		owners, retired, sends, prior := p.runtime.recorder.state()
		preparations := p.runtime.preparations.Load()
		_, err := p.runtime.private.Check(p.run.ctx, publicationActionCheckInput{DestinationID: "publication-" + profile.Scope, ConfigContractID: livePublicationConfigContract(profile.Scope), DomainID: p.run.env.Domain, Action: contract.PublicationWriteValue, Target: invalid, Deadline: p.input.deadline})
		afterOwners, afterRetired, afterSends, afterErr := p.runtime.recorder.state()
		if err == nil || prior != nil || afterErr != nil || owners != afterOwners || retired != afterRetired || sends != afterSends || preparations != p.runtime.preparations.Load() || before.StoreCreate != p.run.spy.StoreCreate || before.StoreCAS != p.run.spy.StoreCAS || before.TrustSign != p.run.spy.TrustSign {
			t.Fatal("inherited profile admitted unsupported per-secret policy")
		}
	}
}

func runLivePublicationScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, name string, input *records.OutputFixtureInput, budget *runBudget) {
	t.Helper()
	selected, known := catalog.LivePublication(name)
	deadline, finite := ctx.Deadline()
	if !known || input == nil || !finite {
		t.Fatal("live publication scenario admission unavailable")
	}
	p := &livePublicationScenario{publicationScenario: &publicationScenario{run: newScenarioRun(t, ctx, env)}, births: make(map[contract.ID]livePublicationBirth), markers: make(map[contract.ID]livePublicationActionExpectation)}
	p.run.phase("setup", func() {
		p.fixture = newEnvironmentFixture(t, p.run.ctx, p.run.env, []int{1}, false)
		var err error
		p.runtime, err = newLivePublicationRuntime(p.run.ctx, input, budget, p.run.env.Custody, deadline)
		if err != nil {
			t.Fatal("selected named publication runtime refused")
		}
		p.runtime.bindEnvironment = t.Setenv
		seenNames := make(map[string]bool)
		for _, profile := range input.Profiles {
			for role, target := range profile.Targets {
				name := livePublicationEntryName(target)
				if !seenNames[name] {
					seenNames[name] = true
					entry := ApplyEntryInput{Name: name, Recipients: []contract.ID{p.fixture.admission.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("private data"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
					if role == 1 {
						entry = suppliedSecret(t, p.run.env, name, "live publication source "+name, custody.StandardValue)
					}
					p.entries = append(p.entries, entry)
				}
				encoded, err := hex.DecodeString(target.ExclusiveNamespaceDigest)
				if err != nil || len(encoded) != 32 {
					t.Fatal("publication namespace premise unavailable")
				}
				p.fixture.admission.admission.publicationNamespaces = append(p.fixture.admission.admission.publicationNamespaces, publicationNamespace{domain: env.Domain, service: livePublicationProvider(profile.Scope), physical: target.PlannedSlot, premise: contract.ID(encoded)})
			}
		}
		p.fixture.session.admission.publicationNamespaces = p.fixture.admission.admission.publicationNamespaces
		slices.SortFunc(p.entries, func(a, b ApplyEntryInput) int { return strings.Compare(a.Name, b.Name) })
		p.selectEntries(p.entries, p.output())
		var names []string
		for _, entry := range p.entries {
			names = append(names, entry.Name)
		}
		p.input = publicationInput{names: names, acting: p.fixture.admission.admission.recipient, deadline: deadline}
	})
	p.run.phase("transition", func() {
		p.execute("initial", selected.Condition == "later-member-refusal")
		if selected.Condition == "later-member-refusal" {
			return
		}
		p.consumers()
		if selected.Condition == "plain-secret-lifecycle" {
			before, state := p.fixture.session.currentOutputConfigurationForApply(p.run.ctx)
			if state.Outcome != 0 {
				t.Fatal("publication configuration unavailable before value change")
			}
			for i, entry := range p.entries {
				if entry.ConfidentialityClass == contract.Plain {
					p.entries[i].InputBytes = []byte("updated plain data")
				} else {
					p.entries[i] = suppliedSecret(t, p.run.env, entry.Name, "live publication updated source "+entry.Name, custody.AlternateStandardValue)
				}
			}
			p.selectEntries(p.entries, nil)
			after, state := p.fixture.session.currentOutputConfigurationForApply(p.run.ctx)
			if state.Outcome != 0 || !reflect.DeepEqual(before, after) {
				t.Fatal("value change altered publication binding")
			}
			p.changed = true
			p.execute("value", false)
			p.consumers()
		}
		p.execute("noop", false)
		if selected.Condition == "plain-secret-lifecycle" {
			if selected.Scope != "github-organization" {
				p.refuseInheritedPolicy()
			} else {
				p.reduced = true
				p.selectEntries(p.entries, p.output())
				p.execute("policy", false)
				p.consumers()
			}
			p.execute("noop", false)
		}
		p.selectEntries(p.entries, &outputApplyInput{})
		p.removed = true
		p.input.names = nil
		for _, profile := range input.Profiles {
			for _, target := range profile.Targets {
				p.input.deletes = append(p.input.deletes, publicationExpectedCoordinate(env.Domain, livePublicationProvider(profile.Scope), target.PlannedSlot))
			}
		}
		p.execute("delete", false)
	})
	p.run.phase("verification", func() {
		p.reopen()
		p.verifySelected(p.fixture.session)
		want := []byte("private data")
		choice := uint8(custody.StandardValue)
		if p.changed {
			want, choice = []byte("updated plain data"), custody.AlternateStandardValue
		}
		for _, entry := range p.entries {
			selected := sessionConsumerSelection(t, p.fixture.session, p.input.acting, entry.Name)
			if entry.ConfidentialityClass == contract.Plain {
				if !bytes.Equal(selected.Entry.ValueBytes, want) {
					t.Fatal("publication canonical plain value differs")
				}
				continue
			}
			if env.ReserveCustody != nil && !env.ReserveCustody("consume", 1) {
				t.Fatal("publication canonical consumer budget refused")
			}
			check := env.Custody.Consume(p.run.ctx, selected, choice)
			if check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 || check.SinkCalls != 1 {
				t.Fatal("publication canonical secret value differs")
			}
		}
	})
	p.run.phase("reopen", func() {
		if p.run.env.FreshCurrent == nil {
			t.Fatal("publication fresh observer unavailable")
		}
		p.run.env.FreshCurrent(t, p.fixture.admission, p.fixture.session)
	})
}
