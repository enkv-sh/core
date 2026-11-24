package core

import (
	"bytes"
	"context"
	"encoding/hex"
	records "enkv.sh/core/internal/testrecords"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

type packagedPublicationTarget struct {
	name, plugin, object string
	destination          contract.OutputDestination
}

func packagedPublicationTargets(family contract.Family) []packagedPublicationTarget {
	cloud := "aws-secrets-manager"
	if family == contract.GCP {
		cloud = "gcp-secret-manager"
	}
	scopes := []string{cloud}
	if family == contract.AWS {
		scopes = append(scopes, "github-environment", "github-organization", "github-repository")
	}
	rows := make([]packagedPublicationTarget, 0, len(scopes))
	for _, scope := range scopes {
		digit := "0"
		if scope == "gcp-secret-manager" {
			digit = "4"
		}
		if scope == "github-environment" {
			digit = "1"
		}
		if scope == "github-organization" {
			digit = "2"
		}
		if scope == "github-repository" {
			digit = "3"
		}
		name := "ENKV_" + strings.Repeat(digit, 64) + "_SECRET"
		profile := records.OutputFixtureProfile{Scope: scope}
		object := ""
		switch scope {
		case "aws-secrets-manager":
			profile.Cloud = &records.OutputFixtureCloud{Provider: "aws", Account: "123456789012", Region: "us-east-1"}
			object = "aws:arn:aws:secretsmanager:us-east-1:123456789012:secret:" + name + "-AbCd12"
		case "gcp-secret-manager":
			profile.Cloud = &records.OutputFixtureCloud{Provider: "gcp", ProjectNumber: "123456789"}
			object = "gcp:projects/123456789/secrets/" + name
		default:
			profile.GitHub = &records.OutputFixtureGitHub{Owner: "owner"}
			if scope == "github-organization" {
				profile.GitHub.SelectedRepositoryIDs = []uint64{7, 11}
				object = "github:orgs/owner/actions/secrets/" + name
			} else {
				profile.GitHub.Repository = "repo"
				object = "github:repos/owner/repo/actions/secrets/" + name
			}
			if scope == "github-environment" {
				profile.GitHub.Environment = "prod"
				object = "github:repos/owner/repo/environments/prod/secrets/" + name
			}
		}
		plugin := scope
		if strings.HasPrefix(scope, "github-") {
			plugin = "github-actions-" + strings.TrimPrefix(scope, "github-")
		}
		rows = append(rows, packagedPublicationTarget{name, plugin, object, livePublicationDestination(profile, false)})
	}
	return rows
}

func packagedSequenceObserve(f installedApplyTestFixture, observation *packagedSequenceObservation, commands *[]packagedSequenceCommand, label string) func() {
	public, private := f.keys.Calls()
	startWrite, startSign, startRead := len(observation.writes), len(observation.signs), observation.reads
	return func() {
		afterPublic, afterPrivate := f.keys.Calls()
		*commands = append(*commands, packagedSequenceCommand{Label: label, WriteStart: startWrite, WriteEnd: len(observation.writes), SignStart: startSign, SignEnd: len(observation.signs), Reads: observation.reads - startRead, QualificationCalls: afterPublic - public, DecryptCalls: afterPrivate - private})
	}
}

func packagedPublicationSequence(t *testing.T, ctx context.Context, f *installedApplyTestFixture, observation *packagedSequenceObservation, commands *[]packagedSequenceCommand, builds map[string]packagedOutputPair, server *packagedPublicationServer) {
	t.Helper()
	destinations := make(map[string]custody.PublicationConfig)
	for _, row := range packagedPublicationTargets(f.env.Trust.Family()) {
		destinations[row.name] = builds[row.plugin].first
	}
	interpret := packagedOutputInterpreter(destinations)
	validator := NewPublicConfigurationValidator(interpret)
	var opened Result
	f.admitted, opened = admitPublicNormal(ctx, f.env.Domain, f.env.Store.Descriptor(), f.basis, f.env.Store, f.composition, interpret)
	if opened.Outcome != ObservedCurrent {
		t.Fatal("publication fixture profile admission", opened)
	}
	reopen := func() *StateSession {
		selected, result := Open(ctx, f.admitted, f.env.Store)
		if selected == nil || result.Outcome != ObservedCurrent {
			t.Fatal("publication selected read", result)
		}
		return selected
	}
	selected := reopen()
	rows := packagedPublicationTargets(f.env.Trust.Family())
	readers := []contract.ID{selected.registry()[0].RecipientID, selected.registry()[1].RecipientID}
	slices.SortFunc(readers, compareGeneratedIDs)
	targets := map[string]contract.OutputTarget{}
	var names, objects []string
	for _, row := range rows {
		target, err := interpret(ctx, row.name, row.destination, row.name, contract.OutputEncodingRaw)
		if err != nil {
			t.Fatal(err)
		}
		targets[row.name] = target
		names = append(names, row.name)
		objects = append(objects, row.object)
	}
	first, second := f.keys.ForkGenerated(t), f.keys.ForkGenerated(t)
	for _, row := range rows {
		pair := builds[row.plugin]
		if err := first.InstallPublication(ctx, pair.first, row.name, row.destination.ConfigContractID); err != nil {
			t.Fatal(err)
		}
		if err := second.InstallPublication(ctx, pair.second, row.name, row.destination.ConfigContractID); err != nil {
			t.Fatal(err)
		}
	}
	applyOutputs := func(label string, entries []ApplyEntryInput, bindings []contract.PublicOutputBinding, routes []contract.PublicRoutingRule, wantDecrypts int) {
		selected = reopen()
		configuration := installedApplyTestConfiguration(t, ctx, selected, entries, currentApplyRecipients(selected.registry()), validator)
		configuration.OutputBindings = observedPublicField(bindings)
		configuration.Routing = observedPublicField(routes)
		engine, err := NewInstalledApply(ApplyInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(), PublicBasis: f.basis, ExpectedControl: currentControlOf(selected), DesiredRecipients: currentApplyRecipients(selected.registry()), PublicConfiguration: configuration, ConfigurationValidator: validator, Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition, FileIdentity: fixtureID(f.env.Domain, "source-file"), CloseInstalled: func() {},
			AdmitCustody: func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warning uint8, deadline time.Time) (*InstalledApplyCustody, error) {
				owner, err := f.keys.NewApplyCustody(q, control, current, fixtureID(f.env.Domain, "source-file"), plain, support, witness, revision, before, warning, deadline)
				if err != nil {
					return nil, err
				}
				return &InstalledApplyCustody{Crypto: owner, BindReceipt: owner.BindReceipt, Close: owner.Close}, nil
			}})
		if err != nil {
			t.Fatal("publication supplied construction", err)
		}
		finish := packagedSequenceObserve(*f, observation, commands, label)
		got := engine.Apply(ctx, fixtureID(f.env.Domain, label), entries)
		engine.Close()
		finish()
		command := (*commands)[len(*commands)-1]
		if got.Result.Outcome != ObservedCurrent || command.SignEnd-command.SignStart != 1 || command.DecryptCalls != wantDecrypts || command.QualificationCalls != 0 {
			t.Fatal("publication supplied Apply", got.Result)
		}
		selected = reopen()
		if selected.root.ValueEntryCount != uint32(len(rows)) || selected.root.Generated.GeneratedCurrent != 0 {
			t.Fatal("publication supplied state shape")
		}
	}
	apply := func(label, value string, choice uint8, wantDecrypts int) {
		selected = reopen()
		entries := make([]ApplyEntryInput, len(rows))
		bindings := make([]contract.PublicOutputBinding, len(rows))
		routes := make([]contract.PublicRoutingRule, len(rows))
		expected := map[string][]byte{}
		finishSource := packagedSequenceObserve(*f, observation, commands, label+"-source")
		for at, row := range rows {
			entries[at] = suppliedSecret(t, f.env, row.name, label+"/"+row.name, choice, readers...)
			target := targets[row.name]
			bindings[at] = contract.PublicOutputBinding{DestinationID: row.name, Destination: observedPublicField(row.destination), Targets: observedPublicField([]contract.PublicOutputTarget{livePublicOutputTarget(row.name, target)})}
			routes[at] = contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: row.name}, Destinations: observedPublicField([]string{row.name})}
			expected[row.object] = []byte(value)
		}
		finishSource()
		sourceCommand := (*commands)[len(*commands)-1]
		if sourceCommand.QualificationCalls != 0 || sourceCommand.DecryptCalls != 0 || sourceCommand.SignEnd != sourceCommand.SignStart || sourceCommand.WriteEnd != sourceCommand.WriteStart {
			t.Fatal("local source sealing acquired a remote effect", sourceCommand)
		}
		applyOutputs(label, entries, bindings, routes, wantDecrypts)
		server.expect("123456789012", expected)
	}
	publish := func(label string, keys *custody.Fixture, useSecond, cleanup bool, wantActions, wantOpens, wantRequests int) {
		selected = reopen()
		var request PublicationRequest
		if cleanup {
			relation, err := selectedPublicationRelation(selected.selectedImage())
			if err != nil {
				t.Fatal(err)
			}
			for id := range relation.coordinates {
				request.DeleteCoordinates = append(request.DeleteCoordinates, id)
			}
			slices.SortFunc(request.DeleteCoordinates, compareGeneratedIDs)
		} else {
			request.Names = slices.Clone(names)
		}
		private := publicationCustodyPrivate(keys)
		engine, err := NewInstalledPublication(PublicationInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(), PublicBasis: f.basis, ExpectedControl: currentControlOf(selected), Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition, CloseInstalled: func() {},
			Namespace: func(domain contract.ID, target contract.OutputTarget) (contract.ID, error) {
				for _, expected := range targets {
					if target.ServiceContractID == expected.ServiceContractID && target.CanonicalTarget == expected.CanonicalTarget {
						return fixtureID(domain, "controlled exclusive "+target.ServiceContractID+"/"+target.CanonicalTarget), nil
					}
				}
				return contract.ID{}, contract.ErrRecord
			},
			SelectPolicyAction: func(ctx context.Context, in PublicationPolicyActionInput) (uint8, error) {
				return private.SelectPolicyAction(ctx, publicationPolicyActionInput(in))
			},
			Actions: func(ctx context.Context, input PublicationExecutionInput) (PublicationActionFacts, error) {
				facts, err := private.Actions(ctx, publicationExecutionInput(input))
				return PublicationActionFacts(facts), err
			},
			Check: func(ctx context.Context, input PublicationActionCheckInput) (PublicationActionCheckFacts, error) {
				facts, err := private.Check(ctx, publicationActionCheckInput(input))
				return PublicationActionCheckFacts(facts), err
			},
			NewOwner: func(ctx context.Context, input PublicationOwnerInput) (PublicationPrivateOwner, error) {
				return private.NewOwner(ctx, publicationOwnerInput{Projection: input.Projection, DestinationID: input.DestinationID, Target: input.Target, Coordinate: input.Coordinate, Birth: input.Birth, UncertainCreate: input.UncertainCreate, ConfigContractID: input.ConfigContractID, ActionCheck: publicationActionCheckFacts(input.ActionCheck), Deadline: input.Deadline})
			},
		})
		if err != nil {
			t.Fatal("publication construction", err)
		}
		server.mu.Lock()
		beforeRequests := server.requests
		server.mu.Unlock()
		finish := packagedSequenceObserve(*f, observation, commands, label)
		got := engine.Publish(ctx, fixtureID(f.env.Domain, label), request)
		engine.Close()
		finish()
		command := (*commands)[len(*commands)-1]
		server.mu.Lock()
		requests := server.requests - beforeRequests
		server.mu.Unlock()
		if got.Result.Outcome != ObservedCurrent || got.Output == nil || got.Summary != contract.PublicationSummaryComplete || command.SignEnd-command.SignStart != 2*wantActions || command.DecryptCalls != wantOpens || command.QualificationCalls != 0 || requests != wantRequests {
			t.Fatal("fixed publication counts/outcome", label, got.Result, got.Summary, command, requests)
		}
		selected = reopen()
		relation, err := selectedPublicationRelation(selected.selectedImage())
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Output.Entries) != len(rows) {
			t.Fatal("publication omitted or added a target")
		}
		actions := 0
		seen := map[contract.ID]bool{}
		for _, targetResult := range got.Output.Entries {
			if seen[targetResult.CoordinateID] {
				t.Fatal("publication repeated a coordinate")
			}
			seen[targetResult.CoordinateID] = true
			coordinate, ok := relation.coordinates[targetResult.CoordinateID]
			if !ok {
				t.Fatal("publication result coordinate absent")
			}
			rowAt := slices.IndexFunc(rows, func(row packagedPublicationTarget) bool {
				return targets[row.name].ServiceContractID == coordinate.ServiceContractID && targets[row.name].CanonicalTarget == coordinate.CanonicalTarget
			})
			if rowAt < 0 {
				t.Fatal("publication coordinate differs from independently selected target")
			}
			row := rows[rowAt]
			config := builds[row.plugin].first
			if useSecond {
				config = builds[row.plugin].second
			}
			expectedActions := []uint8{contract.PublicationWriteValue}
			if cleanup {
				expectedActions = []uint8{contract.PublicationDeleteOwned}
			} else if !useSecond {
				expectedActions = []uint8{contract.PublicationCreateWithValue}
				if row.plugin == "aws-secrets-manager" || row.plugin == "gcp-secret-manager" {
					expectedActions = []uint8{contract.PublicationCreateEmpty, contract.PublicationWriteValue}
				}
			}
			if len(targetResult.Actions) != len(expectedActions) {
				t.Fatal("publication action set differs", label, row.name)
			}
			for at, action := range targetResult.Actions {
				marker, present := relation.markers[action.AttemptID]
				response, err := contract.PublicationResponseContractDigest(marker.Projection.RequestContractDigest, contract.ID(config.Artifact.ArtifactContractID))
				if !present || err != nil || action.Action != expectedActions[at] || action.Disposition != contract.PublicationOutcomeAcknowledged || marker.OperationID != got.OperationID || marker.State != contract.PublicationAcknowledged || marker.ProjectionCommitment != action.ProjectionCommitment || marker.CoordinateID != targetResult.CoordinateID || marker.ExecutorID != hex.EncodeToString(config.Artifact.ExecutorID[:]) || marker.CredentialRouteID != hex.EncodeToString(config.Artifact.CredentialRouteID[:]) || marker.Evidence != action.Evidence || marker.Evidence.ResponseContractDigest != response {
					t.Fatal("publication authenticated exact implementation evidence", label, row.name)
				}
				actions++
			}
		}
		if actions != wantActions {
			t.Fatal("publication action count differs", actions, wantActions)
		}
		server.checkValues(t, objects, cleanup)
	}
	retireBindings := func() {
		selected = reopen()
		prior := make(map[string]contract.ValueEntry, len(rows))
		for _, row := range rows {
			_, prior[row.name] = observeCurrentValueEntry(t, selected, row.name)
		}
		before, err := selectedPublicationRelation(selected.selectedImage())
		if err != nil || len(before.coordinates) != len(rows) {
			t.Fatal("publication binding retirement predecessor", err)
		}
		server.mu.Lock()
		beforeRequests := server.requests
		server.mu.Unlock()
		applyOutputs("outputs-retire", installedApplyCurrentInput(selected), nil, nil, len(rows))
		after, err := selectedPublicationRelation(selected.selectedImage())
		if err != nil || len(after.coordinates) != len(before.coordinates) {
			t.Fatal("publication binding retirement lost a coordinate", err)
		}
		for id, old := range before.coordinates {
			current, present := after.coordinates[id]
			old.BindingState = contract.PublicationBindingRetired
			old.ActiveBindingIncarnationID = contract.ID{}
			if !present || !reflect.DeepEqual(current, old) {
				t.Fatal("publication binding retirement changed owned effect facts")
			}
		}
		for _, row := range rows {
			_, current := observeCurrentValueEntry(t, selected, row.name)
			if !reflect.DeepEqual(current, prior[row.name]) {
				t.Fatal("publication binding retirement changed a supplied value")
			}
		}
		server.mu.Lock()
		requests := server.requests - beforeRequests
		server.mu.Unlock()
		if requests != 0 {
			t.Fatal("publication binding retirement entered a native output")
		}
		server.checkValues(t, objects, false)
	}
	apply("outputs-A-apply", "enkv first secret test value", custody.StandardValue, 2*len(rows))
	if f.env.Trust.Family() == contract.AWS {
		publish("outputs-A-publish", first, false, false, 5, 4, 9)
	} else {
		publish("outputs-A-publish", first, false, false, 2, 1, 2)
	}
	before := make(map[string][]byte, len(rows))
	for _, row := range rows {
		_, entry := observeCurrentValueEntry(t, selected, row.name)
		before[row.name] = bytes.Clone(entry.ValueBytes)
	}
	apply("outputs-B-apply", "enkv other secret test value", custody.AlternateStandardValue, 3*len(rows))
	for _, row := range rows {
		_, entry := observeCurrentValueEntry(t, selected, row.name)
		if bytes.Equal(entry.ValueBytes, before[row.name]) {
			t.Fatal("B supplied value did not change")
		}
	}
	if f.env.Trust.Family() == contract.AWS {
		publish("outputs-B-publish", second, true, false, 4, 4, 7)
		retireBindings()
		publish("outputs-cleanup", second, true, true, 4, 0, 4)
	} else {
		publish("outputs-B-publish", second, true, false, 1, 1, 1)
		retireBindings()
		publish("outputs-cleanup", second, true, true, 1, 0, 2)
	}
	f.selected = selected
}

func packagedPublicationCandidateCharges(t *testing.T, family contract.Family) {
	server := newPackagedPublicationServer(t)
	buildContext, buildCancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer buildCancel()
	builds := packagedOutputBuilds(t, buildContext, server.server.URL)
	buildCancel()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	var fixture installedApplyTestFixture
	var observation *packagedSequenceObservation
	var commands []packagedSequenceCommand
	wantResults, wantRequests, wantKeyScopes := uint64(6), 20, 3
	if family == contract.AWS {
		fixture, observation, commands = packagedGeneratedSequence(t, ctx)
	} else {
		fixture = newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
		if len(fixture.selected.registry()) != 2 {
			t.Fatal("GCP publication fixture does not have exactly two recipients")
		}
		observation = &packagedSequenceObservation{t: t, domain: fixture.env.Domain, writes: make([]packagedSequenceWrite, 0, 4096), signs: make([]packagedSequenceSign, 0, 128), heads: make([]packagedSequenceHead, 0, 128)}
		fixture.env.Store = packagedSequenceStore{Store: fixture.env.Store, observation: observation}
		fixture.env.Trust = packagedSequenceTrust{QualifyingTrust: fixture.env.Trust.(contract.QualifyingTrust), observation: observation}
		wantResults, wantRequests, wantKeyScopes = 0, 5, 0
	}
	packagedPublicationSequence(t, ctx, &fixture, observation, &commands, builds, server)
	packagedSequenceEvidence(t, ctx, fixture, observation, commands, wantResults)
	server.mu.Lock()
	defer server.mu.Unlock()
	wantIdentityReads := 0
	if family == contract.AWS {
		wantIdentityReads = 1
	}
	if server.identityReads != wantIdentityReads {
		t.Fatal("publication AWS account qualification count differs")
	}
	if len(server.keyReads) != wantKeyScopes {
		t.Fatal("publication GitHub key scope count differs")
	}
	for _, count := range server.keyReads {
		if count != 2 {
			t.Fatal("publication GitHub key read count differs")
		}
	}
	if server.requests != wantRequests || len(server.objects) != 0 || len(server.violations) != 0 {
		t.Fatal("complete publication request/cleanup facts differ", server.requests, len(server.objects), server.violations)
	}
}
