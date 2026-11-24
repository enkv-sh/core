package core

import (
	"bytes"
	"context"
	manifestsdk "enkv.sh/sdk/manifest-generator"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Only the tests supply uncaptured typed requests to the private projector.
// Production Manifest captures once before native admission.
func manifestSelectionForTest(ctx context.Context, selected publicSelection, request contract.ManifestRequest) (*manifestsdk.Projection, readerFailure) {
	owned, err := contract.OwnManifestRequest(hermeticManifestRequest(request))
	if err != nil {
		var invalid contract.ManifestRequestError
		if errors.As(err, &invalid) {
			return nil, manifestInputFailure(invalid.Reason)
		}
		return nil, manifestInputFailure(contract.ReasonInvalidInput)
	}
	return buildOwnedManifestSelection(ctx, selected, owned)
}

func manifestFixture(t *testing.T, routes bool, defaultOnly ...bool) (*ReaderEngine, publicSelection, *StateSession, fixtureEnvironment, contract.ID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newNamedEnvironmentFixture(t, ctx, env, []int{0, 3}, false, []string{"", "a/\n雪"})
	authority, target := f.session.admission.recipient, fixtureID(env.Domain, "reader")
	members := []contract.ID{authority, target}
	slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	entries := f.session.currentEntryInputs()
	for i := range entries {
		entries[i].Recipients = members
	}
	entries[1].InputBytes = []byte{0, 10, 65}
	entries = append(entries, sharingSecret(t, env, "manifest secret", members), sharingSecretNamed(t, env, "unselected", "manifest extra secret", members))
	output := &outputApplyInput{bindings: []outputApplyBinding{
		{destinationID: "primary", targets: []outputApplyTarget{outputConfigurationTarget("secret", "primary-secret"), outputConfigurationTarget("unselected", "primary-unselected")}},
		{destinationID: "secondary", targets: []outputApplyTarget{outputConfigurationTarget("secret", "secondary-secret")}},
	}}
	// Policy bytes belong to the fixture service, not the Reader.
	output.bindings[0].targets[0].target.Policy = hermeticNumberPolicy("fixture/numbers/v1", []uint64{3, 7})
	output.bindings[0].targets[1].target.Policy = output.bindings[0].targets[0].target.Policy
	output.bindings[1].targets[0].target.Policy = hermeticTextPolicy("fixture/text/v1", []string{"consumer-one", "consumer-two"})
	output.routes = []outputApplyRoute{
		{entryName: "secret", destinations: []string{}},
		{entryName: "unselected", destinations: []string{"primary"}},
	}
	if routes {
		output.routes[0].destinations = []string{"primary", "secondary"}
	}
	if len(defaultOnly) != 0 && defaultOnly[0] {
		output.bindings = output.bindings[:1]
		for _, plain := range []struct{ name, slot string }{{"", "primary-empty"}, {"a/\n雪", "primary-plain"}} {
			target := outputConfigurationTarget(plain.name, plain.slot)
			target.target.Policy = output.bindings[0].targets[0].target.Policy
			output.bindings[0].targets = append(output.bindings[0].targets, target)
		}
		output.routes = []outputApplyRoute{{defaultRoute: true, destinations: []string{"primary"}}}
	}
	for i := range output.bindings[0].targets {
		output.bindings[0].targets[i].target.ServiceContractID = "private/reader-service/v1"
	}
	s := selectAdmittedOutputConfiguration(t, ctx, f.session, env, keys, entries, output)
	e, _, _ := readerEngineFixture(t, env, s)
	inv, failure := e.beginReaderInvocation(ctx, contract.ReaderManifestOperation, contract.Hash([]byte("manifest fixture request")))
	if failure.Outcome != 0 {
		t.Fatal(failure)
	}
	t.Cleanup(inv.Close)
	selected, failure := inv.loadPublicSelection(ctx, contract.ReaderManifestOperation, inv.admission.request, nil)
	if failure.Outcome != 0 {
		t.Fatal(failure)
	}

	return e, selected, s, env, target
}

// full_only: false
func TestManifestSelectionPreservesCompleteMixedProjection(t *testing.T) {
	_, selected, s, env, target := manifestFixture(t, true)
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	public, private := env.Custody.Calls()
	request := contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{"secret", "a/\n雪", ""}}
	got, failure := manifestSelectionForTest(env.operationContext(), selected, request)
	if failure.Outcome != 0 || got == nil {
		t.Fatal("mixed projection", failure)
	}
	entryID := func(name string) manifestsdk.ID {
		for _, row := range s.root.Names {
			if row.Name == name {
				return manifestsdk.ID(s.valueEntry(row.Slot).Incarnation)
			}
		}
		t.Fatal("fixture name missing")
		return manifestsdk.ID{}
	}
	configuration, result := s.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 {
		t.Fatal(result)
	}
	bindingID := func(name string) manifestsdk.ID {
		for _, row := range configuration.Bindings {
			if row.DestinationID == name {
				return manifestsdk.ID(row.IncarnationID)
			}
		}
		t.Fatal("fixture binding missing")
		return manifestsdk.ID{}
	}
	primaryPolicyDigest := independentManifestPolicyDigest(env.Domain, "fixture/numbers/v1", []byte("3,7"))
	secondaryPolicyDigest := independentManifestPolicyDigest(env.Domain, "fixture/text/v1", []byte(`["consumer-one","consumer-two"]`))
	want := &manifestsdk.Projection{Schema: manifestsdk.Schema, FormatContractID: "ENKV/CONSUMPTION-MANIFEST/v3", ConfigContractID: "ENKV/CONSUMPTION-MANIFEST-CONFIG/v1", Settings: []byte(`{}`),
		Observation: manifestsdk.Observation{DomainID: manifestsdk.ID(env.Domain), HEADRevisionID: manifestsdk.ID(s.head.Core.Revision), SnapshotID: manifestsdk.ID(s.root.Snapshot)}, TargetRecipientID: manifestsdk.ID(target),
		Selection:       manifestsdk.Selection{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames},
		ResolvedEntries: []manifestsdk.EntryIdentity{{Name: "", EntryIncarnationID: entryID("")}, {Name: "a/\n雪", EntryIncarnationID: entryID("a/\n雪")}, {Name: "secret", EntryIncarnationID: entryID("secret")}}, ExcludedEntries: []manifestsdk.ExcludedEntry{},
		Entries: []manifestsdk.Entry{
			{Name: "", EntryIncarnationID: entryID(""), Kind: contract.Plain, PlainValue: []byte{}},
			{Name: "a/\n雪", EntryIncarnationID: entryID("a/\n雪"), Kind: contract.Plain, PlainValue: []byte{0, 10, 65}},
			{Name: "secret", EntryIncarnationID: entryID("secret"), Kind: contract.Secret, Destinations: []manifestsdk.Destination{
				{DestinationID: "primary", BindingIncarnationID: bindingID("primary"), EntryIncarnationID: entryID("secret"), ServiceContractID: "private/reader-service/v1", ConsumerLocator: "primary-secret?stage=AWSCURRENT", TargetContractID: "fixture/target/v1", CanonicalTarget: "primary-secret", TargetData: []byte("target:primary-secret"), PayloadEncoding: 1, PolicyPresent: true, PolicyContractID: "fixture/numbers/v1", PolicyData: []byte("3,7"), PolicyDigest: manifestsdk.ID(primaryPolicyDigest)},
				{DestinationID: "secondary", BindingIncarnationID: bindingID("secondary"), EntryIncarnationID: entryID("secret"), ServiceContractID: "aws", ConsumerLocator: "secondary-secret?stage=AWSCURRENT", TargetContractID: "fixture/target/v1", CanonicalTarget: "secondary-secret", TargetData: []byte("target:secondary-secret"), PayloadEncoding: 1, PolicyPresent: true, PolicyContractID: "fixture/text/v1", PolicyData: []byte(`["consumer-one","consumer-two"]`), PolicyDigest: manifestsdk.ID(secondaryPolicyDigest)},
			}},
		}}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("complete projection differs", got, want)
	}
	if cap(got.Entries) != len(got.Entries) || cap(got.Entries[2].Destinations) != 2 || cap(got.Entries[2].Destinations[0].PolicyData) != len(got.Entries[2].Destinations[0].PolicyData) || cap(got.Entries[2].Destinations[1].PolicyData) != len(got.Entries[2].Destinations[1].PolicyData) {
		t.Fatal("projection retains excess collection capacity")
	}
	for _, row := range configuration.Bindings {
		for _, output := range row.Targets {
			coordinate, err := contract.PublicationCoordinateID(env.Domain, output.ServiceContractID, output.CanonicalTarget)
			if err != nil {
				t.Fatal(err)
			}
			relation, err := selectedPublicationRelation(s.selectedImage())
			if err != nil || !relation.coordinates[coordinate].LastValueAckAttemptID.IsZero() {
				t.Fatal("fixture has publication acknowledgement", err)
			}
		}
	}
	request.EntryNames[0] = "caller changed"
	got.Entries[2].Destinations[0].PolicyData[0] = 99
	again, failure := manifestSelectionForTest(env.operationContext(), selected, contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{"secret"}})
	if failure.Outcome != 0 || again.Entries[0].Destinations[0].PolicyData[0] != '3' {
		t.Fatal("projection policy aliases selected state", failure)
	}
	for _, row := range selected.image.root.Names {
		if row.Name == "a/\n雪" {
			selected.image.valueEntry(row.Slot).ValueBytes[0] = 99
		}
	}
	if got.Entries[1].PlainValue[0] != 0 || got.Entries[2].Name != "secret" {
		t.Fatal("projection borrows mutable input")
	}
	if store.creates != creates || store.cas != cas {
		t.Fatal("manifest wrote state")
	}
	if p, q := env.Custody.Calls(); p != public || q != private {
		t.Fatal("manifest entered private custody")
	}
}

// full_only: false
func TestManifestSelectionRefusesWholeUnauthorizedOrInvalidSet(t *testing.T) {
	_, selected, _, env, target := manifestFixture(t, true)
	for _, name := range []string{"omitted-target", "omitted-selection", "unknown-target", "retired-target", "missing-binding", "duplicate", "unknown-first", "unknown-later", "plain-first", "plain-later", "secret-first", "secret-later"} {
		t.Run(name, func(t *testing.T) {
			request := contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{"", "secret"}}
			want := readerFailure{Result: refused(AdmissionInvalid), diagnostic: contract.ReasonTargetNotAuthorized}
			var restore func()
			switch name {
			case "omitted-target":
				want = readerFailure{Result: refused(InvalidIntent), diagnostic: contract.ReasonMissingRequiredField}
				request.TargetRecipientID = contract.ID{}
			case "omitted-selection":
				want = readerFailure{Result: refused(InvalidIntent), diagnostic: contract.ReasonMissingRequiredField}
				request.EntryNames = nil
			case "unknown-target":
				want.diagnostic = contract.ReasonTargetAbsent
				request.TargetRecipientID = contract.ID{99}
			case "retired-target", "missing-binding":
				want.diagnostic = contract.ReasonTargetAbsent
				row := selected.image.recipientRecord(target)
				old := *row
				restore = func() { *row = old }
				if name == "retired-target" {
					row.Status, row.CurrentBinding = contract.RetiredRecipient, nil
				} else {
					row.CurrentBinding = nil
				}
			case "duplicate":
				want = readerFailure{Result: refused(InvalidIntent), diagnostic: contract.ReasonDuplicateEntry}
				request.EntryNames = []string{"secret", "secret"}
			case "unknown-first":
				want = readerFailure{Result: refused(InvalidIntent), diagnostic: contract.ReasonEntryAbsent}
				request.EntryNames = []string{"!absent", "secret"}
			case "unknown-later":
				want = readerFailure{Result: refused(InvalidIntent), diagnostic: contract.ReasonEntryAbsent}
				request.EntryNames = []string{"secret", "~absent"}
			default:
				provider := "private/nonmatching-service/v1"
				request.ServiceFilter = &provider
				entryName := ""
				if name == "plain-later" {
					entryName = "a/\n雪"
					request.EntryNames = []string{"", "a/\n雪"}
				}
				if name == "secret-first" || name == "secret-later" {
					entryName = "secret"
				}
				for _, named := range selected.image.root.Names {
					if named.Name == entryName {
						row := selected.image.valueEntry(named.Slot)
						old := row.Recipients
						restore = func() { row.Recipients = old }
						row.Recipients = []contract.ID{selected.authorityID}
					}
				}
				if name == "secret-first" {
					request.EntryNames = []string{"secret", "unselected"}
				}
			}
			if restore != nil {
				defer restore()
			}
			got, failure := manifestSelectionForTest(env.operationContext(), selected, request)
			if got != nil || failure != want {
				t.Fatal("invalid whole selection exposed projection", got, failure)
			}
		})
	}
	empty, failure := manifestSelectionForTest(env.operationContext(), selected, contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{}})
	if failure.Outcome != 0 || empty == nil || empty.Entries == nil || len(empty.Entries) != 0 {
		t.Fatal("explicit empty selection", empty, failure)
	}
}

// full_only: false
func TestManifestSelectionRequiresEveryUsableSelectedLocator(t *testing.T) {
	for _, mode := range []string{"qualified", "no-birth", "unknown-create", "unselected-close"} {
		t.Run(mode, func(t *testing.T) {
			_, selected, f, env := opaqueManifestFixture(t, mode)
			got, failure := manifestSelectionForTest(env.operationContext(), selected, contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: f.session.admission.recipient, EntryNames: []string{"TOKEN"}})
			if mode == "qualified" {
				if failure.Outcome != 0 || got == nil {
					t.Fatal("qualified locator refused", failure)
				}
				return
			}
			if got != nil || failure.diagnostic != contract.ReasonLocatorUnusable {
				t.Fatal("unqualified locator exposed projection", got, failure)
			}
		})
	}
}

// full_only: false
func TestManifestSelectionKeepsFixedObservationAndRefusesRereadFailure(t *testing.T) {
	for _, name := range []string{"no-head-reread", "missing-second-pass", "invalid-second-pass", "filtered-missing-second-pass", "expired", "cancelled-empty"} {
		t.Run(name, func(t *testing.T) {
			_, selected, _, env, target := manifestFixture(t, true)
			store := env.Store.(*memoryStore)
			ctx := env.operationContext()
			request := contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{"", "secret"}}
			want := readerFailure{}
			if name == "filtered-missing-second-pass" {
				provider := "private/nonmatching-service/v1"
				request.ServiceFilter = &provider
			}
			if name == "expired" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
				want = readerFailure{Result: refused(AdmissionInvalid), diagnostic: contract.ReasonExpired}
			}
			if name == "cancelled-empty" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				request.EntryNames = []string{}
				want = readerFailure{Result: refused(AdmissionInvalid), diagnostic: contract.ReasonCancelled}
			}
			var outputKey string
			for _, fact := range selected.image.supportFacts {
				for _, row := range fact.rows {
					if row.Kind() == contract.OutputConfigurationSliceSupportKind {
						var err error
						outputKey, err = format.Key(store.Descriptor().Prefix, fact.ref)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			reads := 0
			store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if key == store.Descriptor().HeadKey {
					t.Fatal("projection read later HEAD")
				}
				if key != outputKey {
					return read
				}
				reads++
				if reads == 2 {
					if name == "missing-second-pass" || name == "filtered-missing-second-pass" {
						return contract.ReadResult{Status: contract.ReadMissing}
					}
					if name == "invalid-second-pass" {
						read.Body = bytes.Clone(read.Body)
						read.Body[0] ^= 1
					}
				}
				return read
			}
			defer func() { store.readHook = nil }()
			if name == "missing-second-pass" || name == "filtered-missing-second-pass" {
				want = readerFailure{Result: failure(EvidenceUnavailable, MissingSelectedObject), diagnostic: contract.ReasonSelectedObjectUnavailable}
			}
			if name == "invalid-second-pass" {
				want = readerFailure{Result: failure(IntegrityFailure, InvalidReference), diagnostic: contract.ReasonSelectedObjectInvalid}
			}
			got, failed := manifestSelectionForTest(ctx, selected, request)
			if failed != want || (got == nil) != (want.Outcome != 0) {
				t.Fatal("fixed selection or whole failure", got, failed, want)
			}
			if name == "no-head-reread" && (got.Observation.DomainID != manifestsdk.ID(selected.image.root.Domain) || got.Observation.SnapshotID != manifestsdk.ID(selected.image.root.Snapshot) || got.Observation.HEADRevisionID != manifestsdk.ID(selected.basis.anchor.head.Core.Revision)) {
				t.Fatal("fixed observation changed")
			}
			if name == "missing-second-pass" || name == "filtered-missing-second-pass" || name == "invalid-second-pass" {
				if reads != 2 {
					t.Fatal("failure was not between complete passes", reads)
				}
			}
		})
	}
}

// full_only: false
func TestManifestSelectionResolvesDefaultsAndExactPartition(t *testing.T) {
	t.Run("single-default-default", func(t *testing.T) {
		_, selected, _, env, target := manifestFixture(t, true, true)
		for _, request := range []contract.ManifestRequest{
			{TargetMode: manifestsdk.CurrentAuthority, EntryMode: manifestsdk.AllAuthorized},
			{TargetMode: manifestsdk.ExactRecipient, TargetRecipientID: target, EntryMode: manifestsdk.AllAuthorized},
		} {
			got, f := manifestSelectionForTest(env.operationContext(), selected, request)
			if f.Outcome != 0 || got == nil || len(got.Entries) != 4 || len(got.ExcludedEntries) != 0 {
				t.Fatal("one default default covers every shared entry", got, f)
			}
			for _, row := range got.Entries {
				if row.Kind == contract.Secret && (len(row.Destinations) != 1 || row.Destinations[0].DestinationID != "primary") {
					t.Fatal("default destination vector", row)
				}
			}
		}
	})
	_, selected, _, env, target := manifestFixture(t, false)
	request := contract.ManifestRequest{TargetMode: manifestsdk.CurrentAuthority, EntryMode: manifestsdk.AllAuthorized}
	got, failure := manifestSelectionForTest(env.operationContext(), selected, request)
	if failure.Outcome != 0 || got == nil {
		t.Fatal("default selection", failure)
	}
	if got.TargetRecipientID != manifestsdk.ID(selected.authorityID) || got.Selection != (manifestsdk.Selection{TargetMode: manifestsdk.CurrentAuthority, EntryMode: manifestsdk.AllAuthorized}) {
		t.Fatal("same-image target and scope", got)
	}
	if len(got.Entries) != 3 || len(got.ExcludedEntries) != 1 || got.ExcludedEntries[0].Name != "secret" || got.ExcludedEntries[0].Reason != manifestsdk.NoOutput || len(got.ResolvedEntries) != 4 {
		t.Fatal("Authority must honor the explicitly empty shared route", got)
	}
	request.TargetMode, request.TargetRecipientID = manifestsdk.ExactRecipient, target
	got, failure = manifestSelectionForTest(env.operationContext(), selected, request)
	if failure.Outcome != 0 || got == nil || len(got.Entries) != 3 || len(got.ExcludedEntries) != 1 || got.ExcludedEntries[0].Name != "secret" || got.ExcludedEntries[0].Reason != manifestsdk.NoOutput {
		t.Fatal("shared routes must produce the same partition for both members", got, failure)
	}
	filter := "private/nonmatching-service/v1"
	request.ServiceFilter = &filter
	got, failure = manifestSelectionForTest(env.operationContext(), selected, request)
	if failure.Outcome != 0 || got == nil || len(got.Entries) != 2 || len(got.ExcludedEntries) != 2 || got.ExcludedEntries[0].Name != "secret" || got.ExcludedEntries[0].Reason != manifestsdk.NoOutput || got.ExcludedEntries[1].Name != "unselected" || got.ExcludedEntries[1].Reason != manifestsdk.NoMatchingService {
		t.Fatal("exact filtered partition", got, failure)
	}
}

// full_only: false
func TestManifestSelectionClassifiesBeforeSkippingLocator(t *testing.T) {
	for _, condition := range []string{"excluded-locator", "no-output-interpreter", "no-grants", "absent-empty-target", "retired-empty-target"} {
		t.Run(condition, func(t *testing.T) {
			_, selected, session, env, target := manifestFixture(t, true)
			filter := "private/nonmatching-service/v1"
			request := contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, TargetRecipientID: target, EntryMode: manifestsdk.ExactNames, EntryNames: []string{"secret"}, ServiceFilter: &filter}
			if condition == "no-output-interpreter" {
				request.ServiceFilter = nil
				engine, _, source := readerEngineFixture(t, env, session)
				engine.validator = nil
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				result := engine.Manifest(ctx, contract.ID{71}, hermeticManifestRequest(request))
				if result.StateResult != contract.ReaderSuccess || result.Payload == nil || len(result.Payload.IncludedEntries) != 1 || source.closes != 1 {
					t.Fatal("stored generic facts require no interpreter", result.FailureReason)
				}
				return
			}
			if condition == "excluded-locator" {
				_, fixed, fixture, fixedEnv := opaqueManifestFixture(t, "no-birth")
				request.TargetRecipientID, request.EntryNames = fixture.session.admission.recipient, []string{"TOKEN"}
				selected, env = fixed, fixedEnv
			}
			if condition == "no-grants" {
				request.EntryMode, request.EntryNames = manifestsdk.AllAuthorized, nil
				for _, named := range selected.image.root.Names {
					selected.image.valueEntry(named.Slot).Recipients = []contract.ID{selected.authorityID}
				}
			}
			if condition == "absent-empty-target" || condition == "retired-empty-target" {
				request.EntryNames = []string{}
				if condition == "absent-empty-target" {
					request.TargetRecipientID = contract.ID{99}
				} else {
					row := selected.image.recipientRecord(target)
					row.Status, row.CurrentBinding = contract.RetiredRecipient, nil
				}
			}
			got, failure := manifestSelectionForTest(env.operationContext(), selected, request)
			switch condition {
			case "absent-empty-target", "retired-empty-target":
				if got != nil || failure.diagnostic != contract.ReasonTargetAbsent {
					t.Fatal("empty selection bypassed current target", got, failure)
				}
			case "no-grants":
				if failure.Outcome != 0 || got == nil || len(got.Entries) != 0 || len(got.ExcludedEntries) != 0 || len(got.ResolvedEntries) != 0 {
					t.Fatal("no grants must be complete empty selection", got, failure)
				}
			case "no-output-interpreter":
				if failure.Outcome != 0 || got == nil || len(got.Entries) != 1 || len(got.Entries[0].Destinations) != 2 {
					t.Fatal("stored generic facts require no interpreter", got, failure)
				}
			default:
				if failure.Outcome != 0 || got == nil || len(got.Entries) != 0 || len(got.ExcludedEntries) != 1 || got.ExcludedEntries[0].Reason != manifestsdk.NoMatchingService {
					t.Fatal("nonmatching service partition", got, failure)
				}
			}
		})
	}
}
