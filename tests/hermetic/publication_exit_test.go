package core

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The source history is signed with the existing test Trust. Only terminal
// receipt history is seeded; the exits below execute their actual CAS path.
func publicationExitSelectedFixture(t *testing.T) (fixtureEnvironment, *StateSession, contract.ID, contract.ID, []contract.SupportRecord) {
	t.Helper()
	ctx := t.Context()
	env, current, damaged, damagedRoot, damagedRefs := damagedWorkFixture(t, ctx)
	f := &environmentFixture{session: current, admission: OpenContext{admission: &current.admission}}
	seedBothFullReceiptWindows(t, env, f)
	current = f.session
	root := current.root
	root.Snapshot, root.Transition = damagedRoot.Snapshot, damagedRoot.Transition
	_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, root.Domain)
	coordinate.BindingState = contract.PublicationBindingRetired
	coordinate.ActiveBindingIncarnationID = contract.ID{}
	rows := publicationRelationRows(t, coordinate, marker)
	next := *current
	next.root = root
	next.support = slices.Clone(current.support)
	next.root.RequiredSupport = slices.Clone(current.root.RequiredSupport)
	var pages []format.RequiredSupportPage
	for _, view := range next.support {
		page := format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index}
		for _, row := range view.Records {
			page.Records = append(page.Records, contract.SupportRecord(row))
		}
		pages = append(pages, page)
	}
	for i, row := range rows {
		index := uint16(5 + i)
		object := fixtureID(root.Domain, string([]byte{'p', byte(i)}))
		ref, view, body, err := endWorkSupportPage(root.Domain, object, index, []contract.SupportRecord{row}, nil)
		if err != nil {
			t.Fatal(err)
		}
		key, err := format.Key(current.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		if err := env.Put(ctx, key, body); err != nil {
			t.Fatal(err)
		}
		next.root.RequiredSupport = append(next.root.RequiredSupport, ref)
		next.root.RequiredSupportRecordCount++
		next.support = append(next.support, view)
		pages = append(pages, format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index, Records: []contract.SupportRecord{row}})
	}
	next.recountChildren()
	index, err := current.buildAdministrativeIndex(ctx, next.root, pages, nil, nil, &next)
	if err != nil {
		t.Fatal("actual publication index", err)
	}
	priorGroups := slices.Clone(index.Groups)
	index.Groups = append(index.Groups, damaged.Groups...)
	slices.SortFunc(index.Groups, func(a, b format.AdministrativeGroup) int { return slices.Compare(a.GroupID[:], b.GroupID[:]) })
	positions := make(map[contract.ID]uint16, len(index.Groups))
	for i, group := range index.Groups {
		positions[group.GroupID] = uint16(i)
	}
	for i := range index.Groups {
		group := &index.Groups[i]
		related := slices.Clone(group.RelatedGroupIndexes)
		for j, old := range related {
			related[j] = positions[priorGroups[old].GroupID]
		}
		slices.Sort(related)
		group.RelatedGroupIndexes = related
	}
	for i := range index.Pages {
		for j := range index.Pages[i].Spans {
			owners := slices.Clone(index.Pages[i].Spans[j].GroupIndexes)
			for k, old := range owners {
				owners[k] = positions[priorGroups[old].GroupID]
			}
			slices.Sort(owners)
			index.Pages[i].Spans[j].GroupIndexes = owners
		}
	}
	used := make(map[uint16]bool)
	for _, page := range index.Pages {
		used[page.Ref.Index] = true
	}
	for i, ref := range damagedRefs.owners {
		position := slices.IndexFunc(damaged.Pages, func(page format.AdministrativePage) bool { return page.Ref == ref })
		if position < 0 {
			t.Fatal("publication fixture damaged owner page absent")
		}
		page := damaged.Pages[position]
		var physical uint16
		for used[physical] {
			physical++
		}
		used[physical] = true
		page.Ref.Index = physical
		page.Spans = slices.Clone(page.Spans)
		page.Spans[0].GroupIndexes = []uint16{positions[damaged.Groups[i].GroupID]}
		index.Pages = append(index.Pages, page)
	}
	slices.SortFunc(index.Pages, func(a, b format.AdministrativePage) int { return int(a.Ref.Index) - int(b.Ref.Index) })
	root = next.root
	root.RequiredSupport = nil
	for _, page := range index.Pages {
		root.RequiredSupport = append(root.RequiredSupport, page.Ref)
	}
	root.RequiredSupportRecordCount += uint32(len(damagedRefs.owners))
	root.Generated.Duties, root.Generated.Hazards = damagedRoot.Generated.Duties, damagedRoot.Generated.Hazards
	root.Generated.LiveOwners = damagedRoot.Generated.LiveOwners
	shards, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil {
		t.Fatal(err)
	}
	putSignedDamagedWork(t, ctx, env, current, root, shards)
	admin, result := openAdministrative(ctx, OpenContext{admission: &current.admission}, env.Store)
	if admin == nil || result.Outcome != ObservedCurrent {
		t.Fatal("real publication administrative open", result)
	}
	return env, admin, marker.AttemptID, damaged.Groups[0].GroupID, rows
}

// full_only: false
func TestPublicationDiscardedMarkerCannotSelectLateResult(t *testing.T) {
	env, before, marker, _, originalRows := publicationExitSelectedFixture(t)
	public, private := env.Custody.Calls()
	rows := slices.Clone(originalRows)
	for i := range rows {
		var err error
		if rows[i].Kind == contract.PublicationMarkerSupportKind {
			m, e := contract.InspectPublicationMarker(rows[i].Body)
			if e != nil {
				t.Fatal(e)
			}
			m.State, m.Evidence.Class = contract.PublicationQualifiedNoEffectState, contract.PublicationQualifiedNoEffect
			rows[i].Body, err = contract.EncodePublicationMarker(m)
		} else {
			c, e := contract.InspectPublicationCoordinate(rows[i].Body)
			if e != nil {
				t.Fatal(e)
			}
			c.OwnerState, c.LatestUnresolvedAttemptID = contract.PublicationOwnerNone, contract.ID{}
			rows[i].Body, err = contract.EncodePublicationCoordinate(c)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	// Admit a valid late-result row set while the original marker is still
	// selected. Its later refusal must come from the real EndWork/CAS anchor
	// change, rather than a malformed proposed row or an old-plan adapter.
	staleConstruction, err := before.preparePublicationConstruction(t.Context(), rows)
	if err != nil {
		t.Fatal("healthy late-result construction before exit", err)
	}
	candidate, result := prepareTestEndSelectedWork(t, before, t.Context(), marker, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		publicationExitPreparationFailure(t, before, marker, result)
	}
	selected, result := before.selectCandidate(t.Context(), candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("real publication exit CAS", result)
	}
	after, result := openAdministrative(t.Context(), OpenContext{admission: &before.admission}, env.Store)
	if after == nil || result.Outcome != ObservedCurrent {
		t.Fatal("publication exit cold reopen", result)
	}
	if slices.ContainsFunc(after.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == marker }) ||
		after.root.WarningBits&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) != (WarningPublicationOrderValue|WarningDiscardedExactEvidence) {
		t.Fatal("marker exit lost absence/warning")
	}
	successor := *after
	successor.root.Snapshot, successor.root.Transition = publicationRelationID(90), publicationRelationID(91)
	stale := Candidate{session: after}
	if err := after.materializePublicationRewriteConstruction(t.Context(), &successor, &stale, staleConstruction, []contract.ID{publicationRelationID(92), publicationRelationID(93)}); !errors.Is(err, contract.ErrRecord) {
		t.Fatal("late result revived ended marker", err)
	}
	if len(stale.objects) != 0 {
		t.Fatal("late result emitted writes")
	}
	currentConstruction, err := after.preparePublicationConstruction(t.Context(), rows)
	if err != nil {
		t.Fatal("healthy late-result construction after exit", err)
	}
	currentCandidate := Candidate{session: after}
	if err := after.materializePublicationRewriteConstruction(t.Context(), &successor, &currentCandidate, currentConstruction, []contract.ID{publicationRelationID(92), publicationRelationID(93)}); !errors.Is(err, contract.ErrRecord) {
		t.Fatal("current construction reintroduced disposed marker", err)
	}
	if len(currentCandidate.objects) != 0 {
		t.Fatal("current construction emitted late-result writes")
	}

	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("publication exit used custody")
	}
}

// full_only: false
func TestPublicationAndGeneratedExitsKeepBothOrdersAndFullWindows(t *testing.T) {
	for _, publicationFirst := range []bool{true, false} {
		name := "publication_first"
		if !publicationFirst {
			name = "generated_first"
		}
		t.Run(name, func(t *testing.T) {
			env, current, marker, generated, _ := publicationExitSelectedFixture(t)
			original := current
			order := []contract.ID{marker, generated}
			if !publicationFirst {
				order = []contract.ID{generated, marker}
			}
			public, private := env.Custody.Calls()
			for step, target := range order {
				before := current
				windows, err := before.receiptWindowsFromAdministrativeSupport()
				if err != nil {
					t.Fatal(err)
				}
				if len(windows.Successes) != 256 || len(windows.Failures) != 256 {
					t.Fatal("not both full windows")
				}
				candidate, result := prepareTestEndSelectedWork(t, before, t.Context(), target, env.Trust)
				if candidate == nil || result.Outcome != ObservedCurrent {
					publicationExitPreparationFailure(t, before, target, result)
				}
				current, result = before.selectCandidate(t.Context(), candidate)
				if current == nil || result.Outcome != ObservedCurrent {
					t.Fatal("exit CAS", step, result)
				}
				current, result = openAdministrative(t.Context(), OpenContext{admission: &before.admission}, env.Store)
				if current == nil || result.Outcome != ObservedCurrent {
					t.Fatal("exit cold reopen", step, result)
				}
				if err := current.reserveFirstEndWork(t.Context()); err != nil {
					t.Fatal("remaining exit no longer fits", step, err)
				}
				got, err := current.receiptWindowsFromAdministrativeSupport()
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Successes) != 256 || len(got.Failures) != 256 || !slices.Equal(got.Successes[:255], windows.Successes[1:]) ||
					!slices.Equal(got.Failures, windows.Failures) || got.Successes[255].AdministrativeTargetID != publicationExitTarget(before, target) {
					t.Fatal("receipt windows changed incorrectly", step)
				}
				if !reflect.DeepEqual(current.currentEntryInputs(), original.currentEntryInputs()) ||
					!reflect.DeepEqual(current.root.CurrentAccess, original.root.CurrentAccess) || !reflect.DeepEqual(current.root.ValueEntryPages, original.root.ValueEntryPages) ||
					!reflect.DeepEqual(current.root.Recipients, original.root.Recipients) || current.root.OutputConfiguration != original.root.OutputConfiguration {
					t.Fatal("exit lost current state", step)
				}
				if slices.ContainsFunc(current.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == target }) {
					t.Fatal("exit left local owner")
				}
			}
			if current.root.WarningBits&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) == 0 {
				t.Fatal("permanent warning lost")
			}
			if p, k := env.Custody.Calls(); p != public || k != private {
				t.Fatal("exits used custody")
			}
		})
	}
}

func publicationExitTarget(s *StateSession, id contract.ID) contract.ID {
	for _, group := range s.adminIndex.Groups {
		if group.GroupID == id {
			return group.TargetID
		}
	}
	return contract.ID{}
}

func publicationExitPreparationFailure(t *testing.T, s *StateSession, target contract.ID, result Result) {
	t.Helper()
	ids, err := s.freshEndWorkIDs()
	if err != nil {
		t.Fatal("exit identity boundary", result, err)
	}
	_, next, err := s.deriveEndWorkCandidate(t.Context(), target, ids)
	if err != nil {
		t.Fatal("exit derivation boundary", result, err)
	}
	if _, err := next.validateRelationsMode(t.Context(), true); err != nil {
		t.Fatal("exit successor relation boundary", result, err)
	}
	t.Fatal("exit persistence boundary", result)
}
