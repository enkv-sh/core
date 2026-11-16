package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func liveSelectedPrivateCustody(t testing.TB, ctx context.Context, input liveRunInput, budget *runBudget, s *StateSession, selected contract.BindingTableRow) *custody.Fixture {
	t.Helper()
	bindings, err := s.currentBindings()
	if err != nil {
		t.Fatal(err)
	}
	role := livePrivateKeyRole(input.Settings, selected)
	if role == "" || selected.SubjectKind != 1 {
		t.Fatal("selected ordinary private route absent")
	}
	if role == "reader" {
		return liveSelectedReaderCustody(t, ctx, input, budget, s, selected, "reader")
	}
	routes := make([]custody.Route, len(bindings))
	for i, row := range bindings {
		routes[i].BindingID = row.Binding.BindingID
		if row.Binding.BindingID == selected.Binding.BindingID {
			routes[i].PrivateRoute = liveCredentialRoute(input, role)
		}
	}
	keys, err := openLiveReplacementCustody(t, ctx, input, s.admission.domain, budget, bindings, routes, []string{role})
	if err != nil {
		t.Fatal("current selected private custody", err)
	}
	return keys
}

func liveSelectedReaderCustody(t testing.TB, ctx context.Context, input liveRunInput, budget *runBudget, s *StateSession, selected contract.BindingTableRow, role string) *custody.Fixture {
	t.Helper()
	if role != "reader" && role != "denied-reader" || selected.SubjectID != fixtureID(s.admission.domain, "reader") || !liveReplacementKEKMatches(input.Settings, s.admission.domain, selected, "reader") {
		t.Fatal("selected reader route differs")
	}
	keys, _, err := openLiveReaderCustody(t, ctx, input, s.admission.domain, budget, role)
	if err != nil {
		t.Fatal("selected reader custody", err)
	}
	// The reader is unchanged by reciprocal authority/recovery loss. Its exact
	// current binding must match before this one reader route can be used.
	want, err := contract.PublicBindingDigest(selected.Binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range keys.Bindings() {
		got, err := contract.PublicBindingDigest(row.Binding)
		if err == nil && row.SubjectKind == selected.SubjectKind && row.SubjectID == selected.SubjectID && got == want {
			return keys
		}
	}
	t.Fatal("reader fixture lacks the current selected binding")
	return nil
}
