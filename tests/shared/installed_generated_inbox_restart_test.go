package core

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

type installedInboxRestartStore struct {
	*generatedCleanupDeleteStore
	inbox      string
	mode       string
	hideHEAD   bool
	inboxReads int
	cancel     context.CancelFunc
}

func (s *installedInboxRestartStore) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	if s.hideHEAD && key == s.Descriptor().HeadKey {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
	}
	if key == s.inbox {
		s.inboxReads++
		if s.mode == "read-denied" {
			return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
		}
	}
	r := s.generatedCleanupDeleteStore.Read(ctx, key, maximum)
	if key == s.inbox && s.mode == "changed-bytes" && r.Status == contract.ReadOK {
		r.Body[0] ^= 1
	}
	return r
}

func (s *installedInboxRestartStore) DeleteIfToken(ctx context.Context, key string, token contract.Token) contract.WriteResult {
	if s.mode == "token-conflict" {
		s.deletes++
		s.deleteKey, s.deleteToken = key, token
		return contract.WriteResult{Status: contract.WriteConflict, Reason: contract.ReasonCondition}
	}
	result := s.generatedCleanupDeleteStore.DeleteIfToken(ctx, key, token)
	if s.cancel != nil {
		s.cancel()
	}
	return result
}

func (s *installedInboxRestartStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	result := s.generatedCleanupDeleteStore.CompareAndSwap(ctx, key, token, body)
	if s.mode == "lost-head-before" || s.mode == "lost-head-after" {
		s.hideHEAD = true
	}
	return result
}

// full_only: false
func TestInstalledGeneratedInboxCleanupReopensOnlyNamedMapping(t *testing.T) {
	for _, mode := range []string{"pending", "sibling", "absent", "lost-delete", "lost-head-before", "lost-head-after", "missing-mapping", "zero-inbox", "read-denied", "changed-bytes", "token-conflict"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "acknowledged")
			var target contract.ID
			retire := func(selected *StateSession, current contract.ValueEntry) *StateSession {
				engine := installedGeneratedRetirementEngine(t, ctx, f, selected, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
				out := engine.RetireGenerated(ctx, testID("retirement retained for explicit inbox cleanup"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
				engine.Close()
				if out.Result.Outcome != ObservedCurrent || out.Generated == nil || len(out.Generated.Effects) != 1 {
					t.Fatal("retirement fixture did not finish", out.Result)
				}
				target = out.Generated.Effects[0].Record.InboxID
				return f.open(t, ctx)
			}
			selected = retire(selected, current)
			if mode == "sibling" {
				input := installedGeneratedRetirementEntries(f.env.GeneratedProcess, selected.admission.recipient, 2, "retained healthy sibling")
				engine := installedGeneratedTestEngine(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
				out := engine.Apply(ctx, testID("next generation leaves an independent inbox"), input)
				engine.Close()
				if out.Result.Outcome != ObservedCurrent {
					t.Fatal("independent mapping fixture failed", out.Result)
				}
				selected = f.open(t, ctx)
				_, current = observeCurrentValueEntry(t, selected, "generated")
				selected = retire(selected, current)
			}
			before := selected
			work := mustSelectedGeneratedWork(t, before)
			var release generatedReleasedAttempt
			for _, r := range work.releases {
				if r.release.InboxID == target {
					release = r
				}
			}
			if release.release.InboxID.IsZero() || release.release.State != contract.GeneratedReleasePending {
				t.Fatal("retirement did not retain its exact Pending inbox")
			}
			key, err := format.GeneratedResultKey(f.env.Store.Descriptor().Prefix, f.env.Domain, target)
			if err != nil {
				t.Fatal(err)
			}
			base := requireAdmittedMemoryStore(t, f.env.Store)
			store := &installedInboxRestartStore{generatedCleanupDeleteStore: &generatedCleanupDeleteStore{memoryStore: base}, inbox: key, mode: mode}
			f.env.Store = store
			original := base.Read(ctx, key, release.release.ObjectLength)
			if original.Status != contract.ReadOK {
				t.Fatal("retained original result unavailable")
			}
			if mode == "absent" {
				delete(base.objects, key)
			}
			if mode == "lost-delete" {
				store.lost = true
			}
			if mode == "lost-head-before" {
				base.casMode = "delayed"
			}
			if mode == "lost-head-after" {
				base.casMode = "lost-after"
			}
			inbox := target
			if mode == "missing-mapping" {
				inbox = testID("unmapped temporary inbox")
			}
			if mode == "zero-inbox" {
				inbox = contract.ID{}
			}
			beforeCreates, beforeDeletes := effects()
			_, private := f.keys.Calls()
			selected = f.open(t, ctx)
			_, beforeValue := observeCurrentValueEntry(t, selected, "generated")
			engine := installedGeneratedRetirementEngine(t, ctx, f, selected, nil)
			out := engine.ReleaseGeneratedInbox(ctx, testID("explicit inbox cleanup after restart"), inbox)
			engine.Close()
			store.hideHEAD = false
			base.casMode = ""
			after := f.open(t, ctx)
			afterWork := mustSelectedGeneratedWork(t, after)
			checkGeneratedReceiptRowsUnchanged(t, before, after)
			_, afterValue := observeCurrentValueEntry(t, after, "generated")
			if !reflect.DeepEqual(beforeValue, afterValue) {
				t.Fatal("temporary inbox cleanup changed the selected application value")
			}
			if p, q := effects(); p != beforeCreates || !slices.Equal(q, beforeDeletes) {
				t.Fatal("temporary inbox cleanup repeated a generator request")
			}
			if _, p := f.keys.Calls(); p != private {
				t.Fatal("temporary inbox cleanup decrypted generator or value material")
			}
			if len(out.Receipt) != 0 || out.Payload != nil {
				t.Fatal("temporary inbox cleanup created a receipt or value transition")
			}
			if out.Cleanup != nil {
				basis := out.Cleanup.Basis
				if basis.SourceKind != contract.PendingInboxReleaseSupportKind || basis.SourceID != target || basis.OriginalOperationID != release.attempt.OperationID || basis.OriginalAttemptID != release.attempt.AttemptID || basis.OriginalResult == nil || basis.OriginalResult.ResultID != release.release.OriginalResultID || basis.OriginalResult.ResultBodyDigest != release.release.SelectedHandoffDigest || basis.OriginalResult.ResultLength != release.release.ObjectLength || basis.Target != nil {
					t.Fatal("cleanup result lost the exact original mapping")
				}
				if out.Generated == nil || len(out.Generated.Effects) != 0 || out.Generated.AcknowledgedCount != 0 || out.Generated.ConfirmedCount != 0 || out.Generated.UnknownCount != 0 {
					t.Fatal("Store cleanup reported a generator outcome")
				}
			}
			success := mode == "pending" || mode == "sibling" || mode == "absent"
			present := func(work *generatedSelection, id contract.ID) bool {
				for _, r := range work.releases {
					if r.release.InboxID == id {
						return true
					}
				}
				return false
			}
			switch {
			case success:
				if out.Result.Outcome != ObservedCurrent || out.Generated == nil || out.Generated.StateResult != "success" || out.Cleanup == nil || out.Cleanup.Basis.SourceID != target || present(afterWork, target) {
					t.Fatal("named inbox was not released", out.Result)
				}
				if len(afterWork.releases) != len(work.releases)-1 || before.root.Generated.PendingReleases != after.root.Generated.PendingReleases+1 || before.root.Generated.Attempts != after.root.Generated.Attempts+1 {
					t.Fatal("selected inbox capacity was not returned")
				}
				var remaining []contract.ID
				for _, r := range afterWork.releases {
					remaining = append(remaining, r.release.InboxID)
				}
				slices.SortFunc(remaining, compareGeneratedIDs)
				if !slices.Equal(remaining, out.Cleanup.RemainingInboxIDs) || out.Cleanup.RemainingWorkBasis.HeadRevisionID != after.head.Core.Revision || out.Cleanup.RemainingWorkBasis.Snapshot != after.head.Core.Root {
					t.Fatal("cleanup result differs from the complete selected remaining work")
				}
				wantDeletes := 1
				if mode == "absent" {
					wantDeletes = 0
				}
				if store.deletes != wantDeletes {
					t.Fatal("cleanup sent a deletion for an absent or unrelated inbox")
				}
				for attempt, r := range work.releases {
					if r.release.InboxID == target {
						continue
					}
					if got, ok := afterWork.releases[attempt]; !ok || got.release != r.release {
						t.Fatal("named cleanup changed another selected mapping")
					}
				}
			case mode == "lost-delete":
				if out.Result.Outcome != ObservedCurrent || out.Generated == nil || out.Generated.StateResult != "effect-unknown" || !present(afterWork, target) {
					t.Fatal("lost delete reply established clean release", out.Result)
				}
				retained := afterWork.releases[release.attempt.AttemptID].release
				expected := release.release
				expected.State = contract.GeneratedReleaseUnknown
				if retained != expected || store.deletes != 1 || base.Read(ctx, key, release.release.ObjectLength).Status != contract.ReadMissing {
					t.Fatal("Unknown mapping lost its original handoff or physical effect")
				}
			case mode == "lost-head-before" || mode == "lost-head-after":
				if out.Result.Outcome != UnresolvedCommit || !out.Result.CommitMayHaveOccurred || out.Cleanup == nil || out.Cleanup.RemainingWorkBasis.HeadRevisionID != before.head.Core.Revision || !slices.Contains(out.Cleanup.RemainingInboxIDs, target) {
					t.Fatal("lost selection response overstated current cleanup", out.Result)
				}
				if present(afterWork, target) != (mode == "lost-head-before") {
					t.Fatal("cold observation differs from actual lost selection")
				}
			default:
				want := AdmissionRefused
				if mode == "read-denied" {
					want = EvidenceUnavailable
				}
				if mode == "changed-bytes" {
					want = IntegrityFailure
				}
				if out.Result.Outcome != want || !present(afterWork, target) || !bytes.Equal(before.body, after.body) {
					t.Fatal("refused inbox cleanup changed selected state or outcome", out.Result)
				}
				wantDeletes := 0
				if mode == "token-conflict" {
					wantDeletes = 1
				}
				if store.deletes != wantDeletes || mode == "missing-mapping" && store.inboxReads != 0 {
					t.Fatal("refusal reached an unrelated physical deletion")
				}
			}
			if mode == "lost-delete" || mode == "lost-head-before" || mode == "lost-head-after" {
				store.mode = ""
				store.lost = false
				second := installedGeneratedRetirementEngine(t, ctx, f, after, nil)
				rechecked := second.ReleaseGeneratedInbox(ctx, testID("cold exact inbox observation after unknown result"), target)
				second.Close()
				closed := f.open(t, ctx)
				if mode == "lost-head-after" {
					if rechecked.Result.Outcome != AdmissionRefused {
						t.Fatal("missing mapping was accepted as a new successful cleanup")
					}
				} else if rechecked.Result.Outcome != ObservedCurrent || rechecked.Generated == nil || rechecked.Generated.StateResult != "success" || present(mustSelectedGeneratedWork(t, closed), target) {
					t.Fatal("cold recheck did not release the exact absent inbox", rechecked.Result)
				}
				if store.deletes != 1 {
					t.Fatal("cold recheck repeated a completed physical deletion")
				}
				if base.late != nil {
					if err := base.late(); err != nil {
						t.Fatal(err)
					}
					if observed := f.open(t, ctx); !bytes.Equal(observed.body, closed.body) {
						t.Fatal("late selection replaced the later cleanup")
					}
				}
				checkGeneratedReceiptRowsUnchanged(t, before, closed)
			}
			if mode == "pending" {
				input := installedGeneratedRetirementEntries(f.env.GeneratedProcess, after.admission.recipient, 2, "retained healthy sibling")
				next := installedGeneratedTestEngine(t, ctx, f, after, input, currentApplyRecipients(after.registry()), installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
				applied := next.Apply(ctx, testID("ordinary generated apply after exact inbox release"), input)
				next.Close()
				if applied.Result.Outcome != ObservedCurrent || applied.Generated == nil || applied.Generated.StateResult != "retirement-pending" {
					t.Fatal("released capacity could not admit the next ordinary generated apply", applied.Result)
				}
			}
		})
	}
}

func installedInboxUnobservedFixture(t *testing.T, ctx context.Context) (installedApplyTestFixture, *StateSession, contract.ID, func() (int32, int32)) {
	t.Helper()
	var creates, deletes atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			n := creates.Add(1)
			_, _ = fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%032x","value":"%s","status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`, n, hermeticCloudflareSecret, hermeticCloudflarePermission, hermeticCloudflareAccount)
		case http.MethodDelete:
			if deletes.Add(1) == 1 {
				_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{}}`))
				return
			}
			_, _ = fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, path.Base(r.URL.Path))
		default:
			t.Error("unexpected generated test request")
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	origin := server.URL + "/client/v4"
	artifact, implementation := buildHermeticCloudflareGenerator(t, origin)
	intent, request := hermeticCloudflareIntent()
	process := &generatedProcessFixture{Artifact: artifact, Implementation: implementation, Intent: intent,
		RequestDigest: hermeticCloudflareHTTPRequestDigest(request), Configure: func(tb testing.TB, artifact string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
			return hermeticCloudflareConfig(tb, artifact, origin, implementation, expected)
		}}
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
	f.env.GeneratedProcess = process
	selected := f.selected
	for epoch := uint64(0); epoch < 2; epoch++ {
		input := installedGeneratedRetirementEntries(process, selected.admission.recipient, epoch, "retained healthy sibling")
		engine := installedGeneratedTestEngine(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
		out := engine.Apply(ctx, testID(fmt.Sprintf("unobserved inbox generation %d", epoch)), input)
		engine.Close()
		if out.Result.Outcome != ObservedCurrent {
			t.Fatal("unobserved inbox setup failed", out.Result)
		}
		selected = f.open(t, ctx)
	}
	_, current := observeCurrentValueEntry(t, selected, "generated")
	var inbox contract.ID
	for attempt := 0; attempt < 2; attempt++ {
		engine := installedGeneratedRetirementEngine(t, ctx, f, selected, installedGeneratedRetirementCallbacks(t, f, process))
		out := engine.RetireGenerated(ctx, testID(fmt.Sprintf("unobserved inbox retirement %d", attempt)), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
		engine.Close()
		if out.Result.Outcome != ObservedCurrent || out.Generated == nil || len(out.Generated.Effects) != 1 {
			t.Fatal("unobserved inbox retirement did not finish", out.Result)
		}
		if attempt == 0 {
			if out.Generated.StateResult != "effect-unknown" {
				t.Fatal("first deletion did not retain its actual uncertainty")
			}
			inbox = out.Generated.Effects[0].Record.InboxID
		} else if out.Generated.StateResult != "success" {
			t.Fatal("second deletion did not acknowledge the exact retained target")
		}
		selected = f.open(t, ctx)
	}
	return f, selected, inbox, func() (int32, int32) { return creates.Load(), deletes.Load() }
}

// full_only: false
func TestInstalledGeneratedInboxCleanupRefusesUnobservedAndLiveOriginal(t *testing.T) {
	for _, mode := range []string{"unobserved", "live-original"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			var f installedApplyTestFixture
			var selected *StateSession
			var inbox contract.ID
			var effects func() (int32, int32)
			if mode == "unobserved" {
				f, selected, inbox, effects = installedInboxUnobservedFixture(t, ctx)
				found := false
				for _, r := range mustSelectedGeneratedWork(t, selected).releases {
					if r.release.InboxID == inbox {
						found = r.release.State == contract.GeneratedReleaseUnobserved && r.release.ObjectLength == 0
					}
				}
				if !found {
					t.Fatal("later qualified result did not retain the original Unobserved mapping")
				}
			} else {
				var current contract.ValueEntry
				var count func() (int, []string)
				f, selected, current, count = installedGeneratedRetirementFixture(t, ctx, "unknown")
				engine := installedGeneratedRetirementEngine(t, ctx, f, selected, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
				out := engine.RetireGenerated(ctx, testID("live original retains its result dependency"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
				engine.Close()
				if out.Generated == nil || out.Generated.StateResult != "effect-unknown" || len(out.Generated.Effects) != 1 {
					t.Fatal("live result dependency setup failed", out.Result)
				}
				inbox = out.Generated.Effects[0].Record.InboxID
				selected = f.open(t, ctx)
				work := mustSelectedGeneratedWork(t, selected)
				if len(work.attempts) != 1 || selected.root.Generated.Duties != 1 || selected.root.Generated.PendingReleases != 0 {
					t.Fatal("Unknown original lost its live Duty and adoption dependency")
				}
				effects = func() (int32, int32) { a, b := count(); return int32(a), int32(len(b)) }
			}
			key, err := format.GeneratedResultKey(f.env.Store.Descriptor().Prefix, f.env.Domain, inbox)
			if err != nil {
				t.Fatal(err)
			}
			store := &installedInboxRestartStore{generatedCleanupDeleteStore: &generatedCleanupDeleteStore{memoryStore: requireAdmittedMemoryStore(t, f.env.Store)}, inbox: key}
			f.env.Store = store
			creates, deletes := effects()
			_, private := f.keys.Calls()
			engine := installedGeneratedRetirementEngine(t, ctx, f, selected, nil)
			out := engine.ReleaseGeneratedInbox(ctx, testID("refuse unqualified exact inbox"), inbox)
			engine.Close()
			cold := f.open(t, ctx)
			if out.Result.Outcome != AdmissionRefused || store.deletes != 0 || store.inboxReads != 0 || !bytes.Equal(selected.body, cold.body) {
				t.Fatal("unqualified inbox reached deletion or changed state", out.Result, store.deletes, store.inboxReads)
			}
			if a, b := effects(); a != creates || b != deletes {
				t.Fatal("refused inbox cleanup called the generator")
			}
			if _, p := f.keys.Calls(); p != private {
				t.Fatal("refused inbox cleanup used private result material")
			}
			checkGeneratedReceiptRowsUnchanged(t, selected, cold)
		})
	}
}

// full_only: false
func TestInstalledGeneratedInboxCleanupRefusesOccupiedGeneratedSlot(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "acknowledged")
	engine := installedGeneratedRetirementEngine(t, ctx, f, selected, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
	retired := engine.RetireGenerated(ctx, testID("park inbox before independent active work"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
	engine.Close()
	if retired.Result.Outcome != ObservedCurrent || retired.Generated == nil || len(retired.Generated.Effects) != 1 {
		t.Fatal("independent retained inbox setup failed", retired.Result)
	}
	parked := retired.Generated.Effects[0].Record.InboxID
	selected = f.open(t, ctx)
	base := requireAdmittedMemoryStore(t, f.env.Store)
	store := &installedInboxRestartStore{generatedCleanupDeleteStore: &generatedCleanupDeleteStore{memoryStore: base}, mode: "lost-head-after"}
	f.env.Store = store
	input := installedGeneratedRetirementEntries(f.env.GeneratedProcess, selected.admission.recipient, 2, "retained healthy sibling")
	engine = installedGeneratedTestEngine(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
	base.casMode = "lost-after"
	reserved := engine.Apply(ctx, testID("selected reservation awaiting readback"), input)
	engine.Close()
	store.hideHEAD, store.mode, base.casMode = false, "", ""
	selected = f.open(t, ctx)
	work := mustSelectedGeneratedWork(t, selected)
	if reserved.Result.Outcome != UnresolvedCommit || work.parent == nil || work.phase == nil || selected.root.Generated.ActiveOwner.IsZero() || len(work.attempts) != 1 || len(work.releases) != 1 {
		t.Fatal("interrupted installed apply did not leave its actual selected reservation", reserved.Result)
	}
	var live contract.ID
	for _, a := range work.attempts {
		live = a.record.InboxID
	}
	if live.IsZero() || live == parked {
		t.Fatal("active original and parked inbox are not independent")
	}
	creates, deletes := effects()
	_, private := f.keys.Calls()
	for _, inbox := range []contract.ID{live, parked} {
		store.inbox, _ = format.GeneratedResultKey(store.Descriptor().Prefix, f.env.Domain, inbox)
		engine = installedGeneratedRetirementEngine(t, ctx, f, selected, nil)
		out := engine.ReleaseGeneratedInbox(ctx, testID("occupied slot refuses exact inbox cleanup"), inbox)
		engine.Close()
		cold := f.open(t, ctx)
		if out.Result.Outcome != AdmissionRefused || store.deletes != 0 || store.inboxReads != 0 || !bytes.Equal(selected.body, cold.body) {
			t.Fatal("occupied-slot admission changed active or parked work", out.Result)
		}
		checkGeneratedReceiptRowsUnchanged(t, selected, cold)
	}
	if a, b := effects(); a != creates || !slices.Equal(b, deletes) {
		t.Fatal("occupied-slot refusal repeated a generator request")
	}
	if _, p := f.keys.Calls(); p != private {
		t.Fatal("occupied-slot refusal used private result material")
	}
}

// full_only: false
func TestInstalledGeneratedInboxCleanupRetainsCanceledDeleteObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "acknowledged")
	engine := installedGeneratedRetirementEngine(t, ctx, f, selected, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
	retired := engine.RetireGenerated(ctx, testID("retirement before canceled inbox observation"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
	engine.Close()
	if retired.Result.Outcome != ObservedCurrent || retired.Generated == nil || len(retired.Generated.Effects) != 1 {
		t.Fatal("canceled observation fixture failed", retired.Result)
	}
	inbox := retired.Generated.Effects[0].Record.InboxID
	selected = f.open(t, ctx)
	key, err := format.GeneratedResultKey(f.env.Store.Descriptor().Prefix, f.env.Domain, inbox)
	if err != nil {
		t.Fatal(err)
	}
	callCtx, cancelCall := context.WithCancel(ctx)
	defer cancelCall()
	store := &installedInboxRestartStore{generatedCleanupDeleteStore: &generatedCleanupDeleteStore{memoryStore: requireAdmittedMemoryStore(t, f.env.Store), lost: true}, inbox: key, cancel: cancelCall}
	f.env.Store = store
	creates, deletes := effects()
	_, private := f.keys.Calls()
	engine = installedGeneratedRetirementEngine(t, ctx, f, selected, nil)
	out := engine.ReleaseGeneratedInbox(callCtx, testID("cancel as inbox delete response is lost"), inbox)
	engine.Close()
	cold := f.open(t, ctx)
	work := mustSelectedGeneratedWork(t, cold)
	if out.Result.Outcome == ObservedCurrent || out.Cleanup == nil || out.Cleanup.Basis.SourceID != inbox || !slices.Contains(out.Cleanup.RemainingInboxIDs, inbox) || out.Cleanup.RemainingWorkBasis.HeadRevisionID != selected.head.Core.Revision || !bytes.Equal(selected.body, cold.body) || store.deletes != 1 || store.memoryStore.Read(ctx, key, uint32(contract.GeneratedResultRecordMaxLength)).Status != contract.ReadMissing {
		t.Fatal("canceled physical delete lost its predecessor basis", out.Result)
	}
	found := false
	for _, d := range out.Diagnostics {
		if d.Subject == (contract.DiagnosticSubject{Kind: contract.SubjectStore}) && slices.Equal(d.Path, []contract.DiagnosticField{contract.FieldPresence}) && d.Outcome == contract.DiagnosticUnable && d.Reason == contract.ReasonEvidenceUnavailable && d.SourceLocation == nil {
			found = true
		}
	}
	if !found {
		t.Fatal("uncertain canceled Store deletion has no safe presence diagnostic")
	}
	if len(work.releases) == 0 {
		t.Fatal("canceled deletion removed the authenticated mapping")
	}
	store.cancel = nil
	store.lost = false
	engine = installedGeneratedRetirementEngine(t, ctx, f, cold, nil)
	rechecked := engine.ReleaseGeneratedInbox(ctx, testID("cold absent inbox after canceled deletion"), inbox)
	engine.Close()
	closed := f.open(t, ctx)
	if rechecked.Result.Outcome != ObservedCurrent || rechecked.Generated == nil || rechecked.Generated.StateResult != "success" || rechecked.Cleanup == nil || slices.Contains(rechecked.Cleanup.RemainingInboxIDs, inbox) || store.deletes != 1 {
		t.Fatal("cold canceled-delete recovery repeated deletion or kept the absent inbox", rechecked.Result)
	}
	if a, b := effects(); a != creates || !slices.Equal(b, deletes) {
		t.Fatal("canceled inbox observation called the generator")
	}
	if _, p := f.keys.Calls(); p != private {
		t.Fatal("canceled inbox observation decrypted private material")
	}
	checkGeneratedReceiptRowsUnchanged(t, selected, closed)
}
