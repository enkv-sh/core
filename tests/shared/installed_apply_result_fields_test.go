package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

type installedApplyInterruptionStore struct {
	contract.Store
	memory      *memoryStore
	read        func(context.Context, string, uint32) contract.ReadResult
	created     func(contract.WriteResult)
	swap        func(context.Context, string, contract.Token, []byte) contract.WriteResult
	reads, puts int
	sends       int
}

func (s *installedApplyInterruptionStore) admittedMemoryStore() *memoryStore { return s.memory }
func (s *installedApplyInterruptionStore) StoreConfiguration() contract.StoreConfiguration {
	return s.memory.StoreConfiguration()
}
func (s *installedApplyInterruptionStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	s.reads++
	if s.read != nil {
		return s.read(ctx, key, limit)
	}
	return s.Store.Read(ctx, key, limit)
}
func (s *installedApplyInterruptionStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	s.puts++
	result := s.Store.Create(ctx, key, body)
	if s.created != nil {
		s.created(result)
	}
	return result
}
func (s *installedApplyInterruptionStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	s.sends++
	if s.swap != nil {
		return s.swap(ctx, key, token, body)
	}
	return s.Store.CompareAndSwap(ctx, key, token, body)
}

// full_only: false
func TestInstalledApplyInterruptionRetainsActualStage(t *testing.T) {
	for _, stage := range []string{"before-admission", "admitted-read", "acknowledged-create", "possible-head"} {
		t.Run(stage, func(t *testing.T) {
			base, finish := context.WithTimeout(t.Context(), time.Minute)
			defer finish()
			f := newInstalledApplyTestFixture(t, base, contract.AWS, false)
			ctx, cancel := context.WithCancel(base)
			defer cancel()
			memory := requireAdmittedMemoryStore(t, f.env.Store)
			store := &installedApplyInterruptionStore{Store: f.env.Store, memory: memory}
			f.env.Store = store
			input := []ApplyEntryInput{{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("interrupted value")}}
			engine := f.engine(t, f.selected, input, nil)
			switch stage {
			case "before-admission":
				cancel()
			case "admitted-read":
				store.read = func(context.Context, string, uint32) contract.ReadResult {
					cancel()
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
				}
			case "acknowledged-create":
				store.created = func(written contract.WriteResult) {
					if written.Status != contract.WriteAcknowledged {
						t.Fatal("immutable write was not acknowledged", written)
					}
					cancel()
				}
			case "possible-head":
				store.swap = func(context.Context, string, contract.Token, []byte) contract.WriteResult {
					cancel()
					return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
				}
			}
			request := testID("interrupted installed apply " + stage)
			got := engine.Apply(ctx, request, input)
			engine.Close()
			want := EvidenceUnavailable
			if stage == "before-admission" {
				want = AdmissionRefused
			}
			if stage == "possible-head" {
				want = UnresolvedCommit
			}
			if got.RequestID != request || got.Result.Outcome != want || got.Result.CommitMayHaveOccurred != (stage == "possible-head") || len(got.Receipt) != 0 {
				t.Fatalf("interruption changed its actual stage: %+v", got)
			}
			if len(got.Diagnostics) != 1 || got.Diagnostics[0].Subject.Kind != contract.SubjectObservation || got.Diagnostics[0].Outcome != contract.DiagnosticUnable || got.Diagnostics[0].Reason != contract.ReasonCancelled || !slices.Equal(got.Diagnostics[0].Path, []contract.DiagnosticField{contract.FieldPresence}) {
				t.Errorf("interruption lost its exact cause: %+v", got.Diagnostics)
			}
			if stage == "before-admission" && (store.reads != 0 || store.puts != 0 || store.sends != 0) || stage == "admitted-read" && (store.reads != 1 || store.puts != 0 || store.sends != 0) || stage == "acknowledged-create" && (store.puts != 1 || store.sends != 0) || stage == "possible-head" && (store.puts == 0 || store.sends != 1) {
				t.Fatalf("interruption crossed another effect boundary: reads=%d creates=%d sends=%d", store.reads, store.puts, store.sends)
			}
			if stage == "acknowledged-create" && (got.Result.ObservedRevision != f.selected.head.Core.Revision || got.Result.ObservedSnapshotID != f.selected.root.Snapshot || got.Result.Evidence != AuthenticatedClosure) {
				t.Errorf("acknowledged Create lost its established predecessor observation: %+v", got.Result)
			}
			if stage == "possible-head" && (got.OperationID.IsZero() || got.RequestIdentity.IsZero() || got.Result.RequestedRevision.IsZero() || got.Payload == nil || got.Payload.PredecessorRevisionID != f.selected.head.Core.Revision) {
				t.Errorf("possible HEAD send lost its fixed request: %+v", got)
			}
		})
	}
	t.Run("expired-before-admission", func(t *testing.T) {
		base, finish := context.WithTimeout(t.Context(), time.Minute)
		defer finish()
		f := newInstalledApplyTestFixture(t, base, contract.AWS, false)
		input := []ApplyEntryInput{{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("unused")}}
		engine := f.engine(t, f.selected, input, nil)
		expired, cancel := context.WithDeadline(t.Context(), time.Unix(1, 0))
		defer cancel()
		memory := requireAdmittedMemoryStore(t, f.env.Store)
		reads, creates, sends := memory.reads, memory.creates, memory.cas
		got := engine.Apply(expired, testID("expired installed apply"), input)
		engine.Close()
		if got.Result.Outcome != AdmissionRefused || got.Result.CommitMayHaveOccurred || len(got.Diagnostics) != 1 || got.Diagnostics[0].Reason != contract.ReasonExpired || memory.reads != reads || memory.creates != creates || memory.cas != sends {
			t.Fatal("pre-admission expiry changed effects or lost its cause", got)
		}
	})
}

// full_only: false
func TestInstalledApplyPostPersistenceFieldsMatchExactEvidence(t *testing.T) {
	for _, condition := range []string{"competing-selection", "unknown-without-commit", "committed-unreadable"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
			plain := ApplyEntryInput{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("unchanged field-test sibling"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
			baseline := f.engine(t, f.selected, []ApplyEntryInput{plain}, nil)
			if got := baseline.Apply(ctx, testID("result field warning baseline"), []ApplyEntryInput{plain}); got.Result.Outcome != ObservedCurrent {
				t.Fatal("field-test baseline did not select", got.Result)
			}
			baseline.Close()
			f.selected = seedInstalledApplyDomainWarnings(t, f, f.open(t, ctx), WarningOrphanGeneratedEffect|WarningLateDestructiveEffect)
			base, before := f.env.Store, f.selected
			memory := requireAdmittedMemoryStore(t, base)
			store := &installedApplyInterruptionStore{Store: base, memory: memory}
			f.env.Store = store
			input := []ApplyEntryInput{suppliedSecret(t, f.env, "alpha", "result field source", custody.StandardValue, before.admission.recipient), plain}
			engine := f.engine(t, before, input, nil)
			var bound contract.CompactMutationReceipt
			closes := 0
			admit := engine.installation.AdmitCustody
			engine.installation.AdmitCustody = func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, windows contract.MutationReceiptWindows, warning uint8, deadline time.Time) (*InstalledApplyCustody, error) {
				owner, err := admit(ctx, q, control, current, plain, support, witness, revision, windows, warning, deadline)
				if err != nil || owner == nil {
					return owner, err
				}
				closeOwner, bind := owner.Close, owner.BindReceipt
				owner.Close = sync.OnceFunc(func() { closeOwner(); closes++ })
				owner.BindReceipt = func(ctx context.Context, q contract.CryptoApplyReceiptAdmission) error {
					bound = q.Delta.After.Successes[len(q.Delta.After.Successes)-1]
					return bind(ctx, q)
				}
				return owner, nil
			}
			var requested format.Head
			unreadable := false
			store.read = func(ctx context.Context, key string, limit uint32) contract.ReadResult {
				if unreadable && key == store.Descriptor().HeadKey {
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
				}
				return base.Read(ctx, key, limit)
			}
			store.swap = func(callCtx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
				var err error
				requested, err = format.DecodeHead(body)
				if err != nil {
					t.Fatal(err)
				}
				switch condition {
				case "competing-selection":
					competitor := f
					competitor.env.Store = base
					other := []ApplyEntryInput{{Name: "competitor", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{before.admission.recipient}, InputBytes: []byte("other value")}, plain}
					competing := competitor.engine(t, before, other, nil)
					selected := competing.Apply(ctx, testID("competing selection"), other)
					competing.Close()
					if selected.Result.Outcome != ObservedCurrent {
						t.Fatal("competitor did not select", selected.Result)
					}
					return base.CompareAndSwap(callCtx, key, token, body)
				case "committed-unreadable":
					if w := base.CompareAndSwap(callCtx, key, token, body); w.Status != contract.WriteAcknowledged {
						t.Fatal("candidate did not commit", w)
					}
					unreadable = true
				}
				return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
			}
			request := testID("post-persistence fields " + condition)
			got := engine.Apply(ctx, request, input)
			engine.Close()
			wantOutcome, wantObserved, wantSnapshot, wantEvidence, possible := UnresolvedCommit, before.head.Core.Revision, before.root.Snapshot, AuthenticatedClosure, true
			if condition == "competing-selection" {
				wantOutcome, possible = Contention, false
			}
			if condition == "committed-unreadable" {
				wantObserved, wantSnapshot, wantEvidence = contract.ID{}, contract.ID{}, NoEvidence
			}
			if got.RequestID != request || got.OperationID != requested.Subject.Operation || got.RequestIdentity != bound.RequestIdentityDigest || got.RequestIdentity.IsZero() || got.DomainID != f.env.Domain || got.Result.Outcome != wantOutcome || got.Result.RequestedRevision != requested.Core.Revision || got.Result.ObservedRevision != wantObserved || got.Result.ObservedSnapshotID != wantSnapshot || got.Result.Evidence != wantEvidence || got.Result.CommitMayHaveOccurred != possible || got.WarningBits != before.root.WarningBits || len(got.Receipt) != 0 || closes != 1 || store.sends != 1 {
				t.Fatalf("result fields differ from their exact evidence: result=%+v bound=%+v sends=%d closes=%d", got, bound, store.sends, closes)
			}
			p := got.Payload
			if p == nil || p.PredecessorRevisionID != before.head.Core.Revision || p.RequestedRevisionID != requested.Core.Revision || p.ObservedRevisionID != wantObserved || len(p.LiveDutyIDs) != 0 || len(p.LiveHazardIDs) != 0 {
				t.Fatalf("transition payload changed observation or work facts: %+v", p)
			}
			key, err := format.Key(memory.desc.Prefix, requested.Core.Root)
			if err != nil {
				t.Fatal(err)
			}
			root, err := format.DecodeRoot(memory.objects[key].Body)
			if err != nil || len(root.Names) != 2 || root.Names[0].Name != "alpha" || root.Names[1].Name != "plain" {
				t.Fatal("candidate entry source differs", err)
			}
			slot := root.Names[0].Slot
			pageRef := root.ValueEntryPages[int(slot)/format.PageSlots]
			if pageRef == nil {
				t.Fatal("candidate page absent")
			}
			key, err = format.Key(memory.desc.Prefix, *pageRef)
			if err != nil {
				t.Fatal(err)
			}
			page, err := format.DecodeValueEntryPage(memory.objects[key].Body)
			if err != nil || page.Slots[int(slot)%format.PageSlots] == nil {
				t.Fatal("candidate entry absent", err)
			}
			entry := page.Slots[int(slot)%format.PageSlots]
			// The freshly allocated incarnation is captured input. Independently
			// hash value-entry and membership identities, then BE32-frame the two
			// sorted 34-byte rows and the complete vector under its fixed purpose.
			rows := make([][]byte, 0, 2)
			for _, kind := range []byte{1, 3} {
				preimage := append([]byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00"), f.env.Domain[:]...)
				preimage = append(preimage, kind)
				preimage = append(preimage, entry.Incarnation[:]...)
				secondary := contract.ID{}
				if kind == 3 {
					secondary = before.admission.recipient
				}
				preimage = append(preimage, secondary[:]...)
				id := sha256.Sum256(preimage)
				rows = append(rows, append([]byte{kind, 1}, id[:]...))
			}
			slices.SortFunc(rows, bytes.Compare)
			vector := binary.BigEndian.AppendUint32(nil, 2)
			for _, row := range rows {
				vector = append(binary.BigEndian.AppendUint32(vector, uint32(len(row))), row...)
			}
			preimage := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v1/changed-subjects\x00"), uint32(len(vector)))
			wantSubjects := ChangedSubjectCommitment{Count: 2, IdentityRootDigest: sha256.Sum256(append(preimage, vector...))}
			if p.ChangedSubjects != wantSubjects {
				t.Fatal("payload changed independent subject commitment", p.ChangedSubjects, wantSubjects)
			}
			unreadable = false
			actual, result := Open(ctx, f.admitted, base)
			if actual == nil {
				t.Fatal("actual storage selection unreadable after observation fault removed", result)
			}
			if condition == "competing-selection" && actual.head.Core.Revision == wantObserved || condition == "unknown-without-commit" && actual.head.Core.Revision != before.head.Core.Revision || condition == "committed-unreadable" && actual.head.Core.Revision != requested.Core.Revision {
				t.Fatal("controlled Store effect differs from reported observation", actual.head.Core.Revision, got.Result)
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedAdmissionFailureDoesNotClaimSelectedRelationDamage(t *testing.T) {
	for _, condition := range []string{"closed-routes", "invalid-admission"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			x := newInstalledGeneratedCheckpointFixture(t, ctx, "apply")
			admit := x.callbacks.AdmitAdoption
			calls := 0
			var selected format.Head
			x.callbacks.AdmitAdoption = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedAdoptionInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
				calls++
				memory := requireAdmittedMemoryStore(t, x.f.env.Store)
				var err error
				selected, err = format.DecodeHead(memory.objects[memory.desc.HeadKey].Body)
				if err != nil {
					t.Fatal(err)
				}
				if condition == "closed-routes" {
					x.f.keys.CloseRoutes()
				} else {
					q.Context.AdmissionID = contract.ID{}
				}
				owner, err := admit(ctx, q, control, input, deadline)
				if err == nil || owner != nil {
					t.Fatal("private admission fault did not reach its actual constructor", err)
				}
				return owner, err
			}
			got := x.invoke(t, ctx, "apply", contract.ID{})
			if calls != 1 || selected.Core.Revision.IsZero() || got.Result.Outcome != ObservedCurrent || got.Result.RequestedRevision != selected.Core.Revision || got.Result.ObservedRevision != selected.Core.Revision || got.Result.Evidence != AuthenticatedClosure || got.Result.CommitMayHaveOccurred || got.Payload != nil || len(got.Receipt) != 0 || got.Generated == nil || !got.Generated.EffectsAvailable || len(got.Generated.Effects) != 1 || got.Generated.Effects[0].Record.State != contract.GeneratedEffectTransmitted {
				t.Fatal("private constructor refusal changed selected checkpoint facts", got)
			}
			if len(got.Diagnostics) != 1 || got.Diagnostics[0].Reason != contract.ReasonEvidenceUnavailable || got.Diagnostics[0].Outcome != contract.DiagnosticUnable || got.Diagnostics[0].Subject.Kind != contract.SubjectObservation {
				t.Fatal("unavailable private admission falsely claimed selected relation damage", got.Diagnostics)
			}
			creates, deletes := x.effects()
			if creates != 1 || len(deletes) != 0 {
				t.Fatal("admission refusal changed effect count", creates, deletes)
			}
		})
	}
}
