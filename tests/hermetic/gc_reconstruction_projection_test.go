package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func gcReconstructionFixture(t *testing.T, pending bool) (fixtureEnvironment, *StateSession, contract.GCPlan, contract.GCProgress) {
	t.Helper()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
	plan := gcTestPlan(t, f.session, "reconstruction")
	progress := gcTestProgress(t, plan)
	selected := gcTestSelectState(t, f.session, plan, progress, contract.GCSelect, true)
	progress.Ordinal++
	progress.Targets[0].Consumed = 1
	selected = gcTestSelectState(t, selected, plan, progress, contract.GCReserve, true)
	progress.Ordinal++
	progress.Targets[0].Disposition = contract.GCTargetUnknown
	selected = gcTestSelectState(t, selected, plan, progress, contract.GCRecordProgress, true)
	if pending {
		selected = gcTestSelectState(t, selected, plan, progress, contract.GCClose, false)
	}
	return env, selected, plan, progress
}

// full_only: false
func TestGCReconstructionProjectionPreservesSelectedObligations(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "active"
		if pending {
			name = "pending"
		}
		t.Run(name, func(t *testing.T) {
			env, selected, plan, progress := gcReconstructionFixture(t, pending)
			store := env.Store.(*memoryStore)
			projection := reconstructProjectionFixture(t, env, selected, store)
			assertReconstructionProjectionExact(t, projection, selected, store)
			planBytes, err := contract.EncodeGCPlan(plan)
			if err != nil {
				t.Fatal(err)
			}
			var indexPages []format.AdministrativeIndexPage
			rootCount, planCount, planPart := 0, 0, -1
			for i := 0; i < projection.PartCount(); i++ {
				part, ok := projection.CopyPart(i)
				if !ok {
					t.Fatal("complete projection lost a selected part", i)
				}
				switch part.Kind {
				case ReconstructionRootPart:
					root, err := format.DecodeRoot(part.Body)
					if err != nil || root.ActiveGC != selected.root.ActiveGC || root.GCPlans != selected.root.GCPlans || root.ActiveGC.IsZero() != pending {
						t.Fatal("projection changed GC root ownership", err)
					}
					rootCount++
				case ReconstructionIndexPagePart:
					indexPages = append(indexPages, format.AdministrativeIndexPage{Ref: part.Ref, Body: part.Body})
				case ReconstructionSupportRowPart:
					if part.SupportKind != contract.GCPlanSupportKind {
						continue
					}
					decoded, err := contract.DecodeGCPlan(part.Body)
					if err != nil || part.RecordID != plan.OperationID || !bytes.Equal(part.Body, planBytes) || !reflect.DeepEqual(decoded, plan) {
						t.Fatal("projection changed the original GC plan row", err)
					}
					planCount++
					planPart = i
				}
			}
			index, err := format.DecodeAdministrativeIndexPages(indexPages)
			if err != nil {
				t.Fatal("projected mandatory ownership", err)
			}
			groups := 0
			for _, group := range index.Groups {
				if group.OwnerKind != format.AdministrativeGC {
					continue
				}
				if group.GroupID != plan.OperationID || group.GC == nil || !contract.GCProgressEqual(*group.GC, progress) || group.GC.Targets[0].Consumed != 1 || group.GC.Targets[0].Disposition != contract.GCTargetUnknown || group.GC.RemainingCount != 1 {
					t.Fatal("projection reset GC counters, uncertainty or original commitments")
				}
				groups++
			}
			if rootCount != 1 || planCount != 1 || groups != 1 || planPart < 0 {
				t.Fatal("projection GC inventory differs", rootCount, planCount, groups)
			}
			callerCopy, ok := projection.CopyPart(planPart)
			if !ok {
				t.Fatal("GC plan copy refused")
			}
			callerCopy.Body[0] ^= 1
			retained, ok := projection.CopyPart(planPart)
			if !ok || !bytes.Equal(retained.Body, planBytes) {
				t.Fatal("caller edit changed the projection's GC bytes")
			}
			reads := store.reads
			projection.Close()
			projection.Close()
			if projection.PartCount() != 0 || !bytes.Equal(retained.Body, planBytes) || store.reads != reads {
				t.Fatal("closing projection changed a retained GC copy or performed Store work")
			}
			if _, ok := projection.CopyPart(planPart); ok {
				t.Fatal("closed projection exposed GC bytes")
			}
			if _, ok := projection.PartInfo(planPart); ok {
				t.Fatal("closed projection exposed GC metadata")
			}
			if _, ok := projection.Provenance(); ok {
				t.Fatal("closed projection retained selected provenance")
			}
		})
	}
}

// full_only: false
func TestGCReconstructionRefusesMissingPlan(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "active"
		if pending {
			name = "pending"
		}
		t.Run(name, func(t *testing.T) {
			env, selected, plan, _ := gcReconstructionFixture(t, pending)
			store := env.Store.(*memoryStore)
			var planRef format.Ref
			for _, page := range selected.adminIndex.Pages {
				for _, row := range page.Rows {
					if row.Kind == uint8(contract.GCPlanSupportKind) && row.RecordID == plan.OperationID {
						if page.ReadRequired {
							t.Fatal("GC plan fixture is not optional administrative payload")
						}
						planRef = page.Ref
					}
				}
			}
			if planRef.Object.IsZero() {
				t.Fatal("selected GC plan row is absent")
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			private := 0
			var reader *constructedReadProbe
			engine, err := NewInstalledReconstruction(ReconstructionInstallation{
				Candidate: candidateProbeForSelected(t, env, selected), Normal: &candidateQualifierProbe{},
				Construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
					reader = &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: configuration, missingKey: mustKey(t, store.desc.Prefix, planRef)}
					return reader, Result{}
				},
				Verify: func(ctx context.Context, pins contract.ReconstructionVerificationPins, deadline time.Time) (ReconstructionVerifier, error) {
					private++
					return env.Custody.ReconstructionVerifier(ctx, pins, deadline)
				}, CloseInstalled: func() {},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			creates, cas := store.creates, store.cas
			projection, result := engine.Reconstruct(ctx)
			if projection != nil {
				projection.Close()
				t.Fatal("missing GC payload produced a complete reconstruction")
			}
			if result != (Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}) || private != 0 || reader == nil || reader.reads == 0 || reader.closes != 1 || store.creates != creates || store.cas != cas {
				t.Fatal("missing GC payload did not refuse before private reconstruction", result, private)
			}
		})
	}
}

// full_only: false
func TestGCReconstructionAnchorRequiresExactSignedSubject(t *testing.T) {
	env, selected, _, _ := gcReconstructionFixture(t, false)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	qualifier := &candidateQualifierProbe{}
	anchor, result := anchorPublicCandidate(ctx, candidateProbeForSelected(t, env, selected), env.Domain, qualifier, nil)
	if result != (Result{}) || qualifier.calls != 1 || anchor.head.Core != selected.head.Core || anchor.anchor.role != contract.NormalSigningRole {
		t.Fatal("valid selected GC authorization did not establish its public anchor", result, qualifier.calls)
	}
	subject, err := contract.EncodeGCSubject(*selected.head.GC)
	if err != nil {
		t.Fatal(err)
	}
	subjectOffset := bytes.Index(selected.body, subject)
	if subjectOffset < 4 || bytes.Count(selected.body, subject) != 1 || binary.BigEndian.Uint32(selected.body[subjectOffset-4:subjectOffset]) != uint32(len(subject)) {
		t.Fatal("GC subject is not one exact framed field")
	}
	store := env.Store.(*memoryStore)
	for _, damage := range []string{"missing-subject", "malformed-subject", "changed-signed-subject", "wrong-purpose-signature"} {
		t.Run(damage, func(t *testing.T) {
			probe := candidateProbeForSelected(t, env, selected)
			want := Result{Outcome: IntegrityFailure, Reason: InvalidProof}
			reads := []string{"HEAD", "configuration", "root"}
			switch damage {
			case "missing-subject":
				body := append(bytes.Clone(selected.body[:subjectOffset-4]), 0, 0, 0, 0)
				probe.head.Body = append(body, selected.body[subjectOffset+len(subject):]...)
				want.Reason, reads = InvalidFormat, []string{"HEAD"}
			case "malformed-subject":
				probe.head.Body[subjectOffset] ^= 1
				want.Reason, reads = InvalidFormat, []string{"HEAD"}
			case "changed-signed-subject":
				head := selected.head
				changed := *head.GC
				changed.RequestIdentity = gcTestID("different-signed-request")
				head.GC = &changed
				var err error
				probe.head.Body, err = format.EncodeHead(head)
				if err != nil {
					t.Fatal("changed request is not otherwise canonical", err)
				}
			case "wrong-purpose-signature":
				head := selected.head
				head.AuthorizationSignature = bytes.Clone(head.K1)
				var err error
				probe.head.Body, err = format.EncodeHead(head)
				if err != nil {
					t.Fatal("binding signature is not a canonical signature field", err)
				}
			}
			qualifier := &candidateQualifierProbe{}
			constructed, private := 0, 0
			engine, err := NewInstalledReconstruction(ReconstructionInstallation{
				Candidate: probe, Normal: qualifier, ExpectedDomain: env.Domain,
				Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
					constructed++
					return nil, refused(AdmissionInvalid)
				},
				Verify: func(context.Context, contract.ReconstructionVerificationPins, time.Time) (ReconstructionVerifier, error) {
					private++
					return nil, contract.ErrRecord
				}, CloseInstalled: func() {},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			creates, cas := store.creates, store.cas
			projection, result := engine.Reconstruct(ctx)
			if projection != nil {
				projection.Close()
				t.Fatal("unverified GC authorization produced a projection")
			}
			if result != want || qualifier.calls != 0 || constructed != 0 || private != 0 || !reflect.DeepEqual(probe.calls, reads) || store.creates != creates || store.cas != cas {
				t.Fatal("GC authorization damage crossed its public anchor boundary", result, probe.calls, qualifier.calls, constructed, private)
			}
		})
	}
}
