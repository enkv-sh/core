package crypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
	"enkv.sh/telemetry"
)

func materializationFixture(t *testing.T, ctx context.Context) (contract.MaterializationAdmission, *consumerTestRoute, *MaterializationFileTarget) {
	t.Helper()
	base, route := consumerFixture(t)
	deadline, _ := ctx.Deadline()
	a := contract.MaterializationAdmission{Purpose: contract.MaterializationOperation, RequestID: consumerID("materialization request"), SessionID: consumerID("materialization session"),
		DomainID: base.DomainID, HEADDigest: base.HEADDigest, HEADRevision: base.HEADRevision, SnapshotID: base.SnapshotID, AccessRoot: base.AccessRoot,
		CredentialRoute: route.CredentialRoute(), PublicBasisDigest: consumerID("public basis"), Root: base.Root, HEADToken: base.HEADToken, Recipient: base.Binding, ExpiresAt: deadline,
		Store:      contract.Descriptor{Family: contract.GCP, Identity: consumerID("store"), Coordinate: consumerID("coordinate"), NonBody: consumerID("request fields"), Prefix: "test", HeadKey: "test/HEAD"},
		SourcePins: contract.MaterializationSourcePins{FileID: consumerID("source"), Format: 1, EditableDigest: consumerID("editable"), GeneratedDigest: consumerID("generated"), EditableLength: 21, GeneratedLength: 34, HasGenerated: true},
		Target:     contract.MaterializationTarget{Path: filepath.Join(t.TempDir(), "values.env"), SurfaceID: consumerID("materialization surface"), Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}}
	plain := contract.ValueEntry{Name: "PLAIN", Incarnation: consumerID("plain entry"), ValueState: consumerID("plain value"), OriginSnapshot: base.Core.OriginSnapshotID,
		OriginTransition: base.Core.OriginTransitionID, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{base.Binding.SubjectID}, ValueBytes: []byte("plain"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("plain"))), RetainedLength: uint32(len([]byte("plain")))}
	a.Entries = []contract.MaterializationEntry{{Name: plain.Name, Slot: 0, Entry: plain},
		materializationSecretFixture(t, base, "SUPPLIED", 1, []byte("supplied\nvalue"), false),
		materializationSecretFixture(t, base, "Z_GENERATED", 2, []byte("generated=value"), true)}
	target, err := NewMaterializationFileTarget(a.Target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, route, target
}

func materializationSecretFixture(t *testing.T, base contract.ConsumerSelection, name string, slot uint16, raw []byte, generated bool) contract.MaterializationEntry {
	t.Helper()
	s := base
	s.Slot = slot
	s.Core.Name, s.Core.EntryIncarnationID, s.Core.ValueStateID = name, consumerID(name+" incarnation"), consumerID(name+" value")
	s.Core.ContentLength, s.Core.RetainedLength = uint32(len(raw)), uint32(len(raw))
	s.Entry.ContentLength, s.Entry.RetainedLength = s.Core.ContentLength, s.Core.RetainedLength
	s.Entry.Name, s.Entry.Incarnation, s.Entry.ValueState = name, s.Core.EntryIncarnationID, s.Core.ValueStateID
	if generated {
		s.Core.ValueSource, s.Entry.ValueSource = contract.Generated, contract.Generated
		s.Entry.Generated = generatedConsumerMetadata(s.Core.ValueStateID)
		var err error
		s.Core.GeneratedBindingDigest, err = contract.GeneratedBindingDigest(s.Entry.Generated)
		if err != nil {
			t.Fatal(err)
		}
	}
	payload, keys, err := custody.SealValue(s.Core, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keys[:cap(keys)])
	wrapCore, err := custody.ValueWrapCore(s.Core, s.Binding)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := custody.Wrap(wrapCore, s.Binding.Binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	s.Payload = payload
	s.Access.MaterialID, s.Access.MaterialContextDigest, s.Access.PackageCheck = s.Core.ValueStateID, wrapCore.MaterialContextDigest, payload.PackageCheck
	s.Access.Wraps = []contract.WrapRow{wrap}
	refreshConsumerSelection(t, &s)
	return contract.MaterializationEntry{Name: name, Slot: slot, Entry: s.Entry, Secret: &s}
}

func materializationRetainedAdmission(a contract.MaterializationAdmission, selected contract.PlanningAdmission) contract.MaterializationAdmission {
	a.DomainID, a.HEADDigest, a.HEADRevision, a.SnapshotID, a.AccessRoot = selected.DomainID, selected.HEADDigest, selected.HEADRevision, selected.SnapshotID, selected.AccessRoot
	a.Root, a.HEADToken, a.Recipient, a.CredentialRoute = selected.Root, selected.HEADToken, selected.Authority, selected.CredentialRoute
	a.Entries = make([]contract.MaterializationEntry, len(selected.Targets))
	for i, target := range selected.Targets {
		s := target.Current
		a.Entries[i] = contract.MaterializationEntry{Name: s.Entry.Name, Slot: s.Slot, Entry: s.Entry, Secret: s}
	}
	return a
}

func materializationAssertNoCandidate(t *testing.T, target contract.MaterializationTarget, out contract.MaterializationCompletion, state contract.MaterializationStateResult, stage contract.MaterializationStage, reason contract.MaterializationFailureReason) {
	t.Helper()
	if err := out.Validate(); err != nil {
		t.Fatal("invalid failure union", err, out)
	}
	if out.StateResult != state || out.Facts.Failure == nil || *out.Facts.Failure != (contract.MaterializationFailure{Stage: stage, Reason: reason}) ||
		out.Facts.Replacement != contract.MaterializationNotReplaced || out.Facts.Disclosure != contract.MaterializationDisclosureNone || out.Facts.Cleanup != contract.MaterializationCandidateNotCreated ||
		out.Facts.NativeCompletion != contract.MaterializationNativeNotObserved || out.Facts.CandidateVerification != contract.MaterializationNotObserved || out.Facts.InstalledVerification != contract.MaterializationNotObserved {
		t.Fatal("unsafe pre-staging facts", out)
	}
	entries, err := os.ReadDir(filepath.Dir(target.Path))
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(target.Path) {
		t.Fatal("failed complete selection created a candidate", err)
	}
	old, err := os.ReadFile(target.Path)
	if err != nil || string(old) != "old complete file\n" {
		t.Fatal("failed complete selection changed the destination", err)
	}
}

// full_only: false
func TestMaterializationCustodyOwnsCompleteMixedSet(t *testing.T) {
	base, reader := cryptoTelemetryReader(t)
	ctx, cancel := context.WithTimeout(base, time.Minute)
	defer cancel()
	a, route, target := materializationFixture(t, ctx)
	c, err := NewMaterializationCustody(ctx, route, a, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	for i := range a.Entries {
		entry := &a.Entries[i]
		clear(entry.Entry.ValueBytes)
		clear(entry.Entry.Recipients)
		entry.Name, entry.Entry.Name = "changed", "changed"
		if entry.Secret != nil {
			clear(entry.Secret.Payload.Ciphertext)
			clear(entry.Secret.Access.Wraps[0].RSACiphertext)
			clear(entry.Secret.Binding.Binding.SPKI)
		}
	}
	clear(a.Recipient.Binding.SPKI)
	a.Target.Path = filepath.Join(filepath.Dir(a.Target.Path), "different.env")
	out := c.Materialize(ctx)
	if out.StateResult != contract.MaterializationSuccess || out.Validate() != nil || route.privateCalls != 2 || route.publicCalls != 0 {
		t.Fatal("complete mixed selection failed", out)
	}
	got, err := os.ReadFile(target.Target().Path)
	// This literal is derived from the three fixture values and the declared
	// name ordering/quote rules, independently of the production encoder.
	if err != nil || string(got) != "PLAIN=plain\nSUPPLIED='supplied\nvalue'\nZ_GENERATED=generated=value\n" {
		t.Fatal("complete mixed file differs", err)
	}
	clear(got[:cap(got)])
	if c.raw != nil || c.route != nil || c.target != nil || c.admission.Entries != nil || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
		t.Fatal("completed custody retained private ownership")
	}
	if again := c.Materialize(ctx); again.StateResult != contract.MaterializationRefused || again.Facts.Failure.Reason != contract.MaterializationInvalidAdmission || route.privateCalls != 2 {
		t.Fatal("completed admission reused", again)
	}
	assertCryptoTelemetry(t, reader, "crypto.materialize", map[string]int64{"success": 1, "already_used": 1})
}

// full_only: false
func TestMaterializationCustodyPlainOnlyHasNoPrivateRoute(t *testing.T) {
	ctx := planningContext(t)
	a, route, target := materializationFixture(t, ctx)
	a.Entries = a.Entries[:1]
	if _, err := NewMaterializationCustody(ctx, route, a, target); err == nil {
		t.Fatal("plain-only selection admitted an unnecessary decryptor")
	}
	c, err := NewMaterializationCustody(ctx, nil, a, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if out := c.Materialize(ctx); out.StateResult != contract.MaterializationSuccess || out.Validate() != nil || route.privateCalls != 0 || route.publicCalls != 0 {
		t.Fatal("plain-only selection used private access", out)
	}
	got, err := os.ReadFile(a.Target.Path)
	if err != nil || string(got) != "PLAIN=plain\n" {
		t.Fatal("plain-only file differs", err)
	}
}

// full_only: false
func TestMaterializationCustodyDiagnosticsWithoutMetricsOrTraces(t *testing.T) {
	for _, condition := range []string{"success", "authentication-failure"} {
		t.Run(condition, func(t *testing.T) {
			recorder := telemetry.NewRecorder()
			base := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			ctx, cancel := context.WithTimeout(base, time.Minute)
			defer cancel()
			a, route, target := materializationFixture(t, ctx)
			if condition == "authentication-failure" {
				last := a.Entries[2].Secret
				last.Payload.SemanticCommitment[0] ^= 1
				refreshConsumerSelection(t, last)
				a.Entries[2].Entry = last.Entry
			}
			c, err := NewMaterializationCustody(ctx, route, a, target)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			out := c.Materialize(ctx)
			wantState, wantResult := contract.MaterializationSuccess, telemetry.ResultSuccess
			stages := []telemetry.DiagnosticStage{telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticLocalStaging, telemetry.DiagnosticLocalReplacement, telemetry.DiagnosticLocalCompletion}
			if condition == "authentication-failure" {
				wantState, wantResult = contract.MaterializationPositiveDefect, telemetry.ResultIntegrityFailure
				stages = stages[:1]
			}
			if out.StateResult != wantState || out.Validate() != nil {
				t.Fatal("diagnostic setup changed materialization result", out)
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 16))
			if len(records) != len(stages)+2 || records[0].Event != telemetry.DiagnosticStart || records[len(records)-1].Event != telemetry.DiagnosticReturn || records[len(records)-1].Result != wantResult {
				t.Fatal("missing safe operation diagnostics")
			}
			for i, record := range records {
				if record.Validate() != nil || record.Operation != telemetry.OpCryptoMaterialize || record.Provider != telemetry.ProviderCrypto || record.Call != records[0].Call {
					t.Fatal("invalid private materialization diagnostic")
				}
				if i > 0 && i < len(records)-1 && (record.Event != telemetry.DiagnosticCheckpoint || record.Stage != stages[i-1]) {
					t.Fatal("native stage escaped the owning call")
				}
			}
			wire, err := json.Marshal(struct {
				Records []telemetry.DiagnosticRecord
				Result  contract.MaterializationCompletion
			}{records, out})
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"supplied", "generated=value", "PLAIN", "SUPPLIED", "Z_GENERATED", a.Target.Path, a.Recipient.Binding.KeySelector} {
				if bytes.Contains(wire, []byte(forbidden)) {
					t.Fatal("private content, names or route entered safe diagnostics/result")
				}
			}
		})
	}
}

// full_only: false
func TestMaterializationCustodyLaterFailureCreatesNoCandidate(t *testing.T) {
	ctx := planningContext(t)
	base, originalRoute, originalTarget := materializationFixture(t, ctx)
	for _, condition := range []string{"packet-context", "package-check", "aead", "semantic", "private-route", "private-evidence", "representation"} {
		t.Run(condition, func(t *testing.T) {
			a, err := ownMaterializationAdmission(base)
			if err != nil {
				t.Fatal(err)
			}
			route := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: originalRoute.key, binding: originalRoute.binding}}
			last := a.Entries[2].Secret
			state, stage, reason := contract.MaterializationPositiveDefect, contract.MaterializationAuthentication, contract.MaterializationIntegrityContradiction
			switch condition {
			case "package-check":
				last.Payload.PackageCheck[0] ^= 1
				last.Access.PackageCheck = last.Payload.PackageCheck
			case "aead":
				last.Payload.Ciphertext[0] ^= 1
			case "semantic":
				last.Payload.SemanticCommitment[0] ^= 1
			case "representation":
				a.Entries[2] = materializationSecretFixture(t, *last, last.Entry.Name, last.Slot, []byte("bad\rvalue"), true)
				state, stage, reason = contract.MaterializationRefused, contract.MaterializationEncoding, contract.MaterializationUnrepresentableValue
			case "private-route", "private-evidence":
				state, reason = contract.MaterializationUnavailable, contract.MaterializationPrivateRouteUnavailable
			}
			if condition != "representation" {
				refreshConsumerSelection(t, last)
				a.Entries[2].Entry = last.Entry
			}
			calls := 0
			route.override = func(ctx context.Context, binding contract.KMSBinding, ciphertext []byte, n uint16) PrivateResult {
				calls++
				got := route.testKeyAccess.Decrypt(ctx, binding, ciphertext, n)
				if calls == 2 {
					switch condition {
					case "packet-context":
						got.Packet[4] ^= 1
					case "private-route":
						got.Status, got.Uses = KeyUnavailable, KeyUses{Unknown: 1}
					case "private-evidence":
						got.Uses.Completed = 2
					}
				}
				return got
			}
			if err := os.WriteFile(a.Target.Path, []byte("old complete file\n"), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := NewMaterializationCustody(ctx, route, a, originalTarget)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			out := c.Materialize(ctx)
			materializationAssertNoCandidate(t, a.Target, out, state, stage, reason)
			if calls != 2 || c.raw != nil || c.route != nil || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
				t.Fatal("late failure did not settle complete private ownership")
			}
		})
	}
	t.Run("canceled-before-encoding", func(t *testing.T) {
		a, err := ownMaterializationAdmission(base)
		if err != nil {
			t.Fatal(err)
		}
		a.Entries = a.Entries[:1]
		a.Entries[0].Entry.ValueBytes = []byte("bad\rvalue")
		a.Entries[0].Entry.ContentLength, a.Entries[0].Entry.RetainedLength = uint32(len(a.Entries[0].Entry.ValueBytes)), uint32(len(a.Entries[0].Entry.ValueBytes))
		members, rawLength, code := checkMaterializationAdmission(nil, a)
		if code != contract.CryptoSuccess {
			t.Fatal("invalid cancellation fixture", code)
		}
		private, cancel := context.WithCancel(ctx)
		defer cancel()
		cut := &materializationCancelAfterCheck{Context: private, cancel: cancel}
		c := &MaterializationCustody{target: originalTarget, admission: a, members: members, rawLength: rawLength, deadline: a.ExpiresAt,
			originalDone: ctx.Done(), ctx: cut, cancel: cancel, done: make(chan struct{})}
		cut.owner = c
		go c.observe()
		t.Cleanup(c.Close)
		out := c.Materialize(ctx)
		if !cut.canceledAtMember || private.Err() != context.Canceled {
			t.Fatal("fixture missed cancellation before encoding")
		}
		select {
		case <-private.Done():
		default:
			t.Fatal("canceled lifetime did not settle")
		}
		materializationAssertNoCandidate(t, a.Target, out, contract.MaterializationUnavailable, contract.MaterializationEncoding, contract.MaterializationCanceled)
		if len(cut.backing) != rawLength || !bytes.Equal(cut.backing, make([]byte, len(cut.backing))) || c.raw != nil || c.admission.Entries != nil || c.route != nil || c.target != nil {
			t.Fatal("canceled encoding retained its owner")
		}
	})
}

type materializationCancelAfterCheck struct {
	context.Context
	cancel           context.CancelFunc
	checks           int
	canceledAtMember bool
	owner            *MaterializationCustody
	backing          []byte
}

func (c *materializationCancelAfterCheck) Err() error {
	err := c.Context.Err()
	c.checks++
	if c.checks == 2 {
		c.backing = c.owner.raw[:cap(c.owner.raw)]
		c.cancel()
		select {
		case <-c.Done():
			c.canceledAtMember = true
		default:
		}
	}
	return err
}

type materializationRoutePins struct {
	KeyDecryptor
	family contract.Family
	id     contract.ID
}

func (r *materializationRoutePins) Family() contract.Family      { return r.family }
func (r *materializationRoutePins) CredentialRoute() contract.ID { return r.id }

// full_only: false
func TestMaterializationCustodyRechecksRouteBeforeAuthentication(t *testing.T) {
	ctx := planningContext(t)
	a, route, target := materializationFixture(t, ctx)
	pinned := &materializationRoutePins{KeyDecryptor: route, family: route.Family(), id: route.CredentialRoute()}
	c, err := NewMaterializationCustody(ctx, pinned, a, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	pinned.id = consumerID("changed acquired route")
	out := c.Materialize(ctx)
	if out.StateResult != contract.MaterializationRefused || out.Facts.Failure.Reason != contract.MaterializationInvalidAdmission || out.Validate() != nil || route.privateCalls != 0 {
		t.Fatal("changed acquired route entered authentication", out)
	}
	if _, err := os.Stat(a.Target.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("changed acquired route created destination", err)
	}
}

// full_only: false
func TestMaterializationCustodyRejectsIndependentPinsBeforePrivateUse(t *testing.T) {
	ctx := planningContext(t)
	base, route, target := materializationFixture(t, ctx)
	for _, condition := range []string{"purpose", "observation", "recipient", "membership", "binding", "route", "family", "target", "surface", "expiry", "duplicate-slot", "missing-secret", "entry-substitution", "plain-secret"} {
		t.Run(condition, func(t *testing.T) {
			a, err := ownMaterializationAdmission(base)
			if err != nil {
				t.Fatal(err)
			}
			var decryptor KeyDecryptor = route
			switch condition {
			case "purpose":
				a.Purpose = contract.PlanningOperation
			case "observation":
				a.HEADDigest[0] ^= 1
			case "recipient":
				a.Recipient.SubjectID[0] ^= 1
			case "membership":
				a.Entries[0].Entry.Recipients = []contract.ID{consumerID("different recipient")}
			case "binding":
				a.Recipient.Binding.BindingSerial++
			case "route":
				decryptor = &materializationRoutePins{KeyDecryptor: route, family: route.Family(), id: consumerID("different private route")}
			case "family":
				decryptor = &materializationRoutePins{KeyDecryptor: route, family: contract.AWS, id: route.CredentialRoute()}
			case "target":
				a.Target.Path += ".other"
			case "surface":
				a.Target.SurfaceID[0] ^= 1
			case "expiry":
				a.ExpiresAt = a.ExpiresAt.Add(time.Second)
			case "duplicate-slot":
				a.Entries[2].Slot = a.Entries[1].Slot
			case "missing-secret":
				a.Entries[2].Secret = nil
			case "entry-substitution":
				a.Entries[2].Entry.ValueState[0] ^= 1
			case "plain-secret":
				a.Entries[0].Secret = a.Entries[1].Secret
			}
			c, err := NewMaterializationCustody(ctx, decryptor, a, target)
			if c != nil {
				c.Close()
			}
			var admissionError contract.MaterializationAdmissionError
			if !errors.As(err, &admissionError) || admissionError.Code != contract.CryptoInvalidAdmission || route.privateCalls != 0 || route.publicCalls != 0 {
				t.Fatal("changed admission acquired private access", err)
			}
		})
	}
	t.Run("current-memberships-overflow", func(t *testing.T) {
		ordinary, current := make([]int, 65), make([]int, 65)
		for i := range ordinary {
			ordinary[i], current[i] = 64, 64
		}
		ordinary[64], current[64] = 1, 1
		selected, private := planningRetainedAccessFixture(t, ordinary, current, nil)
		a := materializationRetainedAdmission(base, selected)
		currentContext, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		a.ExpiresAt, _ = currentContext.Deadline()
		memberships := 0
		for _, entry := range a.Entries {
			memberships += len(entry.Entry.Recipients)
		}
		if memberships != 4097 {
			t.Fatal("fixture did not exercise exact membership overflow")
		}
		c, err := NewMaterializationCustody(currentContext, private, a, target)
		if c != nil {
			c.Close()
		}
		var refused contract.MaterializationAdmissionError
		if c != nil || !errors.As(err, &refused) || refused.Code != contract.CryptoCapacityExceeded || private.privateCalls != 0 || private.publicCalls != 0 || target.started {
			t.Fatal("current membership overflow acquired a private owner", err)
		}
	})
	if _, err := os.Stat(base.Target.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid pins created destination", err)
	}
}

// full_only: false
func TestMaterializationCustodyRequiresOriginalContextAndConsumesRefusal(t *testing.T) {
	ctx := planningContext(t)
	a, route, target := materializationFixture(t, ctx)
	c, err := NewMaterializationCustody(ctx, route, a, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	other, cancel := context.WithDeadline(context.Background(), a.ExpiresAt)
	defer cancel()
	if out := c.Materialize(other); out.StateResult != contract.MaterializationRefused || out.Facts.Failure.Reason != contract.MaterializationInvalidAdmission || out.Validate() != nil {
		t.Fatal("different context entered operation", out)
	}
	if out := c.Materialize(ctx); out.StateResult != contract.MaterializationRefused || route.privateCalls != 0 {
		t.Fatal("refused context retained admission", out)
	}
	if c.route != nil || c.admission.Entries != nil || c.raw != nil {
		t.Fatal("refused admission retained owner")
	}
}

// full_only: true
// Proves the maximum encoded file and raw owner, with a 65,536-byte secret.
func TestMaterializationCustodyMaximumRawOwnership(t *testing.T) {
	ctx := planningContext(t)
	a, route, target := materializationFixture(t, ctx)
	plain := a.Entries[0].Entry
	secretBase := *a.Entries[1].Secret
	a.Entries = make([]contract.MaterializationEntry, contract.CryptoMaxValueEntries)
	for i := range a.Entries {
		prefix := "V" + string([]byte{'A' + byte(i/26/26), 'A' + byte(i/26%26), 'A' + byte(i%26)})
		name := prefix + strings.Repeat("N", 256-len(prefix))
		entry := plain
		entry.Name = name
		entry.Incarnation, entry.ValueState = consumerID(name+" incarnation"), consumerID(name+" value")
		entry.ValueBytes = bytes.Repeat([]byte{'x'}, contract.CryptoMaxRawSet/contract.CryptoMaxValueEntries)
		entry.ContentLength, entry.RetainedLength = uint32(len(entry.ValueBytes)), uint32(len(entry.ValueBytes))
		entry.ValueBytes[0] = ' '
		a.Entries[i] = contract.MaterializationEntry{Name: name, Slot: uint16(i), Entry: entry}
	}
	secretRaw := bytes.Repeat([]byte{'x'}, contract.CryptoMaxRawValue)
	secretRaw[0] = ' '
	a.Entries[0] = materializationSecretFixture(t, secretBase, a.Entries[0].Name, 0, secretRaw, false)
	clear(secretRaw[:cap(secretRaw)])
	for i := 509; i < len(a.Entries); i++ {
		a.Entries[i].Entry.ValueBytes = nil
		a.Entries[i].Entry.ContentLength, a.Entries[i].Entry.RetainedLength = 0, 0
	}
	for _, condition := range []string{"aggregate", "individual", "aggregate-overflow", "count-overflow"} {
		t.Run(condition, func(t *testing.T) {
			selected := a
			selected.Entries = slices.Clone(a.Entries)
			switch condition {
			case "individual":
				selected.Entries = selected.Entries[:1]
			case "aggregate-overflow":
				selected.Entries[1].Entry.ValueBytes = bytes.Repeat([]byte{'x'}, contract.CryptoMaxRawSet/contract.CryptoMaxValueEntries+1)
				selected.Entries[1].Entry.ContentLength, selected.Entries[1].Entry.RetainedLength = uint32(len(selected.Entries[1].Entry.ValueBytes)), uint32(len(selected.Entries[1].Entry.ValueBytes))
			case "count-overflow":
				selected.Entries = append(selected.Entries, selected.Entries[0])
			}
			freshTarget, err := NewMaterializationFileTarget(target.Target(), nil)
			if err != nil {
				t.Fatal(err)
			}
			var observedRaw []byte
			write := freshTarget.io.write
			var c *MaterializationCustody
			freshTarget.io.write = func(file *os.File, chunk []byte) (int, error) {
				if observedRaw == nil {
					observedRaw = c.raw[:cap(c.raw)]
				}
				return write(file, chunk)
			}
			c, err = NewMaterializationCustody(ctx, route, selected, freshTarget)
			if condition == "aggregate-overflow" || condition == "count-overflow" {
				var refused contract.MaterializationAdmissionError
				if !errors.As(err, &refused) || refused.Code != contract.CryptoCapacityExceeded || c != nil {
					t.Fatal("oversized complete set admitted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			if out := c.Materialize(ctx); out.StateResult != contract.MaterializationSuccess || out.Validate() != nil || c.raw != nil {
				t.Fatal("maximum raw owner failed", out)
			}
			if !bytes.Equal(observedRaw, make([]byte, len(observedRaw))) || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
				t.Fatal("maximum raw/packet owner capacity retained")
			}
			wantRaw := contract.CryptoMaxRawSet
			if condition == "individual" {
				wantRaw = contract.CryptoMaxRawValue
			}
			if len(observedRaw) != wantRaw {
				t.Fatal("maximum raw owner was not exercised")
			}
			stat, err := os.Stat(selected.Target.Path)
			// 8,388,608 raw bytes + 512 records of 256 name bytes,
			// '=' + two quotes + LF. The single-value case adds 260.
			want := int64(8_521_728)
			if condition == "individual" {
				want = 65_796
			}
			if err != nil || stat.Size() != want {
				t.Fatal("maximum complete surface length", err)
			}
		})
	}
}

// full_only: true
// Proves simultaneous maximum selected ciphertext, retained access and raw/file owners.
func TestMaterializationCustodyMaximumRetainedAccessOwnership(t *testing.T) {
	a, _, initialTarget := materializationFixture(t, planningContext(t))
	ordinary, current := make([]int, 512), make([]int, 512)
	values := make([]retainedAccessValue, 512)
	for i := range values {
		ordinary[i], current[i] = 256, 8
		prefix := "V" + string([]byte{'A' + byte(i/26/26), 'A' + byte(i/26%26), 'A' + byte(i%26)})
		values[i].name = prefix + strings.Repeat("N", 256-len(prefix))
		length := 16_384
		if i == 0 {
			length = 65_536
		} else if i >= 509 {
			length = 0
		}
		values[i].raw = bytes.Repeat([]byte{'x'}, length)
		if length != 0 {
			values[i].raw[0] = ' '
		}
	}
	selected, route := planningRetainedAccessFixture(t, ordinary, current, values)
	for i := range values {
		clear(values[i].raw[:cap(values[i].raw)])
	}
	a = materializationRetainedAdmission(a, selected)
	inputEntries, inputPayloads, inputRSA, inputWrapRows := 0, 0, 0, 0
	for _, entry := range a.Entries {
		s := entry.Secret
		inputEntries += cap(s.Entry.ValueBytes)
		inputPayloads += cap(s.Payload.Ciphertext)
		inputWrapRows += cap(s.Access.Wraps)
		for _, wrap := range s.Access.Wraps {
			inputRSA += cap(wrap.RSACiphertext)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	a.ExpiresAt, _ = ctx.Deadline()
	for _, condition := range []string{"complete", "write-failure"} {
		t.Run(condition, func(t *testing.T) {
			if condition == "write-failure" {
				if err := os.WriteFile(a.Target.Path, []byte("old complete file\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			target, err := NewMaterializationFileTarget(initialTarget.Target(), nil)
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewMaterializationCustody(ctx, route, a, target)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			var backing []byte
			ownedEntries, ownedRSA, wrapCount, membershipCount := 0, 0, 0, 0
			write := target.io.write
			target.io.write = func(file *os.File, chunk []byte) (int, error) {
				if backing == nil {
					backing = c.raw[:cap(c.raw)]
					for _, entry := range c.admission.Entries {
						ownedEntries += cap(entry.Entry.ValueBytes)
						membershipCount += len(entry.Entry.Recipients)
						wrapCount += cap(entry.Secret.Access.Wraps)
						for _, wrap := range entry.Secret.Access.Wraps {
							ownedRSA += cap(wrap.RSACiphertext)
						}
					}
				}
				n, err := write(file, chunk)
				if condition == "write-failure" && err == nil {
					return n, errors.New("controlled native write failure")
				}
				return n, err
			}
			before := route.privateCalls
			out := c.Materialize(ctx)
			if out.Validate() != nil || route.privateCalls-before != 512 || len(backing) != 8_388_608 || ownedEntries != 8_498_688 || ownedRSA != 50_528_256 || wrapCount != 131_584 || membershipCount != 4096 {
				t.Fatal("maximum simultaneous owners were not exercised", out)
			}
			if c.raw != nil || c.route != nil || c.target != nil || c.admission.Entries != nil || !bytes.Equal(backing, make([]byte, len(backing))) || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
				t.Fatal("maximum private owners were not joined and cleared")
			}
			if condition == "complete" {
				info, err := os.Stat(a.Target.Path)
				if err != nil || info.Size() != 8_521_728 || out.StateResult != contract.MaterializationSuccess {
					t.Fatal("maximum complete encrypted selection failed", err, out)
				}
			} else {
				if out.StateResult != contract.MaterializationUnavailable || out.Facts.Replacement != contract.MaterializationNotReplaced || out.Facts.Cleanup != contract.MaterializationCandidateRemoved || out.Facts.Disclosure != contract.MaterializationDisclosureOccurred {
					t.Fatal("maximum failure lost native facts", out)
				}
				old, err := os.ReadFile(a.Target.Path)
				if err != nil || string(old) != "old complete file\n" {
					t.Fatal("maximum failed candidate changed destination", err)
				}
			}
			t.Run(fmt.Sprintf("input-capacity-bytes_entry-%d_payload-%d_rsa-%d_wrap-descriptors-%d", inputEntries, inputPayloads, inputRSA, inputWrapRows*int(unsafe.Sizeof(contract.WrapRow{}))), func(t *testing.T) {
				if inputEntries != 8_498_688 || inputPayloads != 8_396_800 || inputRSA != 50_528_256 || inputWrapRows < 131_584 || inputWrapRows > 512*1024 {
					t.Fatal("selected input backing exceeded its finite account")
				}
			})
			t.Run(fmt.Sprintf("private-size-bytes_wrap-%d_member-%d_entry-%d_selection-%d_value-%d_env-%d_packet-%d", unsafe.Sizeof(contract.WrapRow{}), unsafe.Sizeof(materializationMember{}), unsafe.Sizeof(contract.MaterializationEntry{}), unsafe.Sizeof(contract.ConsumerSelection{}), unsafe.Sizeof(materializationValue{}), unsafe.Sizeof(materializationEnvRecord{}), len(route.returned)), func(t *testing.T) {
				if len(route.returned) != 132 {
					t.Fatal("private packet capacity was not exercised")
				}
			})
		})
	}
}

// full_only: true
// Maximum separately padded 8 MiB content set and delivered file ownership.
func TestMaterializationCustodyMaximumPaddedDelivery(t *testing.T) {
	for _, input := range []uint8{contract.InputEncodingRaw, contract.InputEncodingBase64} {
		t.Run(fmt.Sprint(input), func(t *testing.T) {
			ctx := planningContext(t)
			admission, _, target := materializationFixture(t, ctx)
			plain := admission.Entries[0].Entry
			admission.Entries = make([]contract.MaterializationEntry, 512)
			expected := sha256.New()
			var totalContent, totalRetained, totalDelivered uint64
			for i := range admission.Entries {
				content := 1
				if i < 127 {
					content = 65536
				} else if i == 511 {
					content = 65152
				}
				// Independent padded bit groups, with the one-byte suffix.
				encoded := strings.Repeat("ZGRk", content/3) + "ZA=="
				name := fmt.Sprintf("V%03d", i) + strings.Repeat("N", 252)
				entry := plain
				entry.Name, entry.Incarnation, entry.ValueState = name, consumerID(name+" incarnation"), consumerID(name+" value")
				entry.InputEncoding, entry.OutputEncoding = input, contract.OutputEncodingBase64
				entry.ValueBytes = bytes.Repeat([]byte{'d'}, content)
				if input == contract.InputEncodingBase64 {
					entry.ValueBytes = []byte(encoded)
				}
				entry.ContentLength, entry.RetainedLength = uint32(content), uint32(len(entry.ValueBytes))
				admission.Entries[i] = contract.MaterializationEntry{Name: name, Slot: uint16(i), Entry: entry}
				totalContent += uint64(content)
				totalRetained += uint64(len(entry.ValueBytes))
				totalDelivered += uint64(len(encoded))
				if _, err := fmt.Fprintf(expected, "%s=%s\n", name, encoded); err != nil {
					t.Fatal("independent maximum output construction failed", err)
				}
			}
			if totalContent != 8388608 || totalDelivered != 11186176 {
				t.Fatal("independent maximum construction changed")
			}
			var c *MaterializationCustody
			var retained []byte
			var converted [][]byte
			write := target.io.write
			target.io.write = func(file *os.File, chunk []byte) (int, error) {
				if retained == nil {
					retained = c.raw[:cap(c.raw)]
					for _, value := range c.converted {
						converted = append(converted, value[:cap(value)])
					}
				}
				return write(file, chunk)
			}
			var err error
			c, err = NewMaterializationCustody(ctx, nil, admission, target)
			if err != nil {
				t.Fatal("maximum padded selection refused", err)
			}
			t.Cleanup(c.Close)
			out := c.Materialize(ctx)
			if out.StateResult != contract.MaterializationSuccess || out.Validate() != nil || c.raw != nil || c.converted != nil {
				t.Fatal("maximum padded delivery failed", out)
			}
			if uint64(len(retained)) != totalRetained || !bytes.Equal(retained, make([]byte, len(retained))) {
				t.Fatal("retained materialization owner not cleared")
			}
			for _, value := range converted {
				if !bytes.Equal(value, make([]byte, len(value))) {
					t.Fatal("converted materialization owner not cleared")
				}
			}
			body, err := os.ReadFile(admission.Target.Path)
			// Base64 alphabet needs no quotes: D + 512*(name256+'='+LF).
			if err != nil || len(body) != 11318272 || len(body) > contract.MaterializationMaxEncodedBytes {
				t.Fatal("actual padded file length differs from conservative bound", len(body), err)
			}
			actual := sha256.Sum256(body)
			if !bytes.Equal(actual[:], expected.Sum(nil)) {
				t.Fatal("maximum padded file bytes differ")
			}
		})
	}
}
