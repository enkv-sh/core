package crypto

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func planningFixture(t *testing.T) (contract.PlanningAdmission, *consumerTestRoute) {
	t.Helper()
	f := applyFixture(t, false)
	root, err := contract.DecodeRef(f.q.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	authority := f.q.Bindings[applyBindingIndex(f.q.Bindings, f.control.AuthorityRecipientID)]
	pair := contract.PlanningSourcePair{FileIdentity: consumerID("source file"), EditableDigest: consumerID("editable capture"), GeneratedDigest: consumerID("generated capture"), EditableLength: 71, GeneratedLength: 93}
	a := contract.PlanningAdmission{RequestID: consumerID("planning request"), SessionID: consumerID("planning session"), DomainID: f.control.DomainID,
		HEADDigest: f.q.Context.PredecessorHEADDigest, HEADRevision: consumerID("head revision"), SnapshotID: root.Object, AccessRoot: f.q.Context.CurrentAccessRoot,
		Root: root, HEADToken: contract.Token{Family: contract.GCP, Value: "1"}, CredentialRoute: f.route.CredentialRoute(), Sources: contract.PlanningSources{Trusted: pair, Proposed: pair},
		Control: f.control, Authority: authority, Options: contract.PlanningOptions{Purpose: contract.PlanningEquality}}
	for i, input := range f.q.SealedInputs {
		plain := []byte("first secret")
		if i == 1 {
			plain = []byte{}
		}
		core := contract.ValueCore{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: a.DomainID, Name: input.Name,
			EntryIncarnationID: consumerID(input.Name + " incarnation"), ValueStateID: consumerID(input.Name + " material"), OriginSnapshotID: consumerID("current origin snapshot"), OriginTransitionID: consumerID("current origin transition"),
			DataKeyID: consumerID(input.Name + " current data"), DataKeyEpoch: 1, CommitmentKeyID: consumerID(input.Name + " current commitment"), CommitmentKeyEpoch: 1, ValueSource: contract.Supplied, ContentLength: uint32(len(plain)), InputEncoding: contract.InputEncodingRaw, RetainedLength: uint32(len(plain))}
		payload, keys, err := custody.SealValue(core, plain)
		clear(plain[:cap(plain)])
		if err != nil {
			t.Fatal(err)
		}
		selection := contract.ConsumerSelection{DomainID: a.DomainID, SnapshotID: a.SnapshotID, HEADDigest: a.HEADDigest, AccessRoot: a.AccessRoot, HEADRevision: a.HEADRevision, HEADToken: a.HEADToken, Root: a.Root, Slot: uint16(i), Core: core, Payload: payload, Binding: authority,
			Entry: contract.ValueEntry{Name: input.Name, Incarnation: core.EntryIncarnationID, ValueState: core.ValueStateID, OriginSnapshot: core.OriginSnapshotID, OriginTransition: core.OriginTransitionID, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, Recipients: slices.Clone(f.q.Intent[i].Recipients), InputEncoding: core.InputEncoding, OutputEncoding: contract.OutputEncodingRaw, ContentLength: core.ContentLength, RetainedLength: core.RetainedLength}}
		for _, binding := range f.q.Bindings {
			wrapCore, err := custody.ValueWrapCore(core, binding)
			if err != nil {
				t.Fatal(err)
			}
			wrap, err := custody.Wrap(wrapCore, binding.Binding, keys)
			if err != nil {
				t.Fatal(err)
			}
			selection.Access.MaterialContextDigest = wrapCore.MaterialContextDigest
			selection.Access.Wraps = append(selection.Access.Wraps, wrap)
		}
		clear(keys[:cap(keys)])
		selection.Access.Schema, selection.Access.MaterialKind, selection.Access.MaterialID, selection.Access.PackageCheck = contract.CanonicalSchema, contract.ValueMaterialKind, core.ValueStateID, payload.PackageCheck
		refreshConsumerSelection(t, &selection)
		a.Targets = append(a.Targets, contract.PlanningTarget{Input: contract.PlanningInput{Name: input.Name, Form: contract.PlanningSealed, SealedInput: slices.Clone(input.EnvelopeBytes)}, ProposedRecipients: slices.Clone(f.q.Intent[i].Recipients), CurrentPresent: true, CurrentValueSource: contract.Supplied, CurrentConfidentialityClass: contract.Secret, Current: &selection})
	}
	return a, f.route
}

func clonePlanningFixture(t *testing.T, a contract.PlanningAdmission, route *consumerTestRoute) (contract.PlanningAdmission, *consumerTestRoute) {
	t.Helper()
	owned, err := ownPlanningAdmission(a)
	if err != nil {
		t.Fatal(err)
	}
	return owned, &consumerTestRoute{testKeyAccess: &testKeyAccess{key: route.key, binding: route.binding}}
}

func planningContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func planningReseal(t *testing.T, a *contract.PlanningAdmission, index int, plain []byte) {
	t.Helper()
	envelope, err := contract.DecodeSealedInputEnvelope(a.Targets[index].Input.SealedInput)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Core.ContentLength = uint32(len(plain))
	envelope.Core.RetainedLength = uint32(len(plain))
	envelope, err = custody.SealInput(envelope.Core, a.Authority, plain)
	if err != nil {
		t.Fatal(err)
	}
	a.Targets[index].Input.SealedInput, err = contract.EncodeSealedInputEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
}

func planningRetain(a *contract.PlanningAdmission) {
	for i := range a.Targets {
		t := &a.Targets[i]
		t.Input.Form, t.Input.SealedInput = contract.PlanningRetained, nil
		t.Input.Retained = contract.RetainedSecretInput{Incarnation: t.Current.Entry.Incarnation, Material: t.Current.Entry.ValueState}
	}
}

// full_only: false
func TestPlanningAuthenticatesSuppliedRelations(t *testing.T) {
	base, key := planningFixture(t)
	for _, condition := range []string{"equal-randomized-seals", "changed", "new", "retained", "stale-retained", "membership-mismatch", "plain-generated-conversion", "empty-scope", "owned-capture"} {
		t.Run(condition, func(t *testing.T) {
			a, route := clonePlanningFixture(t, base, key)
			forms := []contract.PlanningSourceForm{contract.PlanningSealed, contract.PlanningSealed}
			relations := []contract.PlanningPrivateRelation{contract.PlanningEqual, contract.PlanningEqual}
			calls := 4
			switch condition {
			case "equal-randomized-seals":
				before := slices.Clone(a.Targets[0].Input.SealedInput)
				planningReseal(t, &a, 0, []byte("first secret"))
				if bytes.Equal(before, a.Targets[0].Input.SealedInput) {
					t.Fatal("fixture did not produce a distinct seal")
				}
			case "changed":
				planningReseal(t, &a, 0, []byte("different"))
				relations[0] = contract.PlanningChanged
			case "new":
				for i := range a.Targets {
					a.Targets[i].Current, a.Targets[i].CurrentPresent = nil, false
					a.Targets[i].CurrentValueSource, a.Targets[i].CurrentConfidentialityClass = 0, 0
				}
				relations[0], relations[1], calls = contract.PlanningNew, contract.PlanningNew, 2
			case "retained", "stale-retained":
				planningRetain(&a)
				forms[0], forms[1], calls = contract.PlanningRetained, contract.PlanningRetained, 2
				if condition == "stale-retained" {
					a.Targets[1].Input.Retained.Material[0] ^= 1
				}
			case "membership-mismatch":
				for i := range a.Targets {
					a.Targets[i].ProposedRecipients = []contract.ID{a.Authority.SubjectID}
				}
			case "plain-generated-conversion":
				a.Targets[0].Current, a.Targets[1].Current = nil, nil
				a.Targets[0].CurrentConfidentialityClass = contract.Plain
				a.Targets[1].CurrentValueSource = contract.Generated
				relations[0], relations[1], calls = contract.PlanningUnchecked, contract.PlanningUnchecked, 2
			case "empty-scope":
				a.Targets, calls = nil, 0
			}
			ctx := planningContext(t)
			c, err := NewPlanningCustody(ctx, route, a)
			if condition == "stale-retained" {
				if err == nil || route.privateCalls != 0 {
					t.Fatal("stale retained pins reached private access")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			if condition == "owned-capture" {
				a.Targets[0].Input.SealedInput[0] ^= 1
				a.Targets[1].Current.Payload.Ciphertext[0] ^= 1
				a.Control.AuthorityKMSBinding.SPKI[0] ^= 1
			}
			got := c.Check(ctx)
			want := contract.PlanningCheckResult{Complete: true, Code: contract.CryptoSuccess}
			if condition != "empty-scope" {
				want.Rows = []contract.PlanningRelation{{Name: "alpha", Form: forms[0], Relation: relations[0], Code: contract.CryptoSuccess}, {Name: "beta", Form: forms[1], Relation: relations[1], Code: contract.CryptoSuccess}}
			}
			if !reflect.DeepEqual(got, want) || route.privateCalls != calls || route.publicCalls != 0 {
				t.Fatalf("unexpected complete relations: %+v; private calls %d; public calls %d", got, route.privateCalls, route.publicCalls)
			}
			if again := c.Check(ctx); again.Code != contract.CryptoAlreadyUsed || again.Complete || len(again.Rows) != 0 || route.privateCalls != calls {
				t.Fatal("private check could be repeated")
			}
			packet := route.returned
			if !bytes.Equal(packet, make([]byte, len(packet))) {
				t.Fatal("provider packet capacity retained private material")
			}
			if len(c.admission.Targets) > 0 {
				backing := c.admission.Targets[0].Input.SealedInput
				c.Close()
				if c.admission.Targets != nil || c.route != nil || c.targets != nil || !bytes.Equal(backing, make([]byte, len(backing))) {
					t.Fatal("Close retained encrypted admission backing")
				}
			}
		})
	}
}

type planningDeadlineContext struct {
	context.Context
	deadline time.Time
}

type planningChangedRoute struct {
	KeyDecryptor
	id contract.ID
}

func (r *planningChangedRoute) CredentialRoute() contract.ID { return r.id }

func (c planningDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

// full_only: false
func TestPlanningRejectsChangedAdmission(t *testing.T) {
	base, key := planningFixture(t)
	t.Run("route-changed-after-admission", func(t *testing.T) {
		a, key := clonePlanningFixture(t, base, key)
		route := &planningChangedRoute{KeyDecryptor: key, id: a.CredentialRoute}
		ctx := planningContext(t)
		owner, err := NewPlanningCustody(ctx, route, a)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.Close()
		route.id[0] ^= 1
		got := owner.Check(ctx)
		if got.Code != contract.CryptoInvalidAdmission || got.Complete || len(got.Rows) != len(a.Targets) ||
			got.Rows[0].Relation != contract.PlanningFailed || key.privateCalls != 0 || key.publicCalls != 0 {
			t.Fatal("changed route was classified as unavailable service", got)
		}
	})
	for _, damage := range []string{"unknown-purpose", "feasibility", "request", "session", "source-pair", "source-file", "source-domain", "source-name", "source-wrap", "route", "control", "authority", "head", "revision", "snapshot", "root", "access", "current-binding", "source-form", "duplicate", "order", "name", "long-name", "entry-count", "recipients", "background", "expired", "other-context", "shorter-deadline", "longer-deadline"} {
		t.Run(damage, func(t *testing.T) {
			a, route := clonePlanningFixture(t, base, key)
			ctx := planningContext(t)
			checkContext := ctx
			checkRefusal := false
			switch damage {
			case "unknown-purpose":
				a.Options.Purpose = contract.PlanningPurpose(255)
			case "feasibility":
				a.Options.Purpose = contract.PlanningRetirementFeasibility
			case "request":
				a.RequestID = contract.ID{}
			case "session":
				a.SessionID = contract.ID{}
			case "source-pair":
				a.Sources.Trusted.GeneratedDigest = contract.ID{}
			case "source-file":
				a.Sources.Proposed.FileIdentity[0] ^= 1
			case "source-domain", "source-name", "source-wrap":
				envelope, err := contract.DecodeSealedInputEnvelope(a.Targets[0].Input.SealedInput)
				if err != nil {
					t.Fatal(err)
				}
				switch damage {
				case "source-domain":
					envelope.Core.DomainID[0] ^= 1
				case "source-name":
					envelope.Core.Name = "other"
				default:
					envelope.AuthorityWrap.BindingSerial++
				}
				a.Targets[0].Input.SealedInput, err = contract.EncodeSealedInputEnvelope(envelope)
				if err != nil {
					t.Fatal(err)
				}
			case "route":
				a.CredentialRoute[0] ^= 1
			case "control":
				a.Control.DomainID[0] ^= 1
			case "authority":
				a.Authority.Binding.BindingSerial++
			case "head":
				a.Targets[0].Current.HEADDigest[0] ^= 1
			case "revision":
				a.Targets[0].Current.HEADRevision[0] ^= 1
			case "snapshot":
				a.Targets[0].Current.SnapshotID[0] ^= 1
			case "root":
				a.Targets[0].Current.Root.Digest[0] ^= 1
			case "access":
				a.Targets[0].Current.AccessRoot[0] ^= 1
			case "current-binding":
				a.Targets[0].Current.Binding.Binding.BindingSerial++
			case "source-form":
				a.Targets[0].Input.Form = "unknown"
			case "duplicate":
				a.Targets[1] = a.Targets[0]
			case "order":
				a.Targets[0], a.Targets[1] = a.Targets[1], a.Targets[0]
			case "name":
				a.Targets[0].Input.Name = string([]byte{0xff})
			case "long-name":
				a.Targets[0].Input.Name = strings.Repeat("a", contract.CryptoMaxName+1)
			case "entry-count":
				a.Targets = make([]contract.PlanningTarget, contract.CryptoMaxValueEntries+1)
			case "recipients":
				a.Targets[0].ProposedRecipients = []contract.ID{a.Authority.SubjectID, a.Authority.SubjectID}
			case "background":
				ctx = context.Background()
			case "expired":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
			case "other-context":
				checkContext, checkRefusal = planningContext(t), true
			case "shorter-deadline", "longer-deadline":
				deadline, _ := ctx.Deadline()
				delta := time.Second
				if damage == "shorter-deadline" {
					delta = -delta
				}
				checkContext, checkRefusal = planningDeadlineContext{Context: ctx, deadline: deadline.Add(delta)}, true
			}
			c, err := NewPlanningCustody(ctx, route, a)
			if checkRefusal {
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				result := c.Check(checkContext)
				if result.Code != contract.CryptoInvalidAdmission || result.Complete || len(result.Rows) != 2 || result.Rows[0].Relation != contract.PlanningUnchecked || result.Rows[1].Code != 0 {
					t.Fatal("changed invocation context accepted", result)
				}
			} else if err == nil {
				c.Close()
				t.Fatal("changed admission accepted")
			}
			if route.privateCalls != 0 || route.publicCalls != 0 {
				t.Fatal("refused admission used a key route")
			}
		})
	}
}

// full_only: false
func TestPlanningPrivateFailuresClearAndJoin(t *testing.T) {
	base, key := planningFixture(t)
	t.Run("cancelled-before-check", func(t *testing.T) {
		a, route := clonePlanningFixture(t, base, key)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		c, err := NewPlanningCustody(ctx, route, a)
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		c.Close()
		result := c.Check(ctx)
		if result.Code != contract.CryptoCancelled || result.Complete || len(result.Rows) != 0 || route.privateCalls != 0 {
			t.Fatal("closed owner entered private check", result)
		}
	})
	t.Run("cancelled-after-complete-prefix", func(t *testing.T) {
		a, route := clonePlanningFixture(t, base, key)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		c, err := NewPlanningCustody(ctx, route, a)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		route.override = func(ctx context.Context, b contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
			private := route.testKeyAccess.Decrypt(ctx, b, ciphertext, length)
			if route.privateCalls == 3 {
				cancel()
			}
			return private
		}
		result := c.Check(ctx)
		want := contract.PlanningCheckResult{Code: contract.CryptoCancelled, Rows: []contract.PlanningRelation{{Name: "alpha", Form: contract.PlanningSealed, Relation: contract.PlanningEqual, Code: contract.CryptoSuccess}, {Name: "beta", Form: contract.PlanningSealed, Relation: contract.PlanningUnchecked}}}
		if !reflect.DeepEqual(result, want) || route.privateCalls != 3 || route.publicCalls != 0 || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
			t.Fatal("cancellation changed safe prefix or fabricated source failure", result)
		}
	})
	for _, damage := range []string{"later-source", "source-context", "current-commitment", "denied", "unavailable", "malformed-packet"} {
		t.Run(damage, func(t *testing.T) {
			a, route := clonePlanningFixture(t, base, key)
			wantCode, first := contract.CryptoSourceAuthenticationFailed, contract.PlanningEqual
			var returned []byte
			switch damage {
			case "later-source", "source-context":
				envelope, err := contract.DecodeSealedInputEnvelope(a.Targets[1].Input.SealedInput)
				if err != nil {
					t.Fatal(err)
				}
				if damage == "later-source" {
					envelope.Ciphertext[0] ^= 1
				} else {
					envelope.Core.FilePredecessorDigest[0] ^= 1
				}
				a.Targets[1].Input.SealedInput, err = contract.EncodeSealedInputEnvelope(envelope)
				if err != nil {
					t.Fatal(err)
				}
			case "current-commitment":
				a.Targets[1].Current.Payload.SemanticCommitment[0] ^= 1
				refreshConsumerSelection(t, a.Targets[1].Current)
				wantCode = contract.CryptoStoredAuthenticationFailed
			case "denied", "unavailable", "malformed-packet":
				first = contract.PlanningFailed
				status, uses := KeyDenied, KeyUses{Denied: 1}
				wantCode = contract.CryptoPrivateRouteUnavailable
				switch damage {
				case "unavailable":
					status, uses, wantCode = KeyUnavailable, KeyUses{Unknown: 1}, contract.CryptoCustodyUnavailable
				case "malformed-packet":
					status, uses, wantCode = KeyOK, KeyUses{Completed: 1}, contract.CryptoSourceAuthenticationFailed
				}
				route.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
					route.privateCalls++
					packet := bytes.Repeat([]byte{0xa5}, 117)
					returned = packet[:cap(packet)]
					return PrivateResult{Status: status, Uses: uses, Packet: packet[:100]}
				}
			}
			ctx := planningContext(t)
			c, err := NewPlanningCustody(ctx, route, a)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			result := c.Check(ctx)
			want := contract.PlanningCheckResult{Code: wantCode, Rows: []contract.PlanningRelation{{Name: "alpha", Form: contract.PlanningSealed, Relation: first, Code: contract.CryptoSuccess}, {Name: "beta", Form: contract.PlanningSealed, Relation: contract.PlanningFailed, Code: wantCode}}}
			calls := 3
			if damage == "current-commitment" {
				calls = 4
			}
			if first == contract.PlanningFailed {
				want.Rows[0].Code = wantCode
				want.Rows[1].Relation, want.Rows[1].Code = contract.PlanningUnchecked, 0
				calls = 1
			}
			if !reflect.DeepEqual(result, want) || route.privateCalls != calls || route.publicCalls != 0 {
				t.Fatalf("unsafe partial check: %+v; private calls %d", result, route.privateCalls)
			}
			if !bytes.Equal(returned, make([]byte, len(returned))) || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
				t.Fatal("failed private call retained packet capacity")
			}
		})
	}
	for _, ending := range []string{"close", "cancel", "expiry"} {
		t.Run(ending+"-joins-late-call", func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, route := clonePlanningFixture(t, base, key)
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				release := make(chan struct{})
				route.started, route.release = make(chan struct{}), release
				c, err := NewPlanningCustody(ctx, route, a)
				if err != nil {
					t.Fatal(err)
				}
				finished := make(chan contract.PlanningCheckResult, 1)
				go func() { finished <- c.Check(ctx) }()
				<-route.started
				closed := make(chan struct{})
				wantCode := contract.CryptoCancelled
				switch ending {
				case "cancel":
					cancel()
				case "expiry":
					time.Sleep(time.Minute)
					wantCode = contract.CryptoExpired
				}
				go func() { c.Close(); close(closed) }()
				synctest.Wait()
				select {
				case <-closed:
					t.Fatal("Close released a live private call")
				default:
				}
				if c.admission.Targets == nil {
					t.Fatal("admission released before join")
				}
				close(release)
				result := <-finished
				<-closed
				if result.Code != wantCode || result.Complete || c.admission.Targets != nil || route.privateCalls != 1 || route.publicCalls != 0 || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
					t.Fatal("late private result escaped cancellation or join", result)
				}
			})
		})
	}
}
