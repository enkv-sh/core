package custody

import (
	"bytes"
	"cmp"
	"context"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

type countedRoute struct {
	*keyRoute
	public, private int
}

type wrappedAdapter struct{ contract.Crypto }

// full_only: false
func TestLiveFacadeRejectsUnknownRuntimeAndBindingSet(t *testing.T) {
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	backing := New(t, contract.GCP, id("live validation"), true, []contract.ID{id("authority"), id("reader")})
	var routes []Route
	for _, row := range backing.Bindings() {
		routes = append(routes, Route{BindingID: row.Binding.BindingID, PublicRoute: backing.publicRoutes[row.Binding.BindingID], PrivateRoute: backing.routes[row.Binding.BindingID]})
	}
	for _, adapter := range []contract.Crypto{nil, wrappedAdapter{backing.Crypto()}, (*privatecrypto.Runtime)(nil)} {
		if _, err := newLive(adapter, backing.authority, backing.recovery, backing.Bindings(), routes); err == nil {
			t.Fatal("unrecognized runtime accepted")
		}
	}
	wrongFamily, err := privatecrypto.New(contract.AWS, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrongFamily.Close)
	if _, err := newLive(wrongFamily, backing.authority, backing.recovery, backing.Bindings(), routes); err == nil {
		t.Fatal("runtime provider mismatch accepted")
	}
	for _, roles := range [][2]contract.ID{{{}, backing.recovery}, {id("unknown authority"), backing.recovery}, {backing.authority, {}}, {backing.authority, id("unknown recovery")}, {backing.authority, backing.authority}} {
		if _, err := newLive(backing.Crypto(), roles[0], roles[1], backing.Bindings(), routes); err == nil {
			t.Fatal("wrong authority or recovery accepted")
		}
	}
	rows := backing.Bindings()
	duplicate := rows[0]
	duplicate.Binding.BindingID = id("second binding generation")
	duplicate.Binding.BindingSerial++
	rows = append(rows, duplicate)
	slices.SortFunc(rows, func(a, b contract.BindingTableRow) int {
		if a.SubjectKind != b.SubjectKind {
			return int(a.SubjectKind) - int(b.SubjectKind)
		}
		if cmp := bytes.Compare(a.SubjectID[:], b.SubjectID[:]); cmp != 0 {
			return cmp
		}
		return cmp.Compare(a.Binding.BindingSerial, b.Binding.BindingSerial)
	})
	routes = append(routes, Route{BindingID: duplicate.Binding.BindingID})
	if _, err := newLive(backing.Crypto(), backing.authority, backing.recovery, rows, routes); err == nil {
		t.Fatal("multiple current generations for one recipient accepted")
	}
}

// full_only: false
func TestLiveFacadeSourceNeedsNoPrivateRoute(t *testing.T) {
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	backing := New(t, contract.GCP, id("public source fixture"), false, []contract.ID{id("authority"), id("reader")})
	runtime, err := privatecrypto.New(contract.GCP, nil)
	if err != nil {
		t.Fatal(err)
	}
	var routes []Route
	for _, row := range backing.Bindings() {
		routes = append(routes, Route{BindingID: row.Binding.BindingID})
	}
	live := NewLive(t, runtime, backing.authority, backing.recovery, backing.Bindings(), routes)
	q, control, deadline := facadeApplyRequest(t, live)
	support, err := contract.EmptyRequiredSupportDescriptor(q.Context.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.SealedInputs) != 1 {
		t.Fatal("public producer returned no source")
	}
	if public, private := backing.Calls(); public != 0 || private != 0 {
		t.Fatalf("source sealing used a provider route: %d/%d", public, private)
	}
	if err := live.AdmitApply(q, control, facadeApplyRecipients(q), nil, support, deadline); err == nil {
		t.Fatal("source preparation installed private apply authority")
	}
	qInit, deadline := facadeInitRequest(t, live)
	if err := live.AdmitInit(qInit, contract.CryptoSupportID(), deadline); err == nil {
		t.Fatal("source preparation installed init routes")
	}
}

func (r *countedRoute) Qualify(ctx context.Context, binding contract.KMSBinding) privatecrypto.KeyResult {
	r.public++
	return r.keyRoute.Qualify(ctx, binding)
}

func (r *countedRoute) Decrypt(ctx context.Context, binding contract.KMSBinding, ciphertext []byte, length uint16) privatecrypto.PrivateResult {
	r.private++
	return r.keyRoute.Decrypt(ctx, binding, ciphertext, length)
}

func facadeInitRequest(t *testing.T, f *Fixture) (contract.CryptoQualifyInitKeysRequest, time.Time) {
	t.Helper()
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	deadline := time.Now().Add(time.Minute)
	q := contract.CryptoQualifyInitKeysRequest{Context: contract.InitKeyContext{Schema: contract.CryptoSchema, GenesisProfile: 1, AdmissionID: id("admission"), SessionID: id("session"), DomainID: id("domain"), CompatibilityID: contract.CompatibilityID(), Expiry: uint64(deadline.UnixNano()), InitID: id("init"), DescriptorDigest: id("descriptor"), GenesisPlanDigest: id("plan"), RequestDescriptor: contract.DescriptorVector{Digest: id("request"), Length: contract.GenesisRequestCoreLength, Count: 1}}, Bindings: f.Bindings()}
	for _, subject := range []contract.ID{f.authority, f.recovery} {
		for _, row := range q.Bindings {
			if row.SubjectID != subject {
				continue
			}
			digest, err := contract.PublicBindingDigest(row.Binding)
			if err != nil {
				t.Fatal(err)
			}
			q.Probes = append(q.Probes, contract.InitProbePlanRow{ProbeID: id("probe" + string(subject[:])), SubjectKind: row.SubjectKind, SubjectID: subject, BindingID: row.Binding.BindingID, PublicBindingDigest: digest})
		}
	}
	return q, deadline
}

// full_only: false
func TestLiveFacadeSeparatesPublicQualificationAndPrivateProbes(t *testing.T) {
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			backing := New(t, family, id("live controlled"), recovery, []contract.ID{id("authority"), id("reader")})
			public := &countedRoute{keyRoute: &keyRoute{owner: backing, subject: backing.authority, id: id("public route")}}
			installed := []privatecrypto.KeyAccess{public}
			var routes []Route
			var private []*countedRoute
			for _, row := range backing.Bindings() {
				route := Route{BindingID: row.Binding.BindingID, PublicRoute: public.id}
				if row.SubjectID == backing.authority || row.SubjectID == backing.recovery {
					route.PrivateRoute = backing.routes[row.Binding.BindingID]
					key := &countedRoute{keyRoute: &keyRoute{owner: backing, subject: row.SubjectID, id: route.PrivateRoute}}
					private = append(private, key)
					installed = append(installed, key)
				}
				routes = append(routes, route)
			}
			runtime, err := privatecrypto.New(family, installed)
			if err != nil {
				t.Fatal(err)
			}
			rows := backing.Bindings()
			live := NewLive(t, runtime, backing.authority, backing.recovery, rows, routes)
			if live.Crypto().InstanceID() != runtime.InstanceID() {
				t.Fatal("live observation replaced the installed runtime")
			}
			if _, err := newLive(runtime, backing.authority, backing.recovery, rows, routes); err == nil {
				t.Fatal("live observation installed twice")
			}
			rows[0].Binding.SPKI[0] ^= 1
			savedRoutes := slices.Clone(routes)
			routes[0].PrivateRoute = id("uninstalled")
			q, deadline := facadeInitRequest(t, live)
			if err := live.AdmitInit(q, contract.CryptoSupportID(), deadline); err != nil {
				t.Fatal(err)
			}
			body, err := contract.EncodeCryptoQualifyInitKeysRequest(q)
			if err != nil {
				t.Fatal(err)
			}
			call := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoQualifyInitKeys, RequestID: id("message"), CustodyInstanceID: runtime.InstanceID(), Body: body}
			if got := live.Crypto().Exchange(context.Background(), call); got.ResultCode != contract.CryptoSuccess {
				t.Fatalf("live qualification: %v", got.ResultCode)
			}
			if public.public != len(q.Bindings) || public.private != 0 {
				t.Fatalf("public route calls: %d/%d", public.public, public.private)
			}
			for _, route := range private {
				if route.public != 0 || route.private != 1 {
					t.Fatalf("private route calls: %d/%d", route.public, route.private)
				}
			}
			if gotPublic, gotPrivate := live.Calls(); gotPublic != len(q.Bindings) || gotPrivate != len(q.Probes) {
				t.Fatalf("live fixture calls: got %d/%d, want %d/%d", gotPublic, gotPrivate, len(q.Bindings), len(q.Probes))
			}
			live.RetireInit()
			if recovery {
				backing.SetDenied(backing.recovery, true)
				q.Context.AdmissionID, q.Context.SessionID = id("next admission"), id("next session")
				if err := live.AdmitInit(q, contract.CryptoSupportID(), deadline); err != nil {
					t.Fatal(err)
				}
				call.Body, err = contract.EncodeCryptoQualifyInitKeysRequest(q)
				if err != nil {
					t.Fatal(err)
				}
				if got := live.Crypto().Exchange(context.Background(), call); got.ResultCode != contract.CryptoPrivateRouteUnavailable {
					t.Fatalf("denied recovery probe: %v", got.ResultCode)
				}
				privateCalls := 0
				for _, route := range private {
					privateCalls += route.private
				}
				if gotPublic, gotPrivate := live.Calls(); gotPublic != public.public || gotPrivate != privateCalls || gotPrivate <= len(q.Probes) {
					t.Fatalf("live fixture lost denied calls: got %d/%d, routes %d/%d", gotPublic, gotPrivate, public.public, privateCalls)
				}
				live.RetireInit()
			}
			for _, mutate := range []func([]Route){
				func(routes []Route) { routes[0].PrivateRoute = id("unknown route") },
				func(routes []Route) { routes[0].BindingID = id("unknown binding") },
				func(routes []Route) { routes[1].BindingID = routes[0].BindingID },
			} {
				bad := slices.Clone(savedRoutes)
				mutate(bad)
				if _, err := newLive(runtime, backing.authority, backing.recovery, backing.Bindings(), bad); err == nil {
					t.Fatal("unknown or duplicate live route accepted")
				}
			}
		}
	}
}

// full_only: false
func TestLiveFacadeRefusesObservationAfterAdmission(t *testing.T) {
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	backing := New(t, contract.GCP, id("used live runtime"), false, []contract.ID{id("authority")})
	var routes []Route
	for _, row := range backing.Bindings() {
		routes = append(routes, Route{BindingID: row.Binding.BindingID, PublicRoute: backing.publicRoutes[row.Binding.BindingID], PrivateRoute: backing.routes[row.Binding.BindingID]})
	}
	q, deadline := facadeInitRequest(t, backing)
	if err := backing.AdmitInit(q, contract.CryptoSupportID(), deadline); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"admitted", "retired", "closed"} {
		if _, err := newLive(backing.Crypto(), backing.authority, backing.recovery, backing.Bindings(), routes); err == nil {
			t.Fatalf("observation installed on %s runtime", state)
		}
		if state == "admitted" {
			backing.RetireInit()
		} else {
			backing.runtime.Close()
		}
	}
}
