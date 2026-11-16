package custody

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

// full_only: false
func TestPrivateRouteWitnessSeparatesProviderOutcomes(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
		f := New(t, family, id("route-witness"), true, []contract.ID{id("authority"), id("reader")})
		var authority, recovery contract.KMSBinding
		for _, row := range f.Bindings() {
			if row.SubjectID == f.authority {
				authority = row.Binding
			}
			if row.SubjectID == f.recovery {
				recovery = row.Binding
			}
		}
		if !contract.IndependentKMSBindings(authority, recovery) {
			t.Fatal("witness keys are not independent")
		}
		for _, tc := range []struct {
			name    string
			route   contract.ID
			wrapped contract.KMSBinding
			want    RouteWitness
		}{
			{"positive", authority.BindingID, authority, RouteWitness{Outcome: contract.CryptoSuccess, Completed: 1}},
			{"wrong-binding", authority.BindingID, recovery, RouteWitness{Outcome: contract.CryptoPrivateRouteUnavailable, Failed: 1}},
			{"denied", recovery.BindingID, authority, RouteWitness{Outcome: contract.CryptoPrivateRouteUnavailable, Denied: 1}},
			{"local-refusal", id("absent-binding"), authority, RouteWitness{Outcome: contract.CryptoInvalidAdmission}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := f.PrivateWitness(context.Background(), tc.route, authority, tc.wrapped); got != tc.want {
					t.Fatalf("witness=%+v want=%+v", got, tc.want)
				}
			})
		}
	}
}

type witnessDamagedRoute struct {
	*keyRoute
	damage   string
	retained []byte
	calls    int
}

func (r *witnessDamagedRoute) Decrypt(ctx context.Context, b contract.KMSBinding, ciphertext []byte, length uint16) privatecrypto.PrivateResult {
	r.calls++
	result := r.keyRoute.Decrypt(ctx, b, ciphertext, length)
	if result.Status != privatecrypto.KeyOK {
		return result
	}
	r.retained = bytes.Repeat([]byte{0x77}, cap(result.Packet)+23)
	copy(r.retained, result.Packet)
	clear(result.Packet[:cap(result.Packet)])
	result.Packet = r.retained[:len(result.Packet)]
	switch r.damage {
	case "kind":
		result.Packet[3] = 2
	case "context":
		result.Packet[4] ^= 1
	case "challenge":
		result.Packet[len(result.Packet)-1] ^= 1
	case "length":
		result.Packet = result.Packet[:len(result.Packet)-1]
	case "missing-use":
		result.Uses = privatecrypto.KeyUses{}
	case "extra-use":
		result.Uses.Completed = 2
	case "failed-with-packet":
		result.Status = privatecrypto.KeyInvalid
		result.Uses = privatecrypto.KeyUses{Failed: 1}
	}
	return result
}

// full_only: false
func TestPrivateRouteWitnessClearsPacketCapacityAndConsumesRuntime(t *testing.T) {
	for _, damage := range []string{"none", "kind", "context", "challenge", "length", "missing-use", "extra-use", "failed-with-packet"} {
		t.Run(damage, func(t *testing.T) {
			id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
			f := New(t, contract.AWS, id("packet-witness"), false, []contract.ID{id("authority")})
			binding := f.Bindings()[0].Binding
			route := &witnessDamagedRoute{keyRoute: &keyRoute{owner: f, subject: f.authority, id: f.routes[binding.BindingID]}, damage: damage}
			runtime, err := privatecrypto.New(contract.AWS, []privatecrypto.KeyAccess{route})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(runtime.Close)
			got := PrivateRouteWitness(context.Background(), runtime, route.id, binding, binding)
			if (got.Outcome == contract.CryptoSuccess) != (damage == "none") || route.calls != 1 {
				t.Fatalf("packet witness outcome=%v calls=%d", got.Outcome, route.calls)
			}
			if !bytes.Equal(route.retained, make([]byte, len(route.retained))) {
				t.Fatal("witness retained private packet capacity")
			}
			if got := PrivateRouteWitness(context.Background(), runtime, route.id, binding, binding); got != (RouteWitness{Outcome: contract.CryptoInvalidAdmission}) || route.calls != 1 {
				t.Fatal("witness runtime reused")
			}
		})
	}
}

// full_only: false
func TestPrivateRouteWitnessRefusesLocalInputsBeforeCallingRoute(t *testing.T) {
	for _, change := range []string{"nil-adapter", "wrapped-adapter", "nil-runtime", "missing-route", "bad-public", "mixed-provider", "cancelled", "admitted-runtime"} {
		t.Run(change, func(t *testing.T) {
			id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
			f := New(t, contract.AWS, id("local-witness"), false, []contract.ID{id("authority")})
			binding := f.Bindings()[0].Binding
			adapter := f.Crypto()
			route := f.routes[binding.BindingID]
			wrapped := binding
			ctx := context.Background()
			want := contract.CryptoInvalidAdmission
			switch change {
			case "nil-adapter":
				adapter = nil
			case "wrapped-adapter":
				adapter = wrappedAdapter{f.Crypto()}
			case "nil-runtime":
				adapter = (*privatecrypto.Runtime)(nil)
			case "missing-route":
				route = id("absent-route")
			case "bad-public":
				wrapped.SPKI = []byte("invalid")
				want = contract.CryptoInvalidInput
			case "mixed-provider":
				wrapped.Provider = contract.GCP
				want = contract.CryptoInvalidInput
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = contract.CryptoCancelled
			case "admitted-runtime":
				q, deadline := facadeInitRequest(t, f)
				if err := f.AdmitInit(q, contract.CryptoSupportID(), deadline); err != nil {
					t.Fatal(err)
				}
			}
			if got := PrivateRouteWitness(ctx, adapter, route, binding, wrapped); got != (RouteWitness{Outcome: want}) {
				t.Fatalf("local witness=%+v want=%v", got, want)
			}
			if public, private := f.Calls(); public != 0 || private != 0 {
				t.Fatal("local refusal called a provider route")
			}
		})
	}
}
