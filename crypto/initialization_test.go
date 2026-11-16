package crypto

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestInitializationCustodyOwnsExactProductionAdmission(t *testing.T) {
	runtime, access, q, request, deadline := initializationCustodyFixture(t)
	routes := map[contract.ID]contract.ID{access.binding.BindingID: access.CredentialRoute()}
	for name, change := range map[string]func() (contract.CryptoQualifyInitKeysRequest, map[contract.ID]contract.ID, time.Time){
		"missing-public-route": func() (contract.CryptoQualifyInitKeysRequest, map[contract.ID]contract.ID, time.Time) {
			return q, nil, deadline
		},
		"wrong-compatibility": func() (contract.CryptoQualifyInitKeysRequest, map[contract.ID]contract.ID, time.Time) {
			v := q
			v.Context.CompatibilityID = contract.Hash([]byte("other compatibility"))
			return v, routes, deadline
		},
		"different-deadline": func() (contract.CryptoQualifyInitKeysRequest, map[contract.ID]contract.ID, time.Time) {
			return q, routes, deadline.Add(time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			invalid, public, expiry := change()
			if owner, err := NewInitializationCustody(runtime, invalid, public, routes, expiry); err == nil || owner != nil {
				t.Fatal("invalid production installation acquired custody")
			}
		})
	}
	if access.publicCalls != 0 || access.privateCalls != 0 {
		t.Fatal("construction used a provider key")
	}
	owner, err := NewInitializationCustody(runtime, q, routes, routes, deadline)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	foreign := request
	foreign.Kind = contract.CryptoCompare
	if reply := owner.Exchange(context.Background(), foreign); reply.ResultCode != contract.CryptoInvalidAdmission {
		t.Fatal("initialization custody admitted a different operation kind")
	}
	if reply := owner.Exchange(context.Background(), request); reply.ResultCode != contract.CryptoSuccess {
		t.Fatalf("production qualification result %v", reply.ResultCode)
	}
	if reply := owner.Exchange(context.Background(), request); reply.ResultCode != contract.CryptoAlreadyUsed {
		t.Fatal("production custody repeated key qualification")
	}
	owner.Close()
	if reply := owner.Exchange(context.Background(), request); reply.ResultCode != contract.CryptoInvalidAdmission || len(reply.Body) != 0 {
		t.Fatal("closed custody released usable evidence")
	}
	if access.publicCalls != 1 || access.privateCalls != 1 || !bytes.Equal(access.returned, make([]byte, len(access.returned))) {
		t.Fatal("production custody repeated key use or retained private backing capacity")
	}
}

// full_only: false
func TestInitializationCustodyCloseJoinsProviderResponse(t *testing.T) {
	runtime, access, q, request, deadline := initializationCustodyFixture(t)
	routes := map[contract.ID]contract.ID{access.binding.BindingID: access.CredentialRoute()}
	owner, err := NewInitializationCustody(runtime, q, routes, routes, deadline)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	access.started = make(chan struct{})
	access.release = release
	result := make(chan contract.CryptoResponse, 1)
	go func() { result <- owner.Exchange(context.Background(), request) }()
	<-access.started
	closed := make(chan struct{})
	go func() { owner.Close(); close(closed) }()
	// Close sets this flag before it retires and joins the admitted session.
	wait := time.NewTimer(time.Second)
	defer wait.Stop()
	for !owner.closed.Load() {
		select {
		case <-wait.C:
			close(release)
			t.Fatal("custody close did not begin")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	select {
	case <-closed:
		t.Fatal("custody closed before joining the provider response")
	default:
	}
	close(release)
	reply := <-result
	<-closed
	if reply.ResultCode != contract.CryptoCancelled || len(reply.Body) != 0 {
		t.Fatal("retired custody released a late qualification result")
	}
	if !bytes.Equal(access.returned, make([]byte, len(access.returned))) {
		t.Fatal("retired custody retained a late private packet")
	}
}

// full_only: false
func TestInitializationCustodyDoesNotAcquireReplacementAdmission(t *testing.T) {
	runtime, access, q, request, deadline := initializationCustodyFixture(t)
	routes := map[contract.ID]contract.ID{access.binding.BindingID: access.CredentialRoute()}
	var original *initAdmission
	owner, err := newInitializationCustody(runtime, q, routes, routes, deadline,
		func(q contract.CryptoQualifyInitKeysRequest, support contract.ID, public, private map[contract.ID]contract.ID, deadline time.Time) (*initAdmission, error) {
			var err error
			original, err = runtime.installInit(q, support, public, private, deadline)
			if err != nil {
				return nil, err
			}
			runtime.retireInit()
			q.Context.AdmissionID = contract.Hash([]byte("replacement admission"))
			q.Context.SessionID = contract.Hash([]byte("replacement session"))
			if err := runtime.admitInit(q, support, public, private, deadline); err != nil {
				return nil, err
			}
			return original, nil
		})
	if owner != nil {
		defer owner.Close()
	}
	if err == nil || owner != nil {
		t.Fatal("constructor acquired a replacement admission after its exact admission retired")
	}
	runtime.mu.Lock()
	replacement := runtime.init
	selected := runtime.slot
	runtime.mu.Unlock()
	if replacement == nil || replacement == original || selected != replacement.session {
		t.Fatal("failed original constructor retired or replaced the foreign selected session")
	}
	if access.publicCalls != 0 || access.privateCalls != 0 {
		t.Fatal("custody construction used a provider key")
	}
	if reply := (&InitializationCustody{runtime: runtime, admission: original}).Exchange(context.Background(), request); reply.ResultCode != contract.CryptoInvalidAdmission {
		t.Fatal("retired exact owner acquired replacement reach")
	}
}

type initializationDispatchContext struct {
	context.Context
	entered, release chan struct{}
	once             sync.Once
}

func (c *initializationDispatchContext) Value(key any) any {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	return c.Context.Value(key)
}

// full_only: false
func TestInitializationCustodyDispatchKeepsOriginalAdmission(t *testing.T) {
	for _, body := range []string{"original", "replacement"} {
		t.Run(body, func(t *testing.T) {
			runtime, access, q, request, deadline := initializationCustodyFixture(t)
			routes := map[contract.ID]contract.ID{access.binding.BindingID: access.CredentialRoute()}
			owner, err := NewInitializationCustody(runtime, q, routes, routes, deadline)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			replacementQ := q
			replacementQ.Context.AdmissionID = contract.Hash([]byte("next initialization admission"))
			replacementQ.Context.SessionID = contract.Hash([]byte("next initialization session"))
			replacementRequest := request
			replacementRequest.Body, err = contract.EncodeCryptoQualifyInitKeysRequest(replacementQ)
			if err != nil {
				t.Fatal(err)
			}
			if body == "replacement" {
				request = replacementRequest
			}
			gate := &initializationDispatchContext{Context: t.Context(), entered: make(chan struct{}), release: make(chan struct{})}
			var release sync.Once
			releaseGate := func() { release.Do(func() { close(gate.release) }) }
			defer releaseGate()
			result := make(chan contract.CryptoResponse, 1)
			go func() { result <- owner.Exchange(gate, request) }()
			select {
			case <-gate.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("initialization dispatch did not enter caller context")
			}
			closed := make(chan struct{})
			go func() { owner.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				releaseGate()
				<-closed
				t.Fatal("initialization context method ran while holding the runtime lock")
			}
			replacement, err := NewInitializationCustody(runtime, replacementQ, routes, routes, deadline)
			if err != nil {
				t.Fatal("fresh initialization after original retirement", err)
			}
			defer replacement.Close()
			releaseGate()
			select {
			case reply := <-result:
				if reply.ResultCode != contract.CryptoInvalidAdmission || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 {
					t.Error("stale initialization dispatch used replacement authority", reply.ResultCode)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("stale initialization dispatch did not return")
			}
			if access.publicCalls != 0 || access.privateCalls != 0 {
				t.Error("stale initialization dispatch called replacement key routes", access.publicCalls, access.privateCalls)
			}
			owner.Close()
			runtime.mu.Lock()
			selected := runtime.init == replacement.admission && runtime.slot == replacement.admission.session
			runtime.mu.Unlock()
			if !selected {
				t.Fatal("stale Close retired the replacement initialization")
			}
			if reply := replacement.Exchange(t.Context(), replacementRequest); reply.ResultCode != contract.CryptoSuccess {
				t.Error("replacement initialization did not retain its independent use", reply.ResultCode)
			}
			if access.publicCalls != 1 || access.privateCalls != 1 {
				t.Error("replacement initialization did not use each key route once", access.publicCalls, access.privateCalls)
			}
		})
	}
}
