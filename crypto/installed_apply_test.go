package crypto

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestApplyCustodyDoesNotAcquireReplacementAdmission(t *testing.T) {
	f := applyFixture(t, false)
	r := newConsumerRuntime(t, f.route)
	var original, replacement *applyAdmission
	owner, err := newApplyCustody(r, consumerID("apply predecessor revision"), contract.MutationReceiptWindows{DomainID: f.q.Context.DomainID}, 0, func() (*applyAdmission, error) {
		if err := r.admitApply(f.q, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline); err != nil {
			return nil, err
		}
		r.mu.Lock()
		original = r.apply
		r.mu.Unlock()
		r.retireApply()
		next := f.q
		next.Context.AdmissionID = consumerID("replacement apply admission")
		next.Context.SessionID = consumerID("replacement apply session")
		if err := r.admitApply(next, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline); err != nil {
			return nil, err
		}
		r.mu.Lock()
		replacement = r.apply
		r.mu.Unlock()
		return original, nil
	})
	if owner != nil {
		defer owner.Close()
	}
	if err == nil || owner != nil {
		t.Fatal("constructor acquired a replacement admission after its exact admission retired")
	}
	r.mu.Lock()
	selected := r.slot
	current := r.apply
	r.mu.Unlock()
	if current != replacement || current == original || selected != replacement.session {
		t.Fatal("failed constructor changed the foreign selected admission")
	}
	body, encodeErr := contract.EncodeCryptoCompareRequest(f.q)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	request := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoCompare, RequestID: consumerID("retired apply request"), CustodyInstanceID: r.InstanceID(), Body: body}
	if reply := (&ApplyCustody{runtime: r, admission: original}).Exchange(context.Background(), request); reply.ResultCode != contract.CryptoInvalidAdmission {
		t.Fatal("retired owner acquired replacement reach")
	}
}

// full_only: false
func TestInstalledApplyCustodyExchangeCannotAcquireReplacement(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, kind := range []uint16{contract.OperationApplyDeclaration, contract.OperationRetireRecipientIdentity, contract.OperationEnvelopeRekey} {
		for _, bodyOwner := range []string{"old", "replacement"} {
			t.Run(fmt.Sprintf("%d/%s", kind, bodyOwner), func(t *testing.T) {
				f := cloneApplyFixture(t, base)
				var plain []contract.MembershipRow
				var retiredSlot uint16
				switch kind {
				case contract.OperationEnvelopeRekey:
					f = secretAccessFixture(t, base, kind)
				case contract.OperationRetireRecipientIdentity:
					v := retirementFixture(t, base, "mixed")
					f, plain, retiredSlot = v.f, v.before, v.slot
				}
				witness := secretAccessWitness(t, &f)
				r := newConsumerRuntime(t, f.route)
				before := contract.MutationReceiptWindows{DomainID: f.q.Context.DomainID}
				install := func(q contract.CryptoCompareRequest) (*ApplyCustody, error) {
					switch kind {
					case contract.OperationApplyDeclaration:
						return NewApplyCustody(r, q, f.control, f.current, nil, f.route.CredentialRoute(), consumerID("custody owner file"), plain, f.support, witness, consumerID("custody predecessor revision"), before, 0, f.deadline)
					case contract.OperationRetireRecipientIdentity:
						return NewRecipientRetirementCustody(r, q, f.control, f.current, retiredSlot, f.route.CredentialRoute(), plain, f.support, witness, consumerID("custody predecessor revision"), before, 0, f.deadline)
					default:
						return NewEnvelopeRekeyCustody(r, q, f.control, f.current, f.route.CredentialRoute(), plain, f.support, witness, consumerID("custody predecessor revision"), before, 0, f.deadline)
					}
				}
				oldOwner, err := install(f.q)
				if err != nil {
					t.Fatal("original custody", err)
				}
				t.Cleanup(oldOwner.Close)
				next := f.q
				next.Context.AdmissionID = consumerID("replacement custody admission")
				next.Context.SessionID = consumerID("replacement custody session")
				oldBody, err := contract.EncodeCryptoCompareRequest(f.q)
				if err != nil {
					t.Fatal(err)
				}
				nextBody, err := contract.EncodeCryptoCompareRequest(next)
				if err != nil {
					t.Fatal(err)
				}
				body := oldBody
				if bodyOwner == "replacement" {
					body = nextBody
				}
				request := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoCompare, RequestID: consumerID("old custody delayed exchange"), CustodyInstanceID: r.InstanceID(), Body: body}
				ctx := &accessEntryContext{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
				release := sync.OnceFunc(func() { close(ctx.release) })
				t.Cleanup(release)
				result := make(chan contract.CryptoResponse, 1)
				go func() { result <- oldOwner.Exchange(ctx, request) }()
				<-ctx.entered
				oldOwner.Close()
				newOwner, err := install(next)
				if err != nil {
					release()
					<-result
					t.Fatal("replacement custody", err)
				}
				t.Cleanup(newOwner.Close)
				replacement := newOwner.admission
				release()
				reply := <-result
				if reply.ResultCode != contract.CryptoInvalidAdmission || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 || f.route.privateCalls != 0 {
					t.Error("retired owner entered replacement custody", reply.ResultCode, reply.KeyUseRows, f.route.privateCalls)
				}
				r.mu.Lock()
				intact := r.apply == replacement && r.slot == replacement.session && !replacement.terminal && !replacement.busy && replacement.stage == contract.CryptoCompare
				r.mu.Unlock()
				if !intact {
					t.Error("old owner changed or terminated replacement admission")
				}
				request.RequestID, request.Body = consumerID("replacement custody positive exchange"), nextBody
				positive := newOwner.Exchange(context.Background(), request)
				wantOpens := uint32(1)
				if kind == contract.OperationApplyDeclaration {
					wantOpens = 2
				}
				wantUse := independentKeyUseRow(next.Bindings[applyBindingIndex(next.Bindings, f.control.AuthorityRecipientID)], contract.KeyUseMaterialOpen, contract.KeyUseCompleted, wantOpens)
				if positive.ResultCode != contract.CryptoSuccess || len(positive.KeyUseRows) != 1 || positive.KeyUseRows[0] != wantUse {
					t.Error("replacement owner lost its usable private admission", positive.ResultCode, positive.KeyUseRows)
				}
				newOwner.Close()
				select {
				case <-replacement.done:
				default:
					t.Error("replacement retirement did not join its observer")
				}
			})
		}
	}
}
