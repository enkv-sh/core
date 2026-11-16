package crypto

import (
	"context"
	"errors"
	"testing"

	"enkv.sh/core/contract"
)

func installedGeneratedTestReservation(t *testing.T, r *Runtime, f generatedRuntimeFixture) *GeneratedCustody {
	t.Helper()
	owner, err := newGeneratedCustody(r, func() (*generatedAdmission, error) {
		return r.admitGeneratedReservationOwned(f.compare, f.reservation, f.base.deadline)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	return owner
}

func installedGeneratedTestCompare(t *testing.T, owner *GeneratedCustody, f generatedRuntimeFixture) contract.CryptoResponse {
	t.Helper()
	body, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	return owner.Exchange(context.Background(), contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoCompare, RequestID: consumerID("installed generated comparison"), CustodyInstanceID: owner.InstanceID(), Body: body})
}

// full_only: false
func TestInstalledGeneratedCustodyCannotReachReplacementSession(t *testing.T) {
	f := generatedRuntimePlanFixture(t, false)
	r := newConsumerRuntime(t, f.base.route)
	first := installedGeneratedTestReservation(t, r, f)
	r.retireSession(first.admission.session)
	f.compare.Context.AdmissionID = consumerID("replacement generated admission")
	f.compare.Context.SessionID = consumerID("replacement generated session")
	var err error
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	second := installedGeneratedTestReservation(t, r, f)
	if out := installedGeneratedTestCompare(t, first, f); out.ResultCode != contract.CryptoInvalidAdmission {
		t.Fatal("stale owner exchanged with replacement", out.ResultCode)
	}
	if code := first.BindCandidate(context.Background(), contract.GeneratedCandidateInput{}); code != contract.CryptoInvalidAdmission {
		t.Fatal("stale owner bound replacement", code)
	}
	if returned := first.InvokeProducer(context.Background(), contract.ID{}, contract.ID{}); returned.Code != contract.CryptoInvalidAdmission || len(returned.Record) != 0 || returned.Facts.Schema != 0 || returned.ExecutableCleanupFailed {
		t.Fatal("stale owner entered replacement", returned.Code)
	}
	first.Close()
	if out := installedGeneratedTestCompare(t, second, f); out.ResultCode != contract.CryptoSuccess {
		t.Fatal("stale owner consumed replacement admission", out.ResultCode)
	}
}

// full_only: false
func TestInstalledGeneratedConstructorRejectsReplacedAdmission(t *testing.T) {
	f := generatedRuntimePlanFixture(t, false)
	r := newConsumerRuntime(t, f.base.route)
	var replacement *GeneratedCustody
	owner, err := newGeneratedCustody(r, func() (*generatedAdmission, error) {
		original, err := r.admitGeneratedReservationOwned(f.compare, f.reservation, f.base.deadline)
		if err != nil {
			return nil, err
		}
		r.retireSession(original.session)
		f.compare.Context.AdmissionID = consumerID("interleaved generated admission")
		f.compare.Context.SessionID = consumerID("interleaved generated session")
		f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
		if err != nil {
			return nil, err
		}
		replacement = installedGeneratedTestReservation(t, r, f)
		return original, nil
	})
	if owner != nil || !errors.Is(err, ErrAdmission) {
		t.Fatal("constructor captured replacement", owner, err)
	}
	if out := installedGeneratedTestCompare(t, replacement, f); out.ResultCode != contract.CryptoSuccess {
		t.Fatal("constructor retired replacement session", out.ResultCode)
	}
}
