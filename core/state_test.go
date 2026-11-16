package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
)

// Empty public admission must fail before it reaches any provider boundary.
type refusalBoundary struct{ t *testing.T }

func (b refusalBoundary) Descriptor() contract.Descriptor {
	b.t.Fatal("refused admission called Store.Descriptor")
	return contract.Descriptor{}
}

func (b refusalBoundary) Read(context.Context, string, uint32) contract.ReadResult {
	b.t.Fatal("refused admission called Store.Read")
	return contract.ReadResult{}
}

func (b refusalBoundary) Create(context.Context, string, []byte) contract.WriteResult {
	b.t.Fatal("refused admission called Store.Create")
	return contract.WriteResult{}
}
func (b refusalBoundary) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	b.t.Fatal("refused admission called Store.CreateHead")
	return contract.WriteResult{}
}

func (b refusalBoundary) CompareAndSwap(context.Context, string, contract.Token, []byte) contract.WriteResult {
	b.t.Fatal("refused admission called Store.CompareAndSwap")
	return contract.WriteResult{}
}

func (b refusalBoundary) Identity() contract.ID {
	b.t.Fatal("refused admission called Trust.Identity")
	return contract.ID{}
}

func (b refusalBoundary) Family() contract.Family {
	b.t.Fatal("refused admission called Trust.Family")
	return 0
}

func (b refusalBoundary) Sign(context.Context, contract.SignRequest) contract.SignResult {
	b.t.Fatal("refused admission called Trust.Sign")
	return contract.SignResult{}
}

func (b refusalBoundary) QualifySigningBinding(context.Context, contract.PublicSigningBinding) contract.SigningQualificationResult {
	b.t.Fatal("refused admission called Trust.QualifySigningBinding")
	return contract.SigningQualificationResult{}
}

func (b refusalBoundary) InstanceID() contract.ID {
	b.t.Fatal("refused admission called Crypto.InstanceID")
	return contract.ID{}
}

func (b refusalBoundary) Exchange(context.Context, contract.CryptoRequest) contract.CryptoResponse {
	b.t.Fatal("refused admission called Crypto.Exchange")
	return contract.CryptoResponse{}
}

// full_only: false
func TestPublicInitAdmissionRefusesBeforeEffects(t *testing.T) {
	boundary := refusalBoundary{t: t}
	want := Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}
	for _, admitted := range []InitContext{{}, {admission: &initAdmission{}}} {
		if session, result := Initialize(context.Background(), admitted, boundary, boundary, boundary, boundary); session != nil || result != want {
			t.Fatalf("empty public init admission: session=%v result=%+v", session, result)
		}
	}
}

// full_only: false
func TestPublicAdmissionRefuses(t *testing.T) {
	boundary := refusalBoundary{t: t}
	want := Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}
	for _, store := range []contract.Store{nil, boundary} {
		if s, r := Open(context.Background(), OpenContext{}, store); s != nil || r != want {
			t.Fatalf("empty public admission: session = %v, result = %+v", s, r)
		}
	}
	s := &StateSession{store: boundary}
	if c, r := s.Compare(context.Background(), nil, nil); c != nil || r != want {
		t.Fatalf("unadmitted comparison: comparison = %v, result = %+v", c, r)
	}
	if p, r := s.Prepare(context.Background(), &Comparison{}, &AdmittedParentTransition{}, boundary); p != nil || r != want {
		t.Fatalf("empty public permit: candidate = %v, result = %+v", p, r)
	}
	if r := s.Select(context.Background(), &Candidate{}); r != want {
		t.Fatalf("empty public candidate: %+v", r)
	}
}

// full_only: false
func TestNilSessionRefuses(t *testing.T) {
	var s *StateSession
	want := Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}
	if c, r := s.Compare(context.Background(), nil, nil); c != nil || r != want {
		t.Fatalf("nil session comparison: comparison = %v, result = %+v", c, r)
	}
	if p, r := s.Prepare(context.Background(), nil, nil, refusalBoundary{t: t}); p != nil || r != want {
		t.Fatalf("nil session preparation: candidate = %v, result = %+v", p, r)
	}
	if r := s.Select(context.Background(), nil); r != want {
		t.Fatalf("nil session selection: %+v", r)
	}
}
