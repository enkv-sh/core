package custody

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

// full_only: false
func TestGeneratedProducerOutcomeBindsMissingAdmission(t *testing.T) {
	f := &Fixture{runtime: &privatecrypto.Runtime{}}
	for _, label := range []string{"first", "second"} {
		id := sha256.Sum256([]byte(label))
		locator := sha256.Sum256([]byte(label + " locator"))
		authority := sha256.Sum256([]byte(label + " authority"))
		record, facts, out := f.InvokeGeneratedProducerOutcome(context.Background(), id, locator, authority)
		if out.Code != contract.CryptoInvalidAdmission || len(record) != 0 || facts.Schema != 0 {
			t.Fatal("missing admission did not return its private outcome")
		}
		if out.ID != id || out.Locator != locator || out.Authority != authority ||
			out.Stage != "entry" || out.Category != "invalid" || out.Effect != "no_send" || out.Qualified ||
			out.Disposition != 0 || out.Reason != 0 {
			t.Fatal("missing admission gained another invocation or unqualified facts")
		}
		encoded, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		var projected map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &projected); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"ID", "Locator", "Authority", "HTTPStatus", "ErrorCodes"} {
			if _, present := projected[name]; present {
				t.Fatal("private invocation binding reached serialized outcome")
			}
		}
	}
}

// full_only: false
func TestGeneratedProducerOutcomeWorksInFixtureFork(t *testing.T) {
	f := New(t, contract.GCP, sha256.Sum256([]byte("identity")), false,
		[]contract.ID{sha256.Sum256([]byte("authority"))})
	child := f.ForkGenerated(t)
	id := sha256.Sum256([]byte("child missing admission"))
	_, _, out := child.InvokeGeneratedProducerOutcome(context.Background(), id, contract.ID{}, contract.ID{})
	if out.Code != contract.CryptoInvalidAdmission || out.ID != id || out.Effect != "no_send" {
		t.Fatal("fork lost its private outcome")
	}
}
