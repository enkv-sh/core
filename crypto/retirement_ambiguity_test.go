package crypto

import (
	"bytes"
	"enkv.sh/core/contract"
	"testing"
)

// full_only: false
func TestRetirementReturnProofHasOneOwnerAndClearsOnDisposal(t *testing.T) {
	for _, stage := range []string{"before-claim", "before-entry", "after-entry"} {
		t.Run(stage, func(t *testing.T) {
			created, err := NewRetirementReturnProof()
			if err != nil {
				t.Fatal(err)
			}
			p := created.(*retirementReturnProof)
			backing := p.scalar
			if p.claim(contract.ID{}) {
				t.Fatal("wrong reservation obtained proof")
			}
			if stage == "before-claim" {
				p.Close()
			} else {
				if !p.claim(created.Commitment()) || p.claim(created.Commitment()) {
					t.Fatal("proof did not bind exactly once")
				}
				if stage == "before-entry" {
					state := generatedPurposeState{producer: &generatedProducerPreparationState{producer: &generatedProducer{retirementProof: p}}}
					state.clear()
				} else {
					o := generatedProducerReturnOwner{retirementProof: p, cancel: func() {}, done: make(chan struct{})}
					o.finish(nil)
				}
			}
			if !bytes.Equal(backing, make([]byte, len(backing))) || p.claim(created.Commitment()) {
				t.Fatal("retired proof retained private material")
			}
			p.Close()
		})
	}
}
