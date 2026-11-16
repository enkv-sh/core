package core

import (
	"bytes"
	"context"
	"io"
	"slices"
	"testing"
	"testing/iotest"

	"enkv.sh/core/contract"
)

type publicationPlanningCancelEntropy struct {
	*bytes.Reader
	cancel context.CancelFunc
}

func (r publicationPlanningCancelEntropy) Read(body []byte) (int, error) {
	n, err := r.Reader.Read(body)
	r.cancel()
	return n, err
}

// full_only: false
func TestPublicationPlanningAllocatesOnlyItsOperationAndAttempts(t *testing.T) {
	for _, condition := range []string{"complete", "zero-operation", "selected-operation", "zero-attempt", "selected-attempt", "operation-attempt", "repeated-attempt", "short-attempt", "entropy-error", "cancel-before-attempt"} {
		t.Run(condition, func(t *testing.T) {
			f, input, private := publicationEngineFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
				target.Capabilities &^= contract.OutputCapabilityCreateWithValue
				target.Capabilities |= contract.OutputCapabilityCreateEmpty
				target.CreateValueBounds = contract.OutputPayloadBounds{}
			})
			operation := fixtureID(f.session.root.Domain, "planned operation")
			first := fixtureID(f.session.root.Domain, "planned first attempt")
			second := fixtureID(f.session.root.Domain, "planned second attempt")
			ids := []contract.ID{operation, first, second}
			wantReason := AdmissionInvalid
			switch condition {
			case "zero-operation":
				ids[0] = contract.ID{}
			case "selected-operation":
				ids[0] = f.session.head.Core.Revision
			case "zero-attempt":
				ids[1] = contract.ID{}
			case "selected-attempt":
				ids[1] = f.session.head.Core.Revision
			case "operation-attempt":
				ids[1] = operation
				wantReason = InvalidIntent
			case "repeated-attempt":
				ids[2] = first
				wantReason = InvalidIntent
			}
			var body []byte
			for _, id := range ids {
				body = append(body, id[:]...)
			}
			if condition == "short-attempt" {
				body = body[:len(body)-1]
			}
			entropy := bytes.NewReader(body)
			var source io.Reader = entropy
			switch condition {
			case "entropy-error":
				source = iotest.ErrReader(io.ErrClosedPipe)
			case "cancel-before-attempt":
				source = publicationPlanningCancelEntropy{Reader: entropy, cancel: cancel}
			}
			f.session.admission.entropy = source
			creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
			plan, state := f.session.planPublication(ctx, input, private.callbacks())
			if len(private.owners) != 0 || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
				t.Fatal("identity planning acquired private work or persisted a candidate")
			}
			if condition != "complete" {
				if plan != nil || state.Outcome != AdmissionRefused || state.Reason != wantReason {
					t.Fatal("invalid planned identity reached an admitted plan", state)
				}
				if condition == "cancel-before-attempt" && entropy.Len() != 2*len(contract.ID{}) {
					t.Fatal("cancelled planning drew another Attempt identity")
				}
				return
			}
			if plan == nil || state.Outcome != ObservedCurrent || plan.operation != operation || len(plan.targets) != 1 || !slices.Equal(plan.targets[0].attempts, []contract.ID{first, second}) || !slices.Equal(plan.targets[0].actions, []uint8{contract.PublicationCreateEmpty, contract.PublicationWriteValue}) || entropy.Len() != 0 {
				t.Fatal("planning did not use exactly its operation and two distinct required Attempts", state, entropy.Len())
			}
		})
	}
}
