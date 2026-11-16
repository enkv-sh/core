package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestConsumerSelectionRequiresAdmittedSessionBeforeEffects(t *testing.T) {
	for _, tc := range []struct {
		name    string
		session *StateSession
	}{
		{"nil-session", nil},
		{"unadmitted-session", &StateSession{store: refusalBoundary{t: t}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selection, result := tc.session.admitConsumerSelection(context.Background(), []string{"value"}, contract.ID{})
			if selection != nil || result != refused(AdmissionInvalid) {
				t.Fatalf("unadmitted consumer selection: selection=%v result=%+v", selection, result)
			}
		})
	}
}
