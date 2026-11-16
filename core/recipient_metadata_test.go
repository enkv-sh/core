package core

import (
	"enkv.sh/core/contract"
	"testing"
)

// full_only: false
func TestApplyRecipientDisplayChangeIncludesUnassignedRecipientSubject(t *testing.T) {
	s, rows := applyRecipientCreationFixture(t)
	current := rows[0]
	current.Recipient.DisplayName = "new display"
	proposal, err := s.admitApplyRecipients(t.Context(), []contract.ApplyRecipientInput{current})
	if err != nil || proposal == nil || len(proposal.changed) != 1 {
		t.Fatal("unassigned display change refused", err)
	}
	c := &Comparison{session: s, recipients: proposal.inputs, recipientChanges: proposal.changed}
	got, err := installedApplyChangedSubjects(c, transitionPlan{})
	identity, identityErr := contract.ChangedSubjectIdentityID(s.root.Domain, contract.ChangedSubjectRecipient, current.Recipient.RecipientID, contract.ID{})
	want, wantErr := contract.ChangedSubjectDescriptor([]contract.ChangedSubjectIdentity{{Kind: contract.ChangedSubjectRecipient, Change: contract.ChangedSubjectUpdated, Identity: identity}})
	if err != nil || identityErr != nil || wantErr != nil || got != want || got.Count != 1 {
		t.Fatal("display-only apply omitted exact recipient subject", got, err)
	}
	if s.registry()[0].DisplayName != "current" {
		t.Fatal("display proposal changed predecessor")
	}
}
