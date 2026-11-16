package core

import (
	"bytes"
	"encoding/pem"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// These facts come from the configured public resources and exact participant
// binding. Parsing them does not authorize a private operation.
func liveCustodyBindings(c liveSettings, domain contract.ID) ([]contract.BindingTableRow, error) {
	if domain.IsZero() || c.RecoveryMode != "disabled" && c.RecoveryMode != "enabled" {
		return nil, contract.ErrRecord
	}
	family, protection := contract.AWS, contract.HardwareProtection
	if c.Provider == "gcp" {
		family, protection = contract.GCP, contract.SoftwareProtection
	} else if c.Provider != "aws" {
		return nil, contract.ErrRecord
	}
	inputs := []struct {
		kind                    uint8
		label, selector, public string
	}{
		{1, "recipient", c.AuthorityKEKID, c.AuthorityKEKPublicKeyPEM},
		{1, "reader", c.ReaderKEKID, c.ReaderKEKPublicKeyPEM},
	}
	if c.RecoveryMode == "enabled" {
		if c.RecoveryKeyID == "" || c.RecoveryPublicKeyPEM == "" {
			return nil, contract.ErrRecord
		}
		inputs = append(inputs, struct {
			kind                    uint8
			label, selector, public string
		}{2, "recovery", c.RecoveryKEKID, c.RecoveryKEKPublicKeyPEM})
	} else if c.RecoveryKeyID != "" || c.RecoveryPublicKeyPEM != "" || c.RecoveryKEKID != "" || c.RecoveryKEKPublicKeyPEM != "" {
		return nil, contract.ErrRecord
	}
	rows := make([]contract.BindingTableRow, 0, len(inputs))
	for _, input := range inputs {
		spki, err := livePublicDER(input.public)
		if err != nil {
			return nil, err
		}
		binding := contract.KMSBinding{BindingID: fixtureID(domain, input.label+"-kek-binding"), BindingIncarnationID: fixtureID(domain, input.label+"-kek-incarnation"), BindingSerial: 1, Provider: family, WrapProfile: contract.RSAOAEPWrapProfile, ProtectionClass: protection, KeySelector: input.selector, SPKI: spki, Fingerprint: contract.Hash(spki)}
		if _, err := contract.KMSBindingLength(binding); err != nil {
			return nil, err
		}
		rows = append(rows, contract.BindingTableRow{SubjectKind: input.kind, SubjectID: fixtureID(domain, input.label), Binding: binding})
	}
	if c.RecoveryMode == "enabled" && !contract.IndependentKMSBindings(rows[0].Binding, rows[2].Binding) {
		return nil, contract.ErrRecord
	}
	slices.SortFunc(rows, func(a, b contract.BindingTableRow) int {
		if a.SubjectKind != b.SubjectKind {
			return int(a.SubjectKind) - int(b.SubjectKind)
		}
		return bytes.Compare(a.SubjectID[:], b.SubjectID[:])
	})
	body, err := contract.EncodeBindingTable(rows)
	if err != nil {
		return nil, err
	}
	return contract.DecodeBindingTable(body)
}

func livePublicDER(value string) ([]byte, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, contract.ErrRecord
	}
	return bytes.Clone(block.Bytes), nil
}

func liveCredentialRoute(input liveRunInput, role string) contract.ID {
	actor := liveRoleSettings(input, role)
	participant := input.Participants[role]
	if actor == nil || participant == "" {
		return contract.ID{}
	}
	// The participant is an admitted run-input identity. A path or profile alone
	// is not a cloud-principal identity and cannot establish role separation.
	return contract.Hash([]byte("ENKV/live-credential-route/v1\x00" + input.RunID + "\x00" + input.Settings.Provider + "\x00" + role + "\x00" + participant))
}

// full_only: false
func TestLiveAssemblyCredentialRoutesBindExplicitParticipants(t *testing.T) {
	input := liveRunInput{RunID: "run", Settings: liveSettings{Provider: "aws"}, Participants: map[string]string{"authority": "operator"}}
	first := liveCredentialRoute(input, "authority")
	input.Settings.CredentialsFile = "/different/location"
	if first.IsZero() || liveCredentialRoute(input, "authority") != first {
		t.Fatal("credential file location became a participant identity")
	}
	input.Participants["authority"] = "another-operator"
	if liveCredentialRoute(input, "authority") == first || !liveCredentialRoute(input, "reader").IsZero() {
		t.Fatal("private route escaped its explicit participant")
	}
}

func liveCustodyRoutes(input liveRunInput, domain contract.ID, bindings []contract.BindingTableRow, role string, initialize bool) []custody.Route {
	routes := make([]custody.Route, len(bindings))
	subject := fixtureID(domain, "recipient")
	if role == "reader" || role == "denied-reader" {
		subject = fixtureID(domain, "reader")
	}
	for i, row := range bindings {
		routes[i].BindingID = row.Binding.BindingID
		if initialize {
			routes[i].PublicRoute = liveCredentialRoute(input, "authority")
			if row.SubjectID == fixtureID(domain, "recipient") {
				routes[i].PrivateRoute = liveCredentialRoute(input, "authority")
			}
			if row.SubjectKind == 2 {
				routes[i].PrivateRoute = liveCredentialRoute(input, "recovery")
			}
		} else if row.SubjectKind == 1 && row.SubjectID == subject {
			routes[i].PrivateRoute = liveCredentialRoute(input, role)
		}
	}
	return routes
}

func liveDomainPublicBindings(c liveSettings, descriptor contract.GenesisDescriptorCore) bool {
	expected, err := liveCustodyBindings(c, descriptor.DomainID)
	if err != nil || (descriptor.Recovery != nil) != (c.RecoveryMode == "enabled") {
		return false
	}
	actual := make([]contract.BindingTableRow, 0, len(expected))
	for _, recipient := range descriptor.Recipients {
		if recipient.Status != contract.CurrentRecipient || recipient.CurrentBinding == nil {
			return false
		}
		actual = append(actual, contract.BindingTableRow{SubjectKind: 1, SubjectID: recipient.RecipientID, Binding: *recipient.CurrentBinding})
	}
	if descriptor.Recovery != nil {
		public, err := livePublicDER(c.RecoveryPublicKeyPEM)
		if err != nil || descriptor.Recovery.Signing.KeySelector != c.RecoveryKeyID || !bytes.Equal(descriptor.Recovery.Signing.SPKI, public) {
			return false
		}
		actual = append(actual, contract.BindingTableRow{SubjectKind: 2, SubjectID: descriptor.Recovery.RoleID, Binding: descriptor.Recovery.KMS})
	}
	left, err := contract.EncodeBindingTable(expected)
	if err != nil {
		return false
	}
	right, err := contract.EncodeBindingTable(actual)
	return err == nil && bytes.Equal(left, right)
}
