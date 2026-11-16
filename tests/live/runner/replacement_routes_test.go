package core

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type liveReplacementActor struct {
	Settings liveSettings
	Route    contract.ID
}

func liveReplacementConstructionInput(t *testing.T, recovery bool) (liveRunInput, contract.ID, []contract.BindingTableRow) {
	t.Helper()
	input, domain := liveCustodyConstructionInput(t, recovery)
	c := &input.Settings
	family := contract.AWS
	if c.Provider == "gcp" {
		family = contract.GCP
	}
	publicPEM := func(der []byte) string { return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})) }
	normal := testtrust.New(t, family, fixtureID(domain, "normal-successor"))
	c.NormalSuccessorKeyID, c.NormalSuccessorPublicKeyPEM = normal.KeySelector(), publicPEM(normal.PublicKey())
	second := testtrust.New(t, family, fixtureID(domain, "normal-successor-2"))
	c.NormalSuccessor2KeyID, c.NormalSuccessor2PublicKeyPEM = second.KeySelector(), publicPEM(second.PublicKey())
	selector := func(label string) string {
		id := fixtureID(domain, label)
		if family == contract.AWS {
			return fmt.Sprintf("arn:aws:kms:us-east-1:123456789012:key/%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:16])
		}
		return fmt.Sprintf("projects/fixture/locations/us-central1/keyRings/fixture/cryptoKeys/key-%x/cryptoKeyVersions/1", id[:16])
	}
	// These tests cover construction and public-route pinning only. They do not
	// claim independent successor-key qualification or execute a replacement.
	c.ReaderSuccessorKEKID, c.ReaderSuccessorKEKPublicKeyPEM = selector("reader-successor"), c.ReaderKEKPublicKeyPEM
	c.AuthoritySuccessor1KEKID, c.AuthoritySuccessor1KEKPublicKeyPEM = selector("authority-1"), c.AuthorityKEKPublicKeyPEM
	c.AuthoritySuccessor2KEKID, c.AuthoritySuccessor2KEKPublicKeyPEM = selector("authority-2"), c.AuthorityKEKPublicKeyPEM
	if recovery {
		signer := testtrust.NewRecovery(t, family, fixtureID(domain, "recovery-successor"))
		c.RecoverySuccessorKeyID, c.RecoverySuccessorPublicKeyPEM = signer.KeySelector(), publicPEM(signer.PublicKey())
		c.RecoverySuccessor1KEKID, c.RecoverySuccessor1KEKPublicKeyPEM = selector("recovery-1"), c.RecoveryKEKPublicKeyPEM
		c.RecoverySuccessor2KEKID, c.RecoverySuccessor2KEKPublicKeyPEM = selector("recovery-2"), c.RecoveryKEKPublicKeyPEM
	}
	input.ReplacementSettings = make(map[string]liveSettings)
	for role, onlyRecovery := range liveReplacementRoles {
		if onlyRecovery && !recovery {
			continue
		}
		actor := *c
		actor.CredentialsFile, actor.Profile = "/fixture/"+role, role
		input.ReplacementSettings[role], input.Participants[role] = actor, role
	}
	// A constructor must work after all broad credentials have been discarded.
	c.CredentialsFile, c.Profile = "", ""
	input.RecoverySettings, input.ReaderSettings, input.DeniedReaderSettings = nil, nil, nil
	bindings, err := liveCustodyBindings(*c, domain)
	if err != nil {
		t.Fatal(err)
	}
	return input, domain, bindings
}

func liveReplacementConstructionRoutes(input liveRunInput, domain contract.ID, bindings []contract.BindingTableRow, role string) []custody.Route {
	routes := make([]custody.Route, len(bindings))
	for i, row := range bindings {
		routes[i] = custody.Route{BindingID: row.Binding.BindingID, PublicRoute: liveCredentialRoute(input, role)}
		if liveReplacementKEKMatches(input.Settings, domain, row, role) {
			routes[i].PrivateRoute = routes[i].PublicRoute
		}
	}
	return routes
}

func liveReplacementActors(input liveRunInput, roles []string) ([]liveReplacementActor, error) {
	if input.RunID == "" || !liveRecoveryAdmitted(input) || len(roles) == 0 || len(roles) > len(liveReplacementRoles) {
		return nil, contract.ErrRecord
	}
	actors := make([]liveReplacementActor, 0, len(roles))
	seen := make(map[string]bool, len(roles))
	for _, role := range roles {
		recovery, known := liveReplacementRoles[role]
		c := liveRoleSettings(input, role)
		route := liveCredentialRoute(input, role)
		if !known || seen[role] || recovery && input.RecoveryMode != "enabled" || c == nil || c.CredentialsFile == "" || input.Settings.Provider == "aws" && c.Profile == "" || route.IsZero() || settingsBinding(*c) != settingsBinding(input.Settings) {
			return nil, contract.ErrRecord
		}

		for otherRole, other := range input.ReplacementSettings {
			if otherRole == role {
				continue
			}
			if input.Participants[otherRole] == input.Participants[role] || other.CredentialsFile == c.CredentialsFile && other.Profile == c.Profile {
				return nil, contract.ErrRecord
			}
		}
		for _, other := range actors {
			if other.Route == route || other.Settings.CredentialsFile == c.CredentialsFile && other.Settings.Profile == c.Profile {
				return nil, contract.ErrRecord
			}
		}
		for _, broad := range []string{"authority", "recovery", "reader", "denied-reader"} {
			other := liveRoleSettings(input, broad)
			if input.Participants[role] == input.Participants[broad] || other != nil && other.CredentialsFile != "" && other.CredentialsFile == c.CredentialsFile && other.Profile == c.Profile {
				return nil, contract.ErrRecord
			}
		}
		for _, prior := range roles[:len(actors)] {
			if input.Participants[prior] == input.Participants[role] {
				return nil, contract.ErrRecord
			}
		}
		seen[role] = true
		actors = append(actors, liveReplacementActor{Settings: *c, Route: route})
	}
	return actors, nil
}

// The initial reader key has no restricted replacement actor. Its public row
// remains in the current table while the lost private route stays absent.
func liveReplacementKEK(c liveSettings, role string) (kind uint8, label, selector, public string) {
	kind, label = 1, "recipient"
	switch role {
	case "authority-decrypter-0":
		selector, public = c.AuthorityKEKID, c.AuthorityKEKPublicKeyPEM
	case "authority-decrypter-1":
		selector, public = c.AuthoritySuccessor1KEKID, c.AuthoritySuccessor1KEKPublicKeyPEM
	case "authority-decrypter-2":
		selector, public = c.AuthoritySuccessor2KEKID, c.AuthoritySuccessor2KEKPublicKeyPEM
	case "recovery-decrypter-0":
		kind, label, selector, public = 2, "recovery", c.RecoveryKEKID, c.RecoveryKEKPublicKeyPEM
	case "recovery-decrypter-1":
		kind, label, selector, public = 2, "recovery", c.RecoverySuccessor1KEKID, c.RecoverySuccessor1KEKPublicKeyPEM
	case "recovery-decrypter-2":
		kind, label, selector, public = 2, "recovery", c.RecoverySuccessor2KEKID, c.RecoverySuccessor2KEKPublicKeyPEM
	case "reader-successor":
		label, selector, public = "reader", c.ReaderSuccessorKEKID, c.ReaderSuccessorKEKPublicKeyPEM
	case "reader":
		label, selector, public = "reader", c.ReaderKEKID, c.ReaderKEKPublicKeyPEM
	default:
		return 0, "", "", ""
	}
	return
}

func liveReplacementKEKMatches(c liveSettings, domain contract.ID, row contract.BindingTableRow, role string) bool {
	kind, label, selector, public := liveReplacementKEK(c, role)
	der, err := livePublicDER(public)
	return err == nil && kind != 0 && row.SubjectKind == kind && row.SubjectID == fixtureID(domain, label) && row.Binding.KeySelector == selector && bytes.Equal(row.Binding.SPKI, der)
}

func livePrivateKeyRole(c liveSettings, row contract.BindingTableRow) string {
	if row.Binding.Provider == contract.AWS && c.Provider != "aws" || row.Binding.Provider == contract.GCP && c.Provider != "gcp" || !row.Binding.Provider.Valid() {
		return ""
	}
	matched := ""
	for _, role := range []string{"authority-decrypter-0", "authority-decrypter-1", "authority-decrypter-2", "reader", "reader-successor", "recovery-decrypter-0", "recovery-decrypter-1", "recovery-decrypter-2"} {
		kind, _, selector, public := liveReplacementKEK(c, role)
		if kind == 2 && c.RecoveryMode != "enabled" {
			continue
		}
		der, err := livePublicDER(public)
		if err == nil && row.SubjectKind == kind && row.Binding.KeySelector == selector && bytes.Equal(row.Binding.SPKI, der) {
			if matched != "" {
				return ""
			}
			matched = role
		}
	}
	return matched
}

func liveSigningRole(c liveSettings, binding contract.PublicSigningBinding) string {
	if binding.Provider == contract.AWS && c.Provider != "aws" || binding.Provider == contract.GCP && c.Provider != "gcp" || !binding.Provider.Valid() {
		return ""
	}
	matched := ""
	for _, entry := range []struct {
		role             string
		kind             uint8
		selector, public string
	}{
		{"normal-signer-0", contract.NormalSigningRole, c.KeyID, c.PublicKeyPEM},
		{"normal-signer-1", contract.NormalSigningRole, c.NormalSuccessorKeyID, c.NormalSuccessorPublicKeyPEM},
		{"normal-signer-2", contract.NormalSigningRole, c.NormalSuccessor2KeyID, c.NormalSuccessor2PublicKeyPEM},
		{"recovery-signer-0", contract.RecoverySigningRole, c.RecoveryKeyID, c.RecoveryPublicKeyPEM},
		{"recovery-signer-1", contract.RecoverySigningRole, c.RecoverySuccessorKeyID, c.RecoverySuccessorPublicKeyPEM},
	} {
		if entry.kind == contract.RecoverySigningRole && c.RecoveryMode != "enabled" {
			continue
		}
		der, err := livePublicDER(entry.public)
		if err == nil && binding.Role == entry.kind && binding.KeySelector == entry.selector && bytes.Equal(binding.SPKI, der) {
			if matched != "" {
				return ""
			}
			matched = entry.role
		}
	}
	return matched
}

// full_only: false
func TestLiveAssemblyReplacementPublicRoleMap(t *testing.T) {
	input, domain, bindings := liveReplacementConstructionInput(t, true)
	c := input.Settings
	for _, entry := range []struct {
		role             string
		kind             uint8
		selector, public string
	}{
		{"authority-decrypter-0", 1, c.AuthorityKEKID, c.AuthorityKEKPublicKeyPEM},
		{"authority-decrypter-1", 1, c.AuthoritySuccessor1KEKID, c.AuthoritySuccessor1KEKPublicKeyPEM},
		{"authority-decrypter-2", 1, c.AuthoritySuccessor2KEKID, c.AuthoritySuccessor2KEKPublicKeyPEM},
		{"reader", 1, c.ReaderKEKID, c.ReaderKEKPublicKeyPEM},
		{"reader-successor", 1, c.ReaderSuccessorKEKID, c.ReaderSuccessorKEKPublicKeyPEM},
		{"recovery-decrypter-0", 2, c.RecoveryKEKID, c.RecoveryKEKPublicKeyPEM},
		{"recovery-decrypter-1", 2, c.RecoverySuccessor1KEKID, c.RecoverySuccessor1KEKPublicKeyPEM},
		{"recovery-decrypter-2", 2, c.RecoverySuccessor2KEKID, c.RecoverySuccessor2KEKPublicKeyPEM},
	} {
		row := bindings[0]
		row.SubjectKind, row.SubjectID = entry.kind, domain
		row.Binding.KeySelector = entry.selector
		var err error
		row.Binding.SPKI, err = livePublicDER(entry.public)
		if err != nil || livePrivateKeyRole(c, row) != entry.role {
			t.Fatalf("wrong private role for %s", entry.role)
		}
		row.SubjectKind = 3 - entry.kind
		if livePrivateKeyRole(c, row) != "" {
			t.Fatal("private role ignored subject kind")
		}
	}
	for _, role := range []string{"normal-signer-0", "normal-signer-1", "normal-signer-2", "recovery-signer-0", "recovery-signer-1"} {
		binding := liveReplacementTestSigningBinding(t, input, role, domain)
		if _, err := contract.EncodePublicSigningBinding(binding); err != nil {
			t.Fatal("replacement signing fixture is not a closed v6 binding", err)
		}
		if liveSigningRole(c, binding) != role {
			t.Fatalf("wrong signing role for %s", role)
		}
		binding.Role = 3 - binding.Role
		if liveSigningRole(c, binding) != "" {
			t.Fatal("signing role ignored public role")
		}
	}
	row := bindings[0]
	role := livePrivateKeyRole(c, row)
	if role == "authority-decrypter-0" {
		c.AuthoritySuccessor1KEKID, c.AuthoritySuccessor1KEKPublicKeyPEM = c.AuthorityKEKID, c.AuthorityKEKPublicKeyPEM
	} else {
		c.ReaderSuccessorKEKID, c.ReaderSuccessorKEKPublicKeyPEM = c.ReaderKEKID, c.ReaderKEKPublicKeyPEM
	}
	if livePrivateKeyRole(c, row) != "" {
		t.Fatal("ambiguous private role configuration admitted")
	}
}

func liveReplacementCustodyInputs(input liveRunInput, domain contract.ID, bindings []contract.BindingTableRow, routes []custody.Route, roles []string) ([]contract.BindingTableRow, []custody.Route, []liveReplacementActor, error) {
	refused := contract.ErrRecord
	actors, err := liveReplacementActors(input, roles)
	if err != nil || domain.IsZero() || len(bindings) != len(routes) {
		return nil, nil, nil, refused
	}
	body, err := contract.EncodeBindingTable(bindings)
	if err != nil {
		return nil, nil, nil, err
	}
	owned, err := contract.DecodeBindingTable(body)
	if err != nil {
		return nil, nil, nil, err
	}
	family, protection := contract.AWS, contract.HardwareProtection
	if input.Settings.Provider == "gcp" {
		family, protection = contract.GCP, contract.SoftwareProtection
	} else if input.Settings.Provider != "aws" {
		return nil, nil, nil, refused
	}
	known := make(map[contract.ID]contract.BindingTableRow, len(owned))
	subjects := make(map[contract.ID]bool, len(owned))
	for _, row := range owned {
		if _, duplicate := known[row.Binding.BindingID]; duplicate || subjects[row.SubjectID] || row.Binding.Provider != family || row.Binding.ProtectionClass != protection {
			return nil, nil, nil, refused
		}
		if !liveReplacementKEKMatches(input.Settings, domain, row, livePrivateKeyRole(input.Settings, row)) {
			return nil, nil, nil, refused
		}
		known[row.Binding.BindingID], subjects[row.SubjectID] = row, true
	}
	want := 2
	if input.RecoveryMode == "enabled" {
		want++
	}
	if len(owned) != want || !subjects[fixtureID(domain, "recipient")] || !subjects[fixtureID(domain, "reader")] || subjects[fixtureID(domain, "recovery")] != (input.RecoveryMode == "enabled") {
		return nil, nil, nil, refused
	}
	for _, route := range routes {
		row, knownBinding := known[route.BindingID]
		if !knownBinding {
			return nil, nil, nil, refused
		}
		delete(known, route.BindingID)
		for _, id := range []contract.ID{route.PublicRoute, route.PrivateRoute} {
			if id.IsZero() {
				continue
			}
			index := slices.IndexFunc(actors, func(a liveReplacementActor) bool { return a.Route == id })
			if index < 0 {
				return nil, nil, nil, refused
			}
		}
		if !route.PrivateRoute.IsZero() {
			index := slices.IndexFunc(actors, func(a liveReplacementActor) bool { return a.Route == route.PrivateRoute })
			if !liveReplacementKEKMatches(input.Settings, domain, row, roles[index]) {
				return nil, nil, nil, refused
			}
		}
	}
	return owned, slices.Clone(routes), actors, nil
}

func liveReplacementSignerInput(input liveRunInput, role string, binding contract.PublicSigningBinding) (liveReplacementActor, error) {
	actors, err := liveReplacementActors(input, []string{role})
	if err != nil {
		return liveReplacementActor{}, err
	}
	if liveSigningRole(input.Settings, binding) != role {
		return liveReplacementActor{}, contract.ErrRecord
	}
	if _, err := contract.SigningBindingDigest(binding); err != nil {
		return liveReplacementActor{}, err
	}
	return actors[0], nil
}

// full_only: false
func TestLiveAssemblyReplacementRoutePreflight(t *testing.T) {
	for _, change := range []string{"empty-roles", "duplicate-role", "unknown-role", "broad-role", "missing-participant", "missing-credentials", "resource-mismatch", "aliased-selected-credentials", "aliased-broad-credentials", "unknown-public-route", "unknown-private-route", "wrong-private-key", "duplicate-route", "missing-route", "wrong-public-key", "wrong-subject", "pending-not-current", "wrong-domain"} {
		t.Run(change, func(t *testing.T) {
			input, domain, bindings := liveReplacementConstructionInput(t, true)
			roles := []string{"authority-decrypter-0", "reader-successor"}
			routes := liveReplacementConstructionRoutes(input, domain, bindings, roles[0])
			switch change {
			case "empty-roles":
				roles = nil
			case "duplicate-role":
				roles[1] = roles[0]
			case "unknown-role":
				roles[1] = "unknown"
			case "broad-role":
				roles[1] = "authority"
			case "missing-participant":
				delete(input.Participants, roles[1])
			case "missing-credentials":
				c := input.ReplacementSettings[roles[1]]
				c.CredentialsFile = ""
				input.ReplacementSettings[roles[1]] = c
			case "resource-mismatch":
				c := input.ReplacementSettings[roles[1]]
				c.Bucket = "wrong-bucket"
				input.ReplacementSettings[roles[1]] = c
			case "aliased-selected-credentials":
				input.ReplacementSettings[roles[1]] = input.ReplacementSettings[roles[0]]
			case "aliased-broad-credentials":
				input.Settings.CredentialsFile = input.ReplacementSettings[roles[0]].CredentialsFile
				input.Settings.Profile = input.ReplacementSettings[roles[0]].Profile
			case "unknown-public-route":
				routes[0].PublicRoute = contract.Hash([]byte("unknown-route"))
			case "unknown-private-route":
				routes[0].PrivateRoute = contract.Hash([]byte("unknown-route"))
			case "wrong-private-key":
				for i, row := range bindings {
					if row.SubjectID == fixtureID(domain, "reader") {
						routes[i].PrivateRoute = liveCredentialRoute(input, roles[0])
					}
				}
			case "duplicate-route":
				routes[1] = routes[0]
			case "missing-route":
				routes = routes[:len(routes)-1]
			case "wrong-public-key":
				bindings[0].Binding.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/ffffffff-ffff-ffff-ffff-ffffffffffff"
				if input.Settings.Provider == "gcp" {
					bindings[0].Binding.KeySelector = "projects/fixture/locations/us-central1/keyRings/fixture/cryptoKeys/unconfigured/cryptoKeyVersions/1"
				}
			case "wrong-subject":
				bindings[0].SubjectID = contract.Hash([]byte("another-subject"))
			case "pending-not-current":
				bindings = append(bindings, bindings[0])
				routes = append(routes, routes[0])
			case "wrong-domain":
				domain = contract.Hash([]byte("another-domain"))
			}
			if _, _, _, err := liveReplacementCustodyInputs(input, domain, bindings, routes, roles); err == nil {
				t.Fatal("malformed replacement routes admitted")
			}
		})
	}
}

func liveReplacementTestSigningBinding(t *testing.T, input liveRunInput, role string, trust contract.ID) contract.PublicSigningBinding {
	t.Helper()
	c := input.Settings
	var selector, public string
	kind := contract.NormalSigningRole
	switch role {
	case "normal-signer-0":
		selector, public = c.KeyID, c.PublicKeyPEM
	case "normal-signer-1":
		selector, public = c.NormalSuccessorKeyID, c.NormalSuccessorPublicKeyPEM
	case "normal-signer-2":
		selector, public = c.NormalSuccessor2KeyID, c.NormalSuccessor2PublicKeyPEM
	case "recovery-signer-0":
		kind, selector, public = contract.RecoverySigningRole, c.RecoveryKeyID, c.RecoveryPublicKeyPEM
	case "recovery-signer-1":
		kind, selector, public = contract.RecoverySigningRole, c.RecoverySuccessorKeyID, c.RecoverySuccessorPublicKeyPEM
	default:
		t.Fatal("unknown signer fixture")
	}
	der, err := livePublicDER(public)
	if err != nil {
		t.Fatal(err)
	}
	family := contract.AWS
	if c.Provider == "gcp" {
		family = contract.GCP
	}
	id := contract.Hash([]byte("signer-public-binding"))
	return contract.PublicSigningBinding{Schema: contract.PublicSigningBindingSchema, Role: kind, Provider: family, SigningProfile: contract.P256SigningProfile, BindingID: id, KeySelector: selector, SPKI: der, Fingerprint: contract.Hash(der), Binding: contract.BindingSubject{Domain: id, Coordinate: id, Store: id, Trust: trust, PublicKey: contract.Hash(der), Interpretation: contract.InterpretationID(), ControlIncarnationID: fixtureID(id, role+"-signer-incarnation"), Epoch: 1}}
}
