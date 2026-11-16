package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/installedarchive"
)

// full_only: false
func TestLiveProtocolReplacementConfiguration(t *testing.T) {
	for _, mode := range []string{"disabled", "enabled"} {
		t.Run(mode, func(t *testing.T) {
			_, input := liveProtocolInvocation(t, "writer")
			input.RecoveryMode, input.Settings.RecoveryMode = mode, mode
			input.RecoverySettings = nil
			input.Settings.RecoveryKeyID, input.Settings.RecoveryPublicKeyPEM, input.Settings.RecoveryKEKID, input.Settings.RecoveryKEKPublicKeyPEM = "", "", "", ""
			fields := []string{"normal_successor_key_id", "normal_successor_public_key_pem", "reader_successor_kek_id", "reader_successor_kek_public_key_pem", "authority_successor_1_kek_id", "authority_successor_1_kek_public_key_pem", "authority_successor_2_kek_id", "authority_successor_2_kek_public_key_pem"}
			if mode == "enabled" {
				input.Settings.RecoveryKeyID, input.Settings.RecoveryPublicKeyPEM, input.Settings.RecoveryKEKID, input.Settings.RecoveryKEKPublicKeyPEM = "initial-recovery-sign", "initial-sign-public", "initial-recovery-kek", "initial-kek-public"
				fields = append(fields, "recovery_successor_key_id", "recovery_successor_public_key_pem", "recovery_successor_1_kek_id", "recovery_successor_1_kek_public_key_pem", "recovery_successor_2_kek_id", "recovery_successor_2_kek_public_key_pem")
			}
			body, err := json.Marshal(input.Settings)
			if err != nil {
				t.Fatal(err)
			}
			var base map[string]json.RawMessage
			if json.Unmarshal(body, &base) != nil {
				t.Fatal("settings fixture unavailable")
			}
			for _, field := range fields {
				base[field] = json.RawMessage(`"public-successor"`)
			}
			decode := func(m map[string]json.RawMessage) liveSettings {
				t.Helper()
				body, err := json.Marshal(m)
				var s liveSettings
				if err != nil || json.Unmarshal(body, &s) != nil {
					t.Fatal("settings fixture unavailable")
				}
				return s
			}
			input.Settings = decode(base)
			if !liveRecoveryAdmitted(input) {
				t.Fatal("complete replacement bundle refused")
			}
			binding := settingsBinding(input.Settings)
			for _, field := range fields {
				value := base[field]
				delete(base, field)
				input.Settings = decode(base)
				if liveRecoveryAdmitted(input) {
					t.Fatalf("partial replacement field %s accepted", field)
				}
				base[field] = json.RawMessage(`"changed-public-successor"`)
				if settingsBinding(decode(base)) == binding {
					t.Fatalf("replacement public field %s escaped the resource binding", field)
				}
				base[field] = value
			}
			input.Settings = decode(base)
			if mode == "disabled" {
				input.Settings.RecoverySuccessorKeyID = "recovery-key"
				if liveRecoveryAdmitted(input) {
					t.Fatal("disabled recovery successor admitted")
				}
				input.Settings = decode(base)
			}
			for _, role := range []string{"normal-signer-0", "normal-signer-1", "authority-decrypter-0", "authority-decrypter-1", "authority-decrypter-2", "reader-successor", "replacement-store", "recovery-signer-0", "recovery-signer-1", "recovery-decrypter-0", "recovery-decrypter-1", "recovery-decrypter-2", "unknown"} {
				actor := input.Settings
				actor.CredentialsFile = "/private/" + role
				input.ReplacementSettings = map[string]liveSettings{role: actor}
				got := liveRoleSettings(input, role)
				if role == "unknown" {
					if got != nil || liveRecoveryAdmitted(input) {
						t.Fatal("unknown replacement role admitted")
					}
					continue
				}
				if got == nil || *got != actor {
					t.Fatalf("replacement route %s not delivered", role)
				}
				want := mode == "enabled" || !strings.HasPrefix(role, "recovery-")
				if liveRecoveryAdmitted(input) != want {
					t.Fatalf("replacement route %s recovery admission differs", role)
				}
				if liveActorsAdmitted(input) {
					t.Fatalf("unselected replacement role %s admitted", role)
				}
			}
		})
	}
}

func liveRecoveryAdmitted(input liveRunInput) bool {
	if input.PublicConfiguration != nil {
		return livePublicConfigurationAdmitted(input)
	}
	s := input.Settings
	if input.RecoveryMode != s.RecoveryMode || s.AuthorityKEKID == "" || s.AuthorityKEKPublicKeyPEM == "" || s.ReaderKEKID == "" || s.ReaderKEKPublicKeyPEM == "" || !liveReplacementAdmitted(input) {
		return false
	}
	switch s.RecoveryMode {
	case "enabled":
		return s.RecoveryKeyID != "" && s.RecoveryPublicKeyPEM != "" && s.RecoveryKEKID != "" && s.RecoveryKEKPublicKeyPEM != ""
	case "disabled":
		return s.RecoveryKeyID == "" && s.RecoveryPublicKeyPEM == "" && s.RecoveryKEKID == "" && s.RecoveryKEKPublicKeyPEM == "" && input.RecoverySettings == nil
	default:
		return false
	}
}

var liveReplacementRoles = map[string]bool{
	"normal-signer-0": false, "normal-signer-1": false, "normal-signer-2": false,
	"authority-decrypter-0": false, "authority-decrypter-1": false, "authority-decrypter-2": false,
	"reader-successor": false, "replacement-store": false,
	"recovery-signer-0": true, "recovery-signer-1": true,
	"recovery-decrypter-0": true, "recovery-decrypter-1": true, "recovery-decrypter-2": true,
}

func liveReplacementAdmitted(input liveRunInput) bool {
	s := input.Settings
	normal := [][2]string{{s.NormalSuccessorKeyID, s.NormalSuccessorPublicKeyPEM}, {s.ReaderSuccessorKEKID, s.ReaderSuccessorKEKPublicKeyPEM}, {s.AuthoritySuccessor1KEKID, s.AuthoritySuccessor1KEKPublicKeyPEM}, {s.AuthoritySuccessor2KEKID, s.AuthoritySuccessor2KEKPublicKeyPEM}}
	recovery := [][2]string{{s.RecoverySuccessorKeyID, s.RecoverySuccessorPublicKeyPEM}, {s.RecoverySuccessor1KEKID, s.RecoverySuccessor1KEKPublicKeyPEM}, {s.RecoverySuccessor2KEKID, s.RecoverySuccessor2KEKPublicKeyPEM}}
	if (s.NormalSuccessor2KeyID == "") != (s.NormalSuccessor2PublicKeyPEM == "") || s.NormalSuccessor2KeyID != "" && (s.NormalSuccessor2KeyID == s.KeyID || s.NormalSuccessor2KeyID == s.NormalSuccessorKeyID || s.NormalSuccessor2PublicKeyPEM == s.PublicKeyPEM || s.NormalSuccessor2PublicKeyPEM == s.NormalSuccessorPublicKeyPEM) {
		return false
	}
	bundle := false
	for _, pair := range append(normal, recovery...) {
		bundle = bundle || pair[0] != "" || pair[1] != ""
	}
	if bundle {
		for _, pair := range normal {
			if pair[0] == "" || pair[1] == "" {
				return false
			}
		}
		for _, pair := range recovery {
			if s.RecoveryMode == "enabled" {
				if pair[0] == "" || pair[1] == "" {
					return false
				}
			} else if pair[0] != "" || pair[1] != "" {
				return false
			}
		}
	}
	for role := range input.ReplacementSettings {
		recovery, known := liveReplacementRoles[role]
		if role == "normal-signer-2" && s.NormalSuccessor2KeyID == "" {
			return false
		}
		if !known || !bundle || recovery && s.RecoveryMode != "enabled" {
			return false
		}
	}
	return true
}

func liveRoleSettings(input liveRunInput, role string) *liveSettings {
	switch role {
	case "authority":
		return &input.Settings
	case "observer":
		return input.ObserverSettings
	case "denied-observer":
		return input.DeniedObserverSettings
	case "reader":
		return input.ReaderSettings
	case "recovery":
		return input.RecoverySettings
	case "denied-reader":
		return input.DeniedReaderSettings
	default:
		if _, known := liveReplacementRoles[role]; known {
			if settings, present := input.ReplacementSettings[role]; present {
				return &settings
			}
		}
		return nil
	}
}

func liveActorsAdmitted(input liveRunInput) bool {
	if input.PublicConfiguration != nil {
		return livePublicConfigurationAdmitted(input)
	}
	if len(input.Scenarios) != 1 || !liveRecoveryAdmitted(input) {
		return false
	}
	definition, ok := catalog.DefinitionFor(input.Scenarios[0])
	if !ok || !slices.Contains(definition.Providers, input.Settings.Provider) {
		return false
	}
	roles := definition.RolesForRecovery(input.RecoveryMode)
	selected := make(map[string]bool, len(roles))
	for _, role := range roles {
		actor := liveRoleSettings(input, role)
		if input.Participants[role] == "" || actor == nil || settingsBinding(*actor) != settingsBinding(input.Settings) {
			return false
		}
		if role != "authority" && actor.CredentialsFile == "" {
			return false
		}
		selected[role] = true
	}
	for _, role := range []string{"observer", "denied-observer", "reader", "recovery", "denied-reader"} {
		if !selected[role] && liveRoleSettings(input, role) != nil {
			return false
		}
	}
	for role := range input.ReplacementSettings {
		if !selected[role] {
			return false
		}
	}
	execution, known := catalog.ExecutionFor(input.Scenarios[0], "live")
	if !known {
		return false
	}
	if definition.DistinctParticipants && input.Participants["authority"] == input.Participants[execution.FreshAfter[0].Role] {
		return false
	}
	for _, role := range roles {
		_, replacement := liveReplacementRoles[role]
		if !replacement && role != "reader" && role != "recovery" && role != "denied-reader" && role != "denied-observer" {
			continue
		}
		actor := liveRoleSettings(input, role)
		for _, other := range roles {
			if other == role || other == "observer" && !replacement {
				continue
			}
			route := liveRoleSettings(input, other)
			if input.Participants[role] == input.Participants[other] || actor.CredentialsFile == route.CredentialsFile && actor.Profile == route.Profile {
				return false
			}
		}
	}
	return true
}
func liveFreshSettings(input liveRunInput) liveSettings {
	execution, known := catalog.ExecutionFor(input.Scenarios[0], "live")
	if !known {
		return liveSettings{}
	}
	settings := liveRoleSettings(input, execution.FreshAfter[0].Role)
	if settings == nil {
		return liveSettings{}
	}
	return *settings
}

func liveReaderActor(input liveRunInput) string {
	execution, known := catalog.ExecutionFor(input.Scenarios[0], "live")
	if !known {
		return ""
	}
	return input.Participants[execution.FreshAfter[0].Role]
}

// full_only: false
func TestLiveProtocolParticipantRouting(t *testing.T) {
	for _, change := range []string{"authority-only", "observer", "reuse", "missing-observer", "wrong-resource", "wrong-provider", "missing-role", "distinct-reuse"} {
		t.Run(change, func(t *testing.T) {
			inv, input := liveProtocolInvocation(t, "writer")
			input.Settings.CredentialsFile = "/private/authority.json"
			observer := input.Settings
			observer.CredentialsFile = "/private/observer.json"
			input.Scenarios = []string{"access.observer-sees-selected-state/members_32_observer"}
			input.ObserverSettings = &observer
			input.Participants = map[string]string{"authority": "operator", "observer": "auditor"}
			want := liveProvider() == "gcp"
			switch change {
			case "authority-only":
				input.Scenarios = []string{"state.single-value-update-preserves-other-values/members_32"}
				input.ObserverSettings = nil
				delete(input.Participants, "observer")
				want = true
			case "reuse":
				input.Participants["observer"] = "operator"
				observer = input.Settings
			case "missing-observer":
				input.ObserverSettings = nil
				want = false
			case "wrong-resource":
				observer.Bucket = "other"
				want = false
			case "wrong-provider":
				observer.Provider = "other"
				want = false
			case "missing-role":
				delete(input.Participants, "observer")
				want = false
			case "distinct-reuse":
				input.Scenarios = []string{"access.distinct-observer-sees-selected-state/members_32_distinct_observer"}
				input.Participants["observer"] = "operator"
				want = false
			}
			inv = liveProtocolBindInvocation(t, inv, input.Scenarios[0])
			if records.WriteJSON(inv.Input, input, 0o400) != nil {
				t.Fatal("input write failed")
			}
			if _, err := loadLiveInput(inv, "writer"); (err == nil) != want {
				t.Fatal("participant admission differs")
			}
			if want {
				expected := input.Settings
				if catalog.HasFixtureCapability(input.Scenarios[0], catalog.FixtureObserver) {
					expected = observer
				}
				if liveFreshSettings(input) != expected {
					t.Fatal("wrong credential route")
				}
			}
			if _, err := os.Stat(filepath.Join(inv.StateDir, "inventory.json")); !os.IsNotExist(err) {
				t.Fatal("admission created fixture inventory")
			}
		})
	}
}

// full_only: false
func TestLiveProtocolCleanupIgnoresUnusedReaderCredentials(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "reader-file-replaces-writer", true: "reader-file-removed"}[missing], func(t *testing.T) {
			inv, input := liveProtocolInvocation(t, "cleanup")
			input.Settings.CredentialsFile = filepath.Join(inv.StateDir, "replacement-writer.json")
			reader := input.Settings
			reader.CredentialsFile = filepath.Join(inv.StateDir, "original-reader.json")
			if !missing {
				if os.WriteFile(reader.CredentialsFile, []byte("synthetic credential file"), 0o600) != nil {
					t.Fatal("replacement credential fixture unavailable")
				}
				input.Settings.CredentialsFile = reader.CredentialsFile
			}
			input.ObserverSettings = &reader
			if records.WriteJSON(inv.Input, input, 0o400) != nil {
				t.Fatal("cleanup input unavailable")
			}
			loaded, err := loadLiveInput(inv, "cleanup")
			if err != nil || loaded.Settings.CredentialsFile != input.Settings.CredentialsFile || settingsBinding(loaded.Settings) != settingsBinding(reader) {
				t.Fatal("unused reader credentials blocked the writer's cleanup binding")
			}
			if missing {
				if _, err := os.Stat(reader.CredentialsFile); !os.IsNotExist(err) {
					t.Fatal("cleanup actor admission read or created an unused reader file")
				}
			}
		})
	}
}

// full_only: false
func TestLiveProtocolDeniedObserverRouting(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		providers []string
	}{
		{"access.provider-refuses-observer/members_32_denied_observer", []string{"gcp"}},
		{"reconstruction.required-public-denied/complete_loss_required_public_denied", []string{"aws", "gcp"}},
	} {
		for _, mode := range []string{"disabled", "enabled"} {
			for _, condition := range []string{"separate", "missing-settings", "wrong-observer-settings", "extra-observer-settings", "missing-role", "authority-participant", "authority-credentials", "wrong-resource", "missing-credentials", "selected-participant", "selected-credentials"} {
				t.Run(scenario.name+"/"+mode+"/"+condition, func(t *testing.T) {
					inv, input := liveProtocolInvocation(t, "writer")
					input.Settings.CredentialsFile = "/private/authority.json"
					input.RecoveryMode, input.Settings.RecoveryMode = mode, mode
					input.Scenarios = []string{scenario.name}
					input.Participants = map[string]string{"authority": "operator", "denied-observer": "denied-auditor"}
					if mode == "enabled" {
						input.Settings.RecoveryKeyID, input.Settings.RecoveryPublicKeyPEM = "recovery-sign", "recovery-sign-public"
						input.Settings.RecoveryKEKID, input.Settings.RecoveryKEKPublicKeyPEM = "recovery-kek", "recovery-kek-public"
					}
					if scenario.name == "reconstruction.required-public-denied/complete_loss_required_public_denied" {
						input.ConfigurationRecovery = &installedarchive.RecoveryWriterInput{Domain: contract.Hash([]byte("public-denial-domain")), OracleDirectory: inv.StateDir}
						input.Settings.NormalSuccessorKeyID, input.Settings.NormalSuccessorPublicKeyPEM = "successor-sign", "successor-sign-public"
						input.Settings.ReaderSuccessorKEKID, input.Settings.ReaderSuccessorKEKPublicKeyPEM = "successor-reader", "successor-reader-public"
						input.Settings.AuthoritySuccessor1KEKID, input.Settings.AuthoritySuccessor1KEKPublicKeyPEM = "successor-authority-1", "successor-authority-1-public"
						input.Settings.AuthoritySuccessor2KEKID, input.Settings.AuthoritySuccessor2KEKPublicKeyPEM = "successor-authority-2", "successor-authority-2-public"
						roles := []string{"replacement-store", "normal-signer-0", "authority-decrypter-0"}
						if mode == "enabled" {
							input.Settings.RecoverySuccessorKeyID, input.Settings.RecoverySuccessorPublicKeyPEM = "successor-recovery-sign", "successor-recovery-sign-public"
							input.Settings.RecoverySuccessor1KEKID, input.Settings.RecoverySuccessor1KEKPublicKeyPEM = "successor-recovery-1", "successor-recovery-1-public"
							input.Settings.RecoverySuccessor2KEKID, input.Settings.RecoverySuccessor2KEKPublicKeyPEM = "successor-recovery-2", "successor-recovery-2-public"
							roles = append(roles, "recovery-signer-0", "recovery-decrypter-0")
						}
						input.ReplacementSettings = make(map[string]liveSettings)
						for _, role := range roles {
							actor := input.Settings
							actor.CredentialsFile = "/private/" + role + ".json"
							input.ReplacementSettings[role] = actor
							input.Participants[role] = role
						}
					}
					if mode == "enabled" {
						recovery := input.Settings
						recovery.CredentialsFile = "/private/recovery.json"
						input.RecoverySettings = &recovery
						input.Participants["recovery"] = "recovery-operator"
					}
					denied := input.Settings
					denied.CredentialsFile = "/private/denied-observer.json"
					input.DeniedObserverSettings = &denied
					switch condition {
					case "missing-settings":
						input.DeniedObserverSettings = nil
					case "wrong-observer-settings":
						input.DeniedObserverSettings, input.ObserverSettings = nil, &denied
					case "extra-observer-settings":
						input.ObserverSettings = &denied
					case "missing-role":
						delete(input.Participants, "denied-observer")
					case "authority-participant":
						input.Participants["denied-observer"] = "operator"
					case "authority-credentials":
						denied.CredentialsFile = input.Settings.CredentialsFile
					case "wrong-resource":
						denied.Bucket = "other"
					case "missing-credentials":
						denied.CredentialsFile = ""
					case "selected-participant", "selected-credentials":
						role := "replacement-store"
						if scenario.name == "access.provider-refuses-observer/members_32_denied_observer" {
							role = "authority"
						}
						if condition == "selected-participant" {
							input.Participants["denied-observer"] = input.Participants[role]
						} else {
							denied.CredentialsFile = liveRoleSettings(input, role).CredentialsFile
						}
					}
					inv = liveProtocolBindInvocation(t, inv, input.Scenarios[0])
					if err := records.WriteJSON(inv.Input, input, 0400); err != nil {
						t.Fatal(err)
					}
					loaded, err := loadLiveInput(inv, "writer")
					want := condition == "separate" && slices.Contains(scenario.providers, liveProvider())
					if (err == nil) != want {
						t.Fatalf("denied observer admission differs: provider=%s scenario=%s mode=%s condition=%s admitted=%t want=%t", liveProvider(), scenario.name, mode, condition, err == nil, want)
					}
					if want && (loaded.DeniedObserverSettings == nil || *loaded.DeniedObserverSettings != denied || loaded.Settings != input.Settings || loaded.Participants["denied-observer"] != "denied-auditor") {
						t.Fatal("refusal case selected another actor")
					}
					if want && scenario.name == "access.provider-refuses-observer/members_32_denied_observer" && (liveFreshSettings(loaded) != denied || liveReaderActor(loaded) != "denied-auditor") {
						t.Fatal("fresh refusal case selected another actor")
					}
					if _, err := os.Stat(filepath.Join(inv.StateDir, "inventory.json")); !os.IsNotExist(err) {
						t.Fatal("admission created fixture inventory")
					}
				})
			}
		}
	}
}

// full_only: false
func TestLiveFreshAccessRefusalNeedsExactProviderEvidence(t *testing.T) {
	for _, test := range []struct {
		result  Result
		refused bool
		want    string
	}{
		{Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable}, true, "access-refused"},
		{Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable}, false, "unavailable"},
		{Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}, true, "unavailable"},
		{Result{Outcome: IntegrityFailure, Reason: InvalidFormat}, true, "integrity-failure"},
		{Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}, true, "failed"},
		{Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure}, false, "success"},
	} {
		if got := readerReadOutcome(test.result, test.refused); got != test.want {
			t.Fatalf("read status = %s; want %s", got, test.want)
		}
	}
}
