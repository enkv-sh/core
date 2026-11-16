package plugininstallation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestPartialResolutionRetainsOnlyVerifiedExecutableFacts(t *testing.T) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	scope := tempDirectory(t)
	one := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "assessment")
	catalog.publish(t, one)
	resolve(t, c, request(scope, "private-renderer", "", Prepare))
	r := request(scope, "private-renderer", "", Ordinary)
	r.Requirements = []Requirement{{Name: "private-generator"}, {Name: "private-renderer"}}
	session, rows, err := c.Resolve(t.Context(), r)
	if err == nil || session != nil || len(rows) != 2 || rows[0].Status != "missing" || rows[0].Role != "" || rows[1].Status != "verified" {
		t.Fatal("partial failure lost the complete assessment or supplied a session", rows, err)
	}
	want := artifact.Digest(sha256.Sum256(one.members["plugin"]))
	if want == one.identity {
		t.Fatal("fixture does not distinguish metadata identity from executable digest")
	}
	if got, ok := rows[1].ExecutableSHA256(); !ok || got != want {
		t.Fatal("verified row lost its exact executable digest", got, ok)
	}
	if got, ok := rows[0].ExecutableSHA256(); ok || !got.IsZero() {
		t.Fatal("failed row supplied executable verification")
	}
	wantWire := artifact.Contract{Kind: "wire", Identity: "0100000000000000000000000000000000000000000000000000000000000000", Version: 1}
	if got, ok := rows[1].WireContract(); !ok || got != wantWire {
		t.Fatal("verified row lost its exact wire declaration", got, ok)
	}
	if got, ok := rows[0].WireContract(); ok || got != (artifact.Contract{}) {
		t.Fatal("failed row supplied protocol verification")
	}
	body, err := json.Marshal(rows[1])
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil || len(members) != 10 || strings.Contains(string(body), want.String()) {
		t.Fatal("private executable fact changed the closed installation JSON", string(body), err)
	}
	for _, change := range []func(*Installation){
		func(r *Installation) { r.Status = "unavailable" },
		func(r *Installation) { r.Reason = "identity-mismatch" },
		func(r *Installation) { r.Artifact = nil },
		func(r *Installation) { r.Role = "output" },
		func(r *Installation) { r.Name = "another-private-id" },
		func(r *Installation) { r.Version = "*" },
	} {
		row := rows[1]
		change(&row)
		if got, ok := row.ExecutableSHA256(); ok || !got.IsZero() {
			t.Fatal("malformed or failed row supplied executable verification")
		}
		if got, ok := row.WireContract(); ok || got != (artifact.Contract{}) {
			t.Fatal("malformed or failed row supplied protocol verification")
		}
	}
	constructed := Installation{Name: "private-renderer", Role: "manifest-generator", Version: "1.0.0", Artifact: &one.identity, Platform: rows[1].Platform, Source: "official", Status: "verified", Reason: "none"}
	if _, ok := constructed.ExecutableSHA256(); ok {
		t.Fatal("caller-constructed row invented executable verification")
	}
	if _, ok := constructed.WireContract(); ok {
		t.Fatal("caller-constructed row invented protocol verification")
	}
	for _, mode := range []Mode{Prepare, Upgrade} {
		for _, missingFirst := range []bool{false, true} {
			for _, ending := range []string{"stable", "source-changed", "source-changed-then-stable", "cancelled", "expired-cause"} {
				name := "prepare"
				if mode == Upgrade {
					name = "upgrade"
				}
				if missingFirst {
					name += "/missing-first"
				} else {
					name += "/verified-first"
				}
				t.Run(name+"/"+ending, func(t *testing.T) {
					missing := "zzzz-missing"
					if missingFirst {
						missing = "aaaa-missing"
					}
					writeSettings(t, c, []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: missing, Directory: t.TempDir()}}}})
					partial := request(scope, "private-renderer", "1.0.0", mode)
					partial.Requirements = []Requirement{{Name: "private-renderer", Version: "1.0.0"}, {Name: missing}}
					slices.SortFunc(partial.Requirements, func(a, b Requirement) int { return strings.Compare(a.Name, b.Name) })
					ctx, cancel := context.WithCancelCause(t.Context())
					defer cancel(nil)
					checks := 0
					partial.CheckSource = func(context.Context) error {
						checks++
						if checks == 2 {
							switch ending {
							case "source-changed-then-stable":
								return ErrSourceChanged
							case "cancelled":
								cancel(context.Canceled)
							case "expired-cause":
								cancel(context.DeadlineExceeded)
							}
						}
						if checks >= 3 && ending == "source-changed" {
							return ErrSourceChanged
						}
						return nil
					}
					session, rows, err := c.Resolve(ctx, partial)
					if !errors.Is(err, ErrInstallation) || !errors.Is(err, ErrMissing) || len(rows) != 2 || checks < 3 {
						t.Fatal("partial assessment lost its aggregate error or final source check", rows, err)
					}
					verifiedIndex := 0
					if missingFirst {
						verifiedIndex = 1
					}
					if rows[verifiedIndex].Name != "private-renderer" || rows[verifiedIndex].Status != "verified" || rows[1-verifiedIndex].Name != missing || rows[1-verifiedIndex].Status != "missing" {
						t.Fatal("partial assessment changed completed installation facts", rows)
					}
					if got, ok := rows[verifiedIndex].ExecutableSHA256(); !ok || got != want {
						t.Fatal("partial assessment lost its exact completed executable fact")
					}
					if ending != "stable" {
						if session != nil {
							t.Fatal("source-tainted or cancelled assessment supplied captures")
						}
						if strings.HasPrefix(ending, "source-changed") && !errors.Is(err, ErrSourceChanged) || ending == "cancelled" && !errors.Is(err, context.Canceled) || ending == "expired-cause" && !errors.Is(err, context.DeadlineExceeded) {
							t.Fatal("partial assessment erased its source or context cause", err)
						}
						return
					}
					installed, ok := session.Lookup("private-renderer")
					if !ok || installed.Identity() != one.identity {
						t.Fatal("settled partial assessment discarded its exact verified capture", rows, err)
					}
					if _, ok := session.Lookup(missing); ok {
						t.Fatal("failed requirement supplied a capture")
					}
				})
			}
		}
	}
	changed := request(scope, "private-renderer", "", Ordinary)
	checks := 0
	changed.CheckSource = func(context.Context) error {
		checks++
		if checks >= 3 {
			return ErrSourceChanged
		}
		return nil
	}
	session, rows, err = c.Resolve(t.Context(), changed)
	if !errors.Is(err, ErrSourceChanged) || session != nil || len(rows) != 1 || rows[0].Status != "verified" {
		t.Fatal("later source change lost completed verification or supplied a session", rows, err)
	}
	if got, ok := rows[0].ExecutableSHA256(); !ok || got != want {
		t.Fatal("later source change erased the completed executable fact")
	}
	if got, ok := rows[0].WireContract(); !ok || got != wantWire {
		t.Fatal("later source change erased the completed protocol fact")
	}
	for _, family := range []struct {
		role, name, contract string
	}{
		{"generator", "private-effect-generator", "0100000000000000000000000000000000000000000000000000000000000000"},
		{"output", "private-effect-output", "private-output/v1"},
	} {
		t.Run(family.role+"-configuration-contract", func(t *testing.T) {
			catalog := newCatalog(t)
			coordinator := catalog.coordinator(t)
			scope := tempDirectory(t)
			plugin := makeFixture(t, family.name, family.role, "1.0.0", "configuration-assessment")
			catalog.publish(t, plugin)
			resolve(t, coordinator, request(scope, family.name, "", Prepare))
			partial := request(scope, family.name, "", Ordinary)
			partial.Requirements = []Requirement{{Name: "private-absent"}, {Name: family.name}}
			session, rows, err := coordinator.Resolve(t.Context(), partial)
			if !errors.Is(err, ErrMissing) || session != nil || len(rows) != 2 || rows[0].Status != "missing" || rows[1].Status != "verified" {
				t.Fatal("partial effect resolution lost its completed assessment", rows, err)
			}
			if got, verified := rows[1].ConfigContractID(); !verified || got != family.contract {
				t.Fatal("verified effect row lost its configuration contract", got, verified)
			}
			if got, verified := rows[0].ConfigContractID(); verified || got != "" {
				t.Fatal("missing effect row supplied a configuration contract", got, verified)
			}
			for _, change := range []func(*Installation){
				func(row *Installation) { row.Status = "unavailable" },
				func(row *Installation) { row.Reason = "identity-mismatch" },
				func(row *Installation) { row.Artifact = nil },
				func(row *Installation) { row.Role = "manifest-generator" },
				func(row *Installation) { row.Name = "another-private-id" },
				func(row *Installation) { row.Version = "*" },
			} {
				row := rows[1]
				change(&row)
				if got, verified := row.ConfigContractID(); verified || got != "" {
					t.Fatal("malformed effect row supplied a configuration contract", got, verified)
				}
			}
			constructed := Installation{Name: family.name, Role: family.role, Version: "1.0.0", Artifact: &plugin.identity, Platform: rows[1].Platform, Source: "official", Status: "verified", Reason: "none"}
			if got, verified := constructed.ConfigContractID(); verified || got != "" {
				t.Fatal("caller-constructed effect row invented a configuration contract", got, verified)
			}
			body, err := json.Marshal(rows[1])
			var members map[string]json.RawMessage
			if err != nil || json.Unmarshal(body, &members) != nil || len(members) != 10 || strings.Contains(string(body), family.contract) {
				t.Fatal("private configuration fact changed the closed installation JSON")
			}
			changed := request(scope, family.name, "", Ordinary)
			checks := 0
			changed.CheckSource = func(context.Context) error {
				checks++
				if checks >= 3 {
					return ErrSourceChanged
				}
				return nil
			}
			session, rows, err = coordinator.Resolve(t.Context(), changed)
			if !errors.Is(err, ErrSourceChanged) || session != nil || len(rows) != 1 || rows[0].Status != "verified" {
				t.Fatal("later source change lost verified effect facts", rows, err)
			}
			if got, verified := rows[0].ConfigContractID(); !verified || got != family.contract {
				t.Fatal("later source change erased the configuration contract", got, verified)
			}
		})
	}
}
