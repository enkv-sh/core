package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationReservationUsesFreshAdmittedConfigurationDigest(t *testing.T) {
	for _, combined := range []bool{false, true} {
		name := "standalone"
		if combined {
			name = "captured-combined"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f, input, private := publicationEngineFixture(t)
			if combined {
				handoff, err := captureApplyPublicationSelection(ctx, f.session)
				if err != nil {
					t.Fatal("capture selected publication", err)
				}
				defer handoff.close()
				input.captured = handoff
			}
			callbacks := private.callbacks()
			plan, state := f.session.planPublication(ctx, input, callbacks)
			if plan == nil || len(plan.targets) != 1 || len(plan.targets[0].actions) != 1 {
				t.Fatal("one-action plan unavailable", state)
			}
			target, action := plan.targets[0], plan.targets[0].actions[0]
			original, err := plan.projection(target, action, target.attempts[0])
			if err != nil || action != contract.PublicationCreateWithValue {
				t.Fatal("original projection unavailable", err)
			}
			entries := f.session.currentEntryInputs()
			selectedTarget := publicationEngineTarget(entries[0].Name, "publication")
			selectOutputConfiguration(t, f, entries, &outputApplyInput{
				bindings: []outputApplyBinding{
					{destinationID: "publication", targets: []outputApplyTarget{selectedTarget}},
					{destinationID: "unrelated", destination: outputFixtureDestination("unrelated", "controlled-provider", selectedTarget.target.Capabilities, selectedTarget.target.Policy)},
				},
				routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}},
			})
			fresh := f.session.root.OutputConfiguration.ConfigurationDigest
			if fresh == original.ConfigurationDigest {
				t.Fatal("unrelated configuration fixture did not advance")
			}
			if combined {
				configuration, state := input.captured.checkCurrent(ctx, f.session, target)
				if state.Outcome != 0 || len(configuration.Bindings) != 2 {
					t.Fatal("unrelated progress changed captured relevant facts", state)
				}
			}
			creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
			candidate, preparation, state := plan.reserveCandidate(ctx, f.session, target, action, callbacks)
			if candidate == nil || preparation == nil {
				t.Fatal("unrelated progress refused the fresh reservation", state)
			}
			if len(private.owners) != 1 {
				t.Fatal("reservation did not acquire one exact owner")
			}
			defer func() {
				if err := preparation.retire(ctx); err != nil {
					t.Error("prepared owner did not settle", err)
				}
				if private.owners[0].retired != 1 {
					t.Error("prepared owner did not settle exactly once")
				}
			}()
			want := original
			want.ConfigurationDigest = fresh
			if candidate.head.OutputReserve == nil || candidate.head.OutputReserve.ConfigurationDigest != fresh || !reflect.DeepEqual(candidate.publication.marker.Projection, want) || !reflect.DeepEqual(preparation.original.dispatch.Projection, want) || !reflect.DeepEqual(private.owners[0].input.Projection, want) || private.owners[0].input.Deadline != input.deadline {
				t.Fatal("projection, reservation and owner do not share fresh admitted meaning")
			}
			if f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs || len(private.owners) != 1 || private.owners[0].prepared != 1 || private.owners[0].armed != 0 || private.owners[0].sent != 0 {
				t.Fatal("unselected reservation entered an effect or changed selected state")
			}
		})
	}
}

// full_only: false
func TestInstalledPublicationPreservesCompatibleAccessProgress(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, family := range []struct {
		name     string
		id       contract.Family
		recovery bool
	}{{"aws", contract.AWS, false}, {"gcp", contract.GCP, true}} {
		f := newInstalledApplyTestFixture(t, ctx, family.id, family.recovery)
		basisControl, err := f.basis.ControlCore(f.env.Domain, f.env.Store.Descriptor())
		if err != nil {
			t.Fatal(err)
		}
		basisBody, err := contract.EncodeControlCore(basisControl)
		if err != nil {
			t.Fatal(err)
		}
		for _, condition := range []string{"unchanged", "advance", "new-incarnation", "zero-generation", "fixed-control-change"} {
			t.Run(family.name+"/"+condition, func(t *testing.T) {
				current, err := contract.DecodeControlCore(basisBody)
				if err != nil {
					t.Fatal(err)
				}
				want := true
				switch condition {
				case "advance":
					current.AccessGeneration++
				case "new-incarnation":
					current.AccessIncarnationID = fixtureID(f.env.Domain, "new access incarnation")
					current.AccessGeneration = 1
				case "zero-generation":
					current.AccessGeneration = 0
					want = false
				case "fixed-control-change":
					current.AuthorityKMSBinding.BindingSerial++
					want = false
				}
				privateCalls := 0
				engine, err := NewInstalledPublication(PublicationInstallation{
					ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(), PublicBasis: f.basis,
					ExpectedControl: current, Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition,
					SelectPolicyAction: func(context.Context, PublicationPolicyActionInput) (uint8, error) {
						privateCalls++
						return 0, contract.ErrRecord
					},
					Namespace: func(contract.ID, contract.OutputTarget) (contract.ID, error) {
						privateCalls++
						return contract.ID{}, contract.ErrRecord
					},
					Actions: func(context.Context, PublicationExecutionInput) (PublicationActionFacts, error) {
						privateCalls++
						return PublicationActionFacts{}, contract.ErrRecord
					},
					Check: func(context.Context, PublicationActionCheckInput) (PublicationActionCheckFacts, error) {
						privateCalls++
						return PublicationActionCheckFacts{}, contract.ErrRecord
					},
					NewOwner: func(context.Context, PublicationOwnerInput) (PublicationPrivateOwner, error) {
						privateCalls++
						return nil, contract.ErrRecord
					}, CloseInstalled: func() {},
				})
				if privateCalls != 0 {
					t.Fatal("construction entered publication custody")
				}
				if !want {
					if err == nil || engine != nil {
						t.Fatal("incompatible expected control admitted")
					}
					return
				}
				if err != nil || engine == nil {
					t.Fatal("compatible access progress refused", err)
				}
				defer engine.Close()
				if condition == "unchanged" {
					for _, lifetime := range []time.Duration{time.Minute, 10 * time.Minute, 15 * time.Minute} {
						deadline := time.Now().Add(lifetime)
						call, cancel := context.WithDeadline(t.Context(), deadline)
						defer cancel()
						for i := 0; i < 2; i++ {
							selected, _, result := engine.installation.current(call)
							if selected == nil || result.Outcome != ObservedCurrent || selected.admission.expires != deadline || !publicationNormalAdmission(call, selected, deadline) {
								t.Errorf("publication admission must retain the original %s deadline: admission=%t result=%+v", lifetime, selected != nil, result)
							}
						}
						if lifetime > 5*time.Minute {
							started := time.Now()
							ordinary, result := admitBorrowedPublicNormal(call, f.env.Domain, f.env.Store.Descriptor(), f.basis, f.env.Store, f.composition, nil)
							finished := time.Now()
							if result.Outcome != ObservedCurrent || ordinary.admission == nil || ordinary.admission.expires.Before(started.Add(5*time.Minute)) || ordinary.admission.expires.After(finished.Add(5*time.Minute)) {
								t.Fatal("publication changed the generic five-minute admission", result)
							}
						}
					}
					parentDeadline := time.Now().Add(time.Minute)
					parent, cancelParent := context.WithDeadline(t.Context(), parentDeadline)
					defer cancelParent()
					clipped, cancelClipped := context.WithTimeout(parent, 15*time.Minute)
					defer cancelClipped()
					selected, _, result := engine.installation.current(clipped)
					if selected == nil || result.Outcome != ObservedCurrent || selected.admission.expires != parentDeadline {
						t.Fatal("publication ignored the earlier parent deadline", result)
					}
					for _, invalid := range []string{"nil", "no_deadline", "expired", "canceled", "over_fifteen_minutes", "unrepresentable"} {
						t.Run(invalid, func(t *testing.T) {
							var call context.Context
							cancel := func() {}
							switch invalid {
							case "nil":
							case "no_deadline":
								call = context.WithoutCancel(t.Context())
							case "expired":
								call, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
							case "canceled":
								call, cancel = context.WithTimeout(t.Context(), time.Minute)
								cancel()
							case "over_fifteen_minutes":
								call, cancel = context.WithTimeout(t.Context(), 16*time.Minute)
							case "unrepresentable":
								call, cancel = context.WithDeadline(context.WithoutCancel(t.Context()), time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC))
							}
							defer cancel()
							store, trust := f.env.Store.(*memoryStore), f.env.Trust.(*fixtureTrust)
							reads, creates, cas, signs := store.reads, store.creates, store.cas, trust.signs
							public, secret := f.env.Custody.Calls()
							selected, _, result := engine.installation.current(call)
							if selected != nil || result != refused(AdmissionInvalid) {
								t.Error("invalid publication deadline admitted", result)
							}
							publicAfter, secretAfter := f.env.Custody.Calls()
							if store.reads != reads || store.creates != creates || store.cas != cas || trust.signs != signs || privateCalls != 0 || publicAfter != public || secretAfter != secret {
								t.Error("invalid publication deadline reached Store, Trust or custody")
							}
						})
					}
				}
				before, err := contract.EncodeControlCore(current)
				if err != nil {
					t.Fatal(err)
				}
				current.NormalSigning.SPKI[0] ^= 1
				current.AuthorityKMSBinding.SPKI[0] ^= 1
				if current.Recovery != nil {
					current.Recovery.Signing.SPKI[0] ^= 1
					current.Recovery.KMS.SPKI[0] ^= 1
				}
				after, err := contract.EncodeControlCore(engine.installation.ExpectedControl)
				if err != nil || !bytes.Equal(after, before) {
					t.Fatal("publication did not own the complete supplied access control", err)
				}
			})
		}
	}
}
