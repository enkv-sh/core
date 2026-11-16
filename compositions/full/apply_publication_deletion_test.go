package compositionfull

import (
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestApplyPublicationOptionsOwnExactBoundedChoices(t *testing.T) {
	for _, input := range []ApplyPublicationOptions{{}, {RepublishAfterUnknown: []contract.ID{}, DeletePlugins: map[contract.ID]string{}}} {
		owned, err := ownApplyPublicationOptions(input)
		if err != nil || !reflect.DeepEqual(owned, input) {
			t.Fatal("empty options changed exact nil or empty fields", err)
		}
	}
	input := ApplyPublicationOptions{RepublishAfterUnknown: make([]contract.ID, contract.MaxPublicationMarkers), DeletePlugins: make(map[contract.ID]string, contract.MaxPublicationCoordinates)}
	for i := range input.RepublishAfterUnknown {
		binary.BigEndian.PutUint32(input.RepublishAfterUnknown[i][28:], uint32(i+1))
		if i < contract.MaxPublicationCoordinates {
			input.DeletePlugins[input.RepublishAfterUnknown[i]] = "private-output"
		}
	}
	owned, err := ownApplyPublicationOptions(input)
	if err != nil || !reflect.DeepEqual(owned, input) {
		t.Fatal("maximum bounded exact choices refused", err)
	}
	first := input.RepublishAfterUnknown[0]
	input.RepublishAfterUnknown[0] = contract.ID{}
	input.DeletePlugins[first] = "caller-change"
	if owned.RepublishAfterUnknown[0] != first || owned.DeletePlugins[first] != "private-output" {
		t.Fatal("combined options borrowed the caller's list or map")
	}
	for _, invalid := range []ApplyPublicationOptions{
		{RepublishAfterUnknown: []contract.ID{{}}},
		{RepublishAfterUnknown: []contract.ID{{1}, {1}}},
		{DeletePlugins: map[contract.ID]string{{}: "private-output"}},
		{DeletePlugins: map[contract.ID]string{{1}: "../output"}},
	} {
		if _, err := ownApplyPublicationOptions(invalid); !errors.Is(err, contract.ErrRecord) {
			t.Fatal("malformed combined choices were admitted", err)
		}
	}
	if _, err := ownApplyPublicationOptions(ApplyPublicationOptions{RepublishAfterUnknown: make([]contract.ID, contract.MaxPublicationMarkers+1)}); !errors.Is(err, contract.ErrRecordCapacity) {
		t.Fatal("excessive blocker list was traversed or admitted", err)
	}
	choices := make(map[contract.ID]string, contract.MaxPublicationCoordinates+1)
	for i := 0; i <= contract.MaxPublicationCoordinates; i++ {
		var id contract.ID
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		choices[id] = "private-output"
	}
	if _, err := ownApplyPublicationOptions(ApplyPublicationOptions{DeletePlugins: choices}); !errors.Is(err, contract.ErrRecordCapacity) {
		t.Fatal("excessive executor map was traversed or admitted", err)
	}
}

// full_only: false
func TestApplyPublicationInvalidChoicesRefuseBeforeSourceAccess(t *testing.T) {
	for _, operation := range []string{"fresh-pair", "continue-pair", "fresh-file", "continue-file"} {
		for _, condition := range []string{"zero-coordinate", "invalid-plugin", "duplicate-blocker", "valid"} {
			t.Run(operation+"/"+condition, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				options := ApplyPublicationOptions{DeletePlugins: map[contract.ID]string{{1}: "private-output"}}
				switch condition {
				case "zero-coordinate":
					options.DeletePlugins = map[contract.ID]string{{}: "private-output"}
				case "invalid-plugin":
					options.DeletePlugins[contract.ID{1}] = "../output"
				case "duplicate-blocker":
					options.RepublishAfterUnknown = []contract.ID{{2}, {2}}
				}
				path := filepath.Join(t.TempDir(), "missing-source.json")
				request, publication, accepted := contract.ID{3}, contract.ID{4}, contract.ID{5}
				var result core.PublicApplyPublicationResult
				switch operation {
				case "fresh-pair":
					result = ApplyConfigurationAndPublish(ctx, request, publication, nil, options, ApplyOptions{}).PublicApplyPublicationResult
				case "continue-pair":
					result = ContinueConfigurationApplyAndPublish(ctx, request, accepted, publication, nil, options).PublicApplyPublicationResult
				case "fresh-file":
					result = ApplyConfigurationAndPublishFile(ctx, request, publication, path, configuration.JSON, options, ApplyOptions{}).PublicApplyPublicationResult
				case "continue-file":
					result = ContinueConfigurationApplyAndPublishFile(ctx, request, accepted, publication, path, configuration.JSON, options).PublicApplyPublicationResult
				}
				stage := "dispatch"
				if condition == "valid" {
					stage = "parse"
					if operation == "fresh-file" || operation == "continue-file" {
						stage = "capture"
					}
				}
				if result.Apply.RequestID != request || result.Apply.Result.Outcome != core.AdmissionRefused || result.Apply.Result.CommitMayHaveOccurred || result.Apply.PreAdmission == nil || result.Apply.PreAdmission.Stage != stage || !result.Apply.RequestIdentity.IsZero() || result.Apply.Payload != nil || len(result.Apply.Receipt) != 0 || result.Publication.Stage != "unstarted" || result.Publication.Reason != "apply-incomplete" || result.Publication.Result != nil {
					t.Fatal("combined choices changed source-access ordering or operation facts", result.Apply.Result, result.Apply.PreAdmission, result.Publication)
				}
			})
		}
	}
}

// full_only: false
func TestApplyPublicationConstructionReceivesOwnedDeletionChoices(t *testing.T) {
	for _, continuation := range []bool{false, true} {
		name := "fresh"
		if continuation {
			name = "continuation"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			source := configurationApplyPair(t, "aws", configuration.JSON, nil)
			defer func() {
				if err := source.pair.Close(); err != nil {
					t.Error(err)
				}
			}()
			before := configurationApplySourceImage(t, filepath.Dir(source.path))
			coordinate, blocker := contract.ID{6}, contract.ID{7}
			options := ApplyPublicationOptions{RepublishAfterUnknown: []contract.ID{blocker}, DeletePlugins: map[contract.ID]string{coordinate: "private-output"}}
			operation := contract.ID{}
			if continuation {
				operation = contract.ID{8}
			}
			store := &configurationObservationStore{result: contract.ReadResult{Status: contract.ReadMissing}}
			var trust *configurationObservationTrust
			applies, publications, closes, private := 0, 0, 0, 0
			result := configurationApplyPublication(ctx, contract.ID{9}, contract.ID{10}, source.pair, operation, options,
				func(_ context.Context, _ *configuration.Model, installation core.ApplyInstallation, _ *configurationInstalledPlugins) (*core.InstalledApply, error) {
					applies++
					options.DeletePlugins[coordinate] = "caller-change"
					options.RepublishAfterUnknown[0] = contract.ID{11}
					store.descriptor = installation.ExpectedStore
					trust = &configurationObservationTrust{id: installation.ExpectedControl.NormalSigning.Binding.Trust, family: installation.ExpectedControl.Provider}
					installation.Store, installation.Trust = store, trust
					if installation.ConfigurationValidator == nil {
						installation.ConfigurationValidator = core.NewPublicConfigurationValidator(nil)
					}
					installation.CloseInstalled = func() { closes++ }
					installation.AdmitCustody = func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*core.InstalledApplyCustody, error) {
						private++
						return nil, contract.ErrRecord
					}
					return core.NewInstalledApply(installation)
				},
				func(_ context.Context, _ *configuration.Model, _ core.PublicationInstallation, choices map[contract.ID]string, _ *configurationInstalledPlugins) (*core.InstalledPublication, error) {
					publications++
					if !reflect.DeepEqual(choices, map[contract.ID]string{coordinate: "private-output"}) {
						t.Error("construction lost or borrowed exact retained executor choices", choices)
					}
					choices[coordinate] = "constructor-owned-change"
					return nil, errors.New("controlled publication construction refusal")
				})
			if applies != 1 || publications != 1 || closes != 1 || store.reads != 1 || store.writes != 0 || trust == nil || trust.signs != 0 || private != 0 || options.DeletePlugins[coordinate] != "caller-change" || result.Apply.Result.Outcome != core.RootLossUnsupported || result.Publication.Stage != "unstarted" || result.Publication.Reason != "apply-incomplete" {
				t.Fatal("constructor choice handoff changed execution or ownership", applies, publications, closes, store.reads, store.writes, private, result.Apply.Result, result.Publication)
			}
			configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
		})
	}
}
