package contract

import (
	"reflect"
	"strings"
	"testing"
)

// full_only: false
func TestMaterializationRequestOwnsNonemptySortedNames(t *testing.T) {
	input := MaterializationRequest{RequestNonce: ID{1}, Names: []string{"z", "a"}}
	got, err := OwnMaterializationRequest(input)
	if err != nil || !reflect.DeepEqual(got.Names, []string{"a", "z"}) {
		t.Fatal("valid sorted request", got, err)
	}
	input.Names[0] = "changed"
	if !reflect.DeepEqual(got.Names, []string{"a", "z"}) {
		t.Fatal("request borrowed caller names")
	}
	for _, names := range [][]string{nil, {}, {"a", "a"}, {strings.Repeat("x", CryptoMaxName+1)}, {string([]byte{0xff})}, make([]string, CryptoMaxValueEntries+1)} {
		if _, err := OwnMaterializationRequest(MaterializationRequest{RequestNonce: ID{1}, Names: names}); err == nil {
			t.Fatal("invalid selection admitted")
		}
	}
	// Canonical names can be empty or unsuitable for dotenv. The private encoder owns representation refusal.
	if _, err := OwnMaterializationRequest(MaterializationRequest{RequestNonce: ID{1}, Names: []string{""}}); err != nil {
		t.Fatal("Core applied output grammar", err)
	}
	names := make([]string, CryptoMaxValueEntries)
	for i := range names {
		names[i] = string(rune(0x100 + i))
	}
	if _, err := OwnMaterializationRequest(MaterializationRequest{RequestNonce: ID{1}, Names: names}); err != nil {
		t.Fatal("exact selection bound refused", err)
	}
	if _, err := OwnMaterializationRequest(MaterializationRequest{Names: []string{"a"}}); err == nil {
		t.Fatal("missing nonce admitted")
	}
}

func completeMaterializationFacts() MaterializationFacts {
	return MaterializationFacts{Replacement: MaterializationReplaced, CandidateVerification: MaterializationVerified,
		InstalledVerification: MaterializationVerified, NativeCompletion: MaterializationComplete,
		Disclosure: MaterializationDisclosureOccurred, Cleanup: MaterializationCandidateRenamed}
}

// full_only: false
func TestMaterializationFactsPreserveLateReplacementAndRejectFalseCompletion(t *testing.T) {
	success := MaterializationCompletion{StateResult: MaterializationSuccess, Facts: completeMaterializationFacts()}
	if err := success.Validate(); err != nil {
		t.Fatal("complete success refused", err)
	}
	for _, change := range []func(*MaterializationCompletion){
		func(c *MaterializationCompletion) { c.StateResult = MaterializationUnavailable },
		func(c *MaterializationCompletion) { c.Facts.Replacement = MaterializationReplacementUnknown },
		func(c *MaterializationCompletion) { c.Facts.InstalledVerification = MaterializationNotObserved },
		func(c *MaterializationCompletion) { c.Facts.Cleanup = MaterializationCandidateCleanupFailed },
		func(c *MaterializationCompletion) { c.Facts.Disclosure = MaterializationDisclosureNone },
		func(c *MaterializationCompletion) {
			c.Facts.Failure = &MaterializationFailure{Stage: MaterializationDirectorySync, Reason: MaterializationIOFailure}
		},
	} {
		bad := success
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("incomplete native success admitted", bad)
		}
	}
	late := success
	late.StateResult = MaterializationUnavailable
	late.Facts.NativeCompletion = MaterializationIncomplete
	late.Facts.Failure = &MaterializationFailure{Stage: MaterializationDirectorySync, Reason: MaterializationIOFailure}
	if late.Validate() != nil || late.Facts.Replacement != MaterializationReplaced || late.Facts.InstalledVerification != MaterializationVerified {
		t.Fatal("late failure lost independent facts")
	}
	late.Facts.Replacement = MaterializationNotReplaced
	late.Facts.InstalledVerification = MaterializationNotObserved
	late.Facts.CandidateVerification = MaterializationNotObserved
	late.Facts.Failure = &MaterializationFailure{Stage: MaterializationStaging, Reason: MaterializationIOFailure}
	late.Facts.Cleanup = MaterializationCandidateCleanupFailed
	late.Facts.CleanupFailure = &MaterializationFailure{Stage: MaterializationCleanup, Reason: MaterializationCleanupFailure}
	late.Facts.ResiduePath = "/private/candidate"
	if late.Validate() != nil {
		t.Fatal("original and cleanup failures cannot coexist")
	}
	late.Facts.ResiduePath = strings.Repeat("x", 4097)
	if late.Validate() == nil {
		t.Fatal("unbounded residue accepted")
	}
	for _, state := range []MaterializationStateResult{"contention", "unsupported", "exact-resume", ""} {
		bad := success
		bad.StateResult = state
		if bad.Validate() == nil {
			t.Fatal("illegal operation outcome accepted", state)
		}
	}

	post := MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: completeMaterializationFacts()}
	post.Facts.NativeCompletion = MaterializationIncomplete
	post.Facts.Failure = &MaterializationFailure{Stage: MaterializationDirectorySync, Reason: MaterializationIOFailure}
	for _, state := range []MaterializationStateResult{MaterializationRefused, MaterializationProfileBlocked, MaterializationRootLossUnsupported, MaterializationPositiveDefect} {
		t.Run("post-replacement/"+string(state), func(t *testing.T) {
			bad := post
			bad.StateResult = state
			if bad.Validate() == nil {
				t.Fatal("post-replacement I/O assigned illegal outcome")
			}
		})
	}
	for _, stage := range []MaterializationStage{MaterializationAdmissionStage, MaterializationLoad, MaterializationAuthentication, MaterializationEncoding} {
		t.Run("early-stage/"+string(stage), func(t *testing.T) {
			bad := post
			bad.Facts.Failure = &MaterializationFailure{Stage: stage, Reason: MaterializationIOFailure}
			if bad.Validate() == nil {
				t.Fatal("early failure carried native progress")
			}
		})
	}
	for _, stage := range []MaterializationStage{MaterializationStaging, MaterializationCandidateSync, MaterializationCandidateClose, MaterializationCandidateVerification} {
		t.Run("candidate-stage/"+string(stage), func(t *testing.T) {
			bad := post
			bad.Facts.Failure = &MaterializationFailure{Stage: stage, Reason: MaterializationIOFailure}
			if bad.Validate() == nil {
				t.Fatal("candidate failure carried installed observation")
			}
		})
	}
	t.Run("candidate-without-incomplete", func(t *testing.T) {
		bad := post
		bad.Facts.Replacement = MaterializationNotReplaced
		bad.Facts.CandidateVerification = MaterializationNotObserved
		bad.Facts.InstalledVerification = MaterializationNotObserved
		bad.Facts.Cleanup = MaterializationCandidateRemoved
		bad.Facts.NativeCompletion = MaterializationNativeNotObserved
		bad.Facts.Failure = &MaterializationFailure{Stage: MaterializationStaging, Reason: MaterializationIOFailure}
		if bad.Validate() == nil {
			t.Fatal("candidate attempt carried unobserved completion")
		}
	})
	t.Run("unknown-replacement-refused", func(t *testing.T) {
		bad := post
		bad.StateResult = MaterializationRefused
		bad.Facts.Replacement = MaterializationReplacementUnknown
		bad.Facts.Cleanup = MaterializationCandidateCleanupUnknown
		bad.Facts.InstalledVerification = MaterializationNotObserved
		bad.Facts.Failure = &MaterializationFailure{Stage: MaterializationRename, Reason: MaterializationIOFailure}
		if bad.Validate() == nil {
			t.Fatal("unknown replacement became refusal")
		}
	})
	t.Run("staging-create-failure", func(t *testing.T) {
		facts := InitialMaterializationFacts()
		facts.NativeCompletion = MaterializationIncomplete
		facts.Failure = &MaterializationFailure{Stage: MaterializationStaging, Reason: MaterializationIOFailure}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() != nil {
			t.Fatal("create failure required a fabricated candidate")
		}
	})
	t.Run("precreate-canceled", func(t *testing.T) {
		facts := InitialMaterializationFacts()
		facts.Failure = &MaterializationFailure{Stage: MaterializationStaging, Reason: MaterializationCanceled}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() != nil {
			t.Fatal("precreate cancellation fabricated native progress")
		}
	})
	t.Run("verified-candidate-close-failure", func(t *testing.T) {
		facts := post.Facts
		facts.Replacement = MaterializationNotReplaced
		facts.Cleanup = MaterializationCandidateRemoved
		facts.InstalledVerification = MaterializationNotObserved
		facts.Failure = &MaterializationFailure{Stage: MaterializationCandidateClose, Reason: MaterializationIOFailure}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() != nil {
			t.Fatal("candidate readback close erased verification")
		}
	})
	t.Run("required-close-cleanup-failure", func(t *testing.T) {
		facts := post.Facts
		facts.CleanupFailure = &MaterializationFailure{Stage: MaterializationDirectoryClose, Reason: MaterializationIOFailure}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() != nil {
			t.Fatal("required close failure erased prior native facts")
		}
	})

	t.Run("proved installed contradiction", func(t *testing.T) {
		facts := post.Facts
		facts.InstalledVerification = MaterializationVerificationFailed
		facts.Failure = &MaterializationFailure{Stage: MaterializationInstalledVerification, Reason: MaterializationVerificationMismatch}
		if (MaterializationCompletion{StateResult: MaterializationPositiveDefect, Facts: facts}).Validate() != nil {
			t.Fatal("proved installed contradiction rejected")
		}
	})
	t.Run("prestage authentication contradiction", func(t *testing.T) {
		facts := InitialMaterializationFacts()
		facts.Failure = &MaterializationFailure{Stage: MaterializationAuthentication, Reason: MaterializationIntegrityContradiction}
		if (MaterializationCompletion{StateResult: MaterializationPositiveDefect, Facts: facts}).Validate() != nil {
			t.Fatal("stored authentication contradiction rejected")
		}
	})

	for _, outcome := range []struct {
		state  MaterializationStateResult
		reason MaterializationFailureReason
	}{{MaterializationRefused, MaterializationInvalidRequest}, {MaterializationProfileBlocked, MaterializationProfileUnqualified}, {MaterializationRootLossUnsupported, MaterializationRootLoss}} {
		t.Run("candidate-progress/"+string(outcome.state), func(t *testing.T) {
			facts := post.Facts
			facts.Replacement = MaterializationNotReplaced
			facts.CandidateVerification = MaterializationNotObserved
			facts.InstalledVerification = MaterializationNotObserved
			facts.Cleanup = MaterializationCandidateRemoved
			facts.Failure = &MaterializationFailure{Stage: MaterializationCandidateSync, Reason: outcome.reason}
			if (MaterializationCompletion{StateResult: outcome.state, Facts: facts}).Validate() == nil {
				t.Fatal("native candidate progress assigned admission outcome")
			}
		})
	}

	for _, failure := range []MaterializationFailure{{MaterializationAdmissionStage, MaterializationUnauthorizedSelection}, {MaterializationDirectorySync, MaterializationIOFailure}, {MaterializationCleanup, MaterializationIOFailure}, {MaterializationSinkClose, MaterializationInvalidAdmission}} {
		t.Run("invalid cleanup owner/"+string(failure.Stage)+"/"+string(failure.Reason), func(t *testing.T) {
			facts := post.Facts
			facts.CleanupFailure = &failure
			if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() == nil {
				t.Fatal("non-cleanup failure entered separate cleanup slot")
			}
		})
	}
	for _, stage := range []MaterializationStage{MaterializationCandidateClose, MaterializationInstalledClose, MaterializationDirectoryClose, MaterializationSinkClose} {
		for _, reason := range []MaterializationFailureReason{MaterializationIOFailure, MaterializationCanceled, MaterializationDeadlineExceeded} {
			t.Run("required cleanup close/"+string(stage)+"/"+string(reason), func(t *testing.T) {
				facts := post.Facts
				facts.CleanupFailure = &MaterializationFailure{Stage: stage, Reason: reason}
				if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() != nil {
					t.Fatal("legitimate required-close failure was discarded")
				}
			})
		}
	}
	for _, stage := range []MaterializationStage{MaterializationRename, MaterializationDirectorySync} {
		t.Run("missing candidate prerequisite/"+string(stage), func(t *testing.T) {
			facts := InitialMaterializationFacts()
			facts.NativeCompletion = MaterializationIncomplete
			facts.Failure = &MaterializationFailure{Stage: stage, Reason: MaterializationIOFailure}
			if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() == nil {
				t.Fatal("native phase ran without verified candidate")
			}
		})
	}
	t.Run("unverified rename candidate", func(t *testing.T) {
		facts := post.Facts
		facts.Replacement = MaterializationNotReplaced
		facts.Cleanup = MaterializationCandidateRemoved
		facts.CandidateVerification = MaterializationNotObserved
		facts.InstalledVerification = MaterializationNotObserved
		facts.Failure = &MaterializationFailure{Stage: MaterializationRename, Reason: MaterializationIOFailure}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() == nil {
			t.Fatal("rename preceded candidate verification")
		}
	})
	for _, stage := range []MaterializationStage{MaterializationDirectorySync, MaterializationInstalledVerification} {
		t.Run("unknown rename before installed phase/"+string(stage), func(t *testing.T) {
			facts := post.Facts
			facts.Replacement = MaterializationReplacementUnknown
			facts.Cleanup = MaterializationCandidateCleanupUnknown
			facts.InstalledVerification = MaterializationNotObserved
			facts.Failure = &MaterializationFailure{Stage: stage, Reason: MaterializationIOFailure}
			if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() == nil {
				t.Fatal("ambiguous rename allowed later normal work")
			}
		})
	}
	t.Run("directory sync before replacement", func(t *testing.T) {
		facts := post.Facts
		facts.Replacement = MaterializationNotReplaced
		facts.Cleanup = MaterializationCandidateRemoved
		facts.InstalledVerification = MaterializationNotObserved
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() == nil {
			t.Fatal("directory sync preceded replacement")
		}
	})
	for _, verification := range []MaterializationVerification{MaterializationNotObserved, MaterializationVerificationFailed} {
		t.Run("primary installed close without verified observation/"+string(verification), func(t *testing.T) {
			facts := post.Facts
			facts.InstalledVerification = verification
			facts.Failure = &MaterializationFailure{Stage: MaterializationInstalledClose, Reason: MaterializationIOFailure}
			if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() == nil {
				t.Fatal("installed close erased earlier verification failure")
			}
		})
	}
	for _, stage := range []MaterializationStage{MaterializationStaging, MaterializationCandidateSync, MaterializationCandidateClose} {
		t.Run("native proof owner/"+string(stage), func(t *testing.T) {
			facts := post.Facts
			facts.Replacement = MaterializationNotReplaced
			facts.Cleanup = MaterializationCandidateRemoved
			facts.CandidateVerification = MaterializationVerificationFailed
			facts.InstalledVerification = MaterializationNotObserved
			facts.Failure = &MaterializationFailure{Stage: stage, Reason: MaterializationVerificationMismatch}
			if (MaterializationCompletion{StateResult: MaterializationPositiveDefect, Facts: facts}).Validate() == nil {
				t.Fatal("native proof attributed to unrelated phase")
			}
		})
	}
	t.Run("verified candidate proves disclosure", func(t *testing.T) {
		facts := post.Facts
		facts.Replacement = MaterializationNotReplaced
		facts.Cleanup = MaterializationCandidateRemoved
		facts.InstalledVerification = MaterializationNotObserved
		facts.Disclosure = MaterializationDisclosureUnknown
		facts.Failure = &MaterializationFailure{Stage: MaterializationCandidateClose, Reason: MaterializationIOFailure}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() == nil {
			t.Fatal("complete candidate observation retained unknown disclosure")
		}
	})
	t.Run("known non-replacement rename error", func(t *testing.T) {
		facts := post.Facts
		facts.Replacement = MaterializationNotReplaced
		facts.Cleanup = MaterializationCandidateRemoved
		facts.InstalledVerification = MaterializationNotObserved
		facts.Failure = &MaterializationFailure{Stage: MaterializationRename, Reason: MaterializationIOFailure}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() != nil {
			t.Fatal("verified candidate with failed rename rejected")
		}
	})
	t.Run("ambiguous rename error", func(t *testing.T) {
		facts := post.Facts
		facts.Replacement = MaterializationReplacementUnknown
		facts.Cleanup = MaterializationCandidateCleanupUnknown
		facts.InstalledVerification = MaterializationNotObserved
		facts.Failure = &MaterializationFailure{Stage: MaterializationRename, Reason: MaterializationIOFailure}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() != nil {
			t.Fatal("ambiguous rename facts rejected")
		}
	})
	t.Run("candidate contradiction owner", func(t *testing.T) {
		facts := post.Facts
		facts.Replacement = MaterializationNotReplaced
		facts.Cleanup = MaterializationCandidateRemoved
		facts.CandidateVerification = MaterializationVerificationFailed
		facts.InstalledVerification = MaterializationNotObserved
		facts.Failure = &MaterializationFailure{Stage: MaterializationCandidateVerification, Reason: MaterializationVerificationMismatch}
		if (MaterializationCompletion{StateResult: MaterializationPositiveDefect, Facts: facts}).Validate() != nil {
			t.Fatal("proved candidate contradiction rejected")
		}
	})
	t.Run("installed verification failure retains close failure", func(t *testing.T) {
		facts := post.Facts
		facts.InstalledVerification = MaterializationVerificationFailed
		facts.Failure = &MaterializationFailure{Stage: MaterializationInstalledVerification, Reason: MaterializationVerificationMismatch}
		facts.CleanupFailure = &MaterializationFailure{Stage: MaterializationInstalledClose, Reason: MaterializationIOFailure}
		if (MaterializationCompletion{StateResult: MaterializationPositiveDefect, Facts: facts}).Validate() != nil {
			t.Fatal("required close replaced original installed contradiction")
		}
	})

	t.Run("installed readback unavailable before observation", func(t *testing.T) {
		facts := post.Facts
		facts.InstalledVerification = MaterializationNotObserved
		facts.Failure = &MaterializationFailure{Stage: MaterializationInstalledVerification, Reason: MaterializationIOFailure}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() != nil {
			t.Fatal("installed open failure fabricated a completed check")
		}
	})
	t.Run("verified installed close failure", func(t *testing.T) {
		facts := post.Facts
		facts.Failure = &MaterializationFailure{Stage: MaterializationInstalledClose, Reason: MaterializationIOFailure}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() != nil {
			t.Fatal("installed close failure erased verification")
		}
	})

	t.Run("native contradiction requires a proof owner without claimed progress", func(t *testing.T) {
		facts := InitialMaterializationFacts()
		facts.Failure = &MaterializationFailure{Stage: MaterializationStaging, Reason: MaterializationIntegrityContradiction}
		if (MaterializationCompletion{StateResult: MaterializationPositiveDefect, Facts: facts}).Validate() == nil {
			t.Fatal("native positive defect had no proof observation")
		}
	})
	for _, verification := range []MaterializationVerification{MaterializationVerified, MaterializationVerificationFailed} {
		t.Run("installed observation resolves rename/"+string(verification), func(t *testing.T) {
			facts := post.Facts
			facts.Replacement = MaterializationReplacementUnknown
			facts.Cleanup = MaterializationCandidateCleanupUnknown
			facts.InstalledVerification = verification
			facts.Failure = &MaterializationFailure{Stage: MaterializationRename, Reason: MaterializationIOFailure}
			if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() == nil {
				t.Fatal("installed observation accepted under unknown replacement")
			}
		})
	}
	for _, stage := range []MaterializationStage{MaterializationDirectoryClose, MaterializationSinkClose, MaterializationCleanup} {
		t.Run("unknown rename retains primary failure/"+string(stage), func(t *testing.T) {
			facts := post.Facts
			facts.Replacement = MaterializationReplacementUnknown
			facts.Cleanup = MaterializationCandidateCleanupUnknown
			facts.InstalledVerification = MaterializationNotObserved
			reason := MaterializationIOFailure
			if stage == MaterializationCleanup {
				reason = MaterializationCleanupFailure
			}
			facts.Failure = &MaterializationFailure{Stage: stage, Reason: reason}
			if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() == nil {
				t.Fatal("cleanup replaced original ambiguous rename failure")
			}
		})
	}
	for _, failure := range []MaterializationFailure{{MaterializationCandidateClose, MaterializationIOFailure}, {MaterializationCleanup, MaterializationCleanupFailure}, {MaterializationInstalledClose, MaterializationIOFailure}} {
		t.Run("cleanup release without acquisition/"+string(failure.Stage), func(t *testing.T) {
			facts := InitialMaterializationFacts()
			facts.Failure = &MaterializationFailure{Stage: MaterializationAuthentication, Reason: MaterializationInvalidAdmission}
			facts.CleanupFailure = &failure
			if (MaterializationCompletion{StateResult: MaterializationRefused, Facts: facts}).Validate() == nil {
				t.Fatal("unacquired native handle entered cleanup result")
			}
		})
	}
	t.Run("unknown rename has no installed handle", func(t *testing.T) {
		facts := post.Facts
		facts.Replacement = MaterializationReplacementUnknown
		facts.Cleanup = MaterializationCandidateCleanupUnknown
		facts.InstalledVerification = MaterializationNotObserved
		facts.Failure = &MaterializationFailure{Stage: MaterializationRename, Reason: MaterializationIOFailure}
		facts.CleanupFailure = &MaterializationFailure{Stage: MaterializationInstalledClose, Reason: MaterializationIOFailure}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() == nil {
			t.Fatal("unknown rename acquired an installed handle")
		}
	})
	for _, stage := range []MaterializationStage{MaterializationDirectoryClose, MaterializationSinkClose} {
		t.Run("early admission handle close/"+string(stage), func(t *testing.T) {
			facts := InitialMaterializationFacts()
			facts.Failure = &MaterializationFailure{Stage: MaterializationAuthentication, Reason: MaterializationInvalidAdmission}
			facts.CleanupFailure = &MaterializationFailure{Stage: stage, Reason: MaterializationIOFailure}
			if (MaterializationCompletion{StateResult: MaterializationRefused, Facts: facts}).Validate() != nil {
				t.Fatal("early admission handle close erased primary refusal")
			}
		})
	}
	t.Run("required cleanup error survives later positive absence", func(t *testing.T) {
		facts := post.Facts
		facts.Replacement = MaterializationNotReplaced
		facts.Cleanup = MaterializationCandidateRemoved
		facts.CandidateVerification = MaterializationNotObserved
		facts.InstalledVerification = MaterializationNotObserved
		facts.Failure = &MaterializationFailure{Stage: MaterializationStaging, Reason: MaterializationIOFailure}
		facts.CleanupFailure = &MaterializationFailure{Stage: MaterializationCleanup, Reason: MaterializationCleanupFailure}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() != nil {
			t.Fatal("positive absence erased required failed cleanup step")
		}
	})
	for _, stage := range []MaterializationStage{MaterializationCandidateClose, MaterializationDirectoryClose, MaterializationSinkClose} {
		t.Run("unknown rename retains separate acquired cleanup/"+string(stage), func(t *testing.T) {
			facts := post.Facts
			facts.Replacement = MaterializationReplacementUnknown
			facts.Cleanup = MaterializationCandidateCleanupUnknown
			facts.InstalledVerification = MaterializationNotObserved
			facts.Failure = &MaterializationFailure{Stage: MaterializationRename, Reason: MaterializationIOFailure}
			facts.CleanupFailure = &MaterializationFailure{Stage: stage, Reason: MaterializationIOFailure}
			if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() != nil {
				t.Fatal("acquired cleanup replaced ambiguous rename failure")
			}
		})
	}
	t.Run("incomplete installed readback retains close error", func(t *testing.T) {
		facts := post.Facts
		facts.InstalledVerification = MaterializationNotObserved
		facts.Failure = &MaterializationFailure{Stage: MaterializationInstalledVerification, Reason: MaterializationIOFailure}
		facts.CleanupFailure = &MaterializationFailure{Stage: MaterializationInstalledClose, Reason: MaterializationIOFailure}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() != nil {
			t.Fatal("close error erased incomplete installed readback")
		}
	})

	t.Run("primary cleanup without candidate acquisition", func(t *testing.T) {
		facts := InitialMaterializationFacts()
		facts.NativeCompletion = MaterializationIncomplete
		facts.Failure = &MaterializationFailure{Stage: MaterializationCleanup, Reason: MaterializationCleanupFailure}
		if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() == nil {
			t.Fatal("primary cleanup had no candidate authority")
		}
	})

	for _, cleanup := range []MaterializationCandidateCleanup{MaterializationCandidateRemoved, MaterializationCandidateCleanupFailed} {
		t.Run("primary acquired candidate cleanup/"+string(cleanup), func(t *testing.T) {
			facts := post.Facts
			facts.Replacement = MaterializationNotReplaced
			facts.Cleanup = cleanup
			facts.CandidateVerification = MaterializationNotObserved
			facts.InstalledVerification = MaterializationNotObserved
			facts.Failure = &MaterializationFailure{Stage: MaterializationCleanup, Reason: MaterializationCleanupFailure}
			if (MaterializationCompletion{StateResult: MaterializationUnavailable, Facts: facts}).Validate() != nil {
				t.Fatal("primary acquired-candidate cleanup error rejected")
			}
		})
	}
}
