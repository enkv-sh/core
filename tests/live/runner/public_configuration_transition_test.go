package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

func runPublicConfigurationTransition(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, row catalog.PublicConfigurationCase, source string) string {
	t.Helper()
	value := []byte("public configuration first secret\x00\xff")
	defer clear(value)
	set := func(bytes []byte) {
		result := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{NoKMS: true}, bytes, "set", "--source", source, "--source-format", "json", "--name", "secret", "--json")
		defer clear(result.Body)
		publicAssertSet(t, result, source, "secret")
	}
	apply := func(policy nativeprocess.Policy, expectedState string) publicChildResult {
		image := publicSourceImage(t, source)
		result := publicCLI(t, ctx, inv, input, budget, "apply", false, policy, nil, "apply", "--source", source, "--source-format", "json", "--json")
		product := publicProduct(t, result, "apply-declaration")
		publicAssertNoRecovery(t, result.Capture)
		publicImageUnchanged(t, image)
		if !publicApplyMatches(result, product, expectedState) {
			t.Fatal("ordinary public apply failed")
		}
		return result
	}
	consume := func(materialize bool) {
		args := []string{"--source", source, "--source-format", "json"}
		if materialize {
			args = append(args, "--materialize-retained")
		}
		result := publicCLI(t, ctx, inv, input, budget, "consumer", true, nativeprocess.Policy{ExpectedSHA256: publicExpected(value)}, nil, args...)
		defer clear(result.Body)
		if result.Code != 0 {
			t.Fatal("public reconstruction failed")
		}
		publicAssertPlain(t, result.Capture, false)
	}
	recovery := func() {
		if input.RecoveryMode != "enabled" {
			return
		}
		image := publicSourceImage(t, source)
		binding := publicRecoveryBinding(t, source)
		oracle := publicCLI(t, ctx, inv, input, budget, "recovery", true, nativeprocess.Policy{ExpectedSHA256: publicExpected(value), RecoveryOracle: true, RecoveryBinding: binding}, nil, "--source", source, "--source-format", "json")
		defer clear(oracle.Body)
		if oracle.Code == 0 {
			t.Fatal("private Recovery oracle claimed Product reconstruction success")
		}
		publicAssertPlain(t, oracle.Capture, true)
		opens := 0
		for _, event := range oracle.Capture.Events {
			if event.Kind == "http-start" && event.Operation == "kms-decrypt" {
				opens++
				if event.Role != "recovery-private" {
					t.Fatal("Recovery oracle attempted another private key route")
				}
			}
			if event.Kind == "http-start" && event.Operation == "kms-sign" || event.Kind == "plaintext" || event.Kind == "recipient-plaintext" {
				t.Fatal("Recovery oracle attempted another private capability")
			}
		}
		if opens != 1 {
			t.Fatal("Recovery oracle did not make one exact selected private call")
		}
		publicImageUnchanged(t, image)
	}
	set(value)
	first := apply(nativeprocess.Policy{}, "success")
	clear(first.Body)
	consume(false)
	if row.Condition == "standard-discovery" || row.Condition == "credential-discovery" {
		args := []string{"--source", source, "--source-format", "json", "--prepare-output-credential"}
		if input.Settings.Provider == "gcp" {
			args = append(args, "--output-project-number", input.Settings.ProjectNumber)
		}
		captured := publicCLI(t, ctx, inv, input, budget, "apply", true, nativeprocess.Policy{}, nil, args...)
		defer clear(captured.Body)
		var output struct {
			OutputPreparation struct {
				Provider         string
				Prepared, Closed bool
			}
		}
		if captured.Code != 0 || json.Unmarshal(captured.Body, &output) != nil || output.OutputPreparation.Provider != input.Settings.Provider || !output.OutputPreparation.Prepared || !output.OutputPreparation.Closed {
			t.Fatal("standard output plugin credential preparation or closure failed")
		}
		witnesses := 0
		for _, event := range captured.Capture.Events {
			if event.Kind == "source-kind" && event.Matched && event.Count == 1 {
				witnesses++
			}
		}
		if witnesses != 1 {
			t.Fatal("output plugin standard source witness missing or repeated")
		}
		return source
	}
	if row.Condition == "portable-validation" {
		if input.RecoveryMode == "enabled" {
			result := publicCLI(t, ctx, inv, input, budget, "successor", true, nativeprocess.Policy{ExpectedSHA256: publicExpected(value)}, nil, "--source", source, "--source-format", "json", "--materialize-retained", "--successor-signing-selector", input.Settings.NormalSuccessorKeyID, "--successor-scratch", filepath.Join(inv.StateDir, "public-successor"))
			defer clear(result.Body)
			var outcome struct {
				PreparationStage uint8
				Successor        *struct {
					Result       Result
					PairPrepared bool
					OutputPath   string
				}
			}
			decodeErr := json.Unmarshal(result.Body, &outcome)
			if result.Code != 0 || decodeErr != nil || outcome.Successor == nil || !outcome.Successor.PairPrepared || outcome.Successor.Result.Outcome != ObservedCurrent || outcome.Successor.OutputPath != filepath.Join(inv.StateDir, "public-successor", "successor.json") {
				t.Fatalf("public successor basis preparation failed: exit=%d stage=%d successor_summary=%t", result.Code, outcome.PreparationStage, outcome.Successor != nil)
			}
			publicAssertPlain(t, result.Capture, false)
			for _, event := range result.Capture.Events {
				if event.Kind == "http-start" && event.Operation == "kms-sign" && event.Role == "normal" {
					t.Fatal("successor restoration attempted lost old Normal private signer")
				}
			}
			// Only the delivered successor pair crosses the cold Reader boundary.
			// The old source remains the input of the finished key operation.
			portable := publicPortablePair(t, outcome.Successor.OutputPath, filepath.Join(inv.StateDir, "portable-successor-pair"))
			publicObservePair(t, ctx, inv, input, budget, portable)
			return outcome.Successor.OutputPath
		}
		return source
	}
	second := apply(nativeprocess.Policy{}, "no-op")
	secondProduct := publicProduct(t, second, "apply-declaration")
	clear(second.Body)
	if !publicApplyUnchanged(secondProduct) {
		t.Fatal("fresh supplied identical apply did not produce exact no-op")
	}
	value = append(value[:0], []byte("changed public secret\xff\x00")...)
	set(value)
	changed := apply(nativeprocess.Policy{}, "success")
	clear(changed.Body)
	consume(false)
	if input.RecoveryMode == "enabled" {
		binding := publicRecoveryBinding(t, source)
		if row.Condition != "retained-input-access" {
			recovery()
		}
		denial := publicCLI(t, ctx, inv, input, budget, "apply", true, nativeprocess.Policy{ExpectedSHA256: publicExpected(value), RecoveryOracle: true, RecoveryBinding: binding}, nil, "--source", source, "--source-format", "json")
		defer clear(denial.Body)
		denied := false
		for _, event := range denial.Capture.Events {
			denied = denied || event.Kind == "http-return" && event.Operation == "kms-decrypt" && event.Role == "recovery-private" && event.Sent && event.PermissionDenied
		}
		if denial.Code == 0 || !denied {
			t.Fatal("ordinary apply context Recovery denial not established")
		}
	}
	if row.Condition == "fresh-secret-apply" {
		return source
	}
	if row.Condition == "retained-input-access" {
		consume(true)
		retained := apply(nativeprocess.Policy{}, "no-op")
		retainedProduct := publicProduct(t, retained, "apply-declaration")
		clear(retained.Body)
		if !publicApplyUnchanged(retainedProduct) {
			t.Fatal("matching retained material did not preserve exact no-op")
		}
		stale := publicPortablePair(t, source, filepath.Join(inv.StateDir, "stale-retained"))
		value = append(value[:0], []byte("fresh generation invalidates retained pin")...)
		set(value)
		fresh := apply(nativeprocess.Policy{}, "success")
		clear(fresh.Body)
		image := publicSourceImage(t, stale)
		refused := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, "apply", "--source", stale, "--source-format", "json", "--json")
		refusedProduct := publicProduct(t, refused, "apply-declaration")
		clear(refused.Body)
		publicImageUnchanged(t, image)
		if refused.Code == 0 || refusedProduct.State == "success" {
			t.Fatal("stale retained material accepted")
		}
		consume(true)
		document := publicSourceDocument(t, source)
		entries := document["entries"].(map[string]any)
		entry := entries["secret"].(map[string]any)
		entry["recipients"] = []string{"consumer"}
		publicWriteSource(t, source, document)
		granted := apply(nativeprocess.Policy{}, "success")
		clear(granted.Body)
		consume(false)
		publicRecipientOracle(t, ctx, inv, input, budget, source, value, false)
		recovery()
		entry["recipients"] = []string{}
		publicWriteSource(t, source, document)
		excluded := apply(nativeprocess.Policy{}, "success")
		clear(excluded.Body)
		consume(false)
		publicRecipientOracle(t, ctx, inv, input, budget, source, value, true)
		recovery()
		// Exact re-add must be prepared from new plaintext; a removed retained pin
		// has no authority to invent a fresh current incarnation.
		removed := entries["secret"]
		delete(entries, "secret")
		publicWriteSource(t, source, document)
		deletion := apply(nativeprocess.Policy{}, "success")
		clear(deletion.Body)
		entries["secret"] = removed
		publicWriteSource(t, source, document)
		readd := apply(nativeprocess.Policy{}, "refused")
		clear(readd.Body)
		if readd.Code == 0 {
			t.Fatal("removed retained pin re-added material")
		}
		set(value)
		added := apply(nativeprocess.Policy{}, "success")
		clear(added.Body)
		consume(false)
		return source
	}
	if row.Condition == "readonly-unknown-outcomes" {
		value = append(value[:0], []byte("read-only state-changing supplied secret")...)
		set(value)
		// Read-only source files are tested as exact bytes. CLI work occurs in its
		// own directory; no success path can regenerate source or dependency files.
		image := publicSourceImage(t, source)
		for path := range image.Files {
			if os.Chmod(path, 0400) != nil {
				t.Fatal("read-only source setup failed")
			}
		}
		readOnlyDirectories := map[string]bool{filepath.Dir(source): true}
		for path := range image.Files {
			readOnlyDirectories[filepath.Dir(path)] = true
		}
		for directory := range readOnlyDirectories {
			if os.Chmod(directory, 0500) != nil {
				t.Fatal("read-only pair directory setup failed")
			}
		}
		changed := apply(nativeprocess.Policy{}, "success")
		changedProduct := publicProduct(t, changed, "apply-declaration")
		clear(changed.Body)
		if publicApplyUnchanged(changedProduct) {
			t.Fatal("read-only state-changing declaration did not change selected value")
		}
		consume(false)
		current := apply(nativeprocess.Policy{}, "no-op")
		currentProduct := publicProduct(t, current, "apply-declaration")
		clear(current.Body)
		if !publicApplyUnchanged(currentProduct) {
			t.Fatal("read-only repeated declaration did not produce exact no-op")
		}
		publicImageUnchanged(t, image)
		for directory := range readOnlyDirectories {
			if os.Chmod(directory, 0700) != nil {
				t.Fatal("pair directory permission restore failed")
			}
		}
		for path := range image.Files {
			if os.Chmod(path, 0600) != nil {
				t.Fatal("source permission restore failed")
			}
		}
		value = append(value[:0], []byte("lost reply selected secret")...)
		set(value)
		lost := apply(nativeprocess.Policy{Fault: "lose-head-reply-and-observation", FaultOrdinal: 1}, "commit-outcome-unknown")
		product := publicProduct(t, lost, "apply-declaration")
		clear(lost.Body)
		if !publicApplyCommitUnknown(lost, product) {
			t.Fatal("lost actual HEAD reply did not preserve commit uncertainty")
		}
		consume(false) // independent selected bytes, no mutation replay
		publicObservePair(t, ctx, inv, input, budget, source)
		value = append(value[:0], []byte("synthetic transport contention secret")...)
		set(value)
		conflict := apply(nativeprocess.Policy{Fault: "head-contention", FaultOrdinal: 1}, "contention")
		clear(conflict.Body)
		if conflict.Code == 0 {
			t.Fatal("pre-send transport contention reported success")
		}
		// This synthetic 412 is transport-only evidence. Real competition is a
		// separate independently prepared declaration launched below.
		publicCompetingApply(t, ctx, inv, input, budget, source)
		return source
	}
	t.Fatal("public transition condition has no executable body")
	return source
}
