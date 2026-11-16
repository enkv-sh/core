package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

func publicCompetingApply(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string) {
	t.Helper()
	competitor := publicPortablePair(t, source, filepath.Join(inv.StateDir, "competing-pair"))
	// The two original processes share the real provider coordinate, carry
	// distinct fresh supplied declarations and each performs its own installed
	// conditional HEAD publication. Neither invocation is restarted.
	if os.Chmod(competitor, 0600) != nil {
		t.Fatal("competing source permission unavailable")
	}
	set := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{NoKMS: true}, []byte("independent competing declaration"), "set", "--source", competitor, "--source-format", "json", "--name", "secret", "--json")
	publicAssertSet(t, set, competitor, "secret")
	clear(set.Body)
	competitors := publicCompetingCommands(t, ctx, inv, input, budget, "apply", "apply", source, competitor)
	first, second := competitors[0].Result, competitors[1].Result
	defer clear(first.Body)
	defer clear(second.Body)
	for index, child := range []publicChildResult{first, second} {
		var product struct {
			State         string `json:"state_result"`
			CommitUnknown bool   `json:"commit_may_have_occurred"`
			Receipt       string `json:"receipt_hex"`
		}
		decoded := json.Unmarshal(child.Body, &product) == nil
		state := "invalid"
		if decoded {
			switch product.State {
			case "success", "no-op", "contention", "commit-outcome-unknown", "refused", "unavailable", "positive-defect", "root-loss-unsupported", "snapshot-size-refusal":
				state = product.State
			}
		}
		head, valid := publicApplyHeadWrite(child.Capture)
		t.Logf("real Apply child=%d capture=%s exit=%d result_decoded=%t state=%s commit_unknown=%t receipt_present=%t head_pair_valid=%t head_status=%d", index,
			filepath.Base(filepath.Dir(child.CapturePath)), child.Code, decoded, state, product.CommitUnknown, product.Receipt != "", valid, head.Status)
	}
	a, b := publicProduct(t, first, "apply-declaration"), publicProduct(t, second, "apply-declaration")
	if !publicApplyCompetitionSettled(input.Settings.Provider, first, second, a, b) {
		t.Fatal("real competing declarations did not preserve one selected result and the provider-qualified loser outcome")
	}
	publicAssertNoRecovery(t, first.Capture)
	publicAssertNoRecovery(t, second.Capture)
}

type publicCompetitor struct {
	Path   string
	Result publicChildResult
}

func publicCompetingCommands(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, role, command string, paths ...string) [2]publicCompetitor {
	t.Helper()
	if len(paths) != 2 {
		t.Fatal("exact two original competitors required")
	}
	results := make(chan publicCompetitor, 2)
	barrier := filepath.Join(inv.StateDir, "real-"+command+"-barrier")
	if os.Mkdir(barrier, 0700) != nil {
		t.Fatal("real conditional competition barrier unavailable")
	}
	competitionContext, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, path := range paths {
		go func(path string) {
			result := publicCompetitor{Path: path}
			defer func() { results <- result }()
			result.Result = publicCLI(t, competitionContext, inv, input, budget, role, false, nativeprocess.Policy{HeadBarrier: barrier}, nil, command, "--source", path, "--source-format", "json", "--json")
		}(path)
	}
	deadline := time.NewTimer(time.Minute)
	ticker := time.NewTicker(10 * time.Millisecond)
	ready := false
	for !ready {
		entries, err := os.ReadDir(barrier)
		if err != nil {
			cancel()
			break
		}
		count := 0
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".ready") {
				count++
			}
		}
		if count == 2 {
			ready = true
			break
		}
		select {
		case <-deadline.C:
			cancel()
		case <-ctx.Done():
			cancel()
		case <-ticker.C:
			continue
		}
		break
	}
	ticker.Stop()
	deadline.Stop()
	if ready {
		if os.WriteFile(filepath.Join(barrier, "release"), nil, 0600) != nil {
			cancel()
			ready = false
		}
	}
	first, second := <-results, <-results
	if !ready {
		t.Fatal("real competing conditional writes did not both reach the original send barrier")
	}
	return [2]publicCompetitor{first, second}
}

func publicCompetingInitialization(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string) (publicChildResult, string) {
	t.Helper()
	paths := make([]string, 2)
	for i := range paths {
		directory := filepath.Join(inv.StateDir, fmt.Sprintf("initialization-competitor-%d", i))
		if os.Mkdir(directory, 0700) != nil {
			t.Fatal("independent initialization source owner unavailable")
		}
		paths[i] = filepath.Join(directory, "configuration.json")
		publicSetupSource(t, input, paths[i])
	}
	competitors := publicCompetingCommands(t, ctx, inv, input, budget, "authority", "init", paths...)
	winner, loser := -1, -1
	for i, competitor := range competitors {
		product := publicProduct(t, competitor.Result, "initialize-empty-domain")
		if competitor.Result.Code == 0 && product.State == "success" && product.Payload.Domain != "" {
			if winner >= 0 {
				t.Fatal("empty initialization published two ready competitors")
			}
			winner = i
		} else if competitor.Result.Code != 0 && product.State == "contention" && product.Payload.Domain == "" {
			loser = i
		}
	}
	if winner < 0 || loser < 0 || publicReadDomain(t, competitors[winner].Path) == publicReadDomain(t, competitors[loser].Path) {
		t.Fatal("real independent empty initialization competition did not settle one winner and contention loser")
	}
	for index, competitor := range competitors {
		sent, status := 0, 0
		for _, event := range competitor.Result.Capture.Events {
			if event.Kind == "http-start" && event.Operation == "head-write" && event.Sent {
				sent++
			}
			if event.Kind == "http-return" && event.Operation == "head-write" && event.Sent {
				status = event.Status
			}
		}
		if sent != 1 || index == winner && (status < 200 || status >= 300) || index == loser && status != 412 {
			t.Fatal("real initialization conditional publication evidence differs")
		}
	}
	// Preserve each original delivered pair and manifest, then transfer only the
	// selected winner's pair into the ordinary source path for clean Reader use.
	if delivered := publicPortablePair(t, competitors[winner].Path, filepath.Dir(source)); delivered != source {
		t.Fatal("selected initialization pair transfer route differs")
	}
	resume := publicCLI(t, ctx, inv, input, budget, "authority", false, nativeprocess.Policy{}, nil, "init", "--source", competitors[winner].Path, "--source-format", "json", "--json")
	resumed := publicProduct(t, resume, "initialize-empty-domain")
	clear(resume.Body)
	winnerProduct := publicProduct(t, competitors[winner].Result, "initialize-empty-domain")
	if resume.Code != 0 || resumed.State != "exact-resume" || resumed.Receipt != winnerProduct.Receipt {
		t.Fatal("selected exact initialization artifacts did not resume by observation")
	}
	for _, event := range resume.Capture.Events {
		if event.Kind == "http-start" && (event.Operation == "kms-sign" || event.Operation == "kms-decrypt" || event.Operation == "head-write" || event.Operation == "store-write") {
			t.Fatal("exact initialization resume attempted a private or mutation capability")
		}
	}
	clear(competitors[loser].Result.Body)
	return competitors[winner].Result, competitors[winner].Path
}
