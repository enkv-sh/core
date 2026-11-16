package installedarchive

import "testing"

// full_only: false
func TestNamedChildCompletionRequiresExactEvidence(t *testing.T) {
	const name = "TestRestrictedReconstructionChild"
	const start = "\x16=== RUN   " + name + "\n"
	const pass = "\x16--- PASS: " + name + " (0.00s)\n"
	const final = "\x16PASS\n"
	const subStart = "\x16=== RUN   " + name + "/enabled/deep\n"
	const subPass = "\x16--- PASS: " + name + "/enabled/deep (0.00s)\n"
	for _, tc := range []struct {
		name, body string
		accepted   bool
	}{
		{"complete", start + pass + final, true},
		{"package_name_reset", start + pass + "\x16=== NAME  \n" + final, true},
		{"early_name_reset", start + "\x16=== NAME  \n" + pass + final, false},
		{"duplicate_name_reset", start + pass + "\x16=== NAME  \n\x16=== NAME  \n" + final, false},
		{"unknown_name", start + "\x16=== NAME  TestOtherChild\n" + pass + final, false},
		{"slash_name", start + subStart + subPass + pass + final, true},
		{"nested", start + "\x16=== RUN   " + name + "/enabled\n" + subStart + subPass + "\x16--- PASS: " + name + "/enabled (0.00s)\n" + pass + final, true},
		{"missing_start", pass + final, false},
		{"missing_pass", start + final, false},
		{"missing_final", start + pass, false},
		{"duplicate_start", start + start + pass + final, false},
		{"duplicate_pass", start + pass + pass + final, false},
		{"duplicate_final", start + pass + final + final, false},
		{"wrong_name", "\x16=== RUN   TestOtherChild\n\x16--- PASS: TestOtherChild (0.00s)\n" + final, false},
		{"extra_test", start + "\x16=== RUN   TestOtherChild\n" + pass + final, false},
		{"skip", start + "\x16--- SKIP: " + name + " (0.00s)\n" + pass + final, false},
		{"fail", start + "\x16--- FAIL: " + name + " (0.00s)\n" + pass + final, false},
		{"unframed", "=== RUN   " + name + "\n--- PASS: " + name + " (0.00s)\nPASS\n", false},
		{"truncated", start + pass + "\x16PASS", false},
		{"missing_subtest_pass", start + subStart + pass + final, false},
		{"duplicate_subtest_start", start + subStart + subStart + subPass + pass + final, false},
		{"duplicate_subtest_pass", start + subStart + subPass + subPass + pass + final, false},
		{"subtest_without_start", start + subPass + pass + final, false},
		{"failed_subtest", start + subStart + "\x16--- FAIL: " + name + "/enabled/deep (0.00s)\n" + pass + final, false},
		{"skipped_subtest", start + subStart + "\x16--- SKIP: " + name + "/enabled/deep (0.00s)\n" + pass + final, false},
		{"helper_before_descendant", start + subStart + pass + subPass + final, false},
		{"echo_cannot_complete_root", start + "    parent.go:1: child transcript\n        \x1b\x16--- PASS: " + name + " (0.00s)\n" + final, false},
		{"echo_cannot_complete_subtest", start + subStart + "    parent.go:1: child transcript\n        \x1b\x16--- PASS: " + name + "/enabled/deep (0.00s)\n" + pass + final, false},
		{"logged_child_transcript", start + "    parent.go:1: child transcript\n        \x1b\x16=== RUN   " + name + "\n        \x1b\x16--- PASS: " + name + " (0.00s)\n        \x1b\x16PASS\n" + pass + final, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output ChildOutput
			if _, err := output.Write([]byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			if err := output.Completed(name); (err == nil) != tc.accepted {
				t.Fatal("completion acceptance", err)
			}
		})
	}
	var output ChildOutput
	if _, err := output.Write(make([]byte, (32<<20)+1)); err != nil {
		t.Fatal(err)
	}
	if output.Completed(name) == nil || output.FailedPrefix(name) == nil {
		t.Fatal("overflow accepted")
	}
}

// full_only: false
func TestNamedChildCompletionRejectsInvalidLifecycle(t *testing.T) {
	const name = "TestRestrictedReconstructionChild"
	const start = "\x16=== RUN   " + name + "\n"
	const pass = "\x16--- PASS: " + name + " (0.00s)\n"
	const final = "\x16PASS\n"
	const subStart = "\x16=== RUN   " + name + "/label/with/slash\n"
	const subPass = "\x16--- PASS: " + name + "/label/with/slash (0.00s)\n"
	const pause = "\x16=== PAUSE " + name + "\n"
	const resume = "\x16=== CONT  " + name + "\n"
	for _, row := range []struct {
		name, body string
		accepted   bool
	}{
		{"pause_resume", start + pause + resume + pass + final, true},
		{"active_name", start + "\x16=== NAME  " + name + "\n" + pass + final, true},
		{"slash_pause_resume", start + subStart + "\x16=== PAUSE " + name + "/label/with/slash\n\x16=== CONT  " + name + "/label/with/slash\n" + subPass + pass + "\x16=== NAME  \n" + final, true},
		{"resume_without_pause", start + resume + pass + final, false},
		{"duplicate_pause", start + pause + pause + resume + pass + final, false},
		{"duplicate_resume", start + pause + resume + resume + pass + final, false},
		{"second_pause", start + pause + resume + pause + resume + pass + final, false},
		{"pass_while_paused", start + pause + pass + final, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			var output ChildOutput
			_, _ = output.Write([]byte(row.body))
			if err := output.Completed(name); (err == nil) != row.accepted {
				t.Fatal("named lifecycle acceptance differs")
			}
		})
	}
	for _, event := range []string{"NAME  ", "PAUSE ", "CONT  "} {
		for _, place := range []string{"after-helper", "after-final", "after-subtest"} {
			t.Run(event+place, func(t *testing.T) {
				body := start + pass + "\x16=== " + event + name + "\n" + final
				switch place {
				case "after-final":
					body = start + pass + final + "\x16=== " + event + name + "\n"
				case "after-subtest":
					body = start + subStart + subPass + "\x16=== " + event + name + "/label/with/slash\n" + pass + final
				}
				var output ChildOutput
				_, _ = output.Write([]byte(body))
				if output.Completed(name) == nil {
					t.Fatal("completed named test accepted another lifecycle event")
				}
			})
		}
	}
}

// full_only: false
func TestNamedChildFailurePrefixRejectsInvalidEvidence(t *testing.T) {
	const name = "TestRestrictedReconstructionChild"
	const start = "\x16=== RUN   " + name + "\n"
	const fail = "\x16--- FAIL: " + name + " (0.00s)\n"
	const subStart = "\x16=== RUN   " + name + "/leaf\n"
	const subFail = "\x16--- FAIL: " + name + "/leaf (0.00s)\n"
	const pass = "\x16--- PASS: " + name + " (0.00s)\n"
	for _, row := range []struct {
		name, body string
		accepted   bool
	}{
		{"empty_crash", "", true},
		{"active_test_crash", start, true},
		{"failed_test", start + fail + "\x16FAIL\n", true},
		{"failed_subtest", start + subStart + subFail + fail + "\x16FAIL\n", true},
		{"passing_test", start + pass + "\x16PASS\n", true},
		{"wrong_root", "\x16=== RUN   TestOther\n", false},
		{"duplicate_run", start + start, false},
		{"malformed_failure", start + "\x16--- FAIL: " + name + "\n", false},
		{"passing_parent_failed_child", start + subStart + subFail + pass, false},
		{"passing_parent_unfinished_child", start + subStart + pass, false},
		{"duplicate_final", start + fail + "\x16FAIL\n\x16FAIL\n", false},
		{"truncated_frame", start + "\x16--- FAIL: ", false},
		{"unexplained_skip", start + "\x16--- SKIP: " + name + " (0.00s)\n", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			var output ChildOutput
			_, _ = output.Write([]byte(row.body))
			if err := output.FailedPrefix(name); (err == nil) != row.accepted {
				t.Fatal("failed-prefix acceptance differs", err)
			}
		})
	}
}
