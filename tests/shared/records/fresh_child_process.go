package records

import "os/exec"

// FreshChildProcess records the writer's own Start/Wait observation. Its join
// does not replace settlement of the enclosing writer process group.
type FreshChildProcess struct {
	Started bool   `json:"started"`
	Joined  bool   `json:"joined"`
	Outcome string `json:"outcome"`
}

// ObserveFreshChildProcess inspects a synchronous Run or CombinedOutput after
// it returns. A missing ProcessState cannot establish a successful wait.
func ObserveFreshChildProcess(command *exec.Cmd, runErr error) FreshChildProcess {
	if command == nil {
		return FreshChildProcess{Outcome: "unknown"}
	}
	if command.Process == nil {
		return FreshChildProcess{Joined: true, Outcome: "not_started"}
	}
	fact := FreshChildProcess{Started: true, Outcome: "unknown"}
	if command.ProcessState == nil {
		return fact
	}
	fact.Joined, fact.Outcome = true, "process_failed"
	if runErr == nil && command.ProcessState.Success() {
		fact.Outcome = "passed"
	}
	return fact
}

func (p FreshChildProcess) Validate() error {
	switch p.Outcome {
	case "passed", "process_failed":
		if p.Started && p.Joined {
			return nil
		}
	case "not_started":
		if !p.Started && p.Joined {
			return nil
		}
	case "unknown":
		if !p.Joined {
			return nil
		}
	}
	return errRecord
}
