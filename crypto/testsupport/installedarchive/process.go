package installedarchive

import (
	"bufio"
	"bytes"
	"errors"
	"regexp"
	"strings"
)

// ChildOutput retains bounded ordinary test terminals from a joined child.
// It provides no process launch or supervision policy.
type ChildOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (o *ChildOutput) Write(body []byte) (int, error) {
	n := len(body)
	remaining := (32 << 20) - o.buffer.Len()
	if n > remaining {
		body = body[:remaining]
		o.overflow = true
	}
	_, _ = o.buffer.Write(body)
	return n, nil
}

func (o *ChildOutput) Bytes() []byte { return bytes.Clone(o.buffer.Bytes()) }

// Completed requires exactly one named test and its final process PASS.
func (o *ChildOutput) Completed(name string) error {
	return o.completion(name, false)
}

// FailedPrefix validates available test directives after a supervised failure.
// Missing terminals grant no success and require the caller's settled process.
func (o *ChildOutput) FailedPrefix(name string) error {
	return o.completion(name, true)
}

func (o *ChildOutput) completion(name string, failedPrefix bool) error {
	if o.overflow || !regexp.MustCompile(`^Test[A-Za-z0-9_]+$`).MatchString(name) ||
		o.buffer.Len() == 0 && !failedPrefix || o.buffer.Len() != 0 && o.buffer.Bytes()[o.buffer.Len()-1] != '\n' {
		return errors.New("child output is incomplete or exceeds its bound")
	}
	positive := regexp.MustCompile(`^--- PASS: (.+) \([0-9]+\.[0-9]+s\)$`)
	negative := regexp.MustCompile(`^--- FAIL: (.+) \([0-9]+\.[0-9]+s\)$`)
	state := 0
	clearedName := false
	started := make(map[string]bool)
	passed := make(map[string]bool)
	failed := make(map[string]bool)
	parallel := make(map[string]uint8)
	scanner := bufio.NewScanner(bytes.NewReader(o.buffer.Bytes()))
	scanner.Buffer(make([]byte, 4096), 32<<20)
	for scanner.Scan() {
		line := scanner.Text()
		// -test.v=test2json marks Go test directives. T.Log escapes this
		// marker, so a retained child transcript cannot complete its parent.
		if !strings.HasPrefix(line, "\x16") {
			continue
		}
		line = strings.TrimPrefix(line, "\x16")
		switch {
		case strings.HasPrefix(line, "=== RUN   "):
			child := strings.TrimPrefix(line, "=== RUN   ")
			if started[child] || child != name && (!strings.HasPrefix(child, name+"/") || len(child) == len(name)+1) || state > 1 {
				return errors.New("child start is missing, duplicated or incorrect")
			}
			if child == name {
				if state != 0 {
					return errors.New("child start is out of order")
				}
				state = 1
			} else if state != 1 {
				return errors.New("subtest start has no helper")
			}
			started[child] = true
		case positive.MatchString(line):
			child := positive.FindStringSubmatch(line)[1]
			if state != 1 || !started[child] || passed[child] || parallel[child] == 1 {
				return errors.New("child pass is out of order")
			}
			if failedPrefix {
				for descendant := range started {
					if strings.HasPrefix(descendant, child+"/") && (!passed[descendant] || failed[descendant]) {
						return errors.New("passing child contradicts a descendant")
					}
				}
			}
			passed[child] = true
			if child == name {
				if len(started) != len(passed) {
					return errors.New("helper passed before its descendants")
				}
				state = 2
			}
		case failedPrefix && negative.MatchString(line):
			child := negative.FindStringSubmatch(line)[1]
			if state != 1 || !started[child] || passed[child] || parallel[child] == 1 {
				return errors.New("child failure is out of order")
			}
			for descendant := range started {
				if strings.HasPrefix(descendant, child+"/") && !passed[descendant] {
					return errors.New("failed child finished before its descendants")
				}
			}
			passed[child], failed[child] = true, true
			if child == name {
				state = 2
			}
		case failedPrefix && line == "FAIL":
			if state == 3 {
				return errors.New("duplicate child final completion")
			}
			state = 3
		case strings.HasPrefix(line, "--- PASS:"), strings.HasPrefix(line, "--- SKIP:"), strings.HasPrefix(line, "--- FAIL:"), line == "FAIL":
			return errors.New("child terminal is incorrect")
		case line == "PASS":
			if state != 2 || len(started) != len(passed) || len(failed) != 0 {
				return errors.New("child final completion is out of order")
			}
			state = 3
		case strings.HasPrefix(line, "=== NAME  "), strings.HasPrefix(line, "=== PAUSE "), strings.HasPrefix(line, "=== CONT  "):
			child := line[10:]
			if line == "=== NAME  " {
				if state != 2 || clearedName {
					return errors.New("package name reset is out of order")
				}
				clearedName = true
				continue
			}
			if state != 1 || !started[child] || passed[child] {
				return errors.New("child event has no active test")
			}
			if strings.HasPrefix(line, "=== PAUSE ") {
				if parallel[child] != 0 {
					return errors.New("child pause is out of order")
				}
				parallel[child] = 1
			} else if strings.HasPrefix(line, "=== CONT  ") {
				if parallel[child] != 1 {
					return errors.New("child continuation is out of order")
				}
				parallel[child] = 2
			}
		}
	}
	if scanner.Err() != nil || !failedPrefix && state != 3 {
		return errors.New("child completion evidence is missing")
	}
	return nil
}
