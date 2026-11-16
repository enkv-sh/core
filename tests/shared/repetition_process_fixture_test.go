package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var componentRepetitionWitnessEntered int

type componentRepetitionWitnessObservation struct {
	PID          int    `json:"pid"`
	InitialState int    `json:"initial_state"`
	Binary       string `json:"binary"`
	BinarySHA256 string `json:"binary_sha256"`
	Fixture      string `json:"fixture"`
	ChildEntered bool   `json:"child_entered"`
	ParentSuffix bool   `json:"parent_suffix"`
}

// full_only: false
func TestFiniteRepetitionProcessWitness(t *testing.T) {
	componentRepetitionWitnessEntered++
	if componentRepetitionWitnessEntered != 1 {
		t.Fatal("component mutable process state was reused")
	}
	path := os.Getenv("ENKV_COMPONENT_REPETITION_WITNESS")
	priorCount := 0
	if path != "" {
		prior, err := os.ReadFile(path)
		if err == nil {
			if len(prior) == 0 || prior[len(prior)-1] != '\n' {
				t.Fatal("incomplete component witness row")
			}
			for _, line := range bytes.Split(prior, []byte{'\n'}) {
				if len(line) == 0 {
					continue
				}
				priorCount++
				var row componentRepetitionWitnessObservation
				if err := json.Unmarshal(line, &row); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(row.Fixture); !os.IsNotExist(err) {
					t.Fatal("prior component fixture survived into next execution", err)
				}
			}
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	fixture := t.TempDir()
	marker := filepath.Join(fixture, "mutable")
	if err := os.WriteFile(marker, []byte("new component fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	reached := false
	t.Run("leaf[a]+b", func(t *testing.T) {
		reached = true
		body, err := os.ReadFile(marker)
		if err != nil || string(body) != "new component fixture" {
			t.Fatal("component fixture self-check failed", err)
		}
		if priorCount == 1 {
			switch os.Getenv("ENKV_COMPONENT_REPETITION_SECOND_FAILURE") {
			case "assertion":
				t.Error("controlled joined component execution two assertion")
			case "race":
				// Both writes follow release, without an order between them.
				// Joining only after both accesses keeps the actual race visible.
				value := 0
				release, joined := make(chan struct{}), make(chan struct{})
				go func() { <-release; value++; close(joined) }()
				close(release)
				value++
				<-joined
				_ = value
			}
		}
	})
	if !reached {
		t.Fatal("literal component child did not run")
	}
	if path == "" {
		// Normal component qualification still runs the fixture self-check.
		return
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	row := componentRepetitionWitnessObservation{
		PID: os.Getpid(), InitialState: componentRepetitionWitnessEntered,
		Binary: binary, BinarySHA256: fmt.Sprintf("%x", sha256.Sum256(body)),
		Fixture: fixture, ChildEntered: reached, ParentSuffix: true,
	}
	output, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	writeErr := json.NewEncoder(output).Encode(row)
	closeErr := output.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
}
