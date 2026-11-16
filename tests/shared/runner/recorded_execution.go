package main

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Recorded capacity is retained provenance, never authority for a new run.
// The private spelling bit preserves historical recovery bytes and hashes.
type recordedExecutionPolicy struct {
	Requested   executionRequest
	Resolved    executionCapacity
	legacyLanes bool
}

type recordedLanesExecutionPolicy struct {
	Requested struct {
		Lanes          *int `json:"lanes,omitempty"`
		MemoryLimitMiB *int `json:"memory_limit_mib,omitempty"`
	} `json:"requested"`
	Resolved struct {
		Lanes          int `json:"lanes"`
		MemoryLimitMiB int `json:"memory_limit_mib"`
	} `json:"resolved"`
}

func recordExecutionPolicy(policy executionPolicy) recordedExecutionPolicy {
	return recordedExecutionPolicy{Requested: policy.Requested.clone(), Resolved: policy.Resolved}
}

func (policy recordedExecutionPolicy) clone() recordedExecutionPolicy {
	policy.Requested = policy.Requested.clone()
	return policy
}

func (policy recordedExecutionPolicy) MarshalJSON() ([]byte, error) {
	if !policy.legacyLanes {
		return json.Marshal(executionPolicy{Requested: policy.Requested, Resolved: policy.Resolved})
	}
	var wire recordedLanesExecutionPolicy
	wire.Requested.Lanes = policy.Requested.Parallel
	wire.Requested.MemoryLimitMiB = policy.Requested.MemoryLimitMiB
	wire.Resolved.Lanes = policy.Resolved.Parallel
	wire.Resolved.MemoryLimitMiB = policy.Resolved.MemoryLimitMiB
	return json.Marshal(wire)
}

func (policy *recordedExecutionPolicy) UnmarshalJSON(body []byte) error {
	refused := errors.New("recorded execution policy fields refused")
	if uniqueJSONKeys(json.NewDecoder(bytes.NewReader(body))) != nil {
		return refused
	}
	var fields struct {
		Resolved map[string]json.RawMessage `json:"resolved"`
	}
	if json.Unmarshal(body, &fields) != nil {
		return refused
	}
	_, lanes := fields.Resolved["lanes"]
	_, parallel := fields.Resolved["parallel"]
	if lanes == parallel {
		return refused
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var current executionPolicy
	if lanes {
		var wire recordedLanesExecutionPolicy
		if decoder.Decode(&wire) != nil {
			return refused
		}
		current.Requested = executionRequest{Parallel: wire.Requested.Lanes, MemoryLimitMiB: wire.Requested.MemoryLimitMiB}
		current.Resolved = executionCapacity{Parallel: wire.Resolved.Lanes, MemoryLimitMiB: wire.Resolved.MemoryLimitMiB}
	} else if decoder.Decode(&current) != nil {
		return refused
	}
	// Historical values are observations. Resolving them against current
	// defaults would change old facts without granting current capacity.
	*policy = recordExecutionPolicy(current)
	policy.legacyLanes = lanes
	return nil
}
