package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	records "enkv.sh/core/internal/testrecords"
)

// The removed monetary field is retained only to reproduce historical bytes
// and identity hashes. It never contributes to an operation allowance.
type recordedCleanupLimits struct {
	records.LiveLimits
	CostAllowanceUSD *float64 `json:"cost_allowance_usd,omitempty"`
}

func cleanupRecordLimits(body []byte) ([]byte, *recordedCleanupLimits, error) {
	refused := errors.New("retained cleanup limits unavailable or inconsistent")
	var envelope struct {
		Limits json.RawMessage `json:"limits"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return nil, nil, refused
	}
	if len(envelope.Limits) == 0 || bytes.Equal(envelope.Limits, []byte("null")) {
		return body, nil, nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(envelope.Limits, &fields) != nil {
		return nil, nil, refused
	}
	if _, historical := fields["cost_allowance_usd"]; !historical {
		return body, nil, nil
	}
	var value recordedCleanupLimits
	decoder := json.NewDecoder(bytes.NewReader(envelope.Limits))
	decoder.DisallowUnknownFields()
	if uniqueJSONKeys(json.NewDecoder(bytes.NewReader(envelope.Limits))) != nil ||
		decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF ||
		value.CostAllowanceUSD == nil || *value.CostAllowanceUSD <= 0 || !limits(value.LiveLimits).valid() {
		return nil, nil, refused
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, envelope.Limits) {
		return nil, nil, refused
	}
	current, err := json.Marshal(value.LiveLimits)
	if err != nil {
		return nil, nil, refused
	}
	from := append([]byte(`"limits":`), envelope.Limits...)
	to := append([]byte(`"limits":`), current...)
	if bytes.Count(body, from) != 1 {
		return nil, nil, refused
	}
	return bytes.Replace(body, from, to, 1), &value, nil
}

func restoreCleanupLimits(body []byte, current *limits, historical *recordedCleanupLimits) ([]byte, error) {
	if historical == nil {
		return body, nil
	}
	if current == nil || limits(historical.LiveLimits) != *current || historical.CostAllowanceUSD == nil || *historical.CostAllowanceUSD <= 0 {
		return nil, errors.New("retained cleanup limits changed")
	}
	currentBody, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	historicalBody, err := json.Marshal(historical)
	if err != nil {
		return nil, err
	}
	from := append([]byte(`"limits":`), currentBody...)
	to := append([]byte(`"limits":`), historicalBody...)
	if bytes.Count(body, from) != 1 {
		return nil, errors.New("retained cleanup limits unavailable")
	}
	return bytes.Replace(body, from, to, 1), nil
}

func decodeCleanupRecord(body []byte, value any) error {
	refused := errors.New("retained cleanup record unavailable or inconsistent")
	decoded := body
	var historical *recordedCleanupLimits
	switch value.(type) {
	case *runRecord, *workerInput:
		var err error
		decoded, historical, err = cleanupRecordLimits(body)
		if err != nil {
			return refused
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return refused
	}
	if recorded, ok := value.(*runRecord); ok {
		recorded.historicalLimits = historical
	}
	canonical, err := json.Marshal(value)
	if input, ok := value.(*workerInput); ok && err == nil {
		canonical, err = restoreCleanupLimits(canonical, input.Limits, historical)
	}
	if err != nil || !bytes.Equal(body, append(canonical, '\n')) {
		return refused
	}
	return nil
}
