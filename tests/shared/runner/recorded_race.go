package main

import (
	"bytes"
	"encoding/json"
)

func raceObservationMatches(observed *bool, options string, expected bool) bool {
	if observed == nil {
		return expected && options == raceOptions
	}
	return *observed == expected && validRaceOptions(expected, options)
}

func decodeRecordedRace(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}

func (value *assemblyClosure) UnmarshalJSON(body []byte) error {
	type fields assemblyClosure
	var wire struct {
		*fields
		Race *bool `json:"race"`
	}
	wire.fields = (*fields)(value)
	if err := decodeRecordedRace(body, &wire); err != nil {
		return err
	}
	value.raceMissing = wire.Race == nil
	if wire.Race != nil {
		value.Race = *wire.Race
	}
	return nil
}

func (value *checkEvidence) UnmarshalJSON(body []byte) error {
	type fields checkEvidence
	var wire struct {
		*fields
		Race *bool `json:"race"`
	}
	wire.fields = (*fields)(value)
	if err := decodeRecordedRace(body, &wire); err != nil {
		return err
	}
	value.raceMissing = wire.Race == nil
	if wire.Race != nil {
		value.Race = *wire.Race
	}
	return nil
}

func (value *resolvedRequest) UnmarshalJSON(body []byte) error {
	type fields resolvedRequest
	var wire struct {
		*fields
		Race *bool `json:"scenario_race"`
	}
	wire.fields = (*fields)(value)
	if err := decodeRecordedRace(body, &wire); err != nil {
		return err
	}
	value.raceMissing = wire.Race == nil
	if wire.Race != nil {
		value.Race = *wire.Race
	}
	return nil
}

func recordedRunRace(value runRecord) (bool, bool) {
	build := value.BuildClosure
	if build == nil || build.raceMissing || !validRaceSettings(build.Race, build.RaceOptions, build.RaceExitSleepMillis) ||
		value.Resolved == nil || value.Resolved.raceMissing || value.Resolved.Race != build.Race {
		return false, false
	}
	return build.Race, true
}
