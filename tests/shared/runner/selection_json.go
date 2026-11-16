package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

func readSelectionFile(path string, destination any) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return err
	}
	var body json.RawMessage
	if records.ReadJSON(absolute, &body) != nil || uniqueJSONKeys(json.NewDecoder(bytes.NewReader(body))) != nil {
		return errors.New("selection file refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("selection file fields refused")
	}
	return nil
}

func uniqueJSONKeys(decoder *json.Decoder) error {
	return canonicalJSONKeys(decoder, "", nil)
}

// Selection and authority schemas refuse null. Stored results have nullable
// fields; their owner supplies that policy without changing key validation.
func canonicalJSONKeys(decoder *json.Decoder, path string, nullable func(string) bool) error {
	return checkedJSONKeys(decoder, path, nullable, nil)
}

// The key policy applies to the containing object. A nil policy requires
// lowercase schema keys everywhere; stored results can carry opaque payloads.
func checkedJSONKeys(decoder *json.Decoder, path string, nullable, canonical func(string) bool) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		if nullable != nil && nullable(path) {
			return nil
		}
		return errors.New("null JSON field refused")
	}
	delimiter, nested := token.(json.Delim)
	if !nested {
		return nil
	}
	seen := map[string]bool{}
	for decoder.More() {
		child := path + "[]"
		if delimiter == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] || (canonical == nil || canonical(path)) && strings.ToLower(name) != name {
				return errors.New("duplicate or noncanonical JSON field")
			}
			seen[name] = true
			child = name
			if path != "" {
				child = path + "." + name
			}
		}
		if err := checkedJSONKeys(decoder, child, nullable, canonical); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
