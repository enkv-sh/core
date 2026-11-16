package compositionfull

func configurationCanonicalBacking(generated map[string]any, family, name string, body []byte) {
	records, ok := generated["canonical_records"].(map[string]any)
	if !ok {
		records = map[string]any{"generators": map[string]any{}, "outputs": map[string]any{}}
		generated["canonical_records"] = records
	}
	records[family].(map[string]any)[name] = body
}
