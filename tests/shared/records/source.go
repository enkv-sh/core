package records

type Source struct {
	ObservationIncomplete bool     `json:"observation_incomplete,omitempty"`
	Algorithm             string   `json:"source_algorithm,omitempty"`
	Tree                  string   `json:"tree,omitempty"`
	PublicRepository      string   `json:"public_repository,omitempty"`
	PublicRevision        string   `json:"public_revision,omitempty"`
	PublicTree            string   `json:"public_tree,omitempty"`
	PublicPaths           []string `json:"public_paths,omitempty"`
	Revision              string   `json:"revision"`
	Dirty                 bool     `json:"dirty"`
	DirtyDiffSHA256       *string  `json:"dirty_diff_sha256"`
	PublicSourcesSHA256   string   `json:"public_sources_sha256,omitempty"`
}
