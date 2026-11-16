package records

// LiveLimits is the passive shared representation. The selected runner and
// worker retain their existing validity, reservation and effect policies.
type LiveLimits struct {
	Requests         uint64 `json:"requests"`
	BodyBytes        uint64 `json:"body_bytes"`
	Objects          uint64 `json:"objects"`
	ObjectBytes      uint64 `json:"object_bytes"`
	GeneratorCreates uint64 `json:"generator_creates"`
	GeneratorRetires uint64 `json:"generator_retires"`
	ElapsedSeconds   uint64 `json:"elapsed_seconds"`
	CleanupRequests  uint64 `json:"cleanup_requests"`
	CleanupBytes     uint64 `json:"cleanup_bytes"`
	CleanupSeconds   uint64 `json:"cleanup_seconds"`
}
