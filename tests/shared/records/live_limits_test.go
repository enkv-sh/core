package records

import (
	"encoding/json"
	"testing"
)

// full_only: false
func TestLiveLimitsWireKeepsExistingFields(t *testing.T) {
	value := LiveLimits{Requests: 1, BodyBytes: 2, Objects: 3, ObjectBytes: 4, GeneratorCreates: 5, GeneratorRetires: 6, ElapsedSeconds: 7, CleanupRequests: 8, CleanupBytes: 9, CleanupSeconds: 10}
	// Distinct numbers identify the ten run and cleanup fields in declaration order.
	const expected = `{"requests":1,"body_bytes":2,"objects":3,"object_bytes":4,"generator_creates":5,"generator_retires":6,"elapsed_seconds":7,"cleanup_requests":8,"cleanup_bytes":9,"cleanup_seconds":10}`
	body, err := json.Marshal(value)
	if err != nil || string(body) != expected {
		t.Fatal("shared limits changed wire representation", string(body), err)
	}
	var decoded LiveLimits
	if err := json.Unmarshal([]byte(expected), &decoded); err != nil || decoded != value {
		t.Fatal("shared limits changed field values", err)
	}
}
