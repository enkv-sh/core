package core

import (
	"testing"
	"time"
)

// Capacity phases are disjoint. Switching to a fresh child ends the current
// operation interval; later operation intervals can be added without overlap.
type capacityTimer struct {
	t       *testing.T
	phase   string
	started time.Time
}

func startCapacityTimer(t *testing.T) *capacityTimer {
	t.Helper()
	return &capacityTimer{t: t, phase: "fixture", started: time.Now()}
}

func (c *capacityTimer) next(phase string) {
	c.t.Helper()
	c.finish()
	c.phase, c.started = phase, time.Now()
}

func (c *capacityTimer) finish() {
	c.t.Helper()
	if c.phase == "" {
		return
	}
	c.t.Logf("capacity-timing test=%s phase=%s elapsed=%s", c.t.Name(), c.phase, time.Since(c.started))
	c.phase = ""
}
