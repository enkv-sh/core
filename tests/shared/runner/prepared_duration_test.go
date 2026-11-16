package main

import (
	"context"
	"testing"
	"time"
)

// full_only: false
func TestPreparedComponentLifetimeDoesNotStartDurationAtConstruction(t *testing.T) {
	for _, row := range []struct {
		name        string
		parentLimit time.Duration
	}{{"unbounded-parent", 0}, {"longer-parent", 2 * componentCheckTimeout}, {"earlier-parent", time.Second}} {
		t.Run(row.name, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
			defer cancel()
			if row.parentLimit != 0 {
				bounded, stop := context.WithTimeout(parent, row.parentLimit)
				defer stop()
				parent = bounded
			}
			// This reaches only the concrete retained lifetime constructor.
			// It does not prepare an artifact or witness a ready queue/body.
			group := newPreparedComponentGroup(parent)
			defer group.cancel()
			want, wantBound := parent.Deadline()
			got, gotBound := group.ctx.Deadline()
			if gotBound != wantBound || gotBound && !got.Equal(want) {
				t.Error("construction started a local work clock before dispatch", got, gotBound, want, wantBound)
			}
			cancel()
			select {
			case <-group.ctx.Done():
			default:
				t.Error("retained lifetime lost parent cancellation")
			}
		})
	}
}
