// Package httptransport owns the shared private request lifetime mechanics.
package httptransport

import (
	"context"

	"enkv.sh/telemetry"
)

// privateLifetimeContext retains deadlines and cancellation without caller values.
type privateLifetimeContext struct{ context.Context }

func (privateLifetimeContext) Value(any) any { return nil }

// PrivateContext retains private telemetry while removing caller callbacks.
func PrivateContext(ctx context.Context) context.Context {
	return telemetry.PrivateContext(privateLifetimeContext{ctx}, ctx)
}
