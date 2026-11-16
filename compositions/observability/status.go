package observability

import "sync/atomic"

// DeliveryStatus counts records for logs, collection batches for metrics, and
// spans for traces. A failed destination does not make another destination
// incomplete or change Product work.
type DeliveryStatus struct {
	Accepted   uint64 `json:"accepted"`
	Written    uint64 `json:"written"`
	Dropped    uint64 `json:"dropped"`
	Failed     uint64 `json:"failed"`
	Incomplete bool   `json:"incomplete"`
}

type deliveryCounter struct {
	accepted   atomic.Uint64
	written    atomic.Uint64
	dropped    atomic.Uint64
	failed     atomic.Uint64
	incomplete atomic.Bool
	settled    atomic.Bool // The route has positively joined its worker and file cleanup.
}

func (counter *deliveryCounter) fail() {
	counter.failed.Add(1)
	counter.incomplete.Store(true)
}

func (counter *deliveryCounter) snapshot() DeliveryStatus {
	if counter == nil {
		return DeliveryStatus{}
	}
	return DeliveryStatus{Accepted: counter.accepted.Load(), Written: counter.written.Load(), Dropped: counter.dropped.Load(), Failed: counter.failed.Load(), Incomplete: counter.incomplete.Load()}
}
