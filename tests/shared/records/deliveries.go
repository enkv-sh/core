package records

import "enkv.sh/compositions/observability"

type DeliveryStatus struct {
	Accepted   *uint64 `json:"accepted"`
	Written    *uint64 `json:"written"`
	Dropped    *uint64 `json:"dropped"`
	Failed     *uint64 `json:"failed"`
	Incomplete *bool   `json:"incomplete"`
}

func (status DeliveryStatus) EvidenceIncomplete() bool {
	return status.Accepted == nil || status.Written == nil || status.Dropped == nil || status.Failed == nil || status.Incomplete == nil || *status.Incomplete
}

func (status DeliveryStatus) clone() DeliveryStatus {
	copy := status
	if status.Accepted != nil {
		value := *status.Accepted
		copy.Accepted = &value
	}
	if status.Written != nil {
		value := *status.Written
		copy.Written = &value
	}
	if status.Dropped != nil {
		value := *status.Dropped
		copy.Dropped = &value
	}
	if status.Failed != nil {
		value := *status.Failed
		copy.Failed = &value
	}
	if status.Incomplete != nil {
		value := *status.Incomplete
		copy.Incomplete = &value
	}
	return copy
}

// InspectDeliveryStatuses admits only destinations selected by the resolved
// worker settings. Missing worker claims remain explicitly incomplete.
func InspectDeliveryStatuses(inv Invocation, claims map[string]DeliveryStatus) map[string]DeliveryStatus {
	settings := inv.TelemetrySettings
	if settings == nil {
		defaults, err := observability.Resolve(observability.Config{}, observability.Options{})
		if err != nil {
			return nil
		}
		settings = &defaults
	}
	type selectedDelivery struct {
		raw, public string
	}
	selected := []selectedDelivery{}
	selectExporters := func(signal string, names []string) {
		for _, name := range names {
			var destination string
			switch settings.ActiveExporters[name].Type {
			case "otlp_file":
				destination = "file"
			case "otlp_http":
				destination = "http"
			default:
				continue
			}
			selected = append(selected, selectedDelivery{signal + "." + name, signal + "." + destination})
		}
	}
	if settings.LogLevel != observability.Off {
		if settings.Console {
			selected = append(selected, selectedDelivery{"logs.console", "logs.console"})
		}
		selectExporters("logs", settings.LogExporters)
	}
	selectExporters("metrics", settings.MetricExporters)
	selectExporters("traces", settings.TraceExporters)
	result := make(map[string]DeliveryStatus, len(selected))
	for _, destination := range selected {
		result[destination.public] = claims[destination.raw].clone()
	}
	return result
}
