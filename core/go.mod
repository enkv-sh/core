module enkv.sh/core

go 1.27.0

require (
	enkv.sh/sdk/protocols/generator v0.1.0
 enkv.sh/sdk/protocols/output v0.1.0
	enkv.sh/sdk/artifact v0.1.0
	enkv.sh/plugins/manifest-generators/generic-json v0.1.0
	enkv.sh/plugins/manifest-generators/opentofu-tfvars-json v0.1.0
	enkv.sh/sdk/manifest-generator v0.1.0
	enkv.sh/telemetry v0.1.0
	go.opentelemetry.io/otel v1.36.0
	go.opentelemetry.io/otel/metric v1.36.0
	go.opentelemetry.io/otel/sdk v1.36.0
	go.opentelemetry.io/otel/sdk/metric v1.36.0
)

require (
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel/trace v1.36.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
)
