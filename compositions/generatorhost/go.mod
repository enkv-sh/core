module enkv.sh/compositions/generatorhost

go 1.27.0

require (
	enkv.sh/core v0.1.0
	enkv.sh/sdk/artifact v0.1.0
	enkv.sh/sdk/generator v0.1.0
	enkv.sh/sdk/protocols/generator v0.1.0
	enkv.sh/telemetry v0.1.0
	go.opentelemetry.io/otel v1.36.0
	go.opentelemetry.io/otel/trace v1.36.0
	golang.org/x/sys v0.33.0
)

require (
	enkv.sh/sdk/manifest-generator v0.1.0 // indirect
	enkv.sh/sdk/protocols/output v0.1.0 // indirect
)
