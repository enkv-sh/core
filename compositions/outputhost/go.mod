module enkv.sh/compositions/outputhost

go 1.27.0

require (
	enkv.sh/compositions/internal/nativeprocess v0.1.0
	enkv.sh/sdk/artifact v0.1.1
	enkv.sh/sdk/protocols/output v0.1.0
	enkv.sh/telemetry v0.1.1
	golang.org/x/sys v0.33.0
)

require (
	go.opentelemetry.io/otel v1.36.0 // indirect
	go.opentelemetry.io/otel/trace v1.36.0 // indirect
)
