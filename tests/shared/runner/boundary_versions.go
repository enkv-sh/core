package main

func reviewedLocalModuleVersion(path string) string {
	switch path {
	case nativeProcessPath, "enkv.sh/sdk/protocols/output", testServicePath:
		return "v0.1.0"
	case "enkv.sh/sdk/artifact", generatorSDKPath, cloudflareProtocolPath,
		outputSDKPath, manifestSDKPath, "enkv.sh/sdk/protocols/manifest-generator",
		"enkv.sh/telemetry":
		return "v0.1.1"
	default:
		return ""
	}
}
