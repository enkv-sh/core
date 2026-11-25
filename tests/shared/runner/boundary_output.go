package main

import (
	"errors"
	"slices"
	"strings"
)

// These are the complete reviewed resolved graphs, including uncompiled requirements.
var awsOutputPins = map[string]string{
	"github.com/aws/aws-sdk-go-v2":                                  "v1.39.0",
	"github.com/aws/aws-sdk-go-v2/config":                           "v1.31.7",
	"github.com/aws/aws-sdk-go-v2/credentials":                      "v1.18.11",
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds":                 "v1.18.7",
	"github.com/aws/aws-sdk-go-v2/internal/configsources":           "v1.4.7",
	"github.com/aws/aws-sdk-go-v2/internal/endpoints/v2":            "v2.7.7",
	"github.com/aws/aws-sdk-go-v2/internal/ini":                     "v1.8.3",
	"github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding": "v1.13.1",
	"github.com/aws/aws-sdk-go-v2/service/internal/presigned-url":   "v1.13.7",
	"github.com/aws/aws-sdk-go-v2/service/sso":                      "v1.29.2",
	"github.com/aws/aws-sdk-go-v2/service/ssooidc":                  "v1.34.3",
	"github.com/aws/aws-sdk-go-v2/service/sts":                      "v1.38.3",
	"github.com/aws/smithy-go":                                      "v1.23.0",
}

var gcpOutputPins = map[string]string{
	"cel.dev/expr":                         "v0.19.0",
	"cloud.google.com/go":                  "v0.112.2",
	"cloud.google.com/go/auth":             "v0.14.1",
	"cloud.google.com/go/auth/oauth2adapt": "v0.2.7",
	"cloud.google.com/go/compute/metadata": "v0.6.0",
	"cloud.google.com/go/longrunning":      "v0.5.6",
	"cloud.google.com/go/translate":        "v1.10.3",
	"github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp": "v1.25.0",
	"github.com/census-instrumentation/opencensus-proto":                       "v0.4.1",
	"github.com/cespare/xxhash/v2":                                             "v2.3.0",
	"github.com/cncf/xds/go":                                                   "v0.0.0-20240905190251-b4127c9b8d78",
	"github.com/davecgh/go-spew":                                               "v1.1.1",
	"github.com/envoyproxy/go-control-plane":                                   "v0.13.1",
	"github.com/envoyproxy/protoc-gen-validate":                                "v1.1.0",
	"github.com/felixge/httpsnoop":                                             "v1.0.4",
	"github.com/go-logr/logr":                                                  "v1.4.2",
	"github.com/go-logr/stdr":                                                  "v1.2.2",
	"github.com/golang/glog":                                                   "v1.2.3",
	"github.com/golang/groupcache":                                             "v0.0.0-20210331224755-41bb18bfe9da",
	"github.com/golang/protobuf":                                               "v1.5.4",
	"github.com/google/go-cmp":                                                 "v0.7.0",
	"github.com/google/go-pkcs11":                                              "v0.3.0",
	"github.com/google/s2a-go":                                                 "v0.1.9",
	"github.com/google/uuid":                                                   "v1.6.0",
	"github.com/googleapis/enterprise-certificate-proxy":                       "v0.3.4",
	"github.com/googleapis/gax-go/v2":                                          "v2.14.1",
	"github.com/kr/pretty":                                                     "v0.3.1",
	"github.com/kr/text":                                                       "v0.2.0",
	"github.com/planetscale/vtprotobuf":                                        "v0.6.1-0.20240319094008-0393e58bdf10",
	"github.com/pmezard/go-difflib":                                            "v1.0.0",
	"github.com/rogpeppe/go-internal":                                          "v1.13.1",
	"github.com/stretchr/testify":                                              "v1.10.0",
	"go.opencensus.io":                                                         "v0.24.0",
	"go.opentelemetry.io/auto/sdk":                                             "v1.1.0",
	"go.opentelemetry.io/contrib/detectors/gcp":                                "v1.32.0",
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc": "v0.58.0",
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp":               "v0.58.0",
	"go.opentelemetry.io/otel":                         "v1.36.0",
	"go.opentelemetry.io/otel/metric":                  "v1.36.0",
	"go.opentelemetry.io/otel/sdk":                     "v1.36.0",
	"go.opentelemetry.io/otel/sdk/metric":              "v1.36.0",
	"go.opentelemetry.io/otel/trace":                   "v1.36.0",
	"golang.org/x/crypto":                              "v0.33.0",
	"golang.org/x/mod":                                 "v0.17.0",
	"golang.org/x/net":                                 "v0.35.0",
	"golang.org/x/oauth2":                              "v0.26.0",
	"golang.org/x/sync":                                "v0.11.0",
	"golang.org/x/sys":                                 "v0.33.0",
	"golang.org/x/term":                                "v0.29.0",
	"golang.org/x/text":                                "v0.22.0",
	"golang.org/x/time":                                "v0.10.0",
	"golang.org/x/tools":                               "v0.21.1-0.20240508182429-e35e4ccd0d2d",
	"golang.org/x/xerrors":                             "v0.0.0-20191204190536-9bdfabe68543",
	"google.golang.org/api":                            "v0.222.0",
	"google.golang.org/appengine":                      "v1.6.8",
	"google.golang.org/genproto/googleapis/api":        "v0.0.0-20241209162323-e6fa225c2576",
	"google.golang.org/genproto/googleapis/bytestream": "v0.0.0-20250212204824-5a70512c5d8b",
	"google.golang.org/genproto/googleapis/rpc":        "v0.0.0-20250212204824-5a70512c5d8b",
	"google.golang.org/grpc":                           "v1.70.0",
	"google.golang.org/protobuf":                       "v1.36.5",
	"gopkg.in/check.v1":                                "v1.0.0-20201130134442-10cb98267c6c",
	"gopkg.in/yaml.v3":                                 "v3.0.1",
}

var githubOutputPins = map[string]string{
	"golang.org/x/crypto": "v0.33.0",
	"golang.org/x/net":    "v0.35.0",
	"golang.org/x/sys":    "v0.33.0",
	"golang.org/x/term":   "v0.29.0",
	"golang.org/x/text":   "v0.22.0",
}

func checkOutputPluginModules(directory string, modules []resolvedModule, packages []compiledPackage, pins map[string]string, directImports ...string) error {
	if len(modules) != len(pins)+4 {
		return errors.New("output plugin module graph changed")
	}
	owned, protocol, sdk, artifacts := 0, 0, 0, 0
	seen := make(map[string]bool, len(modules))
	for _, module := range modules {
		if seen[module.Path] {
			return errors.New("output plugin module duplicated")
		}
		seen[module.Path] = true
		switch module.Path {
		case modulePath(directory):
			if module.Version != "" || module.Replace != nil {
				return errors.New("output plugin module identity differs")
			}
			owned++
		case "enkv.sh/sdk/artifact":
			if module.Version != "v0.1.1" || module.Replace == nil || module.Replace.Path != "../../../sdk/artifact" || module.Replace.Version != "" || module.Replace.Replace != nil {
				return errors.New("output plugin artifact identity differs")
			}
			artifacts++
		case outputSDKPath:
			if module.Version != "v0.1.1" || module.Replace == nil || module.Replace.Path != "../../../sdk/output" || module.Replace.Version != "" || module.Replace.Replace != nil {
				return errors.New("output plugin SDK identity differs")
			}
			sdk++
		case "enkv.sh/sdk/protocols/output":
			if module.Version != "v0.1.0" || module.Replace == nil ||
				module.Replace.Path != "../../../sdk/protocols/output" || module.Replace.Version != "" || module.Replace.Replace != nil {
				return errors.New("output plugin protocol identity differs")
			}
			protocol++
		default:
			version, known := pins[module.Path]
			if !known || module.Version != version || module.Replace != nil {
				return errors.New("output plugin dependency graph differs")
			}
		}
	}
	if owned != 1 || protocol != 1 || sdk != 1 || artifacts != 1 {
		return errors.New("output plugin or protocol module missing")
	}
	for _, p := range packages {
		allowed := p.Standard || withinModule(p.ImportPath, modulePath(directory)) || p.ImportPath == "enkv.sh/sdk/protocols/output" || p.ImportPath == outputSDKPath || p.ImportPath == "enkv.sh/sdk/artifact" || p.ImportPath == "enkv.sh/sdk/artifact/credentialroute"
		if !allowed {
			for path := range pins {
				if withinModule(p.ImportPath, path) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			return errors.New("output plugin imports an unreviewed package")
		}
		if !withinModule(p.ImportPath, modulePath(directory)) {
			continue
		}
		for _, imported := range p.Imports {
			if !strings.Contains(imported, ".") || withinModule(imported, modulePath(directory)) ||
				imported == "enkv.sh/sdk/protocols/output" || imported == outputSDKPath || imported == "enkv.sh/sdk/artifact" || imported == "enkv.sh/sdk/artifact/credentialroute" || slices.Contains(directImports, imported) {
				continue
			}
			return errors.New("output plugin directly imports an unreviewed package")
		}
	}
	return nil
}
