//go:build darwin || linux

package configuration

import "strings"

// These fixed bytes follow the documented field order and two-space layout.
// Their derivation uses no production emitter or parser.
const reconstructionEditableJSON = `{
  "schema": "enkv/configuration/v3",
  "domain": {
    "name": "recovered",
    "provider": "aws",
    "store": {
      "region": "us-east-1",
      "bucket": "fixture-bucket",
      "prefix": "fixture",
      "expected_owner": "123456789012"
    },
    "authority": {
      "display_name": "",
      "signing_key": "` + sourceSigningSelector + `",
      "encryption_key": "` + sourceEncryptionSelector + `"
    },
    "recovery": {
      "enabled": false
    }
  },
  "recipients": {},
  "entries": {},
  "outputs": {
    "destinations": {},
    "routing": {
      "entries": {}
    },
    "groups": []
  },
  "generated": ".enkv/recovered.generated.json"
}
`

const reconstructionEditableYAMLTemplate = `schema: enkv/configuration/v3
domain:
  name: recovered
  provider: aws
  store:
    region: us-east-1
    bucket: fixture-bucket
    prefix: fixture
    expected_owner: "123456789012"
  authority:
    display_name: ""
    signing_key: ` + sourceSigningSelector + `
    encryption_key: ` + sourceEncryptionSelector + `
  recovery:
    enabled: false
recipients: {}
entries: {}
outputs:
  destinations: {}
  routing:
    entries: {}
  groups: []
generated: .enkv/recovered.generated.json
`

func reconstructionEditableYAML() string {
	return reconstructionEditableYAMLTemplate
}

func reconstructionGeneratedLiteral() string {
	return strings.Replace(stableGeneratedLiteral, `"kind": "genesis",
    "descriptor": "AQ=="`, `"kind": "observation",
    "anchor": "AP8B",
    "store_configuration": "AgA=",
    "head": "AwQ=",
    "root": "BQ==",
    "recipient_pages": [
      "Bgc=",
      "CA=="
    ]`, 1)
}
