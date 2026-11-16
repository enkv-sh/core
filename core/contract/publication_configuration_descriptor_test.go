package contract

import "testing"

// full_only: false
func TestOutputConfigurationDescriptorChecksTypedFieldsWithoutEncodedCopy(t *testing.T) {
	_, descriptor, _, configuration := outputShapeImage(OutputEncodingRaw, 0, "l")
	if err := ValidateOutputConfigurationAgainstDescriptor(configuration, descriptor); err != nil {
		t.Fatal("independent descriptor refused", err)
	}
	for _, field := range []string{"digest", "length", "slice-count", "binding-count", "routing-length", "domain", "locator", "policy", "encoding"} {
		t.Run(field, func(t *testing.T) {
			v := cloneOutputConfiguration(configuration)
			d := descriptor
			switch field {
			case "digest":
				d.ConfigurationDigest[0] ^= 1
			case "length":
				d.TotalLength++
			case "slice-count":
				d.SliceCount++
			case "binding-count":
				d.BindingCount++
			case "routing-length":
				d.RoutingLength++
			case "domain":
				v.DomainID[0] ^= 1
			case "locator":
				v.Bindings[0].Targets[0].ConsumerLocator = "x"
			case "policy":
				v.Bindings[0].Destination.Policy.ContractID = "x"
				v.Bindings[0].Targets[0].Policy.ContractID = "x"
			case "encoding":
				v.Bindings[0].Targets[0].PayloadEncoding = 3
			}
			if err := ValidateOutputConfigurationAgainstDescriptor(v, d); err == nil {
				t.Fatal("changed field matched original independent descriptor")
			}
		})
	}
}
