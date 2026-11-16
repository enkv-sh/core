package compositionfull

import (
	"strings"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

func configurationRecipientNames(model *configuration.Model) []contract.ComparisonRecipientLabel {
	labels := make([]contract.ComparisonRecipientLabel, len(model.Recipients))
	for at, row := range model.Recipients {
		name := strings.Clone(row.Reference)
		labels[at] = contract.ComparisonRecipientLabel{RecipientID: row.ID, Name: &name}
	}
	return labels
}

func addConfigurationRecipientNames(payload *contract.ComparisonPayload, before, after []contract.ComparisonRecipientLabel) {
	for _, pair := range []struct {
		labels, names []contract.ComparisonRecipientLabel
	}{{payload.BeforeRecipients, before}, {payload.AfterRecipients, after}} {
		for at := range pair.labels {
			for _, name := range pair.names {
				if pair.labels[at].RecipientID == name.RecipientID {
					pair.labels[at].Name = name.Name
					break
				}
			}
		}
	}
}
