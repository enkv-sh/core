package compositionfull

import (
	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// NewEnvelopeRekeyRefusal reports invalid command fields without reading a source.
func NewEnvelopeRekeyRefusal(format configuration.Format) (core.PublicApplyResult, error) {
	return NewApplyRefusal(format)
}

func RenderEnvelopeRekeyJSON(r core.PublicApplyResult) ([]byte, error) {
	v, err := transitionResultProjection(r, contract.OperationEnvelopeRekey)
	if err != nil {
		return nil, err
	}
	return renderTransitionResultJSON(v)
}

func RenderEnvelopeRekeyHuman(r core.PublicApplyResult) ([]byte, error) {
	v, err := transitionResultProjection(r, contract.OperationEnvelopeRekey)
	if err != nil {
		return nil, err
	}
	return renderTransitionHuman(r, v)
}
