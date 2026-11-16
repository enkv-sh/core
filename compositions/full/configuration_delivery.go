package compositionfull

import (
	"errors"

	"enkv.sh/compositions/configuration"
)

var errConfigurationObservationCleanup = errors.New("configuration observation cleanup failed")

func closeConfigurationDelivery(err error) error {
	result, cleanupFailed := closeConfigurationDeliveryState(err)
	if cleanupFailed {
		result = errors.Join(result, errConfigurationObservationCleanup)
	}
	return result
}

func closeConfigurationDeliveryState(err error) (error, bool) {
	var unknown *configuration.UnknownEdit
	if errors.As(err, &unknown) && unknown != nil && unknown.Observation != nil {
		closeErr := unknown.Observation.Close()
		return errors.Join(err, closeErr), closeErr != nil
	}
	return err, false
}
