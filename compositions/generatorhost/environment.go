package generatorhost

import (
	"context"
	"errors"
	"os"

	"enkv.sh/sdk/artifact/credentialroute"
)

func readEnvironmentInputs(ctx context.Context, route credentialroute.Route) ([]byte, error) {
	if ctx == nil {
		return nil, ErrCredential
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrCredential, err)
	}
	inputs := make([]credentialroute.Input, len(route.Names))
	defer func() {
		for i := range inputs {
			clear(inputs[i].Value[:cap(inputs[i].Value)])
		}
	}()
	total := 3
	for i, name := range route.Names {
		value, present := os.LookupEnv(name)
		total += 6 + len(name) + len(value)
		if total > credentialroute.MaxInputsBytes {
			return nil, ErrCredential
		}
		owned := make([]byte, len(value))
		copy(owned, value)
		inputs[i] = credentialroute.Input{Name: name, Present: present, Value: owned}
	}
	body, err := credentialroute.EncodeInputs(route, inputs)
	if err != nil {
		return nil, errors.Join(ErrCredential, err)
	}
	if err := ctx.Err(); err != nil {
		clear(body[:cap(body)])
		return nil, errors.Join(ErrCredential, err)
	}
	return body, nil
}
