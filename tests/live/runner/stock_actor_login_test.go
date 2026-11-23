package core

import "context"

// The daily login also verifies the live caller. Check every selected profile
// locally before starting the first credential process.
type stockActorLogin struct {
	config   func(liveRunInput, string) error
	identity func(context.Context, liveRunInput, string, string, *runBudget) error
}

func (l stockActorLogin) admit(ctx context.Context, input liveRunInput, directory string, budget *runBudget, roles ...string) error {
	for _, role := range roles {
		if err := l.config(input, role); err != nil {
			return err
		}
	}
	if l.identity != nil {
		for _, role := range roles {
			if err := l.identity(ctx, input, role, directory, budget); err != nil {
				return err
			}
		}
	}
	return nil
}
