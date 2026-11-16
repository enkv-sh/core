package main

import "errors"

func setVerificationProfile(request *runRequest, profile string) error {
	profile, err := resolveVerificationProfile(profile)
	if err != nil {
		return err
	}
	if request.Resolved == nil || profile != "full" && request.Suite != "hermetic" {
		return errors.New("focused verification requires a resolved hermetic run")
	}
	request.Profile = profile
	resolved := request.Resolved
	resolved.Profile = profile
	resolved.Preparation = []string{"build test assembly and check dependency boundaries"}
	if request.Suite == "live" {
		resolved.Preparation = append(resolved.Preparation, "controlled provider and worker checks")
	}
	return nil
}
