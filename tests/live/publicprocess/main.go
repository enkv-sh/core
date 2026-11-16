// This helper is compiled only by the public-configuration live/local test
// orchestration. It calls public installed constructors; it cannot admit init,
// apply, supplied values, or a Core selection through a private fixture.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	compositionaws "enkv.sh/compositions/aws"
	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	compositiongcp "enkv.sh/compositions/gcp"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/testsupport/nativeprocess"
	awsprovider "enkv.sh/providers/aws"
	gcp "enkv.sh/providers/gcp"
)

func main() {
	code := runPublicProcess(os.Args[1:], os.Stdout)
	nativeProcessFinish(code)
	os.Exit(code)
}
func runPublicProcess(args []string, out io.Writer) int {
	if len(args) > 0 && args[0] == sourcePairInspectorFlag {
		return runSourcePairInspector(args[1:], out)
	}
	if len(args) > 0 && args[0] == recipientDenialProbeFlag {
		return runRecipientDenialProbe(args[1:], out)
	}
	if len(args) > 0 && args[0] == readTransportProbeFlag {
		return runReadTransportProbe(args[1:], out)
	}
	flags := flag.NewFlagSet("public-reconstruct", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	source := flags.String("source", "", "")
	format := flags.String("source-format", "", "")
	materialize := flags.Bool("materialize-retained", false, "")
	reconstructOutput := flags.String("reconstruct-output", "", "")
	prepareOutput := flags.Bool("prepare-output-credential", false, "")
	outputProject := flags.String("output-project-number", "", "")
	successorSelector := flags.String("successor-signing-selector", "", "")
	successorScratch := flags.String("successor-scratch", "", "")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || !filepath.IsAbs(*source) {
		return 2
	}
	successor := *successorSelector != ""
	if successor != (*successorScratch != "") || successor && (!*materialize || !filepath.IsAbs(*successorScratch) || filepath.Clean(*successorScratch) != *successorScratch) {
		return 2
	}
	if *reconstructOutput != "" && (*materialize || successor || !filepath.IsAbs(*reconstructOutput) || filepath.Clean(*reconstructOutput) != *reconstructOutput) {
		return 2
	}
	if !*prepareOutput && *outputProject != "" || *prepareOutput && (*materialize || successor || *reconstructOutput != "") {
		return 2
	}
	representation := configuration.JSON
	if *format == "yaml" {
		representation = configuration.YAML
	} else if *format != "json" {
		return 2
	}
	if successor && representation != configuration.JSON {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pair, err := configuration.Capture(ctx, *source, representation)
	if err != nil {
		return 2
	}
	defer pair.Close()
	model, err := configuration.Parse(ctx, pair)
	if err != nil || !model.Resolved {
		return 2
	}
	if successor && (!model.RecoveryEnabled || *successorSelector == model.Authority.SigningSelector || !successorSameLocation(model.Provider, model.Authority.SigningSelector, *successorSelector)) {
		return 2
	}
	if *prepareOutput {
		result := preparePublicOutput(ctx, model, *outputProject)
		if err := pair.Close(); err != nil {
			return publicPreparationRefused(out, preparationClose)
		}
		if json.NewEncoder(out).Encode(struct{ OutputPreparation publicOutputPreparationResult }{result}) != nil || !result.Prepared || !result.Closed {
			return 2
		}
		return 0
	}
	route := contract.Hash([]byte("enkv/test/public-reconstruction/default/v1"))
	routeText := hex.EncodeToString(route[:])
	selected := compositionfull.ReconstructionConfig{Family: model.Provider}
	if model.Provider == contract.AWS {
		normal, ok := contract.ParseAWSKeySelector(model.Authority.SigningSelector, true)
		if !ok {
			return 2
		}
		selected.AWS = &compositionaws.ReconstructionConfig{ExpectedDomain: model.DomainID, ExpectedKEK: model.Authority.EncryptionSelector,
			Candidate: awsprovider.CandidateReadConfig{Region: model.Store.Region, Bucket: model.Store.Bucket, Prefix: model.Store.PrefixBeforeHEAD, ExpectedBucketOwner: model.Store.ExpectedOwner, CredentialRoute: route, Timeout: time.Minute, Transport: &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}},
			Normal:    &awsprovider.PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Region: normal.Region, KeyARN: model.Authority.SigningSelector, CredentialRoute: route, Timeout: time.Minute, Transport: &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}},
			KeyAccess: compositionaws.ReconstructionKeyAccessConfig{CredentialRoute: route, Timeout: time.Minute, Transport: &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}}}
		if model.RecoveryEnabled {
			recovery, ok := contract.ParseAWSKeySelector(model.Recovery.SigningSelector, true)
			if !ok {
				return 2
			}
			selected.AWS.Recovery = &awsprovider.PublicSigningAnchorConfig{Role: contract.RecoverySigningRole, Region: recovery.Region, KeyARN: model.Recovery.SigningSelector, CredentialRoute: route, Timeout: time.Minute, Transport: &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}}
		}
	} else if model.Provider == contract.GCP {
		normal, ok := contract.ParseGCPKeySelector(model.Authority.SigningSelector, true)
		if !ok {
			return 2
		}
		selected.GCP = &compositiongcp.ReconstructionConfig{ExpectedDomain: model.DomainID, ExpectedKEK: model.Authority.EncryptionSelector,
			Candidate: gcp.CandidateReadConfig{Region: model.Store.Region, Bucket: model.Store.Bucket, Prefix: model.Store.PrefixBeforeHEAD, CredentialRoute: routeText},
			Normal:    &gcp.PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Region: normal.Region, KeyVersion: model.Authority.SigningSelector, CredentialRoute: routeText},
			KeyAccess: compositiongcp.ReconstructionKeyAccessConfig{CredentialRoute: route}}
		if model.RecoveryEnabled {
			recovery, ok := contract.ParseGCPKeySelector(model.Recovery.SigningSelector, true)
			if !ok {
				return 2
			}
			selected.GCP.Recovery = &gcp.PublicSigningAnchorConfig{Role: contract.RecoverySigningRole, Region: recovery.Region, KeyVersion: model.Recovery.SigningSelector, CredentialRoute: routeText}
		}
	} else {
		return 2
	}
	engine, err := compositionfull.NewDefaultReconstruction(ctx, selected)
	if err != nil {
		return 2
	}
	defer engine.Close()
	projection, result := engine.Reconstruct(ctx)
	if projection != nil {
		defer projection.Close()
	}
	if result.Outcome != core.ObservedCurrent || projection == nil {
		return 2
	}
	provenance, ok := projection.Provenance()
	if !ok || provenance.Domain != model.DomainID {
		return 2
	}
	if *reconstructOutput != "" {
		if err := emitReconstructedPair(ctx, pair, model, projection, *reconstructOutput); err != nil {
			return publicPreparationRefused(out, preparationReconstructionOutput)
		}
	}
	if *materialize {
		policy, err := nativeProcessLoad()
		if err != nil || len(policy.ExpectedSHA256) == 0 {
			return publicPreparationRefused(out, preparationPolicy)
		}
		observed, err := nativeprocess.ReadProgress(policy.RecordPath)
		if err != nil {
			return publicPreparationRefused(out, preparationProgress)
		}
		matched := 0
		for _, event := range observed.Events {
			if event.Kind == "plaintext" {
				if !event.Matched || event.Count != 1 {
					return publicPreparationRefused(out, preparationPlaintext)
				}
				matched++
			}
		}
		if matched != len(policy.ExpectedSHA256) {
			return publicPreparationRefused(out, preparationPlaintext)
		}
		if err := materializeRetained(ctx, *source, representation, capturedPublicPair(pair), model, projection); err != nil {
			return publicPreparationRefused(out, publicPreparationFailureStage(err))
		}
	}
	var predecessor publicSuccessorPredecessor
	if successor {
		predecessor, err = successorProjectionPredecessor(ctx, projection)
		if err != nil || predecessor.Provenance != provenance {
			return publicPreparationRefused(out, preparationSuccessorPredecessor)
		}
	}
	if err := pair.Close(); err != nil {
		return publicPreparationRefused(out, preparationClose)
	}
	// Release reconstruction and its plaintext owner before opening the separate
	// administrative operation. Its projection count remains a baseline fact.
	parts := projection.PartCount()
	projection.Close()
	engine.Close()
	summary := struct {
		Domain, Revision string
		Parts            int
		Successor        *publicProcessSuccessorResult `json:",omitempty"`
		PreparationStage uint8                         `json:",omitempty"`
	}{Domain: hex.EncodeToString(provenance.Domain[:]), Revision: hex.EncodeToString(provenance.Revision[:]), Parts: parts}
	completed := true
	if successor {
		// The previous pair predates materialization and cannot supply this
		// operation's source facts. Fix the newly committed pair independently.
		retainedPair, err := configuration.Capture(ctx, *source, representation)
		if err != nil {
			return publicPreparationRefused(out, preparationRecapture)
		}
		retained, parseErr := configuration.Parse(ctx, retainedPair)
		closeErr := retainedPair.Close()
		if parseErr != nil || closeErr != nil || retained == nil || !retained.Resolved || retained.DomainID != provenance.Domain {
			return publicPreparationRefused(out, preparationReparse)
		}
		actual, err := replacePublicSuccessor(ctx, *source, representation, capturedPublicPair(retainedPair), retained, predecessor, *successorSelector, *successorScratch)
		completed = err == nil
		summary.PreparationStage = publicPreparationFailureStage(err)
		summary.Successor = &publicProcessSuccessorResult{Domain: hex.EncodeToString(actual.DomainID[:]), Operation: hex.EncodeToString(actual.OperationID[:]), Revision: hex.EncodeToString(actual.Revision[:]), Result: actual.Result, PairPrepared: completed, OutputPath: actual.OutputPath}
	}
	// Only public correlation and bounded actual operation facts leave here.
	if err := json.NewEncoder(out).Encode(summary); err != nil {
		return 2
	}
	if !completed {
		return 2
	}
	return 0
}

type publicProcessSuccessorResult struct {
	Domain, Operation, Revision string
	Result                      core.Result
	PairPrepared                bool
	OutputPath                  string
}

// Closed local test diagnostics identify a refusal gate without serializing
// its error, selectors, source, or protected administrative input.
const (
	preparationPolicy uint8 = iota + 1
	preparationProgress
	preparationPlaintext
	preparationClose
	preparationRecapture
	preparationReparse
	preparationRetainedSource
	preparationRetainedCapture
	preparationRetainedProjection
	preparationRetainedStage
	preparationRetainedMeaning
	preparationRetainedCommit
	preparationSuccessorSource
	preparationSuccessorCapture
	preparationSuccessorBasis
	preparationSuccessorEditable
	preparationSuccessorFiles
	preparationSuccessorInputs
	preparationSuccessorKey
	preparationSuccessorProposal
	preparationSuccessorRestore
	preparationSuccessorDelivery
	preparationSuccessorStage
	preparationSuccessorCommit
	preparationSuccessorPredecessor
	preparationReconstructionOutput
)

type publicPreparationFailure struct {
	stage uint8
	cause error
}

func (publicPreparationFailure) Error() string   { return "public test preparation refused" }
func (e publicPreparationFailure) Unwrap() error { return e.cause }
func publicPreparationFailureStage(err error) uint8 {
	var failure publicPreparationFailure
	if errors.As(err, &failure) {
		return failure.stage
	}
	return 0
}
func publicPreparationRefused(out io.Writer, stage uint8) int {
	if err := json.NewEncoder(out).Encode(struct{ PreparationStage uint8 }{stage}); err != nil {
		return 2
	}
	return 2
}
