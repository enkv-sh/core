package core

import (
	"context"
	"encoding/json"
	manifestsdk "enkv.sh/sdk/manifest-generator"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestReaderManifestUsesSelectedAWSBirthForConsumerRequest(t *testing.T) {
	const slot = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-AbCd12"
	const instance = slot + "-ZyXw98"
	env := memoryScenarioEnvironment(t)
	initial := newEnvironmentFixture(t, t.Context(), env, nil, false)
	f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: initial.admission, session: initial.session}
	entries := []ApplyEntryInput{sharingSecretNamed(t, env, "app-AbCd12", "independent consumer value", []contract.ID{f.session.admission.recipient})}
	target := outputConfigurationTarget("app-AbCd12", slot)

	target.target.Policy = contract.OutputPolicy{}
	target.target.ConsumerLocator = ""
	target.target.LocatorRequiresCreation = true
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"app"}}}}
	f.session = selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, env.Custody, entries, output)
	f.session.admission.publicationNamespaces = []publicationNamespace{{domain: env.Domain, service: "aws", physical: slot, premise: fixtureID(env.Domain, "independent AWS namespace")}}
	f.admission = OpenContext{admission: &f.session.admission}
	p := newPublicationControlledPrivate()
	p.configureOwner = func(o *publicationControlledOwner) {
		o.resource = instance
		o.consumerLocator = instance + "?stage=AWSCURRENT"
	}
	input := publicationInput{names: []string{"app-AbCd12"}, acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	got := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	if got.summary != contract.PublicationSummaryComplete || len(got.output.Entries) != 1 || len(got.output.Entries[0].Actions) != 1 || got.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged || got.output.Entries[0].Actions[0].Evidence.SafeResourceID != instance {
		t.Fatal("selected creation fixture failed", got)
	}
	selected, result := Open(t.Context(), f.admission, f.store)
	if selected == nil {
		t.Fatal("cold selected birth", result)
	}
	engine, _, _ := readerEngineFixture(t, env, selected)
	engine.validator = NewPublicConfigurationValidator(selected.admission.outputInterpreter)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	creates, cas := f.store.creates, f.store.cas
	public, private := env.Custody.Calls()
	manifest := engine.Manifest(ctx, fixtureID(env.Domain, "fresh GET-only consumer manifest"), hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: selected.admission.recipient, EntryNames: []string{"app-AbCd12"}}))
	if manifest.StateResult != contract.ReaderSuccess || manifest.Artifact == nil {
		t.Fatal("manifest issuance", manifest.StateResult, manifest.FailureReason)
	}
	var decoded struct {
		Entries []struct {
			Content struct {
				Destinations []struct {
					Locator string `json:"consumer_locator"`
				} `json:"destinations"`
			} `json:"content"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(manifest.Artifact, &decoded); err != nil || len(decoded.Entries) != 1 || len(decoded.Entries[0].Content.Destinations) != 1 {
		t.Fatal("consumer cannot decode manifest", err)
	}
	secretID, stage, ok := strings.Cut(decoded.Entries[0].Content.Destinations[0].Locator, "?stage=")
	// These are the separate AWS GetSecretValue request fields. The address is
	// obtained only from the artifact; the selected birth is an independent oracle.
	request := struct{ SecretID, VersionStage string }{secretID, stage}
	if !ok || request.SecretID != instance || request.VersionStage != "AWSCURRENT" {
		t.Fatalf("manifest-derived consumer request = %+v; want SecretID=%s VersionStage=AWSCURRENT", request, instance)
	}
	if f.store.creates != creates || f.store.cas != cas {
		t.Fatal("manifest modified selected state")
	}
	if p, q := env.Custody.Calls(); p != public || q != private {
		t.Fatal("manifest used private custody")
	}
}
