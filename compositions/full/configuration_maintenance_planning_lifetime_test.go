package compositionfull

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestMaintenancePlanningCallbackConstructsCustodyAfterSourceRelease(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			maintenancePlanningCredentialEnvironment(t, family)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			source := configurationMaintenancePair(t, family, configuration.JSON, nil)
			model, installed, _, ok := configurationAccessMutationSource(ctx, contract.ID{77}, source.pair)
			if !ok {
				t.Fatal("source did not reach maintenance qualification")
			}
			request := configuration.MaintenanceRequest{OperationKind: contract.OperationEnvelopeRekey, Name: "first"}
			output := maintenanceAdapterTestOutput(t, ctx, source.pair, request)
			defer func() {
				if err := output.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := configureMaintenanceOutput(ctx, source.pair, model, &installed, output, request); err != nil {
				t.Fatal(err)
			}
			controlBytes, err := contract.EncodeControlCore(installed.ExpectedControl)
			if err != nil {
				t.Fatal(err)
			}
			control, err := contract.DecodeControlCore(controlBytes)
			if err != nil {
				t.Fatal(err)
			}
			pins := contract.PlanningSourcePair{FileIdentity: model.FileID,
				EditableDigest: contract.ID(sha256.Sum256(source.editableBytes)), GeneratedDigest: contract.ID(sha256.Sum256(source.generatedBytes)),
				EditableLength: uint64(len(source.editableBytes)), GeneratedLength: uint64(len(source.generatedBytes))}
			token := `"planning-token"`
			if family == "gcp" {
				token = "1"
			}
			admission := contract.PlanningAdmission{
				RequestID: contract.ID{1}, SessionID: contract.ID{2}, DomainID: model.DomainID,
				HEADDigest: contract.ID{3}, HEADRevision: contract.ID{4}, SnapshotID: contract.ID{5}, AccessRoot: contract.ID{6},
				CredentialRoute: installed.Maintenance.CredentialRoute, Control: control,
				Root:      contract.Ref{Kind: contract.RootKind, Domain: model.DomainID, Object: contract.ID{5}, Digest: contract.ID{7}, Format: contract.CanonicalSchema, Length: 1},
				HEADToken: contract.Token{Family: model.Provider, Value: token}, Sources: contract.PlanningSources{Trusted: pins, Proposed: pins},
				Authority: contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: control.AuthorityRecipientID, Binding: control.AuthorityKMSBinding},
				Options:   contract.PlanningOptions{Purpose: contract.PlanningEquality},
			}
			releaseConfigurationBasis(model)
			installed.PublicBasis = core.PublicBasis{}
			custody, err := installed.Maintenance.AdmitFeasibility(ctx, admission)
			if custody != nil {
				defer custody.Close()
			}
			if err != nil || custody == nil {
				t.Fatal("valid callback could not construct custody after source release", err)
			}
			result := custody.Check(ctx)
			if !result.Complete || result.Code != contract.CryptoSuccess || len(result.Rows) != 0 {
				t.Fatal("empty admitted planning scope did not complete", result)
			}
			source.assertUnchanged(t)
		})
	}
}

func maintenancePlanningCredentialEnvironment(t *testing.T, family string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials")
	if family == "aws" {
		for _, key := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY", "AWS_SECRET_KEY"} {
			t.Setenv(key, "")
		}
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWS_CONFIG_FILE", path)
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", path)
		t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
		t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAAAAAAAAAAAA")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "private-standard-secret")
		return
	}
	body := []byte(`{"type":"authorized_user","client_id":"synthetic-client","client_secret":"synthetic-secret","refresh_token":"synthetic-refresh","quota_project_id":"quota-project","universe_domain":"googleapis.com"}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
	t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
	t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
	t.Setenv("GOOGLE_API_USE_MTLS_ENDPOINT", "never")
}
