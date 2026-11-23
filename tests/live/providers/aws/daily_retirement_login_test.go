package core

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	records "enkv.sh/core/internal/testrecords"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/logging"
)

func stockLoginFor(input liveRunInput) stockActorLogin {
	if input.PublicConfiguration != nil && input.PublicConfiguration.Stock != nil && input.PublicConfiguration.Stock.Fixture.DailyRolePrefix != "" {
		return stockActorLogin{config: validateDailyRetirementLogin, identity: verifyDailyRetirementLogin}
	}
	return stockActorLogin{config: validateStockSDKContext}
}

func dailyRetirementLoginUser(role string) string {
	switch role {
	case "authority", "apply", "cleanup":
		return "orders-authority"
	case "reader", "consumer":
		return "orders-recipient"
	default:
		return ""
	}
}

// This exact local fixture format closes credential_process to the AWS CLI's
// browser-login export, including its separate login identity and target role.
func dailyRetirementLoginConfig(input liveRunInput, role, cli string) ([]byte, error) {
	if input.PublicConfiguration == nil || input.PublicConfiguration.Stock == nil {
		return nil, errInventory
	}
	f := input.PublicConfiguration.Stock.Fixture
	actor, ok := input.PublicConfiguration.Actors[role]
	user := dailyRetirementLoginUser(role)
	if !ok || user == "" || f.Validate() != nil || f.Provider != "aws" || f.Purpose != records.StockRetirementProofPurpose ||
		f.DailyRolePrefix == "" || input.Settings.Account != f.Account || input.Settings.Region != f.Region ||
		actor.Provider != f.Provider || actor.Account != f.Account || actor.Region != f.Region || actor.Bucket != f.Bucket ||
		actor.SDKMode != "aws-assume-role" || actor.SDKProfile != "enkv-plugin-"+role || !filepath.IsAbs(actor.SDKHome) ||
		actor.CredentialsFile != "" || actor.SDKCredentialsFile != "" || !filepath.IsAbs(cli) || filepath.Clean(cli) != cli ||
		strings.ContainsAny(cli+actor.SDKHome, "\r\n") {
		return nil, errInventory
	}
	source := "enkv-daily-" + user
	login := source + "-login"
	command := dailyRetirementCredentialProcess(actor.SDKHome, cli, login)
	return []byte(fmt.Sprintf("[profile %s]\nregion = %s\nrole_arn = arn:aws:iam::%s:role/%s-%s\nsource_profile = %s\nrole_session_name = enkv-daily-%s\n\n[profile %s]\nregion = %s\ncredential_process = %s\n\n[profile %s]\nregion = %s\nlogin_session = arn:aws:iam::%s:user/%s\n",
		actor.SDKProfile, f.Region, f.Account, f.DailyRolePrefix, role, source, role,
		source, f.Region, command, login, f.Region, f.Account, user)), nil
}

func dailyRetirementCredentialProcess(home, cli, login string) string {
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
	args := []string{"HOME=" + home, "AWS_CONFIG_FILE=" + filepath.Join(home, ".aws", "config"), "AWS_SHARED_CREDENTIALS_FILE=/dev/null", "AWS_EC2_METADATA_DISABLED=true", "AWS_PAGER=", "PATH=/usr/bin:/bin", cli}
	for i := range args {
		args[i] = quote(args[i])
	}
	return "/usr/bin/env -i " + strings.Join(args, " ") + " configure export-credentials --profile " + login + " --format process"
}

func validateDailyRetirementLogin(input liveRunInput, role string) error {
	cli, err := exec.LookPath("aws")
	if err != nil {
		return errInventory
	}
	expected, err := dailyRetirementLoginConfig(input, role, cli)
	if err != nil {
		return err
	}
	actor := input.PublicConfiguration.Actors[role]
	if _, err := os.Lstat(filepath.Join(actor.SDKHome, ".aws", "credentials")); !os.IsNotExist(err) {
		return errInventory
	}
	body, err := ReadLocalProtectedFile(context.Background(), filepath.Join(actor.SDKHome, ".aws", "config"), 64<<10)
	defer clear(body)
	if err != nil || !bytes.Equal(body, expected) {
		return errInventory
	}
	return nil
}

// Verify the browser source before assuming any role. The second identity read
// binds the selected SDK credentials to the exact actor role and session.
func verifyDailyRetirementLogin(ctx context.Context, input liveRunInput, role, directory string, budget *runBudget) error {
	transport := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, DisableKeepAlives: true, DisableCompression: true}
	defer transport.CloseIdleConnections()
	return verifyDailyRetirementLoginWithTransport(ctx, input, role, directory, budget, transport)
}

func verifyDailyRetirementLoginWithTransport(ctx context.Context, input liveRunInput, role, directory string, budget *runBudget, transport http.RoundTripper) error {
	if ctx == nil || budget == nil || transport == nil || validateDailyRetirementLogin(input, role) != nil {
		return errInventory
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	restore, err := publicSDKEnvironment(input, role, directory)
	if err != nil {
		return err
	}
	defer restore()
	f := input.PublicConfiguration.Stock.Fixture
	actor := input.PublicConfiguration.Actors[role]
	for _, profile := range []string{"enkv-daily-" + dailyRetirementLoginUser(role), actor.SDKProfile} {
		owner := &awsLiveOutput{location: liveOutputLocation{Provider: "aws", Region: f.Region, Account: f.Account}, budget: budget, transport: transport}
		op := &awsOutputRequest{owner: owner, host: "sts." + f.Region + ".amazonaws.com", stage: "authentication", requestLimit: awsOutputRequestLimit, responseLimit: awsOutputRequestLimit}
		client := &http.Client{Transport: op, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(f.Region), config.WithSharedConfigProfile(profile),
			config.WithSharedConfigFiles([]string{filepath.Join(actor.SDKHome, ".aws", "config")}), config.WithSharedCredentialsFiles([]string{}),
			config.WithHTTPClient(client), config.WithRetryer(func() aws.Retryer { return aws.NopRetryer{} }))
		if err != nil || cfg.Credentials == nil {
			return errInventory
		}
		credentials, err := cfg.Credentials.Retrieve(ctx)
		if err != nil || !credentials.HasKeys() || credentials.SessionToken == "" || !credentials.CanExpire || !time.Now().Before(credentials.Expires) {
			return errInventory
		}
		expected := "arn:aws:iam::" + f.Account + ":user/" + dailyRetirementLoginUser(role)
		if profile == actor.SDKProfile {
			expected = "arn:aws:sts::" + f.Account + ":assumed-role/" + f.DailyRolePrefix + "-" + role + "/enkv-daily-" + role
		}
		if err := verifyDailyRetirementIdentity(ctx, f.Account, f.Region, expected, credentials, budget, transport); err != nil {
			return err
		}
	}
	return nil
}

func verifyDailyRetirementIdentity(ctx context.Context, account, region, expected string, credentials aws.Credentials, budget *runBudget, transport http.RoundTripper) error {
	owner := &awsLiveOutput{location: liveOutputLocation{Provider: "aws", Region: region, Account: account}, budget: budget, transport: transport}
	op := &awsOutputRequest{owner: owner, host: "sts." + region + ".amazonaws.com", stage: "authentication", requestLimit: awsOutputRequestLimit, responseLimit: awsOutputRequestLimit}
	client := &http.Client{Transport: op, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sdk := sts.New(sts.Options{Region: region, BaseEndpoint: aws.String("https://" + op.host), Credentials: awsSetupCredentials{value: credentials}, HTTPClient: client, Retryer: aws.NopRetryer{}, Logger: logging.Nop{}})
	out, err := sdk.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return op.failure("authentication_refused", err)
	}
	if out == nil || aws.ToString(out.Account) != account || aws.ToString(out.Arn) != expected || aws.ToString(out.UserId) == "" {
		return op.failure("ownership_mismatch", nil)
	}
	return nil
}
