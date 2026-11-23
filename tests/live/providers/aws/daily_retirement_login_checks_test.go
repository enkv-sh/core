package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/aws/smithy-go/logging"
)

func dailyRetirementTestInput(t *testing.T, role string) liveRunInput {
	t.Helper()
	const account = "123456789012"
	const region = "ap-southeast-2"
	const bucket = "enkv-123456789012-pa-0123456789abcdef0123456789abcdef"
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return liveRunInput{Settings: liveSettings{Provider: "aws", Account: account, Region: region, Bucket: bucket},
		PublicConfiguration: &publicConfigurationInput{
			Stock: &records.StockPluginAcceptanceInput{Fixture: records.StockPluginFixture{
				Schema: 1, Purpose: records.StockRetirementProofPurpose, FixtureID: "0123456789abcdef0123456789abcdef", Provider: "aws",
				Account: account, Region: region, Bucket: bucket, DailyRolePrefix: "enkv-orders-r01-public",
			}},
			Actors: map[string]liveSettings{role: {
				Provider: "aws", Account: account, Region: region, Bucket: bucket, SDKMode: "aws-assume-role", SDKHome: home, SDKProfile: "enkv-plugin-" + role,
			}},
		}}
}

// full_only: false
func TestDailyRetirementLoginConfigKeepsExactBrowserSource(t *testing.T) {
	const cli = "/controlled/aws"
	const expected = "[profile enkv-plugin-apply]\nregion = ap-southeast-2\nrole_arn = arn:aws:iam::123456789012:role/enkv-orders-r01-public-apply\nsource_profile = enkv-daily-orders-authority\nrole_session_name = enkv-daily-apply\n\n[profile enkv-daily-orders-authority]\nregion = ap-southeast-2\ncredential_process = /usr/bin/env -i 'HOME=HOME_PLACEHOLDER' 'AWS_CONFIG_FILE=HOME_PLACEHOLDER/.aws/config' 'AWS_SHARED_CREDENTIALS_FILE=/dev/null' 'AWS_EC2_METADATA_DISABLED=true' 'AWS_PAGER=' 'PATH=/usr/bin:/bin' '/controlled/aws' configure export-credentials --profile enkv-daily-orders-authority-login --format process\n\n[profile enkv-daily-orders-authority-login]\nregion = ap-southeast-2\nlogin_session = arn:aws:iam::123456789012:user/orders-authority\n"
	for _, role := range []string{"authority", "apply", "cleanup", "reader", "consumer"} {
		t.Run(role, func(t *testing.T) {
			input := dailyRetirementTestInput(t, role)
			body, err := dailyRetirementLoginConfig(input, role, cli)
			want := strings.ReplaceAll(expected, "HOME_PLACEHOLDER", input.PublicConfiguration.Actors[role].SDKHome)
			want = strings.ReplaceAll(want, "-apply", "-"+role)
			if role == "reader" || role == "consumer" {
				want = strings.ReplaceAll(want, "orders-authority", "orders-recipient")
			}
			if err != nil || string(body) != want {
				t.Fatal("daily fixture config changed its exact role or browser source")
			}
			path := filepath.Join(t.TempDir(), "config")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			selected, err := config.LoadSharedConfigProfile(t.Context(), "enkv-plugin-"+role, func(o *config.LoadSharedConfigOptions) {
				o.ConfigFiles, o.CredentialsFiles, o.Logger = []string{path}, []string{}, logging.Nop{}
			})
			if err != nil || selected.RoleARN != "arn:aws:iam::123456789012:role/enkv-orders-r01-public-"+role || selected.Source == nil ||
				!strings.HasPrefix(selected.Source.CredentialProcess, "/usr/bin/env -i ") || !strings.HasSuffix(selected.Source.CredentialProcess, " configure export-credentials --profile enkv-daily-"+dailyRetirementLoginUser(role)+"-login --format process") || stockAWSConfigUsesSSO(selected, "123456789012") {
				t.Fatal("SDK discovery or ordinary SSO admission changed")
			}
		})
	}
}

// full_only: false
func TestDailyRetirementLoginRefusesUnapprovedConfigBeforeCredentials(t *testing.T) {
	cliDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cliDir, "aws"), []byte("#!/bin/sh\nexit 91\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", cliDir+":/usr/bin:/bin")
	for _, condition := range []string{"valid", "root", "foreign-user", "wrong-user", "arbitrary-process", "extra-endpoint", "static", "extra-profile", "other-role", "other-source", "other-account", "other-prefix", "ordinary-fixture", "shared-credentials", "unknown-actor", "public-config"} {
		t.Run(condition, func(t *testing.T) {
			input := dailyRetirementTestInput(t, "apply")
			actor := input.PublicConfiguration.Actors["apply"]
			body, err := dailyRetirementLoginConfig(input, "apply", filepath.Join(cliDir, "aws"))
			if err != nil {
				t.Fatal(err)
			}
			text := string(body)
			switch condition {
			case "root":
				text = strings.ReplaceAll(text, ":user/orders-authority", ":root")
			case "foreign-user":
				text = strings.ReplaceAll(text, "login_session = arn:aws:iam::123456789012", "login_session = arn:aws:iam::999999999999")
			case "wrong-user":
				text = strings.ReplaceAll(text, ":user/orders-authority", ":user/orders-recipient")
			case "arbitrary-process":
				text = strings.ReplaceAll(text, "configure export-credentials", "sts get-caller-identity")
			case "extra-endpoint":
				text += "endpoint_url = https://unapproved.invalid\n"
			case "static":
				text += "aws_access_key_id = controlled\naws_secret_access_key = controlled\n"
			case "extra-profile":
				text += "\n[default]\ncredential_process = unapproved\n"
			case "other-role":
				text = strings.ReplaceAll(text, "role/enkv-orders-r01-public-apply", "role/enkv-orders-r01-public-cleanup")
			case "other-source":
				text = strings.ReplaceAll(text, "source_profile = enkv-daily-orders-authority", "source_profile = unapproved")
			case "other-account":
				input.Settings.Account = "999999999999"
			case "other-prefix":
				input.PublicConfiguration.Stock.Fixture.DailyRolePrefix = "unapproved"
			case "ordinary-fixture":
				input.PublicConfiguration.Stock.Fixture.Purpose = "stock-plugin-acceptance"
			case "shared-credentials":
				actor.SDKCredentialsFile = "/unapproved"
				input.PublicConfiguration.Actors["apply"] = actor
			case "unknown-actor":
				delete(input.PublicConfiguration.Actors, "apply")
			case "public-config":
				if err := os.Mkdir(filepath.Join(actor.SDKHome, ".aws"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll(filepath.Join(actor.SDKHome, ".aws"), 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(actor.SDKHome, ".aws", "config")
			if err := os.WriteFile(path, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			if condition == "public-config" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			err = validateDailyRetirementLogin(input, "apply")
			if (err == nil) != (condition == "valid") {
				t.Fatal("daily browser source admission differs", condition, err)
			}
		})
	}
}

// full_only: false
func TestDailyRetirementIdentityRequiresExactLivePrincipal(t *testing.T) {
	const account = "123456789012"
	for _, identity := range []struct{ name, arn string }{
		{"source", "arn:aws:iam::123456789012:user/orders-authority"},
		{"target", "arn:aws:sts::123456789012:assumed-role/enkv-orders-r01-public-apply/enkv-daily-apply"},
	} {
		expected := identity.arn
		for _, condition := range []string{"valid", "root", "other-user", "other-role", "other-session", "other-account", "missing-user-id", "denied", "budget"} {
			t.Run(identity.name+"/"+condition, func(t *testing.T) {
				observed, observedAccount, userID, status := expected, account, "CONTROLLED", 200
				switch condition {
				case "root":
					observed = "arn:aws:iam::123456789012:root"
				case "other-user":
					observed = "arn:aws:iam::123456789012:user/orders-recipient"
				case "other-role":
					observed = "arn:aws:sts::123456789012:assumed-role/unapproved/enkv-daily-apply"
				case "other-session":
					observed = "arn:aws:sts::123456789012:assumed-role/enkv-orders-r01-public-apply/other"
				case "other-account":
					observedAccount = "999999999999"
				case "missing-user-id":
					userID = ""
				case "denied":
					status = 403
				}
				calls := 0
				transport := awsOutputTestTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					body, err := io.ReadAll(r.Body)
					closeErr := r.Body.Close()
					if err != nil || closeErr != nil || string(body) != "Action=GetCallerIdentity&Version=2011-06-15" || r.URL.Host != "sts.ap-southeast-2.amazonaws.com" {
						t.Fatal("identity request changed its bounded fixed route")
					}
					reply := fmt.Sprintf(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>%s</Account><Arn>%s</Arn><UserId>%s</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`, observedAccount, observed, userID)
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(reply)), ContentLength: int64(len(reply)), Request: r}, nil
				})
				budget := &runBudget{limits: liveLimits{Requests: 1, BodyBytes: 2 * awsOutputRequestLimit}, keys: map[string]bool{}}
				if condition == "budget" {
					budget.limits.Requests = 0
				}
				err := verifyDailyRetirementIdentity(context.Background(), account, "ap-southeast-2", expected, aws.Credentials{AccessKeyID: "CONTROLLED", SecretAccessKey: "CONTROLLED", SessionToken: "CONTROLLED"}, budget, transport)
				if (err == nil) != (condition == "valid") || calls != 1 && condition != "budget" || condition == "budget" && calls != 0 {
					t.Fatal("identity mismatch or budget was accepted", condition, calls, err)
				}
			})
		}
	}
}

// full_only: false
func TestDailyRetirementCredentialRefreshPinsOriginalHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "actor home'$(false)`false`")
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "expected-home"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(t.TempDir(), "aws cli'quoted")
	script := `#!/bin/sh
set -eu
test -f "$HOME/expected-home"
test "$AWS_CONFIG_FILE" = "$HOME/.aws/config"
test "$AWS_SHARED_CREDENTIALS_FILE" = /dev/null
test "$AWS_EC2_METADATA_DISABLED" = true
test "$AWS_PAGER" = ''
test "$PATH" = /usr/bin:/bin
test -z "${AWS_ACCESS_KEY_ID+x}${AWS_SECRET_ACCESS_KEY+x}${AWS_SESSION_TOKEN+x}${AWS_PROFILE+x}${AWS_ENDPOINT_URL+x}"
test "$*" = 'configure export-credentials --profile enkv-daily-orders-authority-login --format process'
printf '%s' '{"Version":1,"AccessKeyId":"CONTROLLED","SecretAccessKey":"CONTROLLED","SessionToken":"CONTROLLED","Expiration":"2099-01-01T00:00:00Z","AccountId":"123456789012"}'
`
	if err := os.WriteFile(cli, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"HOME", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ENDPOINT_URL"} {
		t.Setenv(key, "HOSTILE_CONTROLLED_VALUE")
	}
	command := dailyRetirementCredentialProcess(home, cli, "enkv-daily-orders-authority-login")
	provider := processcreds.NewProvider(command)
	for attempt := 0; attempt < 2; attempt++ {
		credentials, err := provider.Retrieve(t.Context())
		if err != nil || !credentials.HasKeys() || credentials.SessionToken != "CONTROLLED" || !credentials.CanExpire || credentials.AccountID != "123456789012" {
			t.Fatal("credential refresh escaped the original browser-login home")
		}
	}
}

// full_only: false
func TestDailyRetirementWorkerAdmitsOnlyItsOwnLogin(t *testing.T) {
	input := dailyRetirementTestInput(t, "apply")
	bin := t.TempDir()
	cli := filepath.Join(bin, "aws")
	if err := os.WriteFile(cli, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	actor := input.PublicConfiguration.Actors["apply"]
	body, err := dailyRetirementLoginConfig(input, "apply", cli)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(actor.SDKHome, ".aws"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(actor.SDKHome, ".aws", "config"), body, 0600); err != nil {
		t.Fatal(err)
	}
	login := stockLoginFor(input)
	if login.identity == nil || login.config(input, "apply") != nil {
		t.Fatal("daily worker did not select browser identity verification")
	}
	identified := 0
	login.identity = func(context.Context, liveRunInput, string, string, *runBudget) error {
		identified++
		return nil
	}
	if err := login.admit(t.Context(), input, actor.SDKHome, nil, "apply", "reader"); err == nil || identified != 0 {
		t.Fatal("identity lookup started with an incomplete actor configuration")
	}
	if err := login.admit(t.Context(), input, actor.SDKHome, nil, "apply"); err != nil || identified != 1 {
		t.Fatal("admitted daily actor missed identity verification")
	}
	input.PublicConfiguration.Stock.Fixture.DailyRolePrefix = ""
	ordinary := stockLoginFor(input)
	if ordinary.identity != nil || ordinary.config(input, "apply") == nil {
		t.Fatal("ordinary stock worker accepted the browser login")
	}
}

// full_only: false
func TestDailyRetirementLoginChecksSourceBeforeAssumeRole(t *testing.T) {
	cliDir := t.TempDir()
	cli := filepath.Join(cliDir, "aws")
	script := "#!/bin/sh\nprintf '%s' '{\"Version\":1,\"AccessKeyId\":\"CONTROLLED_SOURCE\",\"SecretAccessKey\":\"CONTROLLED\",\"SessionToken\":\"CONTROLLED\",\"Expiration\":\"2099-01-01T00:00:00Z\",\"AccountId\":\"123456789012\"}'\n"
	if err := os.WriteFile(cli, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", cliDir+":/usr/bin:/bin")
	for _, condition := range []string{"valid", "source-root", "source-other-account", "role-denied", "other-target", "expired-source"} {
		t.Run(condition, func(t *testing.T) {
			input := dailyRetirementTestInput(t, "apply")
			home := input.PublicConfiguration.Actors["apply"].SDKHome
			body, err := dailyRetirementLoginConfig(input, "apply", cli)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(home, ".aws"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, ".aws", "config"), body, 0600); err != nil {
				t.Fatal(err)
			}
			selectedScript := script
			if condition == "expired-source" {
				selectedScript = strings.ReplaceAll(script, "2099-01-01", "2000-01-01")
			}
			if err := os.WriteFile(cli, []byte(selectedScript), 0700); err != nil {
				t.Fatal(err)
			}
			if err := validateDailyRetirementLogin(input, "apply"); err != nil {
				t.Fatal("controlled local login configuration refused", err)
			}
			var actions []string
			transport := awsOutputTestTransport(func(r *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(r.Body)
				closeErr := r.Body.Close()
				if err != nil || closeErr != nil || r.URL.Host != "sts.ap-southeast-2.amazonaws.com" {
					t.Fatal("STS route or body ownership changed")
				}
				form, err := url.ParseQuery(string(body))
				if err != nil {
					t.Fatal(err)
				}
				action := form.Get("Action")
				actions = append(actions, action)
				status, response := 200, ""
				if action == "AssumeRole" {
					if len(actions) != 2 || form.Get("RoleArn") != "arn:aws:iam::123456789012:role/enkv-orders-r01-public-apply" || form.Get("RoleSessionName") != "enkv-daily-apply" || !strings.Contains(r.Header.Get("Authorization"), "Credential=CONTROLLED_SOURCE/") {
						t.Fatal("source identity was not checked before exact target assumption")
					}
					response = `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>CONTROLLED_TARGET</AccessKeyId><SecretAccessKey>CONTROLLED</SecretAccessKey><SessionToken>CONTROLLED</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>CONTROLLED:enkv-daily-apply</AssumedRoleId><Arn>arn:aws:sts::123456789012:assumed-role/enkv-orders-r01-public-apply/enkv-daily-apply</Arn></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`
					if condition == "role-denied" {
						status = 403
						response = `<ErrorResponse><Error><Code>AccessDenied</Code><Message>controlled</Message></Error></ErrorResponse>`
					}
				} else if action == "GetCallerIdentity" {
					account := "123456789012"
					arn := "arn:aws:iam::123456789012:user/orders-authority"
					key := "CONTROLLED_SOURCE"
					if len(actions) == 1 {
						if condition == "source-root" {
							arn = "arn:aws:iam::123456789012:root"
						}
						if condition == "source-other-account" {
							account = "999999999999"
						}
					} else if len(actions) == 3 {
						arn = "arn:aws:sts::123456789012:assumed-role/enkv-orders-r01-public-apply/enkv-daily-apply"
						key = "CONTROLLED_TARGET"
						if condition == "other-target" {
							arn = strings.ReplaceAll(arn, "public-apply", "public-cleanup")
						}
					} else {
						t.Fatal("identity read escaped the exact preflight sequence")
					}
					if !strings.Contains(r.Header.Get("Authorization"), "Credential="+key+"/") {
						t.Fatal("identity read used another credential")
					}
					response = fmt.Sprintf(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>%s</Account><Arn>%s</Arn><UserId>CONTROLLED</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`, account, arn)
				} else {
					t.Fatal("unexpected provider action", action)
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response)), ContentLength: int64(len(response)), Request: r}, nil
			})
			budget := &runBudget{limits: liveLimits{Requests: 3, BodyBytes: 6 * awsOutputRequestLimit}, keys: map[string]bool{}}
			err = verifyDailyRetirementLoginWithTransport(t.Context(), input, "apply", t.TempDir(), budget, transport)
			want := 3
			switch condition {
			case "source-root", "source-other-account":
				want = 1
			case "role-denied":
				want = 2
			case "expired-source":
				want = 0
			}
			if (err == nil) != (condition == "valid") || len(actions) != want {
				t.Fatal("daily preflight sequence or refusal differs", condition, actions, err)
			}
		})
	}
}
