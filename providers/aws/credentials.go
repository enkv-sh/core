package awsprovider

import (
	"context"
	"time"

	"enkv.sh/providers/aws/credentials"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
)

var ErrCredentials = credentials.ErrCredentials

const credentialLimit = 64 << 10

func LoadSharedCredentialsFile(ctx context.Context, path, profile string, expires time.Time) (provider aws.CredentialsProvider, resultErr error) {
	ctx, call := startTelemetry(ctx, telemetry.OpAuthentication)
	defer func() { finishCredentialTelemetry(call, resultErr == nil) }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if path == "" || profile == "" {
		return nil, ErrCredentials
	}
	b, ok := captureCredentialFile(ctx, path, credentialLimit)
	if !ok {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrCredentials
	}
	if err := ctx.Err(); err != nil {
		clearCredentialBytes(b)
		return nil, err
	}
	parsed, ok := parseOwnedSharedCredentials(b, profile)
	if !ok {
		return nil, ErrCredentials
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v := aws.Credentials{
		AccessKeyID:     parsed.accessKeyID,
		SecretAccessKey: parsed.secretAccessKey,
		SessionToken:    parsed.sessionToken,
	}
	if (v.SessionToken != "" && expires.IsZero()) || (!expires.IsZero() && !time.Now().Before(expires)) {
		return nil, ErrCredentials
	}
	v.Source = "shared-file"
	v.CanExpire = !expires.IsZero()
	v.Expires = expires
	return fileCredentials{value: v}, nil
}

type fileCredentials struct{ value aws.Credentials }

func (c fileCredentials) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if err := ctx.Err(); err != nil {
		return aws.Credentials{}, err
	}
	if c.value.CanExpire && !time.Now().Before(c.value.Expires) {
		return aws.Credentials{}, ErrCredentials
	}
	return c.value, nil
}

type fixedCredentials struct{ value aws.Credentials }

func (c fixedCredentials) Retrieve(context.Context) (aws.Credentials, error) { return c.value, nil }
func retrieve(ctx context.Context, p aws.CredentialsProvider) (provider aws.CredentialsProvider, ok bool) {
	ctx, call := startTelemetry(ctx, telemetry.OpAuthentication)
	defer func() { finishCredentialTelemetry(call, ok) }()
	if ctx.Err() != nil {
		return nil, false
	}
	v, err := p.Retrieve(ctx)
	if err != nil || ctx.Err() != nil || v.AccessKeyID == "" || v.SecretAccessKey == "" || (v.CanExpire && !time.Now().Before(v.Expires)) {
		return nil, false
	}
	return fixedCredentials{value: v}, true
}
