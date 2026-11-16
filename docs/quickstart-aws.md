# Create your first domain on AWS

This guide creates an empty ENKV domain called `demo`. A domain is one set of
values and access rules, stored under one cloud storage location. You will use
an S3 bucket for its state and two AWS KMS keys for its Authority. The Authority
is the operator that can apply changes and decrypt the domain's secrets.

After initialization, continue to [Your first secret](first-secret.md) to add an
application Recipient, store a secret and read it as that application.

## Before you start

Install [ENKV](install.md) and [AWS CLI version 2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).
You need an AWS account, an AWS Region, and permission from the resource owner to
create a bucket, KMS keys and the required access policies. AWS charges for these
resources and their use.

Keep three jobs distinct:

| Job | AWS identity |
|---|---|
| Create resources and assign permissions | The resource owner's provisioning identity. |
| Initialize and change this domain | A limited Authority role or IAM Identity Center permission set. |
| Consume the application's secrets | A separate application identity, prepared in the first-secret guide. |

The commands in the next two sections are **for the resource owner**. ENKV does
not create AWS resources, IAM roles or permissions. Use the organization's
existing identity process; the [permissions guide](aws-permissions.md) explains
what to assign.

This example keeps all resources in `ap-southeast-2` and the same account. Use a
new general-purpose bucket whose name contains lowercase letters, digits and
hyphens, with no dots. Do not use a directory bucket or an S3 access-point alias.
The example uses the state prefix `enkv/demo`; reserve it for this domain.

## 1. Create the bucket

Use one shell for these setup steps. Set the owner profile and a globally
unique bucket name. Replace the two values in angle brackets before running
these commands. If an AWS command fails, stop and resolve it before continuing:

```sh
export ENKV_OWNER_PROFILE='<your-provisioning-profile>'
export ENKV_BUCKET='<your-unique-bucket-name>'
export ENKV_REGION=ap-southeast-2
ENKV_ACCOUNT_ID="$(aws sts get-caller-identity \
  --profile "$ENKV_OWNER_PROFILE" --query Account --output text)"
export ENKV_ACCOUNT_ID

aws s3api create-bucket --profile "$ENKV_OWNER_PROFILE" \
  --region "$ENKV_REGION" --bucket "$ENKV_BUCKET" \
  --create-bucket-configuration LocationConstraint="$ENKV_REGION" \
  --object-ownership BucketOwnerEnforced

aws s3api put-public-access-block --profile "$ENKV_OWNER_PROFILE" \
  --region "$ENKV_REGION" --bucket "$ENKV_BUCKET" \
  --expected-bucket-owner "$ENKV_ACCOUNT_ID" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

The create command above is for `ap-southeast-2`. If you choose `us-east-1`, omit
`--create-bucket-configuration`. See the [AWS create-bucket reference](https://docs.aws.amazon.com/cli/latest/reference/s3api/create-bucket.html)
and [Block Public Access command](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-public-access-block.html).

Use the new bucket's default unversioned storage and SSE-S3 encryption. Do not
enable Object Lock or a policy that expires live ENKV objects. ENKV encrypts
secret values before storage; S3 encryption is an additional storage layer. A
bucket that requires SSE-KMS needs additional S3 KMS permissions and a separate
compatible policy; it is outside this example. See [AWS bucket encryption](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-encryption.html).

For an existing versioned bucket, arrange finite retention of noncurrent object
versions with the owner. Disabling future versioning alone does not remove old
versions. See [S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html).
ENKV garbage collection does not promise physical erasure of provider-retained
copies.

## 2. Create the Authority and application keys

Create separate KMS keys for signing and encryption. Capture the exact key ARNs
from AWS; ENKV does not accept an alias in place of a key ARN.

```sh
ENKV_AUTHORITY_SIGNING_KEY="$(aws kms create-key \
  --profile "$ENKV_OWNER_PROFILE" --region "$ENKV_REGION" \
  --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY --origin AWS_KMS \
  --description 'ENKV demo Authority signing' \
  --query KeyMetadata.Arn --output text)"
export ENKV_AUTHORITY_SIGNING_KEY

ENKV_AUTHORITY_ENCRYPTION_KEY="$(aws kms create-key \
  --profile "$ENKV_OWNER_PROFILE" --region "$ENKV_REGION" \
  --key-spec RSA_3072 --key-usage ENCRYPT_DECRYPT --origin AWS_KMS \
  --description 'ENKV demo Authority encryption' \
  --query KeyMetadata.Arn --output text)"
export ENKV_AUTHORITY_ENCRYPTION_KEY

APP_ENCRYPTION_KEY="$(aws kms create-key \
  --profile "$ENKV_OWNER_PROFILE" --region "$ENKV_REGION" \
  --key-spec RSA_3072 --key-usage ENCRYPT_DECRYPT --origin AWS_KMS \
  --description 'ENKV demo application encryption' \
  --query KeyMetadata.Arn --output text)"
export APP_ENCRYPTION_KEY
```

The application key is a third key. The first-secret guide enrolls it as the
`app` Recipient. Keep `APP_ENCRYPTION_KEY` set to its exact returned ARN for
that guide. Give the application private access only to this key.

The required types are P-256 signing with `ECDSA_SHA_256` and RSA-3072 encryption
with `RSAES_OAEP_SHA_256`. A symmetric KMS key, a different RSA size or an
asymmetric signing key used for encryption will not work. AWS keeps the private
keys in KMS; ENKV retrieves their public keys. The [AWS create-key reference](https://docs.aws.amazon.com/cli/latest/reference/kms/create-key.html)
describes the key options.

Save the account ID, bucket, Region, prefix and all three exact ARNs in your
protected operational records. They are needed to reconstruct configuration after local
file loss. Keep the KMS keys available for as long as their protected data or
retained work requires them.

## 3. Assign access, then sign in as Authority

The owner must assign the [Authority policy](aws-permissions.md#authority-access)
to the intended role or permission set before initialization. Also assign the
[application policy](aws-permissions.md#application-recipient-access) to a
separate application role or permission set. A login alone does not establish
those permissions.

For IAM Identity Center, create a named profile and sign in. Choose the account
and limited Authority role that the owner assigned:

```sh
aws configure sso --profile enkv-demo-authority
aws sso login --profile enkv-demo-authority
export AWS_PROFILE=enkv-demo-authority
export AWS_REGION=ap-southeast-2
aws sts get-caller-identity
```

Configure the application's separate profile now, using its limited assignment:

```sh
aws configure sso --profile enkv-demo-app
```

Keep `AWS_PROFILE=enkv-demo-authority` for initialization and the writer steps in
the first-secret guide. When that guide asks for application credentials, use
`aws sso login --profile enkv-demo-app` and select `AWS_PROFILE=enkv-demo-app`.
For a deployed workload, its assigned IAM role can supply credentials through
the standard AWS SDK chain instead of an interactive SSO login.

Check the returned account and role. ENKV uses the AWS SDK's standard credential
chain. Environment credentials can take precedence over a named profile; use a
shell without credentials for another identity. ENKV does not have an AWS login
command. See [AWS IAM Identity Center login](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
and [credential setting precedence](https://docs.aws.amazon.com/sdkref/latest/guide/settings-reference.html).

## 4. Write the empty configuration

Create a working directory and save this as `enkv.yaml`. Replace the bucket,
account and key values with the actual values from the owner. ENKV does not
expand shell variables inside YAML.

```yaml
schema: enkv/configuration/v3
domain:
  name: demo
  provider: aws
  store:
    region: ap-southeast-2
    bucket: YOUR_BUCKET_NAME
    prefix: enkv/demo
    expected_owner: 'YOUR_12_DIGIT_ACCOUNT_ID'
  authority:
    display_name: Demo operator
    signing_key: YOUR_AUTHORITY_SIGNING_KEY_ARN
    encryption_key: YOUR_AUTHORITY_ENCRYPTION_KEY_ARN
  recovery:
    enabled: false
recipients: {}
entries: {}
outputs:
  destinations: {}
  routing: {}
```

`expected_owner` is the twelve-digit account that owns the bucket. Keep it
quoted. `entries: {}` is intentional: initialization requires an empty value
set. Do not add a `generated` field or create the companion file yourself.

This guide explicitly disables Recovery. If normal Authority access is lost,
there is no independent Recovery authority for this domain. To enable it from
the start, follow [Enable Recovery before initialization](aws-permissions.md#enable-recovery-before-initialization)
and replace the `recovery` block before the next step.

## 5. Initialize and check the result

Run from the directory containing `enkv.yaml`, using the Authority profile:

```sh
enkv init --source enkv.yaml --json
enkv inspect --source enkv.yaml --json
```

Successful initialization creates the empty authenticated domain, updates
`enkv.yaml`, and writes `.enkv/demo.generated.json` and an initialization manifest
under `.enkv/`. Inspection should report an empty domain without reading secret
values. Keep the editable file and generated companion together at the same
relative paths. Keep the initialization manifest and command result as well.

If init reports failure or an unknown outcome, preserve these files and the
result. Do not delete `.enkv/`, recreate the YAML or point a new domain at the
same prefix. Use [Troubleshooting](troubleshooting.md) before another operation.

You now have a domain with no application values. Continue to
[Your first secret](first-secret.md).
