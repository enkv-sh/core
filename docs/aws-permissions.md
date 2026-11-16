# AWS permissions for ENKV

Use this guide when the resource owner assigns access for the
[AWS quickstart](quickstart-aws.md). ENKV has no user database or login service.
AWS credentials and IAM policies determine which cloud operations a caller can
perform. ENKV's authenticated recipient membership determines which selected
secrets that caller can decrypt through a Recipient key.

Use separate identities for provisioning, Authority operations and the
application Recipient. A bucket reader can see public metadata and encrypted
state; bucket access does not grant Authority signing or secret decryption.

## Required access by task

| Task | S3 access | KMS access |
|---|---|---|
| Initialize with Recovery disabled | Prefix get/put and bucket-wide list | Get public keys and metadata for Authority keys; sign with Authority signing key; decrypt with Authority encryption key. |
| Apply normal changes | Get and put; delete for supported cleanup | Sign with Authority key; decrypt with Authority encryption key; public-key/metadata reads for keys selected by the operation. |
| Inspect, public plan or read receipts | Get | No signing or decryption. |
| Prepare a new Recipient | Get | Get public key and metadata for that Recipient's key. |
| Consume an application's secret | Get | Decrypt with that application's Recipient key. |
| Run garbage collection | Get, list and guarded delete | Normal Authority signing/decryption as required by the operation. |
| Initialize with Recovery enabled | As for initialization | Also qualify and use the independent Recovery signing and encryption keys during initialization. |

Official output and generator plugins can need additional service permissions.
Their guides describe those permissions separately. Do not add Secrets Manager,
GitHub or Cloudflare privileges to the domain's storage role unless that role
will intentionally run that integration.

## Authority access

The following example scopes object access to one bucket prefix and KMS access
to three exact keys. It also permits bucket-wide listing for missing-object
detection. Replace every `YOUR_...` value. The Region and account in each key
ARN must be the key's actual values. Save the result as `authority-policy.json`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ObserveMissingDomainObjects",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::YOUR_BUCKET_NAME"
    },
    {
      "Sid": "OperateDomainObjects",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::YOUR_BUCKET_NAME/enkv/demo/*"
    },
    {
      "Sid": "ReadConfiguredPublicKeys",
      "Effect": "Allow",
      "Action": ["kms:DescribeKey", "kms:GetPublicKey"],
      "Resource": ["YOUR_AUTHORITY_SIGNING_KEY_ARN", "YOUR_AUTHORITY_ENCRYPTION_KEY_ARN", "YOUR_APP_ENCRYPTION_KEY_ARN"]
    },
    {
      "Sid": "SignDomainChanges",
      "Effect": "Allow",
      "Action": "kms:Sign",
      "Resource": "YOUR_AUTHORITY_SIGNING_KEY_ARN"
    },
    {
      "Sid": "DecryptAuthorityMaterial",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "YOUR_AUTHORITY_ENCRYPTION_KEY_ARN"
    }
  ]
}
```

S3 bucket actions use the bucket ARN; object actions use an object ARN ending
with the permitted prefix. The bucket-wide list permission is intentional. ENKV must distinguish a missing
object from a denied read during initialization and later work. A missing-object
GET has no `s3:prefix` request field; a list grant conditioned on that field does
not establish the required absence result. AWS documents the 403/404 distinction
in [GetObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html).
This policy allows the identity to list object names throughout the bucket,
while object reads and changes remain restricted to `enkv/demo/`. Use the new
bucket from the quickstart if exposing other object names is unacceptable. See
[AWS S3 action permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html).

The key policy must also permit this access. Keys created by the quickstart's
AWS CLI commands use the programmatic default key policy, which enables the
account to delegate access through IAM. If the owner uses another key policy,
review that policy as well. An IAM allow by itself can be ineffective. See
[AWS default key policies](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html).

For an existing ordinary IAM role, the owner can attach the policy with:

```sh
aws iam put-role-policy --profile "$ENKV_OWNER_PROFILE" \
  --role-name YOUR_AUTHORITY_ROLE_NAME --policy-name ENKVDemoAuthority \
  --policy-document file://authority-policy.json
```

This command needs the role name, not an assumed-role session ARN. It does not
create the role or its trust policy. The owner must first make the role
assumable by the intended human or workload through the organization's identity
process. See [AWS put-role-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/put-role-policy.html).

For IAM Identity Center, put the JSON into a custom permission set's inline
policy and assign that permission set to the operator in this AWS account.
Configure the profile from that assignment. Do not edit the service-managed
`AWSReservedSSO_...` role directly. See [Create a permission set](https://docs.aws.amazon.com/singlesignon/latest/userguide/howtocreatepermissionset.html).
Organization policies, permissions boundaries, session policies, bucket policies
and explicit denies can further restrict access. See [AWS policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html).

The `ReadConfiguredPublicKeys` list includes the app key so that Authority can
prepare the `app` Recipient. This permits public-key qualification; do not grant
the Authority identity private use of the app key merely to add the Recipient. Authority already has its own domain decryption
capability.

## Application Recipient access

The application identity needs object reads and decryption with its own key.
The quickstart exports this exact key ARN as `APP_ENCRYPTION_KEY`. Save the
policy below as `app-policy.json`, replace the placeholders and assign it through
the application's role or permission set using the same owner process.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::YOUR_BUCKET_NAME/enkv/demo/*"
    },
    {
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "YOUR_APP_ENCRYPTION_KEY_ARN"
    }
  ]
}
```

For an ordinary existing IAM role, attach it with:

```sh
aws iam put-role-policy --profile "$ENKV_OWNER_PROFILE" \
  --role-name YOUR_APP_ROLE_NAME --policy-name ENKVDemoRead \
  --policy-document file://app-policy.json
```

Give the application the trusted configuration pair through your deployment
process. Grant it membership only in the values it needs. It does not need
Authority signing, Authority decryption, Recovery access, bucket writes or
resource-administration permissions to consume its selected values.

A missing S3 object can appear as access denied when a caller lacks list
permission. Treat such a read as a failure, not proof that the object is absent.
The application policy deliberately does not grant bucket listing for ordinary
consumption.

## Enable Recovery before initialization

Recovery is a separate authority for supported recovery operations. It needs
independent signing and encryption keys and a separately controlled identity.
It does not recover deleted bucket data or deleted KMS keys. Ordinary `apply`
uses normal Authority capabilities and does not require private Recovery access.

Before the first `init`, the owner can create the additional pair:

```sh
ENKV_RECOVERY_SIGNING_KEY="$(aws kms create-key \
  --profile "$ENKV_OWNER_PROFILE" --region "$ENKV_REGION" \
  --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY --origin AWS_KMS \
  --description 'ENKV demo Recovery signing' \
  --query KeyMetadata.Arn --output text)"
export ENKV_RECOVERY_SIGNING_KEY

ENKV_RECOVERY_ENCRYPTION_KEY="$(aws kms create-key \
  --profile "$ENKV_OWNER_PROFILE" --region "$ENKV_REGION" \
  --key-spec RSA_3072 --key-usage ENCRYPT_DECRYPT --origin AWS_KMS \
  --description 'ENKV demo Recovery encryption' \
  --query KeyMetadata.Arn --output text)"
export ENKV_RECOVERY_ENCRYPTION_KEY
```

Use the exact returned ARNs in the configuration:

```yaml
  recovery:
    enabled: true
    signing_key: YOUR_RECOVERY_SIGNING_KEY_ARN
    encryption_key: YOUR_RECOVERY_ENCRYPTION_KEY_ARN
```

Keep this block under `domain`, at the same indentation as `authority`.
Initialization must resolve both pairs and perform its private qualification.
Its single AWS credential context therefore needs `kms:GetPublicKey` and
`kms:DescribeKey` on all four keys, `kms:Sign` on both signing keys, and
`kms:Decrypt` on both encryption keys, plus the domain S3 access above. The owner
can use a temporary initialization role with those exact permissions.

After initialization, use the limited normal Authority profile for daily work.
Keep private Recovery permissions with the separate Recovery operator; do not
leave them attached to the application role. Preserve the independent Recovery
resource identifiers in your operational records. Changing the YAML flag later
is not a supported way to change an initialized domain's Recovery choice.

Return to [the AWS quickstart](quickstart-aws.md#4-write-the-empty-configuration),
or read [Recovery](recovery.md) for local-file loss and supported recovery paths.
