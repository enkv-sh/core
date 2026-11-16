# Start a domain on Google Cloud

This guide creates an empty ENKV domain for an application named `demo`.
You will use Cloud Storage for state and Cloud KMS for keys. Then continue to
[your first secret](first-secret.md) to give the application a value.

Read [how ENKV works](concepts.md) and [install ENKV](install.md) first.
You also need the [Google Cloud CLI](https://cloud.google.com/sdk/docs/install),
an existing project with billing, and permission to create the resources below.
Cloud Storage and Cloud KMS can incur charges.

There are two kinds of work in this guide. The cloud resource owner creates
resources and grants permissions. The Authority operator then uses ENKV with
limited access to those resources. They can be different people. ENKV does not
create cloud keys, service accounts or IAM grants.

Run the commands in order. Stop after any failed command and resolve its cause
before continuing. The commands below change cloud resources only when the
resource owner runs them.

## 1. Choose the resources

**Cloud resource owner:** use a shell already authenticated for provisioning.
Replace the project ID and bucket name below. Bucket names are globally unique.
Keep these variables in the shell while following both this guide and the
linked permissions guide.

```sh
export ENKV_GCP_PROJECT='your-project-id'
export ENKV_GCP_REGION='australia-southeast1'
export ENKV_GCP_BUCKET='your-unique-enkv-demo-bucket'
export ENKV_GCP_KEYRING='enkv-demo'
```

Use a dedicated regional bucket for this example. Its location must match
`ENKV_GCP_REGION`: ENKV uses the corresponding regional Storage endpoint.
Google's [regional endpoint documentation](https://cloud.google.com/storage/docs/regional-endpoints)
explains the location requirement. Use a region that also supports Cloud KMS.

The main path explicitly disables ENKV Recovery. This means there is no
independent Recovery key pair if normal Authority access is lost. To enable
it, follow [the Recovery option](#option-enable-recovery) before initialization.
The choice is part of the domain's initial trust configuration.

## 2. Create the bucket and keys

**Cloud resource owner:** enable the APIs, then create a private bucket.

```sh
gcloud services enable storage.googleapis.com cloudkms.googleapis.com \
  iam.googleapis.com iamcredentials.googleapis.com \
  --project="$ENKV_GCP_PROJECT"

gcloud storage buckets create "gs://$ENKV_GCP_BUCKET" \
  --project="$ENKV_GCP_PROJECT" --location="$ENKV_GCP_REGION" \
  --uniform-bucket-level-access --public-access-prevention \
  --soft-delete-duration=7d

gcloud kms keyrings create "$ENKV_GCP_KEYRING" \
  --project="$ENKV_GCP_PROJECT" --location="$ENKV_GCP_REGION"
```

Keep this bucket free of rules that delete live ENKV objects by age. Do not
enable object holds or retention locks that prevent required conditional
replacement or deletion. Leave Object Versioning disabled for this example.
If you later enable it, provide finite retention for noncurrent versions.
Soft delete retains deleted or overwritten objects for the chosen seven days;
ENKV deletion does not promise immediate physical erasure.
See Google's [bucket creation options](https://cloud.google.com/sdk/gcloud/reference/storage/buckets/create)
and [soft delete behavior](https://cloud.google.com/storage/docs/soft-delete).

Create three separate keys. The first signs ENKV state. The second protects
the Authority's secret access. The third belongs to the application Recipient
that you will add in the next guide.

```sh
gcloud kms keys create normal-signing \
  --project="$ENKV_GCP_PROJECT" --location="$ENKV_GCP_REGION" \
  --keyring="$ENKV_GCP_KEYRING" --purpose=asymmetric-signing \
  --default-algorithm=ec-sign-p256-sha256 --protection-level=software

for key in authority-encryption app-encryption; do
  gcloud kms keys create "$key" \
    --project="$ENKV_GCP_PROJECT" --location="$ENKV_GCP_REGION" \
    --keyring="$ENKV_GCP_KEYRING" --purpose=asymmetric-encryption \
    --default-algorithm=rsa-decrypt-oaep-3072-sha256 \
    --protection-level=software
done
```

These are ENKV's required algorithms. A symmetric encryption key cannot
replace either encryption key. HSM protection is also supported when the
selected algorithm is available. The
[KMS creation reference](https://cloud.google.com/sdk/gcloud/reference/kms/keys/create)
defines the purpose, algorithm and protection flags.

For these new keys, creation also creates version `1`. Keep exact version
resources; do not substitute a CryptoKey name without `/cryptoKeyVersions/1`.

Asymmetric key generation can take time. Check all three versions before init:

```sh
for key in normal-signing authority-encryption app-encryption; do
  gcloud kms keys versions describe 1 --key="$key" \
    --project="$ENKV_GCP_PROJECT" --location="$ENKV_GCP_REGION" \
    --keyring="$ENKV_GCP_KEYRING" --format='value(state)'
done
```

Each result must be `ENABLED`. If it is `PENDING_GENERATION`, wait and repeat
this read-only check. Investigate any other state or error before continuing.
ENKV does not admit a pending key. See [Cloud KMS key states](https://cloud.google.com/kms/docs/key-states).

```sh
ENKV_GCP_KEY_BASE="projects/$ENKV_GCP_PROJECT/locations/$ENKV_GCP_REGION/keyRings/$ENKV_GCP_KEYRING/cryptoKeys"
export NORMAL_SIGNING_KEY="$ENKV_GCP_KEY_BASE/normal-signing/cryptoKeyVersions/1"
export AUTHORITY_ENCRYPTION_KEY="$ENKV_GCP_KEY_BASE/authority-encryption/cryptoKeyVersions/1"
export APP_ENCRYPTION_KEY="$ENKV_GCP_KEY_BASE/app-encryption/cryptoKeyVersions/1"
```

Do not disable or destroy versions that ENKV still requires. Creating a newer
version does not change an ENKV binding automatically.

## 3. Grant operator and application access

**Cloud resource owner:** complete [Google Cloud permissions](gcp-permissions.md).
It creates the application service account and grants the Authority operator
access to this bucket and these exact keys. It also prepares a separate,
restricted application credential route for the first-secret exercise.

The Authority operator needs signing and decryption with the normal pair.
The operator needs only public-key and metadata reads on `app-encryption`.
The application receives decryption on its own key and read access to state.

## 4. Select the Authority operator's credentials

**Authority operator:** use Application Default Credentials (ADC). At the browser
prompt, choose the limited operator account granted in the previous step.

```sh
gcloud auth application-default login
gcloud auth application-default set-quota-project "$ENKV_GCP_PROJECT"
```

ADC is separate from the account used by `gcloud` commands. A successful
`gcloud auth login` or `gcloud auth list` does not establish ENKV's credential
selection. If `GOOGLE_APPLICATION_CREDENTIALS` is set, ADC can select that file
instead of this local login. Check that it names the intended credentials, or
unset it for this workstation-login path.
See [local ADC setup](https://cloud.google.com/docs/authentication/set-up-adc-local-dev-environment).
The operator needs `serviceusage.services.use` on the quota project, as described
in the [quota-project command](https://cloud.google.com/sdk/gcloud/reference/auth/application-default/set-quota-project).

## 5. Write an empty configuration and initialize

**Authority operator:** work in a new application directory. Set the resource
variables above in this shell too if the owner used a different machine.

```sh
mkdir enkv-demo
cd enkv-demo
umask 077
cat > enkv.yaml <<EOF
schema: enkv/configuration/v3
domain:
  name: demo
  provider: gcp
  store:
    region: "$ENKV_GCP_REGION"
    bucket: "$ENKV_GCP_BUCKET"
    prefix: enkv/demo
  authority:
    display_name: Demo Authority
    signing_key: "$NORMAL_SIGNING_KEY"
    encryption_key: "$AUTHORITY_ENCRYPTION_KEY"
  recovery:
    enabled: false
recipients: {}
entries: {}
outputs:
  destinations: {}
  routing: {}
EOF

enkv init --source enkv.yaml
```

Init checks the nominated public keys, qualifies required private access and
creates the empty domain at this Store prefix. It writes the generated
companion `.enkv/demo.generated.json` and local initialization records. Keep
them with `enkv.yaml`. An existing domain at that prefix is not overwritten.

Continue only after init reports success and exits `0`. If it reports a failure
or an uncertain result, keep its files and use [troubleshooting](troubleshooting.md).
Do not delete the local records and start another init at the same prefix.

Next: [add and consume your first secret](first-secret.md).

## Option: enable Recovery

Before running init, have the owner create **two additional CryptoKeys** named
`recovery-signing` and `recovery-encryption`. Use the same creation commands and
algorithms as `normal-signing` and `authority-encryption`, respectively.
Generate the Recovery signing key in Cloud KMS; do not import it. Keep the
Recovery pair separate from the normal pair and arrange independent access to
it. Two versions of the same encryption CryptoKey do not establish this separation.
Run the same version-state check for `recovery-signing` and
`recovery-encryption`; both version `1` results must be `ENABLED` before init.

Replace the `recovery` block before initialization:

```yaml
  recovery:
    enabled: true
    signing_key: projects/YOUR_PROJECT/locations/australia-southeast1/keyRings/enkv-demo/cryptoKeys/recovery-signing/cryptoKeyVersions/1
    encryption_key: projects/YOUR_PROJECT/locations/australia-southeast1/keyRings/enkv-demo/cryptoKeys/recovery-encryption/cryptoKeyVersions/1
```

Replace `YOUR_PROJECT` and the location with your actual values. The one ADC
context used by init must temporarily have signing and decryption access to
both pairs, plus their public metadata. Follow the
[Recovery permission instructions](gcp-permissions.md#recovery-permissions).
After successful init, ordinary apply needs no private Recovery capability.
Recovery still depends on the required state and surviving cloud keys; it is
not a backup of the bucket.
