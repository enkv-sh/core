# Google Cloud permissions

Use this with [Google Cloud setup](quickstart-gcp.md). The cloud resource owner assigns IAM permissions
and creates one service account. Authority and the Recipient each sign in
under their own OS login.

The example uses a dedicated bucket. Grants on that bucket cover every object
in it, including other prefixes. Use separate buckets or a separately reviewed
IAM design when different domains need different cloud access.

## Choose the identities

Keep the resource variables from the setup guide. Set two IAM member strings:

```sh
export ENKV_GCP_AUTHORITY_USER='user:authority@example.com'
export ENKV_GCP_RECIPIENT_USER='user:recipient@example.com'
```

Replace the addresses with the two people's Google accounts. Authority signs
in directly. The Recipient signs in as the second user and impersonates the
service account created below.

ENKV roles come from the operation and keys used. They are not Google Cloud
IAM roles and are not selected by a username in `enkv.yaml`.

| ENKV use | Store access | KMS private access |
|---|---|---|
| Initialize with Recovery disabled | Read and write state | Normal signing and Authority decryption |
| Ordinary apply | Read/write; deletion for required state cleanup | Normal signing and Authority decryption |
| Prepare the Recipient binding | Read state | None; public-key and metadata reads on its key |
| Materialize a granted secret as the Recipient | Read state | Recipient key decryption only |
| Public inspection and ordinary public plan | Read state | None when using a valid trusted configuration pair |

Output and generator plugins need their own service permissions. Bucket or
KMS access alone does not authorize those external operations.

## Grant the Authority operator access

First create a project custom role for the three public key/metadata operations
used during key preparation and qualification. It grants no signing or decryption.
The metadata permissions are documented for
[CryptoKey reads](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/get)
and [CryptoKeyVersion reads](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/get).

```sh
gcloud iam roles create enkvPublicKeyRead --project="$ENKV_GCP_PROJECT" \
  --title='ENKV public key reads' --stage=GA \
  --permissions=cloudkms.cryptoKeys.get,cloudkms.cryptoKeyVersions.get,cloudkms.cryptoKeyVersions.viewPublicKey

for key in normal-signing authority-encryption recipient-encryption; do
  gcloud kms keys add-iam-policy-binding "$key" \
    --project="$ENKV_GCP_PROJECT" --location="$ENKV_GCP_REGION" \
    --keyring="$ENKV_GCP_KEYRING" --member="$ENKV_GCP_AUTHORITY_USER" \
    --role="projects/$ENKV_GCP_PROJECT/roles/enkvPublicKeyRead"
done

gcloud kms keys add-iam-policy-binding normal-signing \
  --project="$ENKV_GCP_PROJECT" --location="$ENKV_GCP_REGION" \
  --keyring="$ENKV_GCP_KEYRING" --member="$ENKV_GCP_AUTHORITY_USER" \
  --role=roles/cloudkms.signer

gcloud kms keys add-iam-policy-binding authority-encryption \
  --project="$ENKV_GCP_PROJECT" --location="$ENKV_GCP_REGION" \
  --keyring="$ENKV_GCP_KEYRING" --member="$ENKV_GCP_AUTHORITY_USER" \
  --role=roles/cloudkms.cryptoKeyDecrypter

gcloud storage buckets add-iam-policy-binding "gs://$ENKV_GCP_BUCKET" \
  --member="$ENKV_GCP_AUTHORITY_USER" --role=roles/storage.objectUser

gcloud projects add-iam-policy-binding "$ENKV_GCP_PROJECT" \
  --member="$ENKV_GCP_AUTHORITY_USER" --role=roles/serviceusage.serviceUsageConsumer
```

If the custom role already exists, inspect it instead of recreating it or
replacing an unrelated role. For details, see Google's
[custom role command](https://cloud.google.com/sdk/gcloud/reference/iam/roles/create).

Cloud KMS grants are attached to each CryptoKey and cover its versions. IAM
cannot attach a grant to only one version. ENKV still fixes the exact version
in its configuration. The predefined signing and decryption roles are listed
in the [Cloud KMS role reference](https://cloud.google.com/kms/docs/reference/permissions-and-roles).

`roles/storage.objectUser` is convenient for this dedicated bucket. Its object
management scope is wider than ENKV's four ordinary permissions:
`storage.objects.get`, `storage.objects.list`, `storage.objects.create` and
`storage.objects.delete`. A custom role can use those four when your policy
requires narrower grants. Replacement needs both create and delete access.
See the [Storage role reference](https://cloud.google.com/storage/docs/access-control/iam-roles)
and [operation permissions](https://cloud.google.com/storage/docs/access-control/iam-permissions).

## Prepare the Recipient service account

Create a service account with no downloaded private key:

```sh
gcloud iam service-accounts create enkv-demo-recipient \
  --project="$ENKV_GCP_PROJECT" --display-name='ENKV demo Recipient'
export ENKV_GCP_RECIPIENT_ACCOUNT="enkv-demo-recipient@$ENKV_GCP_PROJECT.iam.gserviceaccount.com"
export ENKV_GCP_RECIPIENT_MEMBER="serviceAccount:$ENKV_GCP_RECIPIENT_ACCOUNT"

gcloud storage buckets add-iam-policy-binding "gs://$ENKV_GCP_BUCKET" \
  --member="$ENKV_GCP_RECIPIENT_MEMBER" --role=roles/storage.objectViewer

gcloud kms keys add-iam-policy-binding recipient-encryption \
  --project="$ENKV_GCP_PROJECT" --location="$ENKV_GCP_REGION" \
  --keyring="$ENKV_GCP_KEYRING" --member="$ENKV_GCP_RECIPIENT_MEMBER" \
  --role=roles/cloudkms.cryptoKeyDecrypter

gcloud projects add-iam-policy-binding "$ENKV_GCP_PROJECT" \
  --member="$ENKV_GCP_RECIPIENT_MEMBER" --role=roles/serviceusage.serviceUsageConsumer

gcloud projects add-iam-policy-binding "$ENKV_GCP_PROJECT" \
  --member="$ENKV_GCP_RECIPIENT_USER" --role=roles/serviceusage.serviceUsageConsumer

gcloud iam service-accounts add-iam-policy-binding "$ENKV_GCP_RECIPIENT_ACCOUNT" \
  --project="$ENKV_GCP_PROJECT" --member="$ENKV_GCP_RECIPIENT_USER" \
  --role=roles/iam.serviceAccountTokenCreator
```

The service account has no normal signing or Authority decryption grant. Its
bucket access exposes public metadata and encrypted state. The Recipient can
materialize a secret when its entry grants membership and the service account
can decrypt with the Recipient key. The [service account command](https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/create)
creates this identity. The [IAM binding command](https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/add-iam-policy-binding)
grants the selected person the ability to obtain tokens for it.

## Sign in as the Recipient

Do this at the [first read](first-secret.md#5-materialize-as-the-recipient).
In the Recipient's own OS login, set `ENKV_GCP_PROJECT` to the same project ID
used at setup. The following email must match the account the owner created.
For this local ADC login, start with `GOOGLE_APPLICATION_CREDENTIALS` unset.

```sh
export ENKV_GCP_RECIPIENT_ACCOUNT="enkv-demo-recipient@$ENKV_GCP_PROJECT.iam.gserviceaccount.com"
gcloud auth application-default login \
  --impersonate-service-account "$ENKV_GCP_RECIPIENT_ACCOUNT"
gcloud auth application-default set-quota-project "$ENKV_GCP_PROJECT"
```

Choose the Recipient user's Google account at login. Token Creator permits
impersonation of this service account; it does not itself grant bucket or key
access. Those permissions belong to the service account. Google's
[ADC guide](https://cloud.google.com/docs/authentication/set-up-adc-local-dev-environment)
documents local impersonated ADC support for Go applications such as ENKV.

This writes the Recipient's local ADC file. Keep it under that person's OS
login. For later Authority work, return to Authority's OS login and its ADC.

## Recovery permissions

For enabled Recovery, create its separate keys before init as described in the
[setup guide](quickstart-gcp.md#option-enable-recovery). Grant the init operator
the public-read custom role on both keys. Also grant `roles/cloudkms.signer`
on `recovery-signing` and `roles/cloudkms.cryptoKeyDecrypter` on
`recovery-encryption`, using the same key-scoped binding commands above.

One credential context must have normal and Recovery private access during
init. After successful initialization, the owner can remove the operator's
two private Recovery grants with
[`gcloud kms keys remove-iam-policy-binding`](https://cloud.google.com/sdk/gcloud/reference/kms/keys/remove-iam-policy-binding),
using the same key, member, project, location, key ring and role arguments.
Keep public reads available for later qualification. Arrange private Recovery
access for the separate recovery operator before relying on it. Do not grant
the Recipient those capabilities.

## Check a permission failure

Confirm the credential route, resource project, exact key version, key state
and bucket location. An expired login is different from a valid identity that
lacks a required permission. Quota-project refusal needs
`serviceusage.services.use` on that project; it is not repaired by a KMS grant.
The [quota-project reference](https://cloud.google.com/sdk/gcloud/reference/auth/application-default/set-quota-project)
describes this requirement. Keep ENKV's result and use
[troubleshooting](troubleshooting.md) before repeating an uncertain operation.
