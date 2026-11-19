# Store and use your first secret

Finish [AWS setup](quickstart-aws.md) or [GCP setup](quickstart-gcp.md) for the
`demo` domain. Two people use ENKV. Authority grants the Recipient access to
`API_TOKEN`. The Recipient runs `enkv materialize` to write a private file.
A local worker reads that file.

Authority runs steps 1–4 from the directory with `enkv.yaml` and its generated
companion. Use the Authority credentials from setup. Set `RECIPIENT_ENCRYPTION_KEY`
to the Recipient key ARN (AWS) or key version name (GCP) from the owner. Use the
disposable value below for this exercise. Check each command result before continuing.

<a id="1-prepare-the-application-recipient"></a>

## 1. Prepare the Recipient binding

With normal Authority credentials, run:

```sh
enkv recipients add --json --recipient recipient --mode create \
  --display-name 'Demo Recipient' --encryption-key "$RECIPIENT_ENCRYPTION_KEY"
```

`recipient` is a local alias. ENKV records a stable ID and the public key binding
in the configuration pair. `Demo Recipient` is a display name. Authority enrolls
this identity and grants its entry membership at `apply` in step 4.

## 2. Declare the secret and its access

Replace the empty `entries: {}` in `enkv.yaml` with this block. Preserve every
other part of the initialized file, including `generated` and the recipient ID:

```yaml
entries:
  API_TOKEN:
    confidentiality: secret
    recipients: [recipient]
    source:
      kind: supplied
```

Authority is also a recipient automatically. This local declaration is
temporarily missing its input; the next `set` supplies it. Define membership
**before** sealing the value. Sealed input binds the intended recipient keys.

## 3. Supply the value through stdin

Create a protected working directory and a clearly non-production input:

```sh
umask 077
mkdir -p .private
printf '%s' 'demo-token-not-for-production' > .private/API_TOKEN.input
enkv set --json --name API_TOKEN < .private/API_TOKEN.input
```

`set` reads stdin once and writes protected input to the generated companion.
It makes no Store or KMS call and does not apply the change. The input file
remains plaintext. For real use, obtain it through your approved secret-input
process; do not place a real value in a shell command or public repository.

The example uses `printf` to avoid adding a newline. ENKV preserves input bytes;
an editor-added newline becomes part of the value. Do not use `--confidential=false`
for a secret. No plugin is needed for this supplied value.

## 4. Review and apply

Plan is optional. You can run `enkv apply --json` directly. Apply reads the
current declaration and does not require a saved plan. This guide includes a
review step so you can check the intended change first.

Use the same normal Authority credentials:

```sh
plan_status=0
enkv plan --json || plan_status=$?
case "$plan_status" in
  0|1) ;;
  *) printf 'Plan did not complete (exit %s).\n' "$plan_status"; exit "$plan_status" ;;
esac
```

Plan exits `0` for a complete match and `1` for complete verified differences.
The first addition should produce differences. The block above permits those
two outcomes and stops on any other exit, including in a shell with `set -e`.
Read the plan before running apply. It should describe the intended recipient
and entry changes. Public planning does not decrypt proposed secret bytes or
prove all later private checks will pass.

After you approve the displayed changes, run:

```sh
enkv apply --json
```

A successful apply makes the complete declaration current. It does not modify
the local pair and does not publish to an external service. Preserve the result,
including any operation and observation references, in a protected place. If
apply is refused or uncertain, use [Troubleshooting](troubleshooting.md) before
issuing another mutation.

You can now inspect the selected recipient without displaying secret content:

```sh
enkv inspect --json --recipient recipient
```

Check that the result describes the expected recipient and `API_TOKEN` entry.

## 5. Materialize as the Recipient

Authority gives the Recipient the approved `enkv.yaml` and
`.enkv/demo.generated.json` through a trusted channel. Preserve their relative
paths. Keep Authority's plaintext input and credentials in Authority's workspace.

The Recipient works in their own OS login, in the directory with their copy of
`enkv.yaml`. On AWS, use the Region in `ENKV_REGION` and the Recipient profile
from the quickstart.

```sh
aws sso login --profile orders-recipient
export AWS_PROFILE=orders-recipient
export AWS_REGION="$ENKV_REGION"
aws sts get-caller-identity
```

Check that the AWS account and role match the Recipient assignment. On GCP,
follow [Sign in as the Recipient](gcp-permissions.md#sign-in-as-the-recipient)
to select the Recipient service account through ADC.

With the Recipient credentials for your provider, write `API_TOKEN` to a file.

```sh
umask 077
mkdir -p .private
enkv materialize --json --name API_TOKEN --recipient recipient \
  --out .private/worker.env
```

Expect a successful result and a mode-0600 dotenv file. ENKV resolves the alias
`recipient` in the pair and checks membership in the current entry. It reads the
Store and uses the Recipient key to decrypt the secret. Omitting the recipient
flag selects Authority, which needs its own decryption permission. A successful
write replaces an existing regular file at the selected path.

## 6. Read the file with a local worker

The builtin file profile supports **dotenv 18.0.9 default `parse`**, without
expansion. Do not execute the file with `source` or assume compatibility with
Docker env files. For other consumers, use a suitable
[output or manifest route](outputs.md).

In the Recipient's OS login, run this local worker with Node.js 24 and npm.
It needs read access to `.private/worker.env`. It makes no ENKV or cloud calls.

```sh
(
  set -e
  mkdir worker
  cd worker
  npm init -y
  npm install --save-exact dotenv@18.0.9
  node - <<'JS'
const fs = require('node:fs');
const dotenv = require('dotenv');
const values = dotenv.parse(fs.readFileSync('../.private/worker.env'));
if (values.API_TOKEN !== 'demo-token-not-for-production') process.exit(1);
console.log('Worker read the expected demo value.');
JS
)
```

The worker checks the exact disposable value without printing it. See the
[versioned dotenv parse documentation](https://github.com/motdotla/dotenv/blob/v18.0.9/README.md#parse).

## After the example

Run later domain changes in Authority's original workspace and login. Each
person protects or removes the plaintext files they created. Deletion does not
prove physical erasure. Keep the configuration pair. Do not
delete the cloud keys or bucket while the domain still matters.

Continue with [Daily operations](operations.md), [Access](access.md) or
[Generated secrets](generated-secrets.md).
