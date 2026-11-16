# Store and use your first secret

This guide adds a supplied secret to an initialized `demo` domain and reads it
as an application recipient. Finish [AWS setup](quickstart-aws.md) or
[GCP setup](quickstart-gcp.md) first. You need:

- A successful empty-domain init and its complete `enkv.yaml` pair.
- Normal Authority credentials for preparation and apply.
- The app encryption key in `$APP_ENCRYPTION_KEY`, created by the cloud guide.
- A separate app credential context with Store reads and app-key decryption.

Run commands in the directory containing `enkv.yaml`. Keep the same terminal
environment from setup, or restore its non-secret resource variables. Stop and
read the result if any command fails. Use a disposable example value for this
first pass; the commands below do not contact a real API service.

## 1. Prepare the application recipient

With normal Authority credentials, run:

```sh
enkv recipients add --json --recipient app --mode create \
  --display-name 'Demo application' --encryption-key "$APP_ENCRYPTION_KEY"
```

This writes public recipient data to the local pair. It does not yet enroll
the recipient in current domain state. ENKV writes the recipient's stable `id`
and its public key binding. Later commands can select it with `--recipient app`;
you do not need to copy the ID.

## 2. Declare the secret and its access

Replace the empty `entries: {}` in `enkv.yaml` with this block. Preserve every
other part of the initialized file, including `generated` and the recipient ID:

```yaml
entries:
  API_TOKEN:
    confidentiality: secret
    recipients: [app]
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
enkv inspect --json --recipient app
```

Check that the result describes the expected recipient and `API_TOKEN` entry.

## 5. Read as the application

Switch to the limited application credential context. On AWS, use the profile
from [AWS permissions](aws-permissions.md):

```sh
aws sso login --profile enkv-demo-app
export AWS_PROFILE=enkv-demo-app
```

On GCP, use the application ADC procedure in
[GCP permissions](gcp-permissions.md). A `gcloud` CLI account switch alone does
not switch ENKV's ADC credentials. Keep the complete configuration pair, which
maps the `app` alias to the recipient created in step 1.

For a separate application machine, transfer the approved configuration pair
through your normal controlled deployment process, preserving its relative
paths. The cloud key identifier is not a private key to copy.

As the application identity, write the current secret to a private file:

```sh
umask 077
mkdir -p .private
enkv materialize --json --name API_TOKEN --recipient app \
  --out .private/app.env
```

Expected result: successful materialization and a mode-0600 dotenv file. ENKV
reads the current Store value, not a pending local proposal. It needs the app's
decryption permission; it does not need Authority signing. The `--recipient app`
flag selects the application. Omitting both recipient flags selects Authority,
which needs its own decryption permission even for a shared value. A successful write
replaces an existing regular destination file, so choose the path deliberately.

## 6. Let an application consume it

The builtin file profile supports **dotenv 18.0.9 default `parse`**, without
expansion. Do not execute the file with `source` or assume compatibility with
Docker env files. For other consumers, use a suitable
[output or manifest route](outputs.md).

For an optional Node.js example, use Node.js 24 and npm in a new directory:

```sh
mkdir consumer
cd consumer
npm init -y
npm install --save-exact dotenv@18.0.9
node - <<'JS'
const fs = require('node:fs');
const dotenv = require('dotenv');
const values = dotenv.parse(fs.readFileSync('../.private/app.env'));
if (values.API_TOKEN !== 'demo-token-not-for-production') process.exit(1);
console.log('Application received the expected demo value.');
JS
cd ..
```

The example checks the disposable value without printing it. Your application
can use the returned value directly. See the
[versioned dotenv parse documentation](https://github.com/motdotla/dotenv/blob/v18.0.9/README.md#parse).

## After the example

Return to the normal Authority credential context before later writes. Protect
or remove the plaintext input and output according to your local policy;
deletion does not prove physical erasure. Keep the configuration pair. Do not
delete the cloud keys or bucket while the domain still matters.

Continue with [Daily operations](operations.md), [Access](access.md) or
[Generated secrets](generated-secrets.md).
