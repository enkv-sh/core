# Verify a CLI download

This optional procedure verifies the release's checksum signature and then the
archive checksum. It requires trusted **OpenSSL 3.x**, a SHA-256 tool, and the
CLI Ed25519 public key in SPKI PEM format. The normal HTTPS
[installation route](install.md) does not require OpenSSL.

## Obtain the right inputs

Download the native CLI archive, `checksums.txt` and `checksums.sig` from the
same release. Obtain the CLI verification public key through an independently
trusted channel and confirm its fingerprint through that channel. A key from
the same untrusted source as an altered archive cannot establish authenticity.

Use the **CLI** public key, not the separate official-plugin public key. Do not
use a development key. If the release does not provide the required signature
or independently trusted key information, you cannot complete this check.

## Verify the signature

Check `openssl version`; these commands require the supported 3.x executable.
Replace the key path with your trusted file:

```sh
openssl pkeyutl -verify -rawin -pubin \
  -inkey /absolute/trusted-cli-public.pem \
  -in checksums.txt -sigfile checksums.sig || exit 1
```

Proceed only when verification succeeds. Do not extract or run an archive after
a failed signature check.

## Verify the archive bytes

Set the exact archive filename. On macOS, use:

```sh
archive='enkv-full-0.1.0-beta.2-darwin-arm64.tar.gz'
expected=$(awk -v name="$archive" '$2 == name {print $1}' checksums.txt)
actual=$(shasum -a 256 "$archive") || exit 1
[ -n "$expected" ] && [ "$expected" = "${actual%% *}" ] || exit 1
```

On Linux, use the same comparison with `sha256sum`:

```sh
archive='enkv-full-0.1.0-beta.2-linux-amd64.tar.gz'
expected=$(awk -v name="$archive" '$2 == name {print $1}' checksums.txt)
actual=$(sha256sum "$archive") || exit 1
[ -n "$expected" ] && [ "$expected" = "${actual%% *}" ] || exit 1
```

No output and a zero exit status from the comparison mean the archive matches
the signed checksum. A mismatch, missing filename or failed command means stop
and obtain the correct release files. Keep the verified files and key
fingerprint with your installation record.

Continue with [extraction and PATH setup](install.md#3-put-the-executable-on-path).
This check verifies downloaded bytes; it does not grant cloud access or replace
plugin authentication.
