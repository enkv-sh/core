# Native CLI archives

The `enkv-cli-package` command builds CLI archives for `full`, `aws` and
`gcp` on native `darwin/arm64` and `linux/amd64`. Each archive contains `enkv`,
`LICENSE`, `THIRD_PARTY_NOTICES.md`, and `NOTICE` when the main source owner has
one. It contains no plugin executable. The AWS and GCP selections use the fixed
`enkv_aws` and `enkv_gcp` build tags.

The first beta distributes only the `full` archive on each native platform.
Selected-provider recipes remain available for development. Apple Developer ID
signing and notarization are deferred for this beta; manual macOS approval is
accepted. Production ENKV signatures remain required. A release candidate needs
actual native installation checks and checks of the public downloaded bytes.

These bundles select domain Store/KMS support. They do not compile a provider or
format membership list for plugins. New compatible local plugin IDs and behavior
use the same captured CLI through explicit installation and selection.

Use stock Go 1.27.3 and the native C toolchain. CLI builds enable cgo because the
native plugin hosts require it. Linux requires glibc 2.34 or later. Build the
packaging command from the full composition module in the coordinated source
workspace:

```sh
cd /ABSOLUTE/enkv-core/compositions/full
GOWORK=/ABSOLUTE/enkv-extensions/go.work \
  go build -mod=readonly -o /ABSOLUTE/tools/enkv-cli-package ./cmd/enkv-cli-package
```

The tools directory must exist. The packaging command does not run the CLI,
install plugins, sign files, or send files to a remote service. Packaging is a
CLI release task; a plugin author uses the separate
[artifact tool](https://github.com/enkv-sh/extensions/blob/main/sdk/artifact/README.md) and
[local installation route](https://github.com/enkv-sh/extensions/blob/main/distribution/local-installation.md#trust-a-local-author-build).

## Development assembly

Supply separate Ed25519 SPKI PEM public keys for plugins and CLI checksums.
The catalog must use an explicit loopback IP, HTTPS, and a trailing slash. Supply
the controlled catalog's TLS certificate PEM. The command rejects private-key
PEM inputs. Repeat `-plugin-public-key` to retain earlier plugin verification
keys. Every plugin key must differ from the CLI key.

```sh
/ABSOLUTE/tools/enkv-cli-package \
  -directory /ABSOLUTE/enkv-core/compositions/full \
  -bundle full -version 0.1.0 \
  -workspace /ABSOLUTE/enkv-extensions/go.work \
  -environment development \
  -plugin-public-key /ABSOLUTE/keys/development-plugin-public.pem \
  -cli-public-key /ABSOLUTE/keys/development-cli-public.pem \
  -development-origin https://127.0.0.1:43443/releases/ \
  -development-tls-root /ABSOLUTE/keys/catalog-tls.pem \
  -output /ABSOLUTE/packages/full-development
```

The output directory must not exist. Its parent must exist. A failed command can
leave a partial output directory; use a new directory for the next attempt.
The command writes one `enkv-<bundle>-<version>-<os>-<arch>.tar.gz` and one
`checksums.txt`. It prints the bundle, native platform, assembly environment, source mode,
toolchain, compiled module count, and exact checksum. Build metadata in version strings uses `_` in the archive
filename. Archive members have fixed names, modes, order, and timestamps.
Legal material comes from the selected compiled module owners and Go toolchain.
The shared collector includes supported legal files in each selected package or
input's ancestor directories, all Go source comments, and leading native source
comment blocks. It preserves
separate file copyright notices as well as module licenses. See the
[supported legal layouts](https://github.com/enkv-sh/extensions/blob/main/sdk/artifact/README.md)
for the exact inventory. Before release, review the selected dependency closure
for legal material outside those layouts and inspect the final archive's legal
members on each native platform. Automated collection does not decide which
license applies to a file or establish legal completeness.

For selected-provider development archives, repeat with `-bundle aws` and
`-bundle gcp`, each with a new output directory. The beta needs only `-bundle full`
on each supported native platform. A cross-build does not supply native
qualification, and the command rejects it. Custom compiler flags and compiler
overrides are refused.
Successful compiler diagnostics remain visible on stderr; a compiler failure or
a diagnostic-output failure fails the command.

## Production assembly and versioned inputs

For production, set `-environment production`, use production public keys, and
omit both development options. Production assembly fixes the catalog origin to
`https://enkv.sh/releases/`, permits release-asset redirects only to `github.com`
and `release-assets.githubusercontent.com`, and uses system TLS roots.

The owner must provision different development and production keys. A single
build cannot prove which keys were used in earlier builds. Keep plugin and CLI
signing keys separate in each environment, including retained plugin keys.

Source builds require `-workspace` with an absolute regular workspace file.
For versioned builds, use `-versioned` in place of `-workspace`. All dependencies
must resolve to real versions, including replacements; local checkout
replacements are refused. Follow the [versioned-source instructions](https://github.com/enkv-sh/extensions/blob/main/distribution/README.md#versioned-dependency-builds)
for exact reachable source versions. The command uses `-mod=readonly`,
`GOWORK=off` in versioned mode, the stock Go toolchain, and the same native
platform in both modes. It checks compiled module identities against the selected
source closure before packaging.

## Checksums, signatures, and installation

Each per-build checksum file covers its archive's exact compressed bytes. To
make one checksum file for several archives, use the separate checksum command:

```sh
/ABSOLUTE/tools/enkv-cli-package \
  -checksums /ABSOLUTE/packages/checksums.txt \
  /ABSOLUTE/packages/full-darwin/enkv-full-0.1.0-beta.1-darwin-arm64.tar.gz \
  /ABSOLUTE/packages/full-linux/enkv-full-0.1.0-beta.1-linux-amd64.tar.gz
```

This mode reads regular archive files, computes their exact SHA-256 digests,
sorts by basename, and refuses duplicate names or an existing output file.
It does not rebuild archives. Sign the final checksum file with the separate
CLI signing key, using the artifact signing command's `cli-checksums` purpose.
Keep the exact checksum file and its detached 64-byte signature together.

Normal installation trusts the HTTPS download service and its release account;
it requires no external signature verifier. Operators can additionally verify
the checksum-file signature before extraction or execution with trusted OpenSSL
3.x and an independently trusted CLI public key:

```sh
openssl pkeyutl -verify -pubin -inkey cli-public.pem \
  -rawin -in checksums.txt -sigfile checksums.sig
```

For this optional verification path, also check the selected archive against its
exact checksum row with a trusted SHA-256 tool. A checksum or key beside an
untrusted download does not independently establish authenticity. See the
[installation guide](https://github.com/enkv-sh/extensions/blob/main/distribution/local-installation.md#optional-signature-verification) for
the complete verification example. Release-candidate verification remains required before publication.

Extract into an empty directory and put `enkv` on `PATH`. Retain the legal files.
CLI installation does not install or prepare plugins; run the normal explicit
`prepare` command for the application. Official-plugin signature and integrity
checks remain automatic and mandatory.

The CLI public root embedded in the executable keeps signing purposes separate.
It does not authenticate the executable before execution. The external signature
and checksum checks perform that verification. Replacing the trusted executable
is how an operator changes its embedded distribution roots.
