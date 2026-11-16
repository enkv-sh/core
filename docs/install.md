# Install ENKV

Install the **full** CLI archive for your native platform. It supports both AWS
and GCP domains. You need neither Go nor Git nor a GitHub login to use a
published binary. Cloud setup needs the relevant provider CLI later.

## 1. Choose an available release

Use the [ENKV installation site](https://enkv.sh/) or the
[core release list](https://github.com/enkv-sh/core/releases). Select a published
release and read its platform requirements and known limits. If the release
has no downloadable native archive, there is no binary installation path for
that release yet. Do not substitute GitHub's source-code archive.

| Your machine | Archive suffix | Requirement |
|---|---|---|
| Apple silicon Mac | `darwin-arm64.tar.gz` | Native arm64; use the macOS version supported by the selected release. |
| Linux x86_64 | `linux-amd64.tar.gz` | glibc 2.34 or later; not a musl-only system. |

Check the machine with `uname -s` and `uname -m`. Windows, Intel macOS and Linux
arm64 are not binary targets for this beta. Architecture alone does not prove
that a particular OS version meets the release requirements.

## 2. Download the archive

Download the exact archive through your browser over HTTPS. For example, the
first beta archive names are:

```text
enkv-full-0.1.0-beta.1-darwin-arm64.tar.gz
enkv-full-0.1.0-beta.1-linux-amd64.tar.gz
```

For a terminal download, copy the archive's HTTPS asset link from the release
page. Replace both values below with that release's actual name and link:

```sh
archive='enkv-full-0.1.0-beta.1-darwin-arm64.tar.gz'
archive_url='PASTE_HTTPS_ARCHIVE_ASSET_URL'
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output "$archive" "$archive_url"
```

Stop if the download fails. The normal installation route trusts HTTPS and the
release service. Optional [signature and checksum verification](verify-download.md)
adds a check using an independently trusted CLI public key. Perform that check
before extraction if you choose it.

## 3. Put the executable on PATH

Run these commands in the download directory. Set `archive` to the file you
actually downloaded, including the correct platform suffix:

```sh
archive='enkv-full-0.1.0-beta.1-darwin-arm64.tar.gz'
install_dir=$(mktemp -d) || exit 1
tar -xzf "$archive" -C "$install_dir" || exit 1
mkdir -p "$HOME/.local/bin" || exit 1
install -m 0755 "$install_dir/enkv" "$HOME/.local/bin/enkv" || exit 1
export PATH="$HOME/.local/bin:$PATH"
command -v enkv
enkv --help
```

Keep the archive, its version records, licenses and notices. Add the same PATH
line to your shell's startup file if `$HOME/.local/bin` is not already on PATH.
For the default macOS zsh, this is commonly `~/.zshrc`. Open a new terminal and
check `command -v enkv` again. If it finds a different installation, resolve the
PATH order before using your domain.

Expected result: `enkv --help` prints the supported commands and exits
successfully. It does not need cloud credentials. There is no `enkv --version`
command; identify the installed build from the retained archive and its records.

## 4. Approve the binary on macOS if required

The beta uses ENKV release signatures but does not use Apple Developer ID
signing or notarization. macOS may block the first launch.

After checking the download and attempting `enkv --help`, open **System Settings
→ Privacy & Security**. If macOS offers **Open Anyway** for that executable,
approve that specific file and confirm the next dialog. Then retry
`enkv --help`. Apple describes this procedure in
[Safely open apps on your Mac](https://support.apple.com/en-us/102445).

Do not disable Gatekeeper for the whole machine. A managed Mac can prohibit
manual approval; ask its administrator about the permitted installation route.
A malware or damaged-file warning needs investigation, not repeated approval.

## 5. Set up a domain

Installing the CLI creates no domain, keys or permissions. Continue with
[AWS setup](quickstart-aws.md) or [GCP setup](quickstart-gcp.md).

Plugins are separate executables. A supplied-secret first-use example needs no
generator or output plugin. Later, `enkv prepare` obtains required official
plugins for a valid configuration. Their authentication is mandatory even when
you did not perform optional external CLI signature verification.
