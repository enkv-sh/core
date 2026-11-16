# Security reporting

Report suspected secret disclosure, access-control bypass, unsafe recovery,
signature bypass or another security defect privately. Do not put exploit
details, credentials, secret values, private keys or private operational files
in a public issue.

Use [GitHub private vulnerability reporting for ENKV core](https://github.com/enkv-sh/core/security/advisories/new).
For an SDK, protocol, author tool or official plugin issue, use
[ENKV extensions private reporting](https://github.com/enkv-sh/extensions/security/advisories/new).
If you cannot determine the owner, report to core and describe the affected
command or plugin.

The repository owner must enable this GitHub feature. If **Report a
vulnerability** is unavailable, open an ordinary issue asking only for a
private security contact. Do not include the vulnerability or sensitive data
in that request. GitHub explains the procedure in its
[private reporting guide](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).

Include the CLI archive/version, platform, relevant plugin name/version,
affected operation, expected result and a minimal reproduction using synthetic
values. Describe the suspected impact. Send only material you are authorized
to share. Raw configuration pairs and test logs can contain operational or
sensitive data; they are not required for an initial report.

The maintainer reviews private reports, requests further information through
that channel and coordinates any correction and disclosure. No fixed response
time is promised. Release notes state the affected and corrected versions;
do not assume a beta has a long-term maintenance guarantee.

For ordinary bugs without security implications, use
[GitHub Issues](https://github.com/enkv-sh/core/issues). Read
[Troubleshooting](docs/troubleshooting.md) for safe diagnostic information.

## Operator responsibilities

Protect the configuration pair, cloud credentials, private plaintext inputs and
materialized files. Use separate permissions for normal Authority, application
Recipients and enabled Recovery. Native plugins are trusted executable code;
protocol checks do not confine an untrusted program to a sandbox.

Keep exact resources and independent trust records for recovery. Do not bypass
failed signature checks or retry uncertain effects without the required
evidence. See [Recovery](docs/recovery.md) and [Updates](docs/updates.md).
