# PHP2Shell detector

Evidence-based assessment for **CVE-2026-109618 and CVE-2026-109619**. Python 3.11+;
no third-party runtime dependencies. The repository uses the first CVE's identifier
for its name and evaluates both CVEs on every run.

## Overview

This tool has two deliberately different scopes:

* **Source archive assessment:** hashes a local file and compares it with 24 reviewed
  official PHP source archive identities. A match establishes the code release and
  its vendor-advised status for the two named CVEs.
* **HTTP observation:** makes a HEAD request and records status and narrowly parsed
  PHP version hints. Every completed HTTP observation is **INCONCLUSIVE**. This mode
  cannot certify a live server as vulnerable or patched.

An archive finding does **not** establish which binary is running, whether workers
were restarted, or whether an application is exploitable. This is not a remote RCE
verification tool. There is no active exploit probe or broad scanner.

## CVE information and technical background

The affected product is PHP core. CVE-2026-109618 concerns unsafe handling of memory
exhaustion; CVE-2026-109619 concerns request-owned state surviving into subsequent
requests. Both can lead to unauthenticated remote code execution under relevant
runtime conditions. The vendor rates each 9.2 (CVSS 4.0) and lists CWE-416 among
the weaknesses. See the [technical analysis](docs/technical-analysis.md) for scope,
prerequisites, vector, and vendor links.

| Branch | Affected upstream releases in branch | First fixed release | Included affected archive |
| --- | --- | --- | --- |
| 8.2 | Before 8.2.35 | 8.2.35 | 8.2.34 |
| 8.3 | Before 8.3.36 | 8.3.36 | 8.3.35 |
| 8.4 | Before 8.4.27 | 8.4.27 | 8.4.26 |
| 8.5 | Before 8.5.12 | 8.5.12 | 8.5.11 |

The catalog includes `.tar.gz`, `.tar.bz2`, and `.tar.xz` for each of the eight
listed releases. It is a frozen snapshot reviewed on **2026-11-01**. It does not
infer status for older unsupported branches, later releases, Windows binaries,
distribution packages, containers, or custom builds.

## Detection methodology

Read the target file, compute SHA-256 over all bytes, look up the exact digest in
the bundled catalog, and associate the matched official release with the two PHP
security advisories. Filename and extracted version strings have no authority.
Archives are neither extracted nor executed. A file larger than 128 MiB is rejected.
See [detection methodology](docs/detection-methodology.md).

For HTTP targets the tool sends HEAD only. It collects no body, cookies, response
content, redirect destination, or arbitrary headers. It extracts only PHP version
tokens from Server and X-Powered-By. These are observations, never proof.

## Detection accuracy

| Status | Required evidence | Scope |
| --- | --- | --- |
| VULNERABLE | Exact SHA-256 of a cataloged official affected source release | Scanned source archive only |
| NOT_VULNERABLE | Exact SHA-256 of a cataloged official fixed source release | Scanned source archive, these two CVEs only |
| INCONCLUSIVE | Unrecognized digest or any completed HTTP observation | No vulnerability conclusion |
| ERROR | Invalid input, inaccessible file, network failure, interruption, or output failure | Assessment failed |

Backported patches and custom/repacked archives change the hash and remain
inconclusive. A patched server advertising an old version, a spoofed new version,
missing headers, or conflicting version hints cannot yield a definitive result.
A valid fixed archive on disk says nothing about a running worker. Unknown files
and blocked endpoints are not safe results. Confidence is qualitative and tied to
archive identity, never an arbitrary probability. See [limitations](docs/limitations.md).

## Features

* Independent finding entries for both CVEs, with references and UTC timestamps.
* Console and JSON reports; predictable exit codes and exclusive output-file creation.
* Offline artifact hashing with bounded memory and file size.
* HTTPS certificate verification, no redirect following, no inherited proxies,
  zero retries by default, at most two opt-in retries.
* Redacted URL paths, no credentials or URL query parameters accepted.

## Requirements and installation

Install Python 3.11 or newer. The runtime uses only the standard library.
From the repository directory:

```cmd
py -3 -m venv .venv
.venv\Scripts\activate
python -m pip install .
```

On Linux/macOS activate with `source .venv/bin/activate` after creating the
environment using `python3 -m venv .venv`.

## Usage

Assess an existing locally obtained official archive:

```cmd
python -m cve_detector --target "C:\Downloads\php-8.4.27.tar.xz"
python -m cve_detector --target "C:\Downloads\php-8.4.26.tar.xz" --format json --output report.json
```

Observe an authorized endpoint (example address is illustrative):

```cmd
php2shell-detector --target https://example.com/index.php --timeout 5 --retries 0 --format json
```

The tool does not download archives or invoke a local PHP executable. Supply an
unmodified archive through your normal trusted software acquisition process.

## Command-line arguments

| Option | Meaning / default |
| --- | --- |
| --target | Required HTTP(S) URL or existing local regular file |
| --timeout | Per-socket timeout, 0.1–30 seconds, default 5; HTTP only |
| --retries | Extra connection attempts, 0–2, default 0; HTTP only |
| --format | console (default) or json |
| --output | Create a new UTF-8 report; an existing file is never overwritten |
| --verbose | Progress on stderr without raw target details |
| --quiet | Console status only; JSON stays complete |
| --help | Usage and scope |
| --version | Package version |

No authentication, proxy, insecure TLS, or `--active-check` options are provided.
URLs must not contain user information, queries, fragments, whitespace, or control
characters. Percent-encode non-ASCII paths. Local UNC/network-share targets are
rejected. Local paths appear in reports; review them before sharing.

## Example output

These abridged examples are illustrative classifications, not live scan results:

```text
VULNERABLE | scope=source_archive
CVE-2026-109618: VULNERABLE
CVE-2026-109619: VULNERABLE
Exact official source archive contains code affected by both CVEs.
Runtime exploitability is not tested.

NOT_VULNERABLE | scope=source_archive
CVE-2026-109618: NOT_VULNERABLE
CVE-2026-109619: NOT_VULNERABLE
Exact official source archive is a vendor-fixed release for both named CVEs.

INCONCLUSIVE | scope=http_endpoint
A response was observed; deployed patch state is unverified.

ERROR | scope=unknown
Archive target must be an existing local regular file.
```

## JSON output schema

`schema_version` is 1. Every report includes:

| Field | Type / meaning |
| --- | --- |
| target | string; validated local path or URL with path redacted; unvalidated inputs omitted |
| scope | source_archive, http_endpoint, or unknown |
| status | One of the four statuses |
| verification_method | official_archive_sha256, http_head_observation, or assessment_failed |
| observations | object; digest and matched release metadata, or status_code/php_versions/attempts |
| findings | Two objects with cve, status, evidence_summary, confidence, reference |
| limitations | Array of scope and evidence caveats |
| timestamp | ISO 8601 UTC time with offset |

Both current CVEs share release boundaries and therefore receive the same status;
the individual findings retain their own CVE and authoritative reference. Output
failures replace the result with ERROR on stdout and exit 3. Failed writes may
leave a partial new file; discard that file. JSON remains valid with --quiet.

## Exit codes

0 = NOT_VULNERABLE, 1 = VULNERABLE, 2 = INCONCLUSIVE, 3 = ERROR. Help/version exit 0.
Invalid CLI arguments and interruption exit 3. Automation must handle 2 and 3
explicitly; neither means the target is patched.

## Testing

```cmd
python -m pip install -e ".[dev]"
python -m pip install --upgrade pip
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python -m build
python -m pip_audit --strict --cache-dir .audit-cache
```

Tests use synthetic files and mocked HTTP failures/responses. Catalog decision tests
mock the digest explicitly; they do not pretend synthetic files are real PHP
archives. Separate hashing tests exercise real bytes. Official metadata snapshots
are checked against every bundled digest. See [validation](docs/validation.md) for
the actual local results and checks not executed.

## CI/CD integration

The included GitHub workflows run tests on Windows/Linux and Python 3.11–3.14,
lint, formatting, strict type checks, packaging, and dependency auditing. They use
read-only repository permissions. A configured workflow is not evidence of a
successful hosted CI run. Do not feed artifact results into an endpoint inventory
without independently binding the archive to the deployed build and all workers.

## Limitations and security considerations

Only scan authorized endpoints. HEAD requests still reach application/server logic
and can appear in access logs. HTTP observations cannot prove absence of these
flaws. DNS resolution and slow header delivery can exceed the nominal socket
timeout; there is no absolute wall-clock deadline. The standard-library HTTP parser
imposes its own header limits. No response body is read. Do not expose this CLI as
an unrestricted web service; the operator controls the destination.

The catalog is trusted local package data, not a signed attestation of deployment.
The hash and read-consistency checks do not prevent a malicious local writer from
changing files concurrently; use immutable copies. Catalog updates require human
review of vendor metadata and advisories. No network catalog updates occur during
assessment. This release does not assess CVE-2026-115560 or future issues.

## References

* [PHP advisory for CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
* [PHP advisory for CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
* [Official release metadata example](https://www.php.net/releases/index.php?json&version=8.4.27)
* [Metadata snapshots and provenance](docs/release-metadata/README.md)

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues according to
[SECURITY.md](SECURITY.md). New definitive checks require stronger evidence than
banners, version assertions, configuration toggles, or a generic HTTP response.

## License

MIT; see [LICENSE](LICENSE). Release checksums and version metadata retain their
upstream provenance. This project does not redistribute PHP source archives.
