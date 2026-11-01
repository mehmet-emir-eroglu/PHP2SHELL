# Validation record

Executed locally on Windows with Python **3.12.14**, 2026-11-01.

| Check | Actual result |
| --- | --- |
| pytest | **124 passed**, final run 3.61 seconds |
| Ruff lint | Passed |
| Ruff format check | Passed; 16 Python files already formatted |
| mypy strict | Passed; 10 source files |
| Source distribution and wheel build | Passed |
| Wheel installation in a separate clean environment | Passed with no runtime dependencies |
| Installed module --version and console entry point --help | Passed |
| Installed package + fixed official source archive | NOT_VULNERABLE, archive scope |
| Dependency audit after local pip upgrade | No known vulnerabilities found |

The audit initially reported 12 advisories for the environment's pip 25.0.1.
Upgrading the task-local environment to pip 26.2.2 resolved those reported findings.
The successful audit used pip-audit 2.10.1 with a workspace-local cache and a
five-second request timeout. This is a point-in-time advisory database check,
not a guarantee of absence of vulnerabilities. The detector has no third-party
runtime dependencies. The CI security workflow upgrades pip before auditing.

Other tools: pytest 9.2.0, Ruff 0.17.3, mypy 1.20.2, build 1.6.1,
setuptools 84.2.1. Dependency ranges are constrained in pyproject.toml; future
resolutions may differ and must rerun validation.

## Real archive checks

Downloaded from the official `https://www.php.net/distributions/` directory and
hashed without extraction or execution:

| Archive | SHA-256 | Result / exit |
| --- | --- | --- |
| php-8.4.26.tar.xz | 32a2de53862ad44ed4a5005244ce4f1b50c271e74dced215449a4443b40569f1 | VULNERABLE / 1 |
| php-8.4.27.tar.xz | dcf93923b0e38e0d5252b25b796520b5a47761a08b3488b6d0b5d1115764d3f0 | NOT_VULNERABLE / 0 |

Both findings apply only to the source archive. These checks are separate from the
deterministic suite and require no public target scan. Downloaded PHP archives are
not redistributed in this project.

## Test coverage and boundaries

The suite covers all 24 catalog identities, independently checked affected/fixed
release groups, metadata provenance, real hashing, oversize and changing files,
unknown/repacked archives, misleading/conflicting banners, target validation,
TLS errors, DNS errors, refusal, timeout, malformed HTTP, bounded retries,
redirect refusal, output structure, all exit codes, exclusive file creation,
interruptions, and credential redaction. Five loopback-server cases exercise the
real HTTP client for 200, 302, 403, 405 and 503 responses.

Catalog decision fixtures explicitly mock hashes; synthetic fixtures are not
represented as actual vulnerable PHP releases. Two real archives were checked as
described above. No exploitation or vulnerable runtime deployment was tested.

## Environment issue resolved

The first isolated build failed because setuptools interpreted braces in the
machine's default temporary directory as substitution variables. Rebuilding with
TEMP/TMP set to a workspace-local directory succeeded. This workaround changes
only the local build environment, not detector logic.

## Not executed

Hosted GitHub Actions, Linux execution, and local Python versions other than
3.12.14 remain unverified. The configured CI matrix covers Windows/Linux with
Python 3.11–3.14 after publication. Deployment patch confirmation, remote RCE
verification, independent signature verification, and comprehensive coverage of
PHP release history are not implemented capabilities. Publication has not occurred.
