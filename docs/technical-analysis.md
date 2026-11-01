# Technical analysis

Research date: 2026-11-01. Primary authority: the PHP project's paired advisories.

## CVE-2026-109618

OOM handling can leave incompletely initialized request state reachable during
cleanup. The patch changes allocation-failure handling to avoid unsafe early exits.
The vendor demonstrates unauthenticated RCE under mod_php; applicability elsewhere
depends on the SAPI and application. Configuration changes are not a complete fix.

[Vendor advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w).

## CVE-2026-109619

Persistent worker globals can reference freed request memory. Exploitation requires
a state-producing operation and a later operation consuming stale state. The
vendor describes INI-diagnostic and session-upload-progress paths. Disabling one
path does not eliminate the whole vulnerability class. The complete state-reset
patch is the reliable remediation.

[Vendor advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

## Common metadata and scope

Both advisories list CVSS 4.0 **9.2**, vector
`CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`.
Listed weaknesses include CWE-416, CWE-755 and CWE-824. Fixed branch releases are
8.2.35, 8.3.36, 8.4.27 and 8.5.12. Authentication is not required for the described
attacks. Exact exploit prerequisites differ between routes and runtimes.

No safe, general remote yes/no test was established by this research. That is an
engineering limitation, not a vendor guarantee that none could ever exist. This
tool uses archive identity rather than attempting to reproduce corruption.
Release metadata establishes file identity; advisories establish code-release
status. Their combination does not establish runtime reachability.

No material conflict was found between the selected PHP release metadata and the
paired advisory release boundaries. Other CVEs and downstream backports require
separate investigation. See the README for the exact catalog coverage.
