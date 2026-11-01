# Limitations

* URL mode always remains inconclusive. It is an inventory observation, not a
  remote vulnerability proof. Hidden versions, WAFs, redirects and mixed backends
  cannot be resolved by a single response.
* Archive results cover code identity only. A fixed archive can sit next to an
  unpatched deployment. A vulnerable archive may never be deployed. Results must
  retain the `source_archive` scope when imported into another system.
* Only eight release versions and three compression formats are cataloged.
  Unknown releases, custom builds, repacks, distro backports, binaries and container
  images remain inconclusive regardless of their reported versions.
* Confidence depends on a trustworthy package/catalog and official digest source.
  No independent release signature verification is implemented.
* No active memory corruption, OOM trigger, upload probe or command execution is
  performed. The project does not reproduce exploitation or prove exploitability.
* Timeout is per blocking socket operation. DNS and slow header streams can take
  longer. Retry count and body consumption are bounded; total elapsed time is not.
* Requests go directly to the chosen host; proxy and netrc environment behavior
  is not inherited. Authenticated routes cannot be assessed beyond their response.
* Exclusive report creation prevents overwriting inputs/reports, but disk-write
  failure can leave a partial report. Exit 3 means discard that output.
* Local file paths appear in reports. URL paths are redacted. Do not put secrets
  in hostnames or filenames. The tool does not promise to sanitize arbitrary
  sensitive information chosen as a local path by its operator.
* The two-CVE result cannot establish overall PHP security or coverage of later
  vulnerabilities, including CVE-2026-115560.
