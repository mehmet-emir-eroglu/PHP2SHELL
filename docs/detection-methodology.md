# Detection methodology

1. Validate the target. URL queries, fragments, user information, malformed hosts,
   invalid ports and control characters are rejected. File targets must exist.
2. For HTTP, issue HEAD with verified TLS, no proxy inheritance or redirects.
   Parse only narrow version hints and status. All responses, including access
   denials and server errors, are inconclusive; transport failures are ERROR.
3. For files, hash all bytes with SHA-256, bounded to 128 MiB. Verify basic
   size/mtime consistency. Never unpack, interpret, or execute the input.
4. Compare against the bundled 24-entry official-release catalog. Exact affected
   identity yields VULNERABLE for source code; exact fixed identity yields
   NOT_VULNERABLE for these two CVEs in that artifact. No match is inconclusive.
5. Emit both CVE findings with scope, evidence, confidence, limitations and time.

The catalog is derived from the eight official metadata snapshots in
`release-metadata/`. See their README for URLs and review process. Upstream version
labels are used only after full-file identity is established. Names, banners and
operator assertions cannot create positive or negative findings.

## Evidence hierarchy

Exact official archive identity plus an applicable advisory supports a source-code
release conclusion. It does not prove execution of that source. A supplied filename
or HTTP header is merely a hint. Mitigating a single feature does not establish
patch coverage. No boolean `patched=true` input can override these rules.

## Extending detection

To extend the catalog, retrieve metadata via verified HTTPS from php.net, review
the corresponding advisory, record provenance and date, and add branch-boundary
regressions. Update the strict catalog-size and review-date checks deliberately.
Do not add user-editable runtime catalogs as a shortcut to definitive findings.
Adding installed-package verification needs trustworthy package origin and a
binding between the inspected package, binary, and serving workers.
