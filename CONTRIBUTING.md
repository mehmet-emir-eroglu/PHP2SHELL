# Contributing

Use Python 3.11+, install `.[dev]` in a virtual environment, and run the README's
test, lint, format, type-check and build commands. Keep network tests deterministic
and avoid public targets. A new detection rule needs authoritative provenance,
positive and negative evidence requirements, and regressions for plausible false
positives. Preserve INCONCLUSIVE whenever patch or deployment evidence is missing.

Catalog updates require review of both CVE advisories and exact official metadata.
Do not treat filenames, banners, version ordering or user assertions as proof.
Do not add memory-exhaustion, corruption or code-execution probes.

Use small changes with a clear description and actual test results. Do not include
credentials, real target reports, virtual environments or downloaded PHP archives.
Review SECURITY.md before reporting vulnerabilities.
