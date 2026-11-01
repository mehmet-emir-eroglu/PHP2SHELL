# Official PHP release metadata snapshots

Retrieved over HTTPS on 2026-11-01 from:

* https://www.php.net/releases/index.php?json&version=8.2.34
* https://www.php.net/releases/index.php?json&version=8.2.35
* https://www.php.net/releases/index.php?json&version=8.3.35
* https://www.php.net/releases/index.php?json&version=8.3.36
* https://www.php.net/releases/index.php?json&version=8.4.26
* https://www.php.net/releases/index.php?json&version=8.4.27
* https://www.php.net/releases/index.php?json&version=8.5.11
* https://www.php.net/releases/index.php?json&version=8.5.12

The adjacent JSON files preserve the responses used to build the runtime catalog.
The test suite checks the catalog's digest, version and filename against them.
They are provenance records, not independent signatures. To review an update,
re-fetch from the official source, compare checksums and release status, review
both CVE advisories, and rerun all boundary tests. Never silently replace a
previously published digest or infer a new branch's status from numeric ordering.
