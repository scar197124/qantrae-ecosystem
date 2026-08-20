# QANTRAE RC8 — Public Surface & Release Integrity

RC8 builds on RC7 with scanner, analysis-engine, API-handler, and navigation logic frozen.

## Added
- Public `robots.txt` that allows normal pages while discouraging crawling of API endpoints.
- Public `sitemap.xml` covering the ecosystem home, trust pages, and all four product layers.
- Compact root `404.html` with no-index metadata and a safe return path.
- Release checksum inventory (`checksums.sha256`) for traceability after download, upload, or deployment.

## Removed from public package
- `_inline_checks/` QA helper scripts. These were release-time validation artifacts, not runtime dependencies.

## Preserved
- RC6 edge hardening.
- RC7 public-facing metadata/accessibility polish.
- Scanner and analysis engines unchanged.
- Product navigation wiring unchanged.
- API handler logic unchanged.
