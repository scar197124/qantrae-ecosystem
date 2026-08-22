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

## Brand identity hardening candidate

- Replaced the early exact-host brand list with a structured Verified Brand Registry.
- Added exact domain-boundary matching for RBC, Scotiabank, TD, BMO, CIBC, and National Bank of Canada.
- Preserved existing PayPal, technology, marketplace, streaming, and social-brand checks in the same evidence model.
- Added explicit detection for protected-brand claims outside every verified domain boundary.
- Prevented legitimate bank subdomains from being penalized as generic subdomain stacking.
- Kept Sense local-only: no page fetch, API call, credential collection, or scan upload was added.

## RC10 Identity Evidence Panel

- Added a four-part identity explanation: claimed identity, actual host, verified boundary, and decision.
- Added a safe official-site route for detected protected-brand mismatches.
- Kept safe routes registry-controlled, HTTPS-only, user-initiated, and isolated with `noopener` / `noreferrer`.
- Added responsive one-, two-, and four-column evidence layouts without changing family navigation.
- Preserved the RC9 engine, all other product engines, API handlers, and release perimeter.

## RC11 Engine & API Coverage Hardening

- Enforced CAUTION for unsecured HTTP even when the hostname is an official registered brand domain.
- Rejected unsupported schemes such as FTP instead of treating them as ordinary web targets.
- Added direct IPv6 destination detection alongside IPv4.
- Normalized common brand separators and joined spellings for Royal Bank, TD Bank, and National Bank claims.
- Added a rental-payment lure signal for apartment, landlord, lease, deposit, application-fee, and e-transfer combinations.
- Added a user-triggered API connection test in QANTRAE IT.
- Made provider states explicit: connected, ready, key not configured, unavailable, timed out, and partial/full coverage.
- Added machine-readable provider capability states to the intelligence bridge health response.
- Preserved consent-first API behavior and the independence of the offline verdict.
