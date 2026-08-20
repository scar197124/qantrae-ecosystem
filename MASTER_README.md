# QANTRAE RC8 — Public Surface & Release Integrity Candidate

Built from the known-good RC4 QR scanner package.

Final QA polish applied without changing scanner analysis engines or navigation wiring:
- IT camera releases when scanner closes, user leaves the scanner view, tab hides, or page exits
- Camera privacy note added next to the IT QR scanner
- Mobile tap targets and keyboard focus visibility strengthened across products
- IT QR status/error contrast improved
- Stale duplicate IT 404 build replaced with a compact QANTRAE-safe 404 page
- Product color inheritance and adaptive header system preserved

## RC6 edge-hardening update — 2026-08-20

This experiment intentionally leaves all product HTML, CSS, scanner code, analysis engines, navigation wiring, and API logic unchanged.

Added at the Vercel edge only:
- `X-DNS-Prefetch-Control: off` to reduce unintended DNS prefetching
- `Cross-Origin-Resource-Policy: same-origin` for static ecosystem resources
- `Origin-Agent-Cluster: ?1` for stronger browser origin isolation
- API routes explicitly retain `Cross-Origin-Resource-Policy: cross-origin` so approved CORS callers continue to work
- API routes receive a restrictive JSON-safe Content Security Policy (`default-src 'none'`)

Purpose: tighten browser-facing security without disturbing the known-good RC5 application behavior.


## RC7 public-release polish — 2026-08-20

RC7 builds directly on the verified RC6 package and keeps scanner/analysis logic frozen.

Polish applied:
- Removed internal build/version wording from public browser-tab titles for Lite, Sense, Shield, and IT
- Added concise public-facing descriptions to Sense and IT and refreshed product descriptions for release clarity
- Added product-specific browser theme colors and explicit color-scheme hints
- Added visible keyboard focus treatment and `prefers-reduced-motion` support without changing layouts or engines
- Added `aria-current="page"` to the active ecosystem navigation link
- Added no-index metadata and a description to the IT 404 page
- Preserved RC6 edge-hardening headers and all scanner/API behavior

Purpose: make the public-facing build read like a release rather than an internal QA artifact while keeping the functional surface stable.


## RC8 public-surface & release-integrity pass — 2026-08-20

RC8 keeps the functional application frozen and adds a cleaner public-release perimeter.

Added:
- `robots.txt` with API routes excluded from crawler discovery
- `sitemap.xml` for the public ecosystem and four product layers
- Root `404.html` with a compact QANTRAE-safe return path and no-index metadata
- `checksums.sha256` so downloaded/deployed files can be verified byte-for-byte
- `RELEASE_NOTES.md` to make the release delta explicit

Removed from the public package:
- `_inline_checks/` internal QA extraction scripts; they are not runtime dependencies

Preserved:
- RC6 edge headers
- RC7 accessibility and metadata polish
- Scanner/engine logic, API handler logic, and navigation wiring
