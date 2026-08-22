# QANTRAE Security Layer — Brand Identity Hardening Candidate

The protected server-side intelligence and RDAP bridges remain intact. Product analysis engines remain frozen.

RC5 release QA adds no new external services. The IT QR scanner uses the packaged local scanner component and local decoder assets. Camera access is released when the scanner closes, the user leaves the scanner view, the tab/page is hidden, or the page exits.

Deployment should still use platform-side WAF/rate limiting/bot controls as the outer protection layer.

## Verified Brand Registry

Sense now contains a local, curated registry for major Canadian bank identities plus the existing protected brands. Matching uses exact hostname boundaries: an approved domain authorizes itself and dot-delimited subdomains, but never look-alike prefixes, path text, user-info, or suffix tricks.

The engine separates three states:
- verified boundary match;
- protected-brand claim outside every verified boundary;
- no protected-brand claim detected.

The registry is supporting evidence, not a guarantee. It does not fetch pages, collect credentials, or transmit scan input. Unknown brands are not automatically treated as fraudulent.

## Identity Evidence & Safe Route

RC10 exposes the registry decision instead of leaving it buried in a score. A protected-brand mismatch shows the claimed organization, the actual hostname, the registry boundary, and a stop decision. The optional safe route comes only from the curated registry, requires HTTPS, opens only after a user click, and never forwards the suspicious URL or scan input.
