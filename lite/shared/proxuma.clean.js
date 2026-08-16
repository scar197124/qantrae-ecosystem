
function analyzeURL(url) {
  let findings = [];
  let score = 0;

  let hostname = "";
  let protocol = "";
  let pathname = "";
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname || "";
    protocol = parsed.protocol || "";
    pathname = parsed.pathname || "";
    var port = parsed.port || "";
    var username = parsed.username || "";
    var search = parsed.search || "";
  } catch (e) {
    return {
      verdict: "UNKNOWN",
      confidence: 0,
      score: 0,
      summary: "Invalid URL.",
      breakdown: {
        domainRisk: 0,
        protocolRisk: 0,
        pathRisk: 0,
        redirectRisk: 0,
        encodingRisk: 0
      },
      findings: [{ level: "INFO", msg: "URL could not be parsed." }]
    };
  }

  let domainRisk = 0;
  let protocolRisk = 0;
  let pathRisk = 0;
  let redirectRisk = 0;
  let encodingRisk = 0;

  const trusted = ["google.com", "google", "gstatic.com"];
  const isTrusted = trusted.some(d => hostname === d || hostname.endsWith("." + d));

  if (protocol === "https:") {
    findings.push({
      level: "LOW",
      msg: "Connection uses HTTPS. This helps protect transport but does not guarantee safety."
    });
  } else if (protocol && protocol !== "https:") {
    protocolRisk += 10;
    findings.push({
      level: "MEDIUM",
      msg: "Connection is not using HTTPS."
    });
  }

  if (isTrusted) {
    findings.push({
      level: "LOW",
      msg: "Trusted platform detected."
    });
  }

  if (hostname.includes("share")) {
    redirectRisk += 10;
    findings.push({
      level: "MEDIUM",
      msg: "Redirect or shared link detected."
    });
  }

  if (url.includes("share.google")) {
    findings.push({
      level: "INFO",
      msg: "Content requires access (restricted)."
    });
  }

  if (/%[0-9A-Fa-f]{2}/.test(url)) {
    encodingRisk += 5;
    findings.push({
      level: "LOW",
      msg: "Encoded characters present in URL."
    });
  }

  const hostLabels = hostname.split(".").filter(Boolean);
  const pathDepth = pathname.split("/").filter(Boolean).length;
  const percentCount = (url.match(/%[0-9A-Fa-f]{2}/g) || []).length;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    domainRisk += 35;
    findings.push({ level: "HIGH", msg: "Direct IP destination detected." });
  }
  if (/xn--/i.test(hostname)) {
    domainRisk += 35;
    findings.push({ level: "HIGH", msg: "Punycode hostname detected; verify the real domain carefully." });
  }
  if (username) {
    domainRisk += 32;
    findings.push({ level: "HIGH", msg: "Username-in-link structure detected before the real host." });
  }
  if (port && port !== "80" && port !== "443") {
    protocolRisk += 10;
    findings.push({ level: "MEDIUM", msg: "Unusual network port detected." });
  }
  if (hostLabels.length >= 5) {
    domainRisk += 10;
    findings.push({ level: "MEDIUM", msg: "Heavy subdomain stack can push the real root domain out of view." });
  }
  if (pathDepth >= 7) {
    pathRisk += 8;
    findings.push({ level: "MEDIUM", msg: "Deep path nesting detected." });
  }
  if (percentCount >= 8 || /%25(?:2f|3a|40|5c|2e)/i.test(url)) {
    encodingRisk += 12;
    findings.push({ level: "MEDIUM", msg: "Heavy or nested URL encoding detected." });
  }

  if ((pathname || "").length > 60 || url.length > 100) {
    pathRisk += 5;
    findings.push({
      level: "LOW",
      msg: "Long path or URL length detected."
    });
  }

  score = domainRisk + protocolRisk + pathRisk + redirectRisk + encodingRisk;

  let verdict = "LOW";
  if (url.includes("share.google")) {
    verdict = "UNKNOWN";
  } else if (score > 60) {
    verdict = "HIGH";
  } else if (score > 30) {
    verdict = "MEDIUM";
  }

  let confidence = Math.min(100, Math.max(35, score + 35));
  if (verdict === "UNKNOWN") confidence = 70;
  if (verdict === "LOW") confidence = Math.max(confidence, 65);

  let summary = "Link appears relatively safe.";
  if (verdict === "UNKNOWN") {
    summary = "The platform appears trusted, but the content cannot be verified because access is restricted.";
  } else if (verdict === "MEDIUM") {
    summary = "This link shows some suspicious characteristics and should be reviewed carefully.";
  } else if (verdict === "HIGH") {
    summary = "This link shows strong indicators of elevated risk.";
  }

  return {
    verdict,
    score,
    confidence,
    summary,
    breakdown: {
      domainRisk,
      protocolRisk,
      pathRisk,
      redirectRisk,
      encodingRisk
    },
    findings
  };
}
