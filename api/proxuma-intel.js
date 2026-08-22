/* QANTRAE protected serverless intelligence + redirect-resolution bridge.
   Defensive boundary: public HTTP(S) web destinations only. This function is not
   an open proxy and never returns arbitrary response bodies from scanned targets.
   Configure VIRUSTOTAL_API_KEY and/or GOOGLE_WEBRISK_API_KEY server-side only.
   QANTRAE_ALLOWED_ORIGIN (or legacy PROXUMA_ALLOWED_ORIGIN) may add comma-separated origins.
*/
const dns = require('dns').promises;
const net = require('net');
const http = require('http');
const https = require('https');
const crypto = require('crypto');

const RATE_WINDOW_MS = 60_000;
const MAX_BODY_BYTES = 8 * 1024;
const MAX_URL_CHARS = 2048;
const MAX_DOMAIN_CHARS = 253;
const MAX_PROVIDER_BYTES = 256 * 1024;
const MAX_REDIRECTS = 5;
const MAX_HEADER_BYTES = 16 * 1024;
const SAFE_SHORTENER_HOSTS = new Set([
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','cutt.ly','rebrand.ly',
  'lnkd.in','s.id','rb.gy','shorturl.at','short.io','tiny.cc','t.ly','bitly.com','trib.al',
  'lnk.to','qrco.de','soo.gd','bl.ink','shorte.st','snip.ly'
]);
const buckets = new Map();

function applySecurityHeaders(res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, nosnippet');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  res.setHeader('Vary', 'Origin');
}

function allowedOrigins() {
  const set = new Set([
    'https://qantrae-ecosystem.vercel.app',
    'http://localhost:3000',
    'http://localhost:5173'
  ]);
  const extra = [process.env.QANTRAE_ALLOWED_ORIGIN, process.env.PROXUMA_ALLOWED_ORIGIN]
    .filter(Boolean).join(',');
  extra.split(',').map(s => s.trim()).filter(Boolean).forEach(v => set.add(v));
  return set;
}

function applyCors(req, res) {
  const origin = String(req.headers?.origin || '');
  if (origin && !allowedOrigins().has(origin)) return false;
  if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept');
  return true;
}

function clientIp(req) {
  const raw = String(req.headers?.['x-forwarded-for'] || req.headers?.['x-real-ip'] || req.socket?.remoteAddress || 'unknown');
  return raw.split(',')[0].trim().slice(0, 80) || 'unknown';
}

function limit(req, res, key, max) {
  const now = Date.now();
  const id = `${key}:${clientIp(req)}`;
  const prior = buckets.get(id);
  const entry = !prior || now >= prior.reset ? { count: 0, reset: now + RATE_WINDOW_MS } : prior;
  entry.count += 1;
  buckets.set(id, entry);
  if (buckets.size > 5000) for (const [k, v] of buckets) if (now >= v.reset) buckets.delete(k);
  res.setHeader('X-RateLimit-Limit', String(max));
  res.setHeader('X-RateLimit-Remaining', String(Math.max(0, max - entry.count)));
  res.setHeader('X-RateLimit-Reset', String(Math.ceil(entry.reset / 1000)));
  if (entry.count <= max) return true;
  res.setHeader('Retry-After', String(Math.max(1, Math.ceil((entry.reset - now) / 1000))));
  res.status(429).json({ error: 'Too many requests. Please try again shortly.' });
  return false;
}

function bodyTooLarge(req) {
  const len = Number(req.headers?.['content-length'] || 0);
  return Number.isFinite(len) && len > MAX_BODY_BYTES;
}

function mappedV4(ip) {
  const v = String(ip || '').toLowerCase();
  let m = v.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (m && net.isIPv4(m[1])) return m[1];
  m = v.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (!m) return null;
  const hi = parseInt(m[1], 16), lo = parseInt(m[2], 16);
  return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}

function isPrivateIp(ip) {
  if (!ip) return true;
  const mapped = mappedV4(ip);
  if (mapped) return isPrivateIp(mapped);
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    return p[0] === 0 || p[0] === 10 || p[0] === 127 || p[0] >= 224 ||
      (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
      (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 0 && p[2] === 0) ||
      (p[0] === 192 && p[1] === 0 && p[2] === 2) ||
      (p[0] === 192 && p[1] === 168) ||
      (p[0] === 198 && (p[1] === 18 || p[1] === 19)) ||
      (p[0] === 198 && p[1] === 51 && p[2] === 100) ||
      (p[0] === 203 && p[1] === 0 && p[2] === 113);
  }
  const v = String(ip).toLowerCase();
  return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') ||
    /^fe[89ab][0-9a-f]:/.test(v) || v.startsWith('ff') || v.startsWith('2001:db8:');
}

function validDomain(domain) {
  if (!domain || domain.length > MAX_DOMAIN_CHARS || domain.includes('..') || net.isIP(domain)) return false;
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(domain);
}

function normalWebPort(u) {
  const port = u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80);
  if (!Number.isInteger(port) || ![80, 443].includes(port)) throw new Error('Only standard web ports are allowed');
  return port;
}

async function publicAddressesFor(host) {
  if (net.isIP(host)) {
    if (isPrivateIp(host)) throw new Error('Private destinations are blocked');
    return [{ address: host, family: net.isIPv4(host) ? 4 : 6 }];
  }
  const answers = await dns.lookup(host, { all: true, verbatim: true });
  if (!answers.length || answers.some(a => isPrivateIp(a.address))) throw new Error('Private destinations are blocked');
  return answers;
}

async function assertPublicHttpUrl(raw) {
  if (typeof raw !== 'string' || raw.length > MAX_URL_CHARS) throw new Error('URL is too long');
  let u;
  try { u = new URL(raw); } catch { throw new Error('Invalid URL'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http(s) destinations are allowed');
  if (!u.hostname || u.username || u.password) throw new Error('Unsafe URL form');
  normalWebPort(u);
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.localhost')) {
    throw new Error('Private destinations are blocked');
  }
  await publicAddressesFor(host);
  return u;
}

function domainMatchesUrl(domain, u) {
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return host === domain || host.endsWith(`.${domain}`);
}

async function requestRedirectHeaders(rawUrl, timeoutMs = 4500) {
  const u = await assertPublicHttpUrl(rawUrl);
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const addresses = await publicAddressesFor(host);
  const selected = addresses[0];
  const port = normalWebPort(u);
  const client = u.protocol === 'https:' ? https : http;

  return await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => { if (!settled) { settled = true; fn(value); } };
    const req = client.request({
      protocol: u.protocol,
      hostname: host,
      port,
      method: 'GET',
      path: `${u.pathname || '/'}${u.search || ''}`,
      headers: {
        'Host': u.host,
        'User-Agent': 'QANTRAE-LinkResolver/2.0',
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.1',
        'Connection': 'close'
      },
      lookup: (_hostname, _options, cb) => cb(null, selected.address, selected.family),
      timeout: timeoutMs,
      maxHeaderSize: MAX_HEADER_BYTES,
      servername: u.protocol === 'https:' ? host : undefined
    }, (response) => {
      const result = { status: Number(response.statusCode || 0), location: response.headers.location || null };
      response.destroy();
      finish(resolve, result);
    });
    req.on('timeout', () => req.destroy(new Error('Destination request timed out')));
    req.on('error', err => finish(reject, err));
    req.end();
  });
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 4500) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try { return await fetch(url, { ...options, signal: controller.signal }); }
  finally { clearTimeout(timer); }
}

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function providerStatusFromHttp(status) {
  if (status === 404) return 'not_found';
  if (status === 429) return 'rate_limited';
  if (status === 401 || status === 403) return 'provider_rejected';
  if (status >= 500) return 'provider_error';
  if (status >= 400) return 'provider_rejected';
  return 'provider_error';
}

function providerFailure(error, checkedAt, attempts = 1) {
  const name = String(error?.name || '');
  const message = String(error?.message || 'Provider request failed');
  const lower = message.toLowerCase();
  let status = 'provider_error';
  if (name === 'AbortError' || lower.includes('timed out') || lower.includes('timeout') || lower.includes('aborted')) status = 'timeout';
  else if (lower.includes('response too large') || lower.includes('json')) status = 'malformed_response';
  return { status, checkedAt, attempts, message: status === 'timeout' ? 'Provider timed out' : 'Provider unavailable' };
}

async function fetchProvider(url, options = {}, { timeoutMs = 4500, retries = 1 } = {}) {
  let attempt = 0;
  while (true) {
    attempt += 1;
    try {
      const response = await fetchWithTimeout(url, options, timeoutMs);
      if (response.ok || response.status === 404) return { response, attempts: attempt };
      const retryable = response.status === 429 || response.status === 502 || response.status === 503 || response.status === 504;
      if (retryable && attempt <= retries) {
        const retryAfter = Number(response.headers.get('retry-after') || 0);
        const delay = retryAfter > 0 && retryAfter <= 2 ? retryAfter * 1000 : 250 * attempt;
        try { await response.body?.cancel?.(); } catch (_) {}
        await sleep(delay);
        continue;
      }
      return { response, attempts: attempt };
    } catch (error) {
      const retryable = error?.name === 'AbortError' || /network|fetch|socket|timeout|aborted/i.test(String(error?.message || ''));
      if (retryable && attempt <= retries) {
        await sleep(250 * attempt);
        continue;
      }
      error.attempts = attempt;
      throw error;
    }
  }
}

async function safeJson(response, maxBytes = MAX_PROVIDER_BYTES) {
  const declared = Number(response.headers.get('content-length') || 0);
  if (declared && declared > maxBytes) throw new Error('Provider response too large');
  const text = await response.text();
  if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error('Provider response too large');
  return text ? JSON.parse(text) : null;
}

async function resolveRedirectChain(startUrl) {
  const initial = await assertPublicHttpUrl(String(startUrl));
  const initialHost = initial.hostname.replace(/^www\./, '').toLowerCase();
  if (!SAFE_SHORTENER_HOSTS.has(initialHost)) throw new Error('Resolver accepts supported short-link services only');
  let current = initial.toString();
  const chain = [];
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const u = await assertPublicHttpUrl(current);
    chain.push(u.toString());
    const r = await requestRedirectHeaders(u.toString(), 4500);
    if (r.status >= 300 && r.status < 400) {
      if (!r.location) return { finalUrl: u.toString(), finalHost: u.hostname.toLowerCase(), redirectCount: chain.length - 1, chain, status: r.status };
      if (i === MAX_REDIRECTS) throw new Error('Too many redirects');
      current = new URL(r.location, u).toString();
      continue;
    }
    return { finalUrl: u.toString(), finalHost: u.hostname.toLowerCase(), redirectCount: chain.length - 1, chain, status: r.status || null };
  }
  throw new Error('Destination resolution failed');
}

module.exports = async function handler(req, res) {
  const requestStartedAt = Date.now();
  applySecurityHeaders(res);
  if (!applyCors(req, res)) return res.status(403).json({ error: 'Origin not allowed' });
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (bodyTooLarge(req)) return res.status(413).json({ error: 'Request body too large' });

  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  const wrKey = process.env.GOOGLE_WEBRISK_API_KEY;

  if (req.method === 'GET') {
    if (!limit(req, res, 'health', 30)) return;
    const configuredProviders = Number(Boolean(vtKey)) + Number(Boolean(wrKey));
    return res.status(200).json({
      ok: true,
      service: 'qantrae-intel-bridge',
      resolver: true,
      protected: true,
      providers: { virustotal: !!vtKey, webrisk: !!wrKey },
      providerStates: {
        rdap: 'available_without_key',
        virustotal: vtKey ? 'configured' : 'key_not_configured',
        webrisk: wrKey ? 'configured' : 'key_not_configured'
      },
      coverage: {
        level: configuredProviders === 2 ? 'full-capability' : 'partial-capability',
        configuredReputationProviders: configuredProviders,
        totalReputationProviders: 2
      },
      checkedAt: new Date().toISOString()
    });
  }
  if (req.method !== 'POST') return res.status(405).json({ error: 'GET, POST, or OPTIONS required' });
  if (!String(req.headers?.['content-type'] || '').toLowerCase().startsWith('application/json')) {
    return res.status(415).json({ error: 'JSON request required' });
  }

  const body = typeof req.body === 'string' ? (() => { try { return JSON.parse(req.body); } catch { return {}; } })() : (req.body || {});
  if (!body || Array.isArray(body) || typeof body !== 'object') return res.status(400).json({ error: 'Invalid request' });
  const mode = String(body.mode || 'intel').trim().toLowerCase();
  const url = String(body.url || '').trim();
  const domain = String(body.domain || '').trim().toLowerCase().replace(/\.$/, '');

  if (mode === 'resolve') {
    if (!limit(req, res, 'resolve', 12)) return;
    if (!/^https?:\/\//i.test(url) || url.length > MAX_URL_CHARS) return res.status(400).json({ error: 'A normal http(s) URL is required.' });
    try {
      const result = await resolveRedirectChain(url);
      return res.status(200).json({ ok: true, mode: 'resolve', ...result, checkedAt: new Date().toISOString() });
    } catch (e) {
      return res.status(400).json({ error: e?.message || 'Destination resolution failed.' });
    }
  }

  if (mode !== 'intel') return res.status(400).json({ error: 'Unsupported operation' });
  if (!limit(req, res, 'intel', 24)) return;
  if (!/^https?:\/\//i.test(url) || url.length > MAX_URL_CHARS || !validDomain(domain)) {
    return res.status(400).json({ error: 'A valid http(s) URL and public domain are required.' });
  }

  let safeUrl;
  try {
    safeUrl = await assertPublicHttpUrl(url);
    if (!domainMatchesUrl(domain, safeUrl)) return res.status(400).json({ error: 'Domain does not match URL' });
  } catch (e) {
    return res.status(400).json({ error: e?.message || 'Unsafe URL' });
  }

  const requestId = typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : crypto.randomBytes(12).toString('hex');
  const providers = {};

  async function checkVirusTotal() {
    const checkedAt = new Date().toISOString();
    if (!vtKey) return { status: 'not_configured', checkedAt, attempts: 0, provider: 'VirusTotal' };
    try {
      const id = Buffer.from(safeUrl.toString()).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      const { response: r, attempts } = await fetchProvider(`https://www.virustotal.com/api/v3/urls/${encodeURIComponent(id)}`, {
        headers: { 'x-apikey': vtKey, 'Accept': 'application/json' }
      }, { timeoutMs: 4500, retries: 1 });
      if (r.status === 404) return { status: 'not_found', found: false, checkedAt, attempts, provider: 'VirusTotal' };
      if (!r.ok) return { status: providerStatusFromHttp(r.status), httpStatus: r.status, checkedAt, attempts, provider: 'VirusTotal' };
      let data;
      try { data = await safeJson(r); }
      catch (_) { return { status: 'malformed_response', checkedAt, attempts, provider: 'VirusTotal' }; }
      if (!data?.data?.attributes) return { status: 'malformed_response', checkedAt, attempts, provider: 'VirusTotal' };
      const stats = data.data.attributes.last_analysis_stats || {};
      return {
        status: 'success', found: true, checkedAt, attempts, provider: 'VirusTotal',
        malicious: Number(stats.malicious || 0), suspicious: Number(stats.suspicious || 0),
        harmless: Number(stats.harmless || 0), undetected: Number(stats.undetected || 0),
        lastAnalysisDate: data.data.attributes.last_analysis_date || null
      };
    } catch (error) {
      return { provider: 'VirusTotal', ...providerFailure(error, checkedAt, Number(error?.attempts || 1)) };
    }
  }

  async function checkWebRisk() {
    const checkedAt = new Date().toISOString();
    if (!wrKey) return { status: 'not_configured', checkedAt, attempts: 0, provider: 'Google Web Risk' };
    try {
      const q = new URLSearchParams();
      q.set('uri', safeUrl.toString());
      ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'].forEach(t => q.append('threatTypes', t));
      q.set('key', wrKey);
      const { response: r, attempts } = await fetchProvider(`https://webrisk.googleapis.com/v1/uris:search?${q.toString()}`, {
        headers: { 'Accept': 'application/json' }
      }, { timeoutMs: 4500, retries: 1 });
      if (!r.ok) return { status: providerStatusFromHttp(r.status), httpStatus: r.status, checkedAt, attempts, provider: 'Google Web Risk' };
      let data;
      try { data = await safeJson(r); }
      catch (_) { return { status: 'malformed_response', checkedAt, attempts, provider: 'Google Web Risk' }; }
      if (!data || typeof data !== 'object') return { status: 'malformed_response', checkedAt, attempts, provider: 'Google Web Risk' };
      return { status: 'success', threats: Array.isArray(data.threat?.threatTypes) ? data.threat.threatTypes : [], checkedAt, attempts, provider: 'Google Web Risk' };
    } catch (error) {
      return { provider: 'Google Web Risk', ...providerFailure(error, checkedAt, Number(error?.attempts || 1)) };
    }
  }

  const [virustotal, webrisk] = await Promise.all([checkVirusTotal(), checkWebRisk()]);
  providers.virustotal = virustotal;
  providers.webrisk = webrisk;

  const providerValues = Object.values(providers);
  const configured = providerValues.filter(p => p.status !== 'not_configured').length;
  const usableStatuses = new Set(['success', 'not_found']);
  const responded = providerValues.filter(p => usableStatuses.has(p.status)).length;
  const successful = providerValues.filter(p => p.status === 'success').length;
  const coverage = {
    total: providerValues.length,
    configured,
    responded,
    successful,
    label: configured === 0 ? 'No providers configured' : `${responded} of ${configured} configured providers returned usable data`
  };

  return res.status(200).json({
    ok: true,
    mode: 'intel',
    requestId,
    domain,
    providers,
    coverage,
    checkedAt: new Date().toISOString(),
    durationMs: Date.now() - requestStartedAt,
    scoringPolicy: 'Live provider intelligence is supporting evidence only; the offline score is not changed by this response.'
  });
};
