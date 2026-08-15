/* QANTRAE IT protected optional serverless intelligence + short-link bridge (Vercel-compatible).
   Secrets stay server-side. Configure VIRUSTOTAL_API_KEY and/or GOOGLE_WEBRISK_API_KEY.
   PROXUMA_ALLOWED_ORIGIN may contain a comma-separated allowlist of additional origins.
   The in-process limiter is a best-effort guard; use platform/WAF rate limiting as the outer layer. */
const dns = require('dns').promises;
const net = require('net');

const RATE_WINDOW_MS = 60_000;
const MAX_BODY_BYTES = 8 * 1024;
const MAX_URL_CHARS = 2048;
const MAX_DOMAIN_CHARS = 253;
const MAX_PROVIDER_BYTES = 256 * 1024;
const buckets = new Map();

function applySecurityHeaders(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  res.setHeader('Vary', 'Origin');
}

function allowedOrigins() {
  const set = new Set(['https://scar197124.github.io','http://localhost:3000','http://localhost:5173']);
  String(process.env.PROXUMA_ALLOWED_ORIGIN || '').split(',').map(s=>s.trim()).filter(Boolean).forEach(v=>set.add(v));
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
  if (buckets.size > 5000) {
    for (const [k,v] of buckets) if (now >= v.reset) buckets.delete(k);
  }
  const remaining = Math.max(0, max - entry.count);
  res.setHeader('X-RateLimit-Limit', String(max));
  res.setHeader('X-RateLimit-Remaining', String(remaining));
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

function isPrivateIp(ip) {
  if (!ip) return true;
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) || (p[0] === 198 && (p[1] === 18 || p[1] === 19));
  }
  const v = ip.toLowerCase();
  return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80:') || v.startsWith('::ffff:127.') || v.startsWith('::ffff:10.') || v.startsWith('::ffff:192.168.');
}

function validDomain(domain) {
  if (!domain || domain.length > MAX_DOMAIN_CHARS || domain.includes('..')) return false;
  if (net.isIP(domain)) return !isPrivateIp(domain);
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(domain);
}

async function assertPublicHttpUrl(raw) {
  if (typeof raw !== 'string' || raw.length > MAX_URL_CHARS) throw new Error('URL is too long');
  let u;
  try { u = new URL(raw); } catch { throw new Error('Invalid URL'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http(s) destinations are allowed');
  if (!u.hostname || u.username || u.password) throw new Error('Unsafe URL form');
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) throw new Error('Private destinations are blocked');
  if (net.isIP(host)) { if (isPrivateIp(host)) throw new Error('Private destinations are blocked'); }
  else {
    const answers = await dns.lookup(host, { all: true, verbatim: true });
    if (!answers.length || answers.some(a => isPrivateIp(a.address))) throw new Error('Private destinations are blocked');
  }
  return u;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 4500) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  if (options.signal) {
    if (options.signal.aborted) controller.abort();
    else options.signal.addEventListener('abort', () => controller.abort(), { once: true });
  }
  try { return await fetch(url, { ...options, signal: controller.signal }); }
  finally { clearTimeout(timer); }
}

async function safeJson(response, maxBytes = MAX_PROVIDER_BYTES) {
  const declared = Number(response.headers.get('content-length') || 0);
  if (declared && declared > maxBytes) throw new Error('Provider response too large');
  const text = await response.text();
  if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error('Provider response too large');
  return text ? JSON.parse(text) : null;
}

async function resolveRedirectChain(startUrl) {
  let current = String(startUrl);
  const chain = [];
  for (let i = 0; i < 8; i++) {
    const u = await assertPublicHttpUrl(current);
    const r = await fetchWithTimeout(u.toString(), { method: 'GET', redirect: 'manual', headers: { 'User-Agent': 'QANTRAE-LinkResolver/1.0', 'Accept': '*/*' } }, 5000);
    chain.push(u.toString());
    if (r.status >= 300 && r.status < 400) {
      const loc = r.headers.get('location');
      if (!loc) break;
      current = new URL(loc, u).toString();
      continue;
    }
    try { if (r.body?.cancel) await r.body.cancel(); } catch {}
    return { finalUrl: u.toString(), finalHost: u.hostname.toLowerCase(), redirectCount: Math.max(0, chain.length - 1), chain, status: r.status };
  }
  const u = await assertPublicHttpUrl(current);
  return { finalUrl: u.toString(), finalHost: u.hostname.toLowerCase(), redirectCount: Math.max(0, chain.length - 1), chain, status: null };
}

module.exports = async function handler(req, res) {
  applySecurityHeaders(res);
  if (!applyCors(req, res)) return res.status(403).json({ error: 'Origin not allowed' });
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (bodyTooLarge(req)) return res.status(413).json({ error: 'Request body too large' });

  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  const wrKey = process.env.GOOGLE_WEBRISK_API_KEY;
  if (req.method === 'GET') {
    if (!limit(req, res, 'health', 60)) return;
    return res.status(200).json({ ok: true, service: 'qantrae-intel-bridge', resolver: true, protected: true, providers: { virustotal: !!vtKey, webrisk: !!wrKey }, checkedAt: new Date().toISOString() });
  }
  if (req.method !== 'POST') return res.status(405).json({ error: 'GET, POST, or OPTIONS required' });

  const body = typeof req.body === 'string' ? (()=>{ try{return JSON.parse(req.body)}catch{return {}} })() : (req.body || {});
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
      return res.status(400).json({ error: e && e.message ? e.message : 'Destination resolution failed.' });
    }
  }

  if (!limit(req, res, 'intel', 24)) return;
  if (!/^https?:\/\//i.test(url) || url.length > MAX_URL_CHARS || !validDomain(domain)) return res.status(400).json({ error: 'A valid http(s) URL and public domain are required.' });
  try { await assertPublicHttpUrl(url); } catch (e) { return res.status(400).json({ error: e.message || 'Unsafe URL' }); }
  const providers = {};

  if (vtKey) {
    try {
      const id = Buffer.from(url).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
      const r = await fetchWithTimeout('https://www.virustotal.com/api/v3/urls/' + encodeURIComponent(id), { headers: { 'x-apikey': vtKey, 'Accept': 'application/json' } }, 4500);
      if (r.status === 404) providers.virustotal = { found: false };
      else {
        const data = await safeJson(r).catch(()=>null);
        if (!r.ok || !data) throw new Error('VirusTotal lookup failed');
        const stats = data.data?.attributes?.last_analysis_stats || {};
        providers.virustotal = { found: true, malicious: Number(stats.malicious||0), suspicious: Number(stats.suspicious||0), harmless: Number(stats.harmless||0), undetected: Number(stats.undetected||0), lastAnalysisDate: data.data?.attributes?.last_analysis_date || null };
      }
    } catch { providers.virustotal = { error: true }; }
  }

  if (wrKey) {
    try {
      const q = new URLSearchParams();
      q.set('uri', url);
      ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE'].forEach(t=>q.append('threatTypes',t));
      q.set('key', wrKey);
      const r = await fetchWithTimeout('https://webrisk.googleapis.com/v1/uris:search?' + q.toString(), { headers: { 'Accept': 'application/json' } }, 4500);
      const data = await safeJson(r).catch(()=>null);
      if (!r.ok || !data) throw new Error('Web Risk lookup failed');
      const threats = Array.isArray(data.threat?.threatTypes) ? data.threat.threatTypes : [];
      providers.webrisk = { threats };
    } catch { providers.webrisk = { error: true }; }
  }

  return res.status(200).json({ ok: true, domain, providers, checkedAt: new Date().toISOString() });
};
