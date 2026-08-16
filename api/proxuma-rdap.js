/* QANTRAE IT protected RDAP bridge (Vercel-compatible).
   Fixed upstream only: this endpoint never fetches arbitrary user-provided URLs. */
const net = require('net');
const RATE_WINDOW_MS = 60_000;
const MAX_RESPONSE_BYTES = 512 * 1024;
const buckets = new Map();

function headers(res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, nosnippet');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  res.setHeader('Vary', 'Origin');
}
function origins() {
  const set = new Set(['https://qantrae-ecosystem.vercel.app','http://localhost:3000','http://localhost:5173']);
  const extra=[process.env.QANTRAE_ALLOWED_ORIGIN,process.env.PROXUMA_ALLOWED_ORIGIN].filter(Boolean).join(',');
  String(extra).split(',').map(s=>s.trim()).filter(Boolean).forEach(v=>set.add(v));
  return set;
}
function cors(req,res){const o=String(req.headers?.origin||'');if(o&&!origins().has(o))return false;if(o)res.setHeader('Access-Control-Allow-Origin',o);res.setHeader('Access-Control-Allow-Methods','GET,OPTIONS');res.setHeader('Access-Control-Allow-Headers','Accept');return true;}
function ip(req){return String(req.headers?.['x-forwarded-for']||req.headers?.['x-real-ip']||req.socket?.remoteAddress||'unknown').split(',')[0].trim().slice(0,80)||'unknown';}
function limit(req,res,max=30){const now=Date.now(),id=ip(req),p=buckets.get(id),e=!p||now>=p.reset?{count:0,reset:now+RATE_WINDOW_MS}:p;e.count++;buckets.set(id,e);if(buckets.size>5000)for(const[k,v]of buckets)if(now>=v.reset)buckets.delete(k);res.setHeader('X-RateLimit-Limit',String(max));res.setHeader('X-RateLimit-Remaining',String(Math.max(0,max-e.count)));if(e.count<=max)return true;res.setHeader('Retry-After',String(Math.max(1,Math.ceil((e.reset-now)/1000))));res.status(429).json({error:'Too many requests. Please try again shortly.'});return false;}
function validDomain(d){if(!d||d.length>253||d.includes('..')||net.isIP(d))return false;return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(d);}
async function readJsonBounded(r){const declared=Number(r.headers.get('content-length')||0);if(declared&&declared>MAX_RESPONSE_BYTES)throw new Error('RDAP response too large');const t=await r.text();if(Buffer.byteLength(t,'utf8')>MAX_RESPONSE_BYTES)throw new Error('RDAP response too large');return t?JSON.parse(t):null;}

module.exports = async function handler(req,res){
  headers(res);
  if(!cors(req,res))return res.status(403).json({error:'Origin not allowed'});
  if(req.method==='OPTIONS')return res.status(204).end();
  if(req.method!=='GET')return res.status(405).json({error:'GET or OPTIONS required'});
  if(!limit(req,res,30))return;
  const domain=String(req.query?.domain||'').trim().toLowerCase().replace(/\.$/,'');
  if(!validDomain(domain))return res.status(400).json({error:'A valid public domain is required.'});
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),5000);
  try{
    const r=await fetch('https://rdap.org/domain/'+encodeURIComponent(domain),{headers:{Accept:'application/rdap+json, application/json','User-Agent':'QANTRAE-RDAP/1.0'},redirect:'error',signal:controller.signal});
    const data=await readJsonBounded(r).catch(()=>null);
    if(!r.ok||!data)return res.status(r.status===404?404:502).json({error:r.status===404?'Domain not found':'RDAP lookup unavailable'});
    return res.status(200).json({ok:true,domain,result:data,checkedAt:new Date().toISOString()});
  }catch(e){return res.status(502).json({error:e?.name==='AbortError'?'RDAP lookup timed out':'RDAP lookup unavailable'});}finally{clearTimeout(timer);}
};
