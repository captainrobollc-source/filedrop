// filedrop: a private place to pass files and text between your own devices.
// No dependencies. Everything lives in ./data (kept across Pocket deploys).
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3001);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_MB = Number(process.env.MAX_MB || 4096);   // per file
const KEEP_FREE_MB = 1024;                           // refuse uploads that would leave less than this free
const DATA = path.join(__dirname, 'data');
const STORE = path.join(DATA, 'files');
const PUBLIC = path.join(__dirname, 'public');
fs.mkdirSync(STORE, { recursive: true });

const F = { index: path.join(DATA, 'index.json'), notes: path.join(DATA, 'notes.json'), auth: path.join(DATA, 'auth.json') };
const readJSON = (f, d) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return d; } };
const writeJSON = (f, v) => { fs.writeFileSync(f + '.tmp', JSON.stringify(v)); fs.renameSync(f + '.tmp', f); };

let files = readJSON(F.index, []);
let notes = readJSON(F.notes, []);
let auth = readJSON(F.auth, null);
let version = Date.now(); // bumps on every change so clients can poll cheaply

// Clean up half-finished uploads from a previous run.
for (const n of fs.readdirSync(STORE)) if (n.endsWith('.part')) fs.rmSync(path.join(STORE, n), { force: true });
files = files.filter(f => fs.existsSync(path.join(STORE, f.id)));

// ---------- auth: one password, signed cookie ----------
const COOKIE = 'fd';
const COOKIE_DAYS = 365;
function hashPassword(pw, salt) { return crypto.scryptSync(pw, salt, 32).toString('hex'); }
function setPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  auth = { salt, hash: hashPassword(pw, salt), secret: crypto.randomBytes(32).toString('hex') };
  writeJSON(F.auth, auth);
}
function checkPassword(pw) {
  if (!auth) return false;
  const a = Buffer.from(hashPassword(pw, auth.salt), 'hex'), b = Buffer.from(auth.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function makeCookie() {
  const exp = Date.now() + COOKIE_DAYS * 864e5;
  const sig = crypto.createHmac('sha256', auth.secret).update(String(exp)).digest('hex');
  return `${exp}.${sig}`;
}
function signedIn(req) {
  if (!auth) return false;
  const m = (req.headers.cookie || '').match(new RegExp(`(?:^|; )${COOKIE}=([^;]+)`));
  if (!m) return false;
  const [exp, sig] = m[1].split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const want = crypto.createHmac('sha256', auth.secret).update(exp).digest('hex');
  return sig.length === want.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want));
}
const failures = new Map(); // ip -> { n, until }
function tooManyTries(ip) {
  const f = failures.get(ip);
  return f && f.n >= 8 && f.until > Date.now();
}
function noteFailure(ip) {
  const f = failures.get(ip) || { n: 0, until: 0 };
  if (f.until < Date.now()) f.n = 0;
  f.n++; f.until = Date.now() + 15 * 60_000;
  failures.set(ip, f);
}

// ---------- helpers ----------
function send(res, code, body, headers = {}) {
  const isObj = body && typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(code, { 'content-type': isObj ? 'application/json' : 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(isObj ? JSON.stringify(body) : body);
}
function readBody(req, limit = 2e6) {
  return new Promise((resolve, reject) => {
    const parts = []; let n = 0;
    req.on('data', c => { n += c.length; if (n > limit) { reject(new Error('Too large')); req.destroy(); } else parts.push(c); });
    req.on('end', () => { try { resolve(n ? JSON.parse(Buffer.concat(parts)) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
function deviceName(ua = '') {
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua)) return 'iPad';
  if (/Android/.test(ua)) return 'Android';
  if (/Macintosh/.test(ua)) return 'Mac';
  if (/Windows/.test(ua)) return 'Windows';
  if (/Linux/.test(ua)) return 'Linux';
  return 'Unknown device';
}
function cleanName(name) {
  name = String(name || 'file').replace(/[\\/\x00-\x1f]/g, '_').trim().slice(0, 200);
  return name || 'file';
}
const MIME = {
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp',
  '.heic': 'image/heic', '.svg': 'image/svg+xml', '.mp4': 'video/mp4', '.mov': 'video/quicktime', '.webm': 'video/webm',
  '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.wav': 'audio/wav', '.pdf': 'application/pdf', '.txt': 'text/plain; charset=utf-8',
  '.json': 'application/json', '.zip': 'application/zip', '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript',
};
// Types that are safe to show inline. Anything else is always downloaded.
const INLINE_OK = /^(image\/(jpeg|png|gif|webp|heic)|video\/|audio\/|application\/pdf|text\/plain)/;
function freeMB() {
  try { const s = fs.statfsSync(DATA); return (s.bavail * s.bsize) / 1048576; } catch { return Infinity; }
}
function totals() { return { count: files.length, bytes: files.reduce((a, f) => a + f.size, 0), freeMB: Math.round(freeMB()) }; }

// ---------- upload (raw body, streamed to disk) ----------
function handleUpload(req, res, url) {
  const name = cleanName(url.searchParams.get('name'));
  const len = Number(req.headers['content-length'] || 0);
  if (len > MAX_MB * 1048576) return send(res, 413, { error: `Files can be up to ${MAX_MB} MB` });
  if (freeMB() - len / 1048576 < KEEP_FREE_MB) return send(res, 507, { error: 'The phone is almost out of storage' });
  const id = crypto.randomBytes(9).toString('base64url');
  const tmp = path.join(STORE, id + '.part');
  const out = fs.createWriteStream(tmp);
  let size = 0, aborted = false;
  req.on('data', c => {
    size += c.length;
    if (size > MAX_MB * 1048576 && !aborted) { aborted = true; req.destroy(); out.destroy(); fs.rm(tmp, { force: true }, () => {}); send(res, 413, { error: 'Too large' }); }
  });
  req.on('aborted', () => { aborted = true; out.destroy(); fs.rm(tmp, { force: true }, () => {}); });
  req.pipe(out);
  out.on('finish', () => {
    if (aborted) return;
    fs.renameSync(tmp, path.join(STORE, id));
    const type = String(req.headers['x-file-type'] || '') || MIME[path.extname(name).toLowerCase()] || 'application/octet-stream';
    const entry = { id, name, size, type: type.slice(0, 100), added: Date.now(), from: deviceName(req.headers['user-agent']) };
    files.unshift(entry);
    writeJSON(F.index, files);
    version = Date.now();
    console.log(`[upload] ${name} (${(size / 1048576).toFixed(1)} MB) from ${entry.from}`);
    send(res, 200, entry);
  });
  out.on('error', e => { if (!aborted) { aborted = true; send(res, 500, { error: e.message }); } });
}

// ---------- download (with Range support so video plays on phones) ----------
function handleDownload(req, res, id, wantDownload) {
  const f = files.find(x => x.id === id);
  if (!f) return send(res, 404, 'Not found');
  const file = path.join(STORE, f.id);
  const size = fs.statSync(file).size;
  const inline = !wantDownload && INLINE_OK.test(f.type);
  const headers = {
    'content-type': inline ? f.type : 'application/octet-stream',
    'content-disposition': `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(f.name)}`,
    'x-content-type-options': 'nosniff',
    'content-security-policy': "sandbox; default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'",
    'accept-ranges': 'bytes',
    'cache-control': 'private, max-age=86400',
  };
  const m = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
  if (m && (m[1] || m[2])) {
    let start = m[1] ? Number(m[1]) : size - Number(m[2]);
    let end = m[1] && m[2] ? Number(m[2]) : size - 1;
    if (start >= size || start < 0 || end < start) return send(res, 416, '', { 'content-range': `bytes */${size}` });
    end = Math.min(end, size - 1);
    res.writeHead(206, { ...headers, 'content-range': `bytes ${start}-${end}/${size}`, 'content-length': end - start + 1 });
    if (req.method === 'HEAD') return res.end();
    return fs.createReadStream(file, { start, end }).pipe(res);
  }
  res.writeHead(200, { ...headers, 'content-length': size });
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(file).pipe(res);
}

// ---------- server ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  const ip = req.socket.remoteAddress;
  try {
    if (p === '/healthz') return send(res, 200, 'ok');

    // static assets (the page itself decides whether to show login, setup or the app)
    if (p === '/' || p === '/index.html' || p === '/manifest.json' || p === '/icon.svg') {
      const file = path.join(PUBLIC, p === '/' ? 'index.html' : p.slice(1));
      const type = { '.html': 'text/html; charset=utf-8', '.json': 'application/manifest+json', '.svg': 'image/svg+xml' }[path.extname(file)];
      return send(res, 200, fs.readFileSync(file), { 'content-type': type });
    }

    if (p === '/api/me') return send(res, 200, { setup: !auth, signedIn: signedIn(req) });

    if (p === '/api/setup' && req.method === 'POST') {
      if (auth) return send(res, 403, { error: 'A password is already set' });
      const { password } = await readBody(req);
      if (typeof password !== 'string' || password.length < 6) return send(res, 400, { error: 'Use at least 6 characters' });
      setPassword(password);
      return send(res, 200, { ok: true }, { 'set-cookie': cookieHeader(req) });
    }
    if (p === '/api/login' && req.method === 'POST') {
      if (tooManyTries(ip)) return send(res, 429, { error: 'Too many tries. Wait 15 minutes.' });
      const { password } = await readBody(req);
      if (!checkPassword(String(password || ''))) { noteFailure(ip); return send(res, 401, { error: 'Wrong password' }); }
      failures.delete(ip);
      return send(res, 200, { ok: true }, { 'set-cookie': cookieHeader(req) });
    }

    // everything below needs a signed-in device
    if (!signedIn(req)) return send(res, 401, { error: 'Sign in first' });

    if (p === '/api/logout' && req.method === 'POST') return send(res, 200, { ok: true }, { 'set-cookie': `${COOKIE}=; Path=/; Max-Age=0` });
    if (p === '/api/password' && req.method === 'POST') {
      const { current, password } = await readBody(req);
      if (!checkPassword(String(current || ''))) return send(res, 401, { error: 'Current password is wrong' });
      if (typeof password !== 'string' || password.length < 6) return send(res, 400, { error: 'Use at least 6 characters' });
      setPassword(password); // new secret signs out every other device
      return send(res, 200, { ok: true }, { 'set-cookie': cookieHeader(req) });
    }
    if (p === '/api/state') {
      if (url.searchParams.get('v') === String(version)) return send(res, 200, { version, unchanged: true });
      return send(res, 200, { version, files, notes, totals: totals(), maxMB: MAX_MB });
    }
    if (p === '/api/upload' && req.method === 'POST') return handleUpload(req, res, url);
    let m;
    if ((m = p.match(/^\/f\/([\w-]+)(?:\/.*)?$/)) && (req.method === 'GET' || req.method === 'HEAD')) {
      return handleDownload(req, res, m[1], url.searchParams.has('dl'));
    }
    if ((m = p.match(/^\/api\/files\/([\w-]+)$/)) && req.method === 'DELETE') {
      const f = files.find(x => x.id === m[1]);
      if (!f) return send(res, 404, { error: 'Not found' });
      fs.rmSync(path.join(STORE, f.id), { force: true });
      files = files.filter(x => x !== f);
      writeJSON(F.index, files); version = Date.now();
      return send(res, 200, { ok: true });
    }
    if (p === '/api/notes' && req.method === 'POST') {
      const { text } = await readBody(req);
      if (typeof text !== 'string' || !text.trim()) return send(res, 400, { error: 'Empty' });
      const note = { id: crypto.randomBytes(6).toString('base64url'), text: text.slice(0, 100_000), added: Date.now(), from: deviceName(req.headers['user-agent']) };
      notes.unshift(note);
      writeJSON(F.notes, notes); version = Date.now();
      return send(res, 200, note);
    }
    if ((m = p.match(/^\/api\/notes\/([\w-]+)$/)) && req.method === 'DELETE') {
      notes = notes.filter(n => n.id !== m[1]);
      writeJSON(F.notes, notes); version = Date.now();
      return send(res, 200, { ok: true });
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: e.message });
  }
});

function cookieHeader(req) {
  // Secure only when reached over HTTPS (Pocket's TLS front end, or Tailscale HTTPS).
  const https = req.headers['x-forwarded-proto'] === 'https';
  return `${COOKIE}=${makeCookie()}; Path=/; Max-Age=${COOKIE_DAYS * 86400}; HttpOnly; SameSite=Strict${https ? '; Secure' : ''}`;
}

server.requestTimeout = 0; // big uploads over slow links must not be cut off
server.listen(PORT, HOST, () => console.log(`filedrop listening on ${HOST}:${PORT}${auth ? '' : ' (no password yet: open the page to set one)'}`));
