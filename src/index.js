/**
 * Ephemeral file sharing on Cloudflare Workers.
 *
 *   R2   - ciphertext only
 *   KV   - metadata (auto-expires, which is what makes links die on time)
 *   Cron - sweeps expired / burned objects out of R2
 *   DO   - optional: a strongly consistent download counter (COUNTER binding)
 *
 * The Worker is deliberately dumb about content. Files are encrypted in the
 * browser with AES-256-GCM before the first byte leaves it; the key lives in
 * the URL fragment, which is never sent to any server. This Worker stores an
 * opaque blob of equal-sized encrypted chunks and an encrypted header, and
 * cannot recover the filename, the media type, or the bytes.
 *
 * Uploads always go through R2 multipart, so a 2 KB note and a 40 GB tarball
 * take the same code path and neither is bounded by the Worker body limit.
 */

const MIN_CHUNK = 1 << 20;          // 1 MiB
const MAX_CHUNK = 64 << 20;         // 64 MiB
const R2_MIN_PART = 5 << 20;        // R2 multipart: every part but the last
const GCM_TAG = 16;                 // AES-GCM tag appended to every chunk
const MAX_PARTS = 10000;            // R2 multipart ceiling
const MAX_HEADER = 4096;            // encrypted name/type blob, base64
const MAX_TTL = 30 * 86400;         // nothing lives longer than 30 days
const PENDING_MAX_AGE = 6 * 3600e3; // abandoned multipart uploads get aborted
// KV backstops in case the sweep stops running: tombstones outlive any share
// (objects also carry their own expiry), pending records outlive R2's default
// 7-day abort-incomplete-multipart lifecycle rule.
const TOMBSTONE_TTL = MAX_TTL + 5 * 86400;
const PENDING_TTL = 8 * 86400;
// A burn download may still be streaming when its tombstone is written; give
// it this long before the sweep deletes the object underneath it.
const TOMBSTONE_GRACE = 10 * 60e3;
// KV allows about 1000 operations per invocation; stay well inside it and let
// the next hourly run pick up the rest.
const SWEEP_TOMBSTONES = 500;
const SWEEP_PENDING = 200;
const DEFAULT_MAX_SIZE_MB = 5120;
const ID_ALPHABET = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
// Resume tickets live as long as a burned object is guaranteed to survive, and
// a chain of renewed tickets never outlasts RESUME_SPAN from the counted
// download that started it. A ticket is a bearer value and can be replayed
// until it expires; a chain that stops moving forward through the file dies
// after RESUME_REPEATS reissues, so it cannot keep a full re-read alive for
// the whole span.
const TICKET_TTL = TOMBSTONE_GRACE;
const RESUME_SPAN = 6 * 3600e3;
const RESUME_REPEATS = 8;
const TICKET_LABEL = 'ephemeral-files/v1/resume-ticket';
const MAX_TICKET = 1024;
// KV entry holding a random 32-byte ticket secret when TICKET_SECRET is unset.
const TICKET_SECRET_KEY = 'k:ticket-secret';
// A download counter object clears itself this long after its share expires.
const COUNTER_MARGIN = 3600e3;
// base64url of a 32-byte value: the download auth key and its verifier.
const AUTH_SHAPE = /^[A-Za-z0-9_-]{43}$/;

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  // No includeSubDomains: this is a template, and a deploy on an apex or parent
  // name must not pin unrelated sibling hosts to HTTPS for a year.
  'strict-transport-security': 'max-age=31536000',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()',
};

// Mirrors public/_headers so the /f/<id> share pages, which the Worker serves,
// are locked down exactly like the statically served ones.
const PAGE_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
  "connect-src 'self'; manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/* ---------------------------------------------------------------- helpers */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...SECURITY_HEADERS,
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

const fail = (message, status = 400) => json({ error: message }, status);

function randomId(len = 16) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let out = '';
  // 57-char alphabet: 16 chars is ~93 bits, far past guessing range.
  for (const b of bytes) out += ID_ALPHABET[b % ID_ALPHABET.length];
  return out;
}

async function sha256(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function b64url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(text) {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/**
 * Compare two secrets without leaking their contents or length through timing:
 * hash both to a fixed width first, then diff every byte.
 */
async function secretEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const [ha, hb] = await Promise.all([sha256(a), sha256(b)]);
  let diff = 0;
  for (let i = 0; i < ha.length; i++) diff |= ha.charCodeAt(i) ^ hb.charCodeAt(i);
  return diff === 0;
}

let warnedMaxSize = false;

/** MAX_SIZE_MB as a positive number of MiB; a typo or negative value falls back loudly. */
function maxSizeMB(env) {
  const raw = env.MAX_SIZE_MB;
  if (raw === undefined || raw === null || raw === '') return DEFAULT_MAX_SIZE_MB;
  const value = Number(raw);
  if (Number.isFinite(value) && value > 0) return value;
  if (!warnedMaxSize) {
    warnedMaxSize = true;
    console.warn(JSON.stringify({ ev: 'config', warning: `MAX_SIZE_MB is not a positive number; using ${DEFAULT_MAX_SIZE_MB}` }));
  }
  return DEFAULT_MAX_SIZE_MB;
}

const maxBytes = (env) => maxSizeMB(env) * 1024 * 1024;
const validId = (id) => typeof id === 'string' && /^[A-Za-z0-9]{16,32}$/.test(id);

const BRAND_DEFAULTS = {
  name: 'ephemeral',
  tagline: 'Encrypted in your browser. Gone when it expires.',
  footer: 'AES-256-GCM in the browser \u00b7 the server stores ciphertext and cannot read the name or the contents',
  logo: '',
  accent: '#1f6feb',
  accentDark: '#4c8dff',
};

function brandText(value, fallback, maxLength, allowEmpty = false) {
  if (typeof value !== 'string') return fallback;
  const text = value.trim().slice(0, maxLength);
  return text || (allowEmpty ? '' : fallback);
}

function brandColor(value, fallback) {
  return typeof value === 'string' && /^#[0-9a-f]{6}$/i.test(value.trim())
    ? value.trim().toLowerCase()
    : fallback;
}

function brandAssetPath(value) {
  if (typeof value !== 'string' || !value.trim()) return '';
  const path = value.trim();
  try {
    const url = new URL(path, 'https://brand.invalid');
    if (!path.startsWith('/') || path.startsWith('//') || url.origin !== 'https://brand.invalid' || url.hash) return '';
    return `${url.pathname}${url.search}`;
  } catch {
    return '';
  }
}

export function getBrandConfig(env = {}) {
  return {
    name: brandText(env.BRAND_NAME, BRAND_DEFAULTS.name, 60),
    tagline: brandText(env.BRAND_TAGLINE, BRAND_DEFAULTS.tagline, 160, true),
    footer: brandText(env.BRAND_FOOTER, BRAND_DEFAULTS.footer, 240, true),
    logo: brandAssetPath(env.BRAND_LOGO),
    accent: brandColor(env.BRAND_ACCENT, BRAND_DEFAULTS.accent),
    accentDark: brandColor(env.BRAND_ACCENT_DARK, BRAND_DEFAULTS.accentDark),
  };
}

/**
 * Uploading is owner-only and fails closed: with no UPLOAD_TOKEN configured
 * nobody can upload, so a fresh deploy is never an open file dump. Downloads
 * stay open to whoever holds the link - that is what the link is for.
 */
async function authorized(request, env) {
  if (!env.UPLOAD_TOKEN) return false;
  const header = request.headers.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : header;
  return secretEquals(token, env.UPLOAD_TOKEN);
}

const denied = (env) =>
  env.UPLOAD_TOKEN
    ? fail('invalid upload token', 401)
    : fail('uploads are disabled: set UPLOAD_TOKEN with `wrangler secret put UPLOAD_TOKEN`', 503);

/**
 * Per-IP throttle. Enabled by uncommenting the [[ratelimits]] binding in
 * wrangler.toml; absent binding means no throttle, never a broken deploy.
 */
async function throttled(request, env, limiter, scope = limiter) {
  const binding = env[limiter];
  if (!binding?.limit) return false;
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const { success } = await binding.limit({ key: `${scope}:${ip}` });
  return !success;
}

const missingLogged = new Set();

/** A clear 503 instead of a TypeError-turned-500 when wrangler config lost a binding. */
function misconfigured(env, names) {
  const missing = names.find((name) => !env[name]);
  if (!missing) return null;
  if (!missingLogged.has(missing)) {
    missingLogged.add(missing);
    console.error(JSON.stringify({ ev: 'config', error: `missing ${missing} binding` }));
  }
  return fail(`server misconfigured: the ${missing} binding is missing from wrangler config`, 503);
}

const errorText = (err) => String(err?.stack || err);

// Share ids never reach the logs: observability retains them for days, which an
// ephemeral service should not do.
const routeOf = (pathname) => pathname.replace(/\/[A-Za-z0-9]{16,32}(?=\/|$)/g, '/:id');

function logError(request, err, extra = {}) {
  console.error(JSON.stringify({
    ev: 'error',
    method: request.method,
    route: routeOf(new URL(request.url).pathname),
    ray: request.headers.get('cf-ray') || undefined,
    ...extra,
    error: errorText(err),
  }));
}

const ttlUntil = (expires) => Math.max(Math.ceil((expires - Date.now()) / 1000), 60);

const putTombstone = (env, id) =>
  env.META.put(`x:${id}`, '1', { expirationTtl: TOMBSTONE_TTL, metadata: { at: Date.now() } });

/* --------------------------------------------------------- download auth */

// Off by default so cached web clients and older CLI copies, which never send
// x-ef-auth, keep working; the owner sets DOWNLOAD_AUTH = "enforce" once they
// have had time to refresh.
const authEnforced = (env) => env.DOWNLOAD_AUTH === 'enforce';

/**
 * Shares uploaded by current clients carry `auth`: base64url(sha256(authKey)),
 * where authKey is derived from the link key in the browser. A downloader
 * proves it holds the link key by sending authKey itself in x-ef-auth, so a
 * leaked id alone (logs, history without the fragment) cannot spend a view.
 * Returns a Response to refuse with, or the request's auth state, which resume
 * tickets carry: 'none' (share has no auth), 'key' (verified) or 'open' (share
 * has auth, the request did not present it, and the policy allowed that).
 */
async function downloadAuth(request, env, record) {
  if (!record.auth) return 'none';
  const presented = request.headers.get('x-ef-auth');
  if (presented === null) {
    return authEnforced(env) ? fail('this link needs an up-to-date client: reload the page or update the CLI', 401) : 'open';
  }
  if (!AUTH_SHAPE.test(presented)) return fail('wrong link key', 403);
  const verifier = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', fromB64url(presented))));
  return (await secretEquals(verifier, record.auth)) ? 'key' : fail('wrong link key', 403);
}

/* -------------------------------------------------------- resume tickets */

let storedSecret = null;     // Promise<Uint8Array>: the KV-held secret, once per isolate
let ticketKeyCache = { tag: null, key: null };

/**
 * The high-entropy secret tickets are keyed with: TICKET_SECRET if set, else a
 * random 32 bytes created once and kept in KV. Never UPLOAD_TOKEN alone: a
 * ticket is a known message and its MAC, so a key derived only from the token
 * would let anyone holding a ticket test guesses at the token offline.
 */
function ticketSecret(env) {
  if (env.TICKET_SECRET) return Promise.resolve(new TextEncoder().encode(env.TICKET_SECRET));
  if (!storedSecret) {
    const secret = (async () => {
      const stored = await env.META.get(TICKET_SECRET_KEY);
      if (typeof stored === 'string' && AUTH_SHAPE.test(stored)) return fromB64url(stored);
      // Two locations creating it at once each keep their own for a while;
      // a ticket that then fails to verify is refused, never counted.
      const fresh = crypto.getRandomValues(new Uint8Array(32));
      await env.META.put(TICKET_SECRET_KEY, b64url(fresh));
      return fresh;
    })();
    secret.catch(() => { if (storedSecret === secret) storedSecret = null; });
    storedSecret = secret;
  }
  return storedSecret;
}

/**
 * HMAC key for resume tickets: the ticket secret, bound to UPLOAD_TOKEN so
 * rotating the token still invalidates every ticket. Null without a token.
 */
function ticketKey(env) {
  if (!env.UPLOAD_TOKEN) return null;
  const tag = `${env.TICKET_SECRET ? 's' : 'kv'}:${env.TICKET_SECRET || ''}:${env.UPLOAD_TOKEN}`;
  if (ticketKeyCache.tag !== tag) {
    const token = env.UPLOAD_TOKEN;
    const hmac = { name: 'HMAC', hash: 'SHA-256' };
    const key = (async () => {
      const base = await crypto.subtle.importKey('raw', await ticketSecret(env), hmac, false, ['sign']);
      const derived = await crypto.subtle.sign('HMAC', base, new TextEncoder().encode(`${TICKET_LABEL}\n${token}`));
      return crypto.subtle.importKey('raw', derived, hmac, false, ['sign', 'verify']);
    })();
    key.catch(() => { if (ticketKeyCache.key === key) ticketKeyCache = { tag: null, key: null }; });
    ticketKeyCache = { tag, key };
  }
  return ticketKeyCache.key;
}

/**
 * Opaque to clients: base64url(JSON payload) "." base64url(HMAC-SHA-256).
 * Payload: id, s (object size), a (auth state), exp (this ticket), end (the
 * whole chain), c (ciphertext chunk size), o (furthest start served), r
 * (reissues since the start last moved forward by a chunk). Null when no
 * UPLOAD_TOKEN is configured, or when the ticket secret cannot be read: the
 * download then goes ahead without one.
 */
async function issueTicket(env, { id, s, a, end, c, o = 0, r = 0 }) {
  const key = ticketKey(env);
  if (!key) return null;
  try {
    const exp = Math.min(Date.now() + TICKET_TTL, end);
    const payload = b64url(new TextEncoder().encode(JSON.stringify({ id, s, a, exp, end, c, o, r })));
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', await key, new TextEncoder().encode(payload)));
    return `${payload}.${b64url(mac)}`;
  } catch (err) {
    console.error(JSON.stringify({ ev: 'error', step: 'ticket', error: errorText(err) }));
    return null;
  }
}

/** The ticket's payload if it is authentic, unexpired and for this id; otherwise null. */
async function readTicket(env, ticket, id) {
  const key = ticketKey(env);
  if (!key || typeof ticket !== 'string' || ticket.length > MAX_TICKET) return null;
  const parts = ticket.split('.');
  if (parts.length !== 2 || !parts.every((p) => /^[A-Za-z0-9_-]+$/.test(p))) return null;
  try {
    const valid = await crypto.subtle.verify('HMAC', await key, fromB64url(parts[1]), new TextEncoder().encode(parts[0]));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(fromB64url(parts[0])));
    const now = Date.now();
    if (payload?.id !== id || !(payload.exp > now) || !(payload.end > now)) return null;
    if (!Number.isSafeInteger(payload.s) || payload.s <= 0) return null;
    return payload;
  } catch {
    return null;
  }
}

/* ----------------------------------------------------------------- ranges */

/**
 * undefined when there is no Range header, null for anything but the single
 * `bytes=N-` / `bytes=N-M` form this Worker serves, else { start, end }.
 */
function parseRange(header) {
  if (header === null) return undefined;
  const m = /^bytes=(\d{1,15})-(\d{0,15})$/.exec(header.trim());
  if (!m) return null;
  const start = Number(m[1]);
  const end = m[2] === '' ? null : Number(m[2]);
  return end !== null && end < start ? null : { start, end };
}

/** The slice of a `size`-byte object a parsed range asks for, or null if none of it exists. */
function rangeSpan(range, size) {
  if (!range || range.start >= size) return null;
  const last = range.end === null ? size - 1 : Math.min(range.end, size - 1);
  return { offset: range.start, length: last - range.start + 1, last };
}

const unsatisfiable = (size) => {
  const response = fail('range not satisfiable: send a single bytes=N- or bytes=N-M range inside the file', 416);
  if (size) response.headers.set('content-range', `bytes */${size}`);
  return response;
};

/** The download response, whole or partial. Always opaque, always an attachment. */
function fileResponse(id, object, { head = false, span = null, remaining, ticket = null }) {
  const headers = {
    ...SECURITY_HEADERS,
    // Always opaque and always an attachment: the origin can never be talked
    // into serving user content as HTML, SVG or script.
    'content-type': 'application/octet-stream',
    'content-length': String(span ? span.length : object.size),
    'content-disposition': `attachment; filename="${id}.bin"`,
    'content-security-policy': "default-src 'none'; sandbox",
    'cache-control': 'no-store',
    'accept-ranges': 'bytes',
  };
  if (span) headers['content-range'] = `bytes ${span.offset}-${span.last}/${object.size}`;
  if (remaining !== undefined) headers['x-downloads-remaining'] = remaining;
  if (ticket) headers['x-resume-ticket'] = ticket;
  return new Response(head ? null : object.body, { status: span ? 206 : 200, headers });
}

const ticketRefused = () => fail('resume ticket expired or not valid; start the download again', 410);

/**
 * A Range request with a valid ticket continues a download that was already
 * counted: served straight from R2 without loading or counting the record, so
 * a burned one-read link can still finish inside the grace period before the
 * sweep deletes its object. Null means "no usable ticket"; the caller refuses
 * it for a limited share rather than count it as a new download.
 */
async function resumeDownload(request, env, id, range) {
  const ticket = await readTicket(env, request.headers.get('x-resume-ticket'), id);
  if (!ticket) return null;
  // Issued while unauthenticated downloads were allowed; once the owner turns
  // enforcement on, that ticket must go through the full check again.
  if (ticket.a === 'open' && authEnforced(env)) return null;
  const span = rangeSpan(range, ticket.s);
  if (!span) return unsatisfiable(ticket.s);
  // Forward progress: a request starting at least one chunk past the furthest
  // start served so far resets the count; anything else (a retry at the same
  // offset, a renewal, a restart from 0) uses up one of RESUME_REPEATS.
  const step = Number.isSafeInteger(ticket.c) && ticket.c > 0 ? ticket.c : ticket.s;
  let o = Number.isSafeInteger(ticket.o) && ticket.o >= 0 ? ticket.o : 0;
  let r = Number.isSafeInteger(ticket.r) && ticket.r >= 0 ? ticket.r : 0;
  if (span.offset >= o + step) { o = span.offset; r = 0; } else r += 1;
  if (r > RESUME_REPEATS) return ticketRefused();
  const object = await env.BUCKET.get(id, { range: { offset: span.offset, length: span.length } });
  if (!object) return fail('not found or expired', 404);
  const next = await issueTicket(env, { id, s: ticket.s, a: ticket.a, end: ticket.end, c: ticket.c, o, r });
  return fileResponse(id, object, { span, ticket: next });
}

/* ------------------------------------------------------- download counter */

const counterStub = (env, id) => env.COUNTER.get(env.COUNTER.idFromName(id));

/**
 * Atomically spends one download of a limited share in its DownloadCounter.
 * Resolves to { ok, count }; ok false means the limit is already reached.
 */
async function claimDownload(env, record) {
  const response = await counterStub(env, record.id).fetch('https://counter/claim', {
    method: 'POST',
    body: JSON.stringify({ limit: record.limit, seed: record.downloads, expires: record.expires }),
  });
  if (!response.ok) throw new Error(`download counter answered ${response.status}`);
  return response.json();
}

/**
 * Optional strongly consistent download counter, one object per share id.
 * Only used when the COUNTER binding exists (see wrangler.toml): KV is
 * eventually consistent, so without it two downloads racing on a one-read
 * link in different locations can both be served. Every claim takes the
 * higher of its own count and the KV record's, so links created before the
 * binding keep what they have left, and downloads counted only in KV while the
 * binding was removed still count when it comes back.
 */
export class DownloadCounter {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    const { pathname } = new URL(request.url);
    const storage = this.state.storage;
    if (request.method === 'POST' && pathname === '/clear') {
      await storage.deleteAlarm();
      await storage.deleteAll();
      return new Response(JSON.stringify({ ok: true }));
    }
    if (request.method !== 'POST' || pathname !== '/claim') return new Response('not found', { status: 404 });

    const body = await request.json().catch(() => null);
    const limit = Number(body?.limit);
    const seed = Number(body?.seed);
    const expires = Number(body?.expires);
    if (!Number.isSafeInteger(limit) || limit < 1 || !Number.isFinite(expires)) {
      return new Response(JSON.stringify({ error: 'bad claim' }), { status: 400 });
    }

    // Read, decide and write as one step: no other claim runs in between.
    const result = await this.state.blockConcurrencyWhile(async () => {
      const stored = await storage.get('count');
      if (stored === undefined) await storage.setAlarm(expires + COUNTER_MARGIN);
      // Always take the larger of this object's count and the KV record's:
      // downloads served while the binding was removed are counted only in
      // KV, and KV can only lag this object while the binding exists.
      const seeded = Number.isSafeInteger(seed) && seed > 0 ? Math.min(seed, limit) : 0;
      let count = Math.max(Number.isSafeInteger(stored) ? stored : 0, seeded);
      if (count >= limit) {
        if (count !== stored) await storage.put('count', count);
        return { ok: false, count };
      }
      count += 1;
      await storage.put('count', count);
      return { ok: true, count };
    });
    return new Response(JSON.stringify(result));
  }

  // The share has expired: nothing will ask about it again.
  async alarm() {
    await this.state.storage.deleteAll();
  }
}

/* ------------------------------------------------------------------- api */

async function loadRecord(env, id) {
  if (!validId(id)) return null;
  const record = await env.META.get(`f:${id}`, 'json');
  if (!record) return null;
  // Expired: KV's own expirationTtl removes the record and the object's
  // customMetadata.expires gets it swept, so a read path writes nothing.
  if (record.expires <= Date.now()) return null;
  return record;
}

async function uploadInit(request, env) {
  if (!(await authorized(request, env))) return denied(env);
  if (await throttled(request, env, 'UPLOAD_LIMIT')) return fail('too many uploads, slow down', 429);

  const body = await request.json().catch(() => null);
  if (!body) return fail('bad request');

  const size = Number(body.size);       // ciphertext length, in bytes
  const chunk = Number(body.chunkSize); // plaintext chunk length, in bytes
  if (!Number.isSafeInteger(size) || size <= 0) return fail('size required');
  if (size > maxBytes(env)) return fail(`file exceeds the ${maxSizeMB(env)} MiB limit`, 413);
  if (!Number.isSafeInteger(chunk) || chunk < MIN_CHUNK || chunk > MAX_CHUNK) return fail('bad chunk size');
  if (Math.ceil(size / (chunk + GCM_TAG)) > MAX_PARTS) return fail('too many chunks', 413);

  // R2 multipart needs every part but the last to be at least 5 MiB; a
  // smaller chunk would only fail at complete, after the whole upload.
  if (size > chunk + GCM_TAG && chunk + GCM_TAG < R2_MIN_PART) {
    return fail(`bad chunk size: a file of more than one chunk needs chunks of at least ${R2_MIN_PART - GCM_TAG} bytes`);
  }

  const ttl = Math.min(Math.max(Math.trunc(Number(body.ttl)) || 86400, 60), MAX_TTL);
  // A garbled limit used to become "unlimited". Absent or null (what older CLI
  // copies send for a bad --limit) still means unlimited; anything else must be
  // a number, numeric strings included. Older CLI copies send --limit
  // unchecked, so their fractions are truncated and their negative numbers
  // (`--limit -1`) still mean unlimited, as they always did. Current clients
  // refuse a negative limit before sending it.
  if (body.limit != null) {
    const n = Number(body.limit);
    if (!Number.isFinite(n)) return fail('bad limit: use a non-negative integer, 0 for unlimited');
    if (n < 0) console.warn(JSON.stringify({ ev: 'compat', warning: 'negative download limit treated as unlimited' }));
  }
  const limit = Math.min(Math.max(Math.trunc(Number(body.limit)) || 0, 0), 1e6); // 0 = unlimited

  const id = randomId();
  const expires = Date.now() + ttl * 1000;
  const multipart = await env.BUCKET.createMultipartUpload(id, {
    httpMetadata: { contentType: 'application/octet-stream' },
    customMetadata: { expires: String(expires) },
  });

  try {
    await env.META.put(
      `u:${id}`,
      JSON.stringify({ id, size, chunk, ttl, expires, limit, uploadId: multipart.uploadId }),
      { metadata: { created: Date.now() }, expirationTtl: PENDING_TTL },
    );
  } catch (err) {
    // Without the record the sweep could never find this upload to abort it.
    await multipart.abort().catch(() => {});
    throw err;
  }

  return json({ id, uploadId: multipart.uploadId });
}

async function uploadPart(request, env, url) {
  if (!(await authorized(request, env))) return denied(env);

  const id = url.searchParams.get('id');
  const uploadId = url.searchParams.get('uploadId');
  const partNumber = Number(url.searchParams.get('part'));
  if (!validId(id) || !uploadId) return fail('bad part request');
  if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > MAX_PARTS) return fail('bad part number');

  const pending = await env.META.get(`u:${id}`, 'json');
  if (!pending || pending.uploadId !== uploadId) return fail('unknown upload', 404);

  // Bound what a client can push: no part past the declared end of the file,
  // and no part larger than one encrypted chunk.
  const cipherChunk = pending.chunk + GCM_TAG;
  if (partNumber > Math.ceil(pending.size / cipherChunk)) return fail('part out of range');
  // Refuse before buffering when the client says up front it is too big.
  // Chunked bodies carry no length, so the check after reading stays.
  const declared = request.headers.get('content-length');
  if (declared !== null && Number(declared) > cipherChunk) return fail('bad part size', 413);

  const bytes = await request.arrayBuffer();
  if (bytes.byteLength === 0 || bytes.byteLength > cipherChunk) return fail('bad part size', 413);

  const part = await env.BUCKET.resumeMultipartUpload(id, uploadId).uploadPart(partNumber, bytes);
  return json({ partNumber: part.partNumber, etag: part.etag });
}

async function uploadComplete(request, env, ctx, url) {
  if (!(await authorized(request, env))) return denied(env);

  const body = await request.json().catch(() => null);
  if (!body || !validId(body.id) || !Array.isArray(body.parts) || !body.parts.length) return fail('bad request');
  if (typeof body.header !== 'string' || body.header.length > MAX_HEADER || !/^[A-Za-z0-9_-]+={0,2}$/.test(body.header)) {
    return fail('bad header');
  }
  // Optional: older clients do not send it, and their shares are never challenged.
  if (body.auth != null && (typeof body.auth !== 'string' || !AUTH_SHAPE.test(body.auth))) {
    return fail('bad auth: expected the base64url SHA-256 of the download key');
  }

  const pending = await env.META.get(`u:${body.id}`, 'json');
  if (!pending || pending.uploadId !== body.uploadId) return fail('unknown upload', 404);
  if (body.parts.length > MAX_PARTS) return fail('too many parts');

  const lastPart = Math.ceil(pending.size / (pending.chunk + GCM_TAG));
  const seen = new Set();
  const parts = [];
  for (const p of body.parts) {
    const partNumber = Number(p?.partNumber);
    if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > lastPart || seen.has(partNumber)) {
      return fail('bad part list: part numbers must be unique integers within the file');
    }
    if (typeof p.etag !== 'string' || !p.etag) return fail('bad part list: every part needs its etag');
    seen.add(partNumber);
    parts.push({ partNumber, etag: p.etag });
  }
  parts.sort((a, b) => a.partNumber - b.partNumber);

  const multipart = env.BUCKET.resumeMultipartUpload(pending.id, pending.uploadId);

  // The expiry clock starts at init. An upload that outlasted it would hand
  // back a link that is already dead.
  if (pending.expires <= Date.now()) {
    await multipart.abort().catch(() => {});
    await env.META.delete(`u:${pending.id}`);
    return fail('the upload took longer than the chosen expiry, so the link would already be dead; upload again with a longer expiry', 410);
  }

  const object = await multipart.complete(parts);
  if (typeof object?.size === 'number' && object.size !== pending.size) {
    await env.BUCKET.delete(pending.id);
    await env.META.delete(`u:${pending.id}`);
    return fail('uploaded size does not match declared size');
  }

  const deleteToken = randomId(32);
  const record = {
    id: pending.id,
    size: pending.size,
    chunk: pending.chunk,
    header: body.header,          // AES-GCM blob: filename + media type
    protected: Boolean(body.protected),
    created: Date.now(),
    expires: pending.expires,
    limit: pending.limit,
    downloads: 0,
    del: await sha256(deleteToken),
  };
  if (body.auth != null) record.auth = body.auth; // base64url(sha256(authKey)), see downloadAuth

  try {
    await env.META.put(`f:${pending.id}`, JSON.stringify(record), { expirationTtl: ttlUntil(record.expires) });
  } catch (err) {
    // No record means no link: drop the bytes rather than orphan them, and
    // say so in a way the client can act on.
    logError(request, err, { step: 'complete' });
    await env.BUCKET.delete(pending.id).catch(() => {});
    ctx.waitUntil(env.META.delete(`u:${pending.id}`).catch(() => {}));
    return fail('could not save the share; please upload again', 503);
  }
  ctx.waitUntil(env.META.delete(`u:${pending.id}`).catch((err) => logError(request, err, { step: 'complete' })));

  return json({
    id: record.id,
    url: new URL(`/f/${record.id}`, url).toString(),
    expires: record.expires,
    deleteToken,
  });
}

async function uploadAbort(request, env) {
  if (!(await authorized(request, env))) return denied(env);

  const body = await request.json().catch(() => null);
  if (!body || !validId(body.id)) return fail('bad request');

  const pending = await env.META.get(`u:${body.id}`, 'json');
  if (pending && pending.uploadId === body.uploadId) {
    await env.BUCKET.resumeMultipartUpload(body.id, body.uploadId).abort().catch(() => {});
    await env.META.delete(`u:${body.id}`);
  }
  return json({ ok: true });
}

/** Everything the share page needs. None of it is readable without the link key. */
async function meta(env, id) {
  const record = await loadRecord(env, id);
  if (!record) return fail('not found or expired', 404);
  return json({
    id: record.id,
    size: record.size,
    chunk: record.chunk,
    header: record.header,
    protected: record.protected,
    expires: record.expires,
    remaining: record.limit ? Math.max(record.limit - record.downloads, 0) : null,
    now: Date.now(), // lets clients correct `expires` for their own clock skew
    auth: Boolean(record.auth), // downloads should send x-ef-auth
  });
}

async function download(request, env, ctx, id) {
  // HEAD only asks whether the link is live: it must not spend a read, and
  // it has no reason to open the object body or honour a range.
  const head = request.method === 'HEAD';
  const range = head ? undefined : parseRange(request.headers.get('range'));
  const resuming = Boolean(range) && request.headers.has('x-resume-ticket');
  if (range && validId(id)) {
    const resumed = await resumeDownload(request, env, id, range);
    if (resumed) return resumed;
  }

  const record = await loadRecord(env, id);
  if (!record) return fail('not found or expired', 404);
  // Spent, but a stale KV read in this location has not caught up with the burn.
  if (record.limit > 0 && record.downloads >= record.limit) return fail('not found or expired', 404);
  // A resume whose ticket did not verify (expired, rotated token, refused
  // under enforce): counting it would quietly spend another download while
  // the client takes the answer as its continuation. Unlimited shares are
  // never counted, so they just serve the range.
  if (resuming && record.limit > 0) return ticketRefused();

  // Refusals before this point and in the next few lines spend nothing.
  const auth = await downloadAuth(request, env, record);
  if (auth instanceof Response) return auth;
  let span = null;
  if (range !== undefined) {
    span = rangeSpan(range, record.size);
    if (!span) return unsatisfiable(record.size);
  }
  // Minted up front so nothing can fail between opening the body and returning it.
  const ticket = head ? null : await issueTicket(env, {
    id: record.id,
    s: record.size,
    a: auth,
    end: Math.min(Date.now() + RESUME_SPAN, record.expires + TICKET_TTL),
    c: record.chunk + GCM_TAG,
    o: span ? span.offset : 0,
  });

  // Opened before anything is counted: a failed R2 read spends nothing.
  const object = head
    ? await env.BUCKET.head(record.id)
    : await env.BUCKET.get(record.id, span ? { range: { offset: span.offset, length: span.length } } : undefined);
  if (!object) {
    await env.META.delete(`f:${id}`);
    return fail('not found or expired', 404);
  }

  // Unlimited shares are never counted: nothing reads the number, and a KV
  // write per download would let one link holder drain the write quota.
  if (!head && record.limit > 0) {
    let claimed = false;
    try {
      if (env.COUNTER) {
        // The authoritative count. KV still gets the burn and the new number
        // below, for meta and for deploys without the binding.
        const claim = await claimDownload(env, record);
        if (!claim.ok) {
          await object.body?.cancel().catch(() => {});
          return fail('not found or expired', 404);
        }
        record.downloads = claim.count;
        claimed = true;
      } else {
        record.downloads += 1;
      }
      if (record.downloads >= record.limit) {
        // Kill the link before the first byte goes out; the sweep reclaims the
        // bytes after a grace period, so the object is never deleted out from
        // under this response while it streams.
        await env.META.delete(`f:${id}`);
        await putTombstone(env, id);
      } else {
        ctx.waitUntil(
          env.META.put(`f:${id}`, JSON.stringify(record), { expirationTtl: ttlUntil(record.expires) })
            .catch((err) => logError(request, err, { step: 'count' })),
        );
      }
    } catch (err) {
      if (!claimed) {
        // Fail closed: without the counter, a burn that did not land must not
        // serve the bytes; a counter that did not answer spent nothing.
        await object.body?.cancel().catch(() => {});
        throw err;
      }
      // The counter has already spent this download and refuses any more, so
      // serve it rather than burn a view for nothing. KV catches up on the
      // next count; without a tombstone the object goes at its expiry.
      logError(request, err, { step: 'burn' });
    }
  }

  return fileResponse(record.id, object, {
    head,
    span,
    ticket,
    remaining: record.limit ? String(Math.max(record.limit - record.downloads, 0)) : 'unlimited',
  });
}

async function revoke(request, env, ctx, id) {
  const record = await loadRecord(env, id);
  if (!record) return fail('not found or expired', 404);

  const token = request.headers.get('x-delete-token') || '';
  if (!token || !(await secretEquals(record.del, await sha256(token)))) return fail('bad delete token', 403);

  await env.META.delete(`f:${id}`);
  await env.BUCKET.delete(record.id);
  // Best effort: the counter's own alarm clears it at expiry anyway.
  if (env.COUNTER && record.limit > 0) {
    ctx.waitUntil(
      counterStub(env, record.id).fetch('https://counter/clear', { method: 'POST' })
        .catch((err) => logError(request, err, { step: 'revoke' })),
    );
  }
  return json({ ok: true });
}

async function handleApi(request, env, ctx, url) {
  const path = url.pathname.slice(4); // strip "/api"
  const method = request.method;

  if (method === 'GET' && path === '/config') {
    return json({
      maxSizeMB: maxSizeMB(env),
      configured: Boolean(env.UPLOAD_TOKEN),
      brand: getBrandConfig(env),
      downloadAuth: authEnforced(env) ? 'enforce' : 'optional',
    });
  }
  // Lets the UI unlock without starting an upload. Rate-limited like uploads,
  // and it reveals nothing beyond whether the presented token is the right one.
  if (method === 'GET' && path === '/auth') {
    if (await throttled(request, env, 'UPLOAD_LIMIT')) return fail('too many attempts', 429);
    return (await authorized(request, env)) ? json({ ok: true }) : denied(env);
  }

  const broken = misconfigured(env, ['META', 'BUCKET']);
  if (broken) return broken;

  if (method === 'POST' && path === '/upload/init') return uploadInit(request, env);
  if (method === 'PUT' && path === '/upload/part') return uploadPart(request, env, url);
  if (method === 'POST' && path === '/upload/complete') return uploadComplete(request, env, ctx, url);
  if (method === 'POST' && path === '/upload/abort') return uploadAbort(request, env);

  const file = path.match(/^\/f\/([^/]+)$/);
  if (file && method === 'GET') {
    // Same binding as downloads but its own counter, so the share page's
    // meta + download pair does not halve anyone's existing download budget.
    if (await throttled(request, env, 'DOWNLOAD_LIMIT', 'DOWNLOAD_LIMIT:meta')) return fail('too many requests', 429);
    return meta(env, file[1]);
  }
  // Revoke is not throttled: it already needs a 32-character delete token, and
  // older clients delete a whole bundle at once and drop the tokens whatever
  // the answer, so a 429 here would strand live files.
  if (file && method === 'DELETE') return revoke(request, env, ctx, file[1]);

  const direct = path.match(/^\/d\/([^/]+)$/);
  if (direct && (method === 'GET' || method === 'HEAD')) {
    if (await throttled(request, env, 'DOWNLOAD_LIMIT')) return fail('too many requests', 429);
    return download(request, env, ctx, direct[1]);
  }

  return fail('not found', 404);
}

/* ---------------------------------------------------------------- sweeper */

/** Every key under a KV prefix, one page (up to 1000 keys) at a time. */
async function* kvPages(env, prefix) {
  let cursor;
  do {
    const page = await env.META.list({ prefix, cursor });
    yield page.keys;
    cursor = !page.list_complete && page.cursor ? page.cursor : undefined;
  } while (cursor);
}

/** R2 objects whose own customMetadata.expires has passed. */
async function sweepExpired(env, now) {
  let deleted = 0;
  let cursor;
  do {
    const listing = await env.BUCKET.list({ limit: 1000, cursor, include: ['customMetadata'] });
    const stale = listing.objects
      .filter((o) => {
        const expires = Number(o.customMetadata?.expires);
        return Number.isFinite(expires) && expires <= now;
      })
      .map((o) => o.key);
    if (stale.length) {
      await env.BUCKET.delete(stale);
      deleted += stale.length;
    }
    cursor = listing.truncated ? listing.cursor : undefined;
  } while (cursor);
  return { deleted };
}

/** Objects of burned links. Tombstones without metadata predate the grace period and count as old. */
async function sweepTombstones(env, now) {
  let deleted = 0;
  let waiting = 0;
  for await (const keys of kvPages(env, 'x:')) {
    const due = [];
    for (const key of keys) {
      if (now - (Number(key.metadata?.at) || 0) < TOMBSTONE_GRACE) waiting += 1;
      else if (deleted + due.length < SWEEP_TOMBSTONES) due.push(key.name);
    }
    if (due.length) {
      await env.BUCKET.delete(due.map((name) => name.slice(2)));
      for (let i = 0; i < due.length; i += 50) {
        await Promise.all(due.slice(i, i + 50).map((name) => env.META.delete(name)));
      }
      deleted += due.length;
    }
    if (deleted >= SWEEP_TOMBSTONES) break;
  }
  return { deleted, waiting };
}

/** Multipart uploads nobody finished within PENDING_MAX_AGE of init. */
async function sweepPending(env, now) {
  let aborted = 0;
  pages: for await (const keys of kvPages(env, 'u:')) {
    for (const key of keys) {
      if (now - (key.metadata?.created ?? 0) < PENDING_MAX_AGE) continue;
      if (aborted >= SWEEP_PENDING) break pages;
      const record = await env.META.get(key.name, 'json');
      if (record?.uploadId) {
        await env.BUCKET.resumeMultipartUpload(record.id, record.uploadId).abort().catch(() => {});
      }
      await env.META.delete(key.name);
      aborted += 1;
    }
  }
  return { aborted };
}

/**
 * Hourly: delete objects past their expiry, collect tombstones left by
 * burn-after-read downloads, and abort multipart uploads nobody finished.
 * Each phase runs even if an earlier one failed; any failure still rejects so
 * the cron run is recorded as failed.
 */
async function sweep(env) {
  const now = Date.now();
  const failed = [];
  const phases = [['expired', sweepExpired], ['tombstones', sweepTombstones], ['pending', sweepPending]];
  for (const [phase, run] of phases) {
    try {
      console.log(JSON.stringify({ ev: 'sweep', phase, ...(await run(env, now)) }));
    } catch (err) {
      failed.push(phase);
      console.error(JSON.stringify({ ev: 'sweep', phase, error: errorText(err) }));
    }
  }
  if (failed.length) throw new Error(`sweep failed in: ${failed.join(', ')}`);
}

/* ------------------------------------------------------------------ entry */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/api/')) {
      try {
        return await handleApi(request, env, ctx, url);
      } catch (err) {
        logError(request, err); // details never reach the client; the ray id lets the owner find them
        const ray = request.headers.get('cf-ray');
        return json(ray ? { error: 'internal error', ray } : { error: 'internal error' }, 500);
      }
    }

    // Existing static assets are served before the Worker runs, so this only
    // handles /f/<id> share pages: same single-page app, no server rendering,
    // and the key in the fragment is never part of the request. Nothing else
    // gets the app - an unknown path is a 404, not a soft landing.
    if (!/^\/f\/[A-Za-z0-9]{16,32}\/?$/.test(url.pathname)) {
      return new Response('not found', { status: 404, headers: { ...SECURITY_HEADERS, 'content-type': 'text/plain' } });
    }

    const broken = misconfigured(env, ['ASSETS']);
    if (broken) return broken;

    // Ask for "/" rather than "/index.html": the asset server redirects the
    // latter to the former, which would strip the share id from the URL.
    const page = await env.ASSETS.fetch(new Request(new URL('/', url), request));
    const headers = new Headers(page.headers);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
    headers.set('content-security-policy', PAGE_CSP);
    headers.set('cache-control', 'no-store');
    return new Response(page.body, { status: page.status, headers });
  },

  // Awaited, not waitUntil: the sweep gets the cron invocation's own time
  // budget, and a failure marks the run as failed in the dashboard.
  async scheduled(_event, env) {
    await sweep(env);
  },
};
