/**
 * Ephemeral file sharing on Cloudflare Workers.
 *
 *   R2   - ciphertext only
 *   KV   - metadata (auto-expires, which is what makes links die on time)
 *   Cron - sweeps expired / burned objects out of R2
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
const GCM_TAG = 16;                 // AES-GCM tag appended to every chunk
const MAX_PARTS = 10000;            // R2 multipart ceiling
const MAX_HEADER = 4096;            // encrypted name/type blob, base64
const MAX_TTL = 30 * 86400;         // nothing lives longer than 30 days
const PENDING_MAX_AGE = 6 * 3600e3; // abandoned multipart uploads get aborted
const ID_ALPHABET = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
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

const maxBytes = (env) => (Number(env.MAX_SIZE_MB) || 5120) * 1024 * 1024;
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
async function throttled(request, env, limiter) {
  const binding = env[limiter];
  if (!binding?.limit) return false;
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const { success } = await binding.limit({ key: `${limiter}:${ip}` });
  return !success;
}

/* ------------------------------------------------------------------- api */

async function loadRecord(env, id) {
  if (!validId(id)) return null;
  const record = await env.META.get(`f:${id}`, 'json');
  if (!record) return null;
  if (record.expires <= Date.now()) {
    await env.META.delete(`f:${id}`);
    await env.META.put(`x:${id}`, '1'); // tombstone; the cron sweep collects it
    return null;
  }
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
  if (size > maxBytes(env)) return fail(`file exceeds the ${Number(env.MAX_SIZE_MB) || 5120} MiB limit`, 413);
  if (!Number.isSafeInteger(chunk) || chunk < MIN_CHUNK || chunk > MAX_CHUNK) return fail('bad chunk size');
  if (Math.ceil(size / (chunk + GCM_TAG)) > MAX_PARTS) return fail('too many chunks', 413);

  const ttl = Math.min(Math.max(Math.trunc(Number(body.ttl)) || 86400, 60), MAX_TTL);
  const limit = Math.min(Math.max(Math.trunc(Number(body.limit)) || 0, 0), 1e6); // 0 = unlimited

  const id = randomId();
  const expires = Date.now() + ttl * 1000;
  const multipart = await env.BUCKET.createMultipartUpload(id, {
    httpMetadata: { contentType: 'application/octet-stream' },
    customMetadata: { expires: String(expires) },
  });

  await env.META.put(
    `u:${id}`,
    JSON.stringify({ id, size, chunk, ttl, expires, limit, uploadId: multipart.uploadId }),
    { metadata: { created: Date.now() } },
  );

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

  const bytes = await request.arrayBuffer();
  if (bytes.byteLength === 0 || bytes.byteLength > cipherChunk) return fail('bad part size', 413);

  const part = await env.BUCKET.resumeMultipartUpload(id, uploadId).uploadPart(partNumber, bytes);
  return json({ partNumber: part.partNumber, etag: part.etag });
}

async function uploadComplete(request, env, url) {
  if (!(await authorized(request, env))) return denied(env);

  const body = await request.json().catch(() => null);
  if (!body || !validId(body.id) || !Array.isArray(body.parts) || !body.parts.length) return fail('bad request');
  if (typeof body.header !== 'string' || !body.header || body.header.length > MAX_HEADER) return fail('bad header');

  const pending = await env.META.get(`u:${body.id}`, 'json');
  if (!pending || pending.uploadId !== body.uploadId) return fail('unknown upload', 404);
  if (body.parts.length > MAX_PARTS) return fail('too many parts');

  await env.BUCKET.resumeMultipartUpload(pending.id, pending.uploadId).complete(
    body.parts
      .map((p) => ({ partNumber: Number(p.partNumber), etag: String(p.etag) }))
      .sort((a, b) => a.partNumber - b.partNumber),
  );

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

  await env.META.put(`f:${pending.id}`, JSON.stringify(record), {
    expirationTtl: Math.max(Math.ceil((record.expires - Date.now()) / 1000), 60),
  });
  await env.META.delete(`u:${pending.id}`);

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
  });
}

async function download(request, env, ctx, id) {
  const record = await loadRecord(env, id);
  if (!record) return fail('not found or expired', 404);

  const object = await env.BUCKET.get(record.id);
  if (!object) {
    await env.META.delete(`f:${id}`);
    return fail('not found or expired', 404);
  }

  record.downloads += 1;
  const burned = record.limit > 0 && record.downloads >= record.limit;
  if (burned) {
    // Kill the link now; the sweep reclaims the bytes, so we never delete an
    // object out from under a response that is still streaming.
    ctx.waitUntil(env.META.delete(`f:${id}`).then(() => env.META.put(`x:${id}`, '1')));
  } else {
    ctx.waitUntil(
      env.META.put(`f:${id}`, JSON.stringify(record), {
        expirationTtl: Math.max(Math.ceil((record.expires - Date.now()) / 1000), 60),
      }),
    );
  }

  return new Response(request.method === 'HEAD' ? null : object.body, {
    headers: {
      ...SECURITY_HEADERS,
      // Always opaque and always an attachment: the origin can never be talked
      // into serving user content as HTML, SVG or script.
      'content-type': 'application/octet-stream',
      'content-length': String(object.size),
      'content-disposition': `attachment; filename="${record.id}.bin"`,
      'content-security-policy': "default-src 'none'; sandbox",
      'cache-control': 'no-store',
      'x-downloads-remaining': record.limit ? String(Math.max(record.limit - record.downloads, 0)) : 'unlimited',
    },
  });
}

async function revoke(request, env, id) {
  const record = await loadRecord(env, id);
  if (!record) return fail('not found or expired', 404);

  const token = request.headers.get('x-delete-token') || '';
  if (!token || !(await secretEquals(record.del, await sha256(token)))) return fail('bad delete token', 403);

  await env.META.delete(`f:${id}`);
  await env.BUCKET.delete(record.id);
  return json({ ok: true });
}

async function handleApi(request, env, ctx, url) {
  const path = url.pathname.slice(4); // strip "/api"
  const method = request.method;

  if (method === 'GET' && path === '/config') {
    return json({
      maxSizeMB: Number(env.MAX_SIZE_MB) || 5120,
      configured: Boolean(env.UPLOAD_TOKEN),
      brand: getBrandConfig(env),
    });
  }
  // Lets the UI unlock without starting an upload. Rate-limited like uploads,
  // and it reveals nothing beyond whether the presented token is the right one.
  if (method === 'GET' && path === '/auth') {
    if (await throttled(request, env, 'UPLOAD_LIMIT')) return fail('too many attempts', 429);
    return (await authorized(request, env)) ? json({ ok: true }) : denied(env);
  }
  if (method === 'POST' && path === '/upload/init') return uploadInit(request, env);
  if (method === 'PUT' && path === '/upload/part') return uploadPart(request, env, url);
  if (method === 'POST' && path === '/upload/complete') return uploadComplete(request, env, url);
  if (method === 'POST' && path === '/upload/abort') return uploadAbort(request, env);

  const file = path.match(/^\/f\/([^/]+)$/);
  if (file && method === 'GET') return meta(env, file[1]);
  if (file && method === 'DELETE') return revoke(request, env, file[1]);

  const direct = path.match(/^\/d\/([^/]+)$/);
  if (direct && (method === 'GET' || method === 'HEAD')) {
    if (await throttled(request, env, 'DOWNLOAD_LIMIT')) return fail('too many requests', 429);
    return download(request, env, ctx, direct[1]);
  }

  return fail('not found', 404);
}

/* ---------------------------------------------------------------- sweeper */

/**
 * Hourly: delete objects past their expiry, collect tombstones left by
 * burn-after-read downloads, and abort multipart uploads nobody finished.
 */
async function sweep(env) {
  const now = Date.now();
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

  const tombstones = await env.META.list({ prefix: 'x:' });
  for (const key of tombstones.keys) {
    await env.BUCKET.delete(key.name.slice(2));
    await env.META.delete(key.name);
    deleted += 1;
  }

  let aborted = 0;
  const pending = await env.META.list({ prefix: 'u:' });
  for (const key of pending.keys) {
    if (now - (key.metadata?.created ?? 0) < PENDING_MAX_AGE) continue;
    const record = await env.META.get(key.name, 'json');
    if (record?.uploadId) {
      await env.BUCKET.resumeMultipartUpload(record.id, record.uploadId).abort().catch(() => {});
    }
    await env.META.delete(key.name);
    aborted += 1;
  }

  console.log(`sweep: deleted ${deleted} object(s), aborted ${aborted} upload(s)`);
}

/* ------------------------------------------------------------------ entry */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/api/')) {
      try {
        return await handleApi(request, env, ctx, url);
      } catch (err) {
        console.error(err); // never surfaced to the client
        return fail('internal error', 500);
      }
    }

    // Existing static assets are served before the Worker runs, so this only
    // handles /f/<id> share pages: same single-page app, no server rendering,
    // and the key in the fragment is never part of the request. Nothing else
    // gets the app - an unknown path is a 404, not a soft landing.
    if (!/^\/f\/[A-Za-z0-9]{16,32}\/?$/.test(url.pathname)) {
      return new Response('not found', { status: 404, headers: { ...SECURITY_HEADERS, 'content-type': 'text/plain' } });
    }

    // Ask for "/" rather than "/index.html": the asset server redirects the
    // latter to the former, which would strip the share id from the URL.
    const page = await env.ASSETS.fetch(new Request(new URL('/', url), request));
    const headers = new Headers(page.headers);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
    headers.set('content-security-policy', PAGE_CSP);
    headers.set('cache-control', 'no-store');
    return new Response(page.body, { status: page.status, headers });
  },

  async scheduled(_event, env, ctx) {
    ctx.waitUntil(sweep(env));
  },
};
