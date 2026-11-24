/**
 * Drives the Worker's fetch and scheduled handlers against in-memory fakes of
 * KV, R2 and the assets binding. No wrangler, no dependencies.
 * Run with: node test/worker.mjs
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import worker, { DownloadCounter } from '../src/index.js';

const report = (...args) => process.stdout.write(`${args.join(' ')}\n`);

let failures = 0;
const check = (name, condition) => {
  report(`${condition ? 'ok  ' : 'FAIL'} ${name}`);
  if (!condition) failures += 1;
};

// The Worker logs structured lines; keep them out of the test output but
// available to assertions.
const logs = [];
for (const level of ['log', 'warn', 'error']) console[level] = (...args) => logs.push({ level, text: args.join(' ') });

/* ------------------------------------------------------------------ fakes */

class FakeKV {
  constructor() {
    this.data = new Map(); // name -> { value, metadata, expiration }
    this.ops = [];         // [op, key]
    this.failPut = null;   // (key) => boolean
  }
  live(key) {
    const entry = this.data.get(key);
    if (!entry) return null;
    if (entry.expiration && entry.expiration * 1000 <= Date.now()) return null;
    return entry;
  }
  async get(key, type) {
    this.ops.push(['get', key]);
    const entry = this.live(key);
    if (!entry) return null;
    return (type === 'json' || type?.type === 'json') ? JSON.parse(entry.value) : entry.value;
  }
  async put(key, value, options = {}) {
    this.ops.push(['put', key]);
    if (this.failPut?.(key)) throw new Error('KV put failed (injected)');
    if (options.expirationTtl !== undefined && !(options.expirationTtl >= 60)) throw new Error('expirationTtl below 60');
    this.data.set(key, {
      value: String(value),
      metadata: options.metadata ?? null,
      expiration: options.expirationTtl ? Math.floor(Date.now() / 1000) + options.expirationTtl : null,
    });
  }
  async delete(key) {
    this.ops.push(['delete', key]);
    this.data.delete(key);
  }
  async list({ prefix = '', cursor, limit = 1000 } = {}) {
    this.ops.push(['list', prefix]);
    // Cursors resume after the last key returned, so deleting listed keys
    // between pages does not skip anything (as with the real service).
    const names = [...this.data.keys()].filter((k) => k.startsWith(prefix) && this.live(k) && (!cursor || k > cursor)).sort();
    const slice = names.slice(0, limit);
    const done = names.length <= limit;
    return {
      keys: slice.map((name) => {
        const { metadata } = this.data.get(name);
        return metadata ? { name, metadata } : { name };
      }),
      list_complete: done,
      ...(done ? {} : { cursor: slice.at(-1) }),
    };
  }
  writes(key) {
    return this.ops.filter(([op, k]) => (op === 'put' || op === 'delete') && (!key || k === key)).length;
  }
}

class FakeR2 {
  constructor() {
    this.objects = new Map(); // key -> { bytes, customMetadata }
    this.uploads = new Map(); // uploadId -> { key, parts: Map, customMetadata, state }
    this.gets = 0;
    this.failList = false;
    this.nextUpload = 0;
  }
  async createMultipartUpload(key, options = {}) {
    const uploadId = `upload-${++this.nextUpload}`;
    this.uploads.set(uploadId, { key, parts: new Map(), customMetadata: options.customMetadata ?? {}, state: 'open' });
    return this.resumeMultipartUpload(key, uploadId);
  }
  resumeMultipartUpload(key, uploadId) {
    const r2 = this;
    const upload = () => {
      const u = r2.uploads.get(uploadId);
      if (!u || u.key !== key || u.state !== 'open') throw new Error('no such upload');
      return u;
    };
    return {
      key,
      uploadId,
      async uploadPart(partNumber, value) {
        const bytes = new Uint8Array(value instanceof ArrayBuffer ? value : await new Response(value).arrayBuffer());
        const etag = `etag-${partNumber}-${bytes.length}`;
        upload().parts.set(partNumber, { bytes, etag });
        return { partNumber, etag };
      },
      async complete(parts) {
        const u = upload();
        const chunks = parts.map(({ partNumber, etag }) => {
          const part = u.parts.get(partNumber);
          if (!part || part.etag !== etag) throw new Error('bad part');
          return part.bytes;
        });
        // Real R2: every part but the last must be at least 5 MiB.
        if (chunks.slice(0, -1).some((c) => c.length < 5 << 20)) throw new Error('EntityTooSmall');
        const bytes = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
        let at = 0;
        for (const c of chunks) { bytes.set(c, at); at += c.length; }
        u.state = 'completed';
        r2.objects.set(key, { bytes, customMetadata: u.customMetadata });
        return { key, size: bytes.length, customMetadata: u.customMetadata };
      },
      async abort() {
        upload().state = 'aborted';
      },
    };
  }
  async get(key, options = {}) {
    this.gets += 1;
    this.lastRange = options.range ?? null;
    const o = this.objects.get(key);
    if (!o) return null;
    let bytes = o.bytes;
    if (options.range) {
      // Real R2 refuses a range that starts past the end; the Worker must never send one.
      const { offset = 0, length } = options.range;
      if (offset >= o.bytes.length) throw new Error('InvalidRange');
      bytes = o.bytes.subarray(offset, length === undefined ? undefined : offset + length);
    }
    return {
      key, size: o.bytes.length, body: new Response(bytes).body, customMetadata: o.customMetadata,
      ...(options.range ? { range: options.range } : {}),
    };
  }
  async head(key) {
    const o = this.objects.get(key);
    return o ? { key, size: o.bytes.length, customMetadata: o.customMetadata } : null;
  }
  async delete(keys) {
    for (const key of [].concat(keys)) this.objects.delete(key);
  }
  async list({ limit = 1000, cursor } = {}) {
    if (this.failList) throw new Error('R2 list failed (injected)');
    const keys = [...this.objects.keys()].filter((k) => !cursor || k > cursor).sort();
    const slice = keys.slice(0, limit);
    const truncated = keys.length > limit;
    return {
      objects: slice.map((key) => ({ key, size: this.objects.get(key).bytes.length, customMetadata: this.objects.get(key).customMetadata })),
      truncated,
      ...(truncated ? { cursor: slice.at(-1) } : {}),
    };
  }
}

const tick = () => new Promise((resolve) => setImmediate(resolve));

/** Durable Object storage. Every read yields, so unserialised read-modify-write races. */
class FakeDOStorage {
  constructor() {
    this.data = new Map();
    this.alarm = null;
  }
  async get(key) { await tick(); return this.data.get(key); }
  async put(key, value) { await tick(); this.data.set(key, value); }
  async delete(key) { return this.data.delete(key); }
  async deleteAll() { this.data.clear(); }
  async getAlarm() { return this.alarm; }
  async setAlarm(at) { this.alarm = Number(at); }
  async deleteAlarm() { this.alarm = null; }
}

/** One object per name; blockConcurrencyWhile runs its callbacks one at a time, as the runtime does. */
class FakeDONamespace {
  constructor(Class, env = {}) {
    this.Class = Class;
    this.env = env;
    this.objects = new Map(); // name -> { instance, state }
    this.calls = [];          // [name, pathname]
  }
  idFromName(name) { return { name, toString: () => `do:${name}` }; }
  object(name) {
    if (!this.objects.has(name)) {
      let queue = Promise.resolve();
      const state = {
        storage: new FakeDOStorage(),
        blockConcurrencyWhile(fn) {
          const run = queue.then(fn);
          queue = run.catch(() => {});
          return run;
        },
      };
      this.objects.set(name, { state, instance: new this.Class(state, this.env) });
    }
    return this.objects.get(name);
  }
  get(id) {
    const ns = this;
    return {
      async fetch(input, init) {
        const request = new Request(input, init);
        ns.calls.push([id.name, new URL(request.url).pathname]);
        await tick(); // a real call crosses the network: let racing callers interleave
        return ns.object(id.name).instance.fetch(request);
      },
    };
  }
}

const ASSETS = {
  async fetch() {
    return new Response('<!doctype html><title>app</title>', { headers: { 'content-type': 'text/html' } });
  },
};

const TOKEN = 'test-upload-token-0123456789';
const freshEnv = (extra = {}) => ({ META: new FakeKV(), BUCKET: new FakeR2(), ASSETS, UPLOAD_TOKEN: TOKEN, MAX_SIZE_MB: '5120', ...extra });

function makeCtx() {
  const pending = [];
  return { waitUntil: (p) => pending.push(p), settle: () => Promise.all(pending) };
}

async function call(env, method, path, { body, token = TOKEN, headers = {}, ctx = makeCtx() } = {}) {
  const init = { method, headers: { ...headers } };
  if (token) init.headers.authorization = `Bearer ${token}`;
  if (body instanceof Uint8Array) init.body = body;
  else if (body !== undefined) {
    init.body = JSON.stringify(body);
    init.headers['content-type'] = 'application/json';
  }
  const response = await worker.fetch(new Request(`https://share.example${path}`, init), env, ctx);
  await ctx.settle();
  const type = response.headers.get('content-type') || '';
  const data = type.includes('json') ? await response.json() : null;
  return { status: response.status, headers: response.headers, data, response };
}

const CHUNK = (5 << 20) - 16; // smallest chunk R2 accepts for a file of more than one part
const CIPHER_CHUNK = CHUNK + 16;
const HEADER = 'aGVhZGVyLWJsb2I';

const bytesOf = (n, seed = 1) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed) & 255);

/** init + parts + complete; returns { init, done, parts }. */
async function upload(env, bytes, { limit = 0, ttl = 3600, declare = bytes.length, complete = true, auth } = {}) {
  const init = await call(env, 'POST', '/api/upload/init', { body: { size: declare, chunkSize: CHUNK, ttl, limit } });
  const parts = [];
  for (let i = 0, n = 1; i < bytes.length; i += CIPHER_CHUNK, n++) {
    const part = await call(env, 'PUT', `/api/upload/part?id=${init.data.id}&uploadId=${init.data.uploadId}&part=${n}`, {
      body: bytes.subarray(i, i + CIPHER_CHUNK),
    });
    parts.push({ partNumber: part.data.partNumber, etag: part.data.etag });
  }
  if (!complete) return { init, parts };
  const done = await call(env, 'POST', '/api/upload/complete', {
    body: { id: init.data.id, uploadId: init.data.uploadId, parts, header: HEADER, protected: false, ...(auth === undefined ? {} : { auth }) },
  });
  return { init, parts, done };
}

const bodyOf = async (res) => Buffer.from(await res.response.arrayBuffer());

const completeWith = (env, init, parts, header = HEADER) =>
  call(env, 'POST', '/api/upload/complete', { body: { id: init.data.id, uploadId: init.data.uploadId, parts, header } });

/* ------------------------------------------------------------------- auth */
{
  const off = await call(freshEnv({ UPLOAD_TOKEN: undefined }), 'POST', '/api/upload/init', { body: { size: 10, chunkSize: CHUNK } });
  check('auth: no UPLOAD_TOKEN configured -> 503', off.status === 503);
  const env = freshEnv();
  const wrong = await call(env, 'POST', '/api/upload/init', { body: { size: 10, chunkSize: CHUNK }, token: 'nope' });
  check('auth: wrong token -> 401', wrong.status === 401);
  check('auth: /api/auth accepts the right token', (await call(env, 'GET', '/api/auth')).status === 200);
  check('auth: /api/auth rejects a wrong token', (await call(env, 'GET', '/api/auth', { token: 'nope' })).status === 401);
  const part = await call(env, 'PUT', '/api/upload/part?id=aaaaaaaaaaaaaaaa&uploadId=x&part=1', { body: bytesOf(4), token: null });
  check('auth: part without token -> 401', part.status === 401);
}

/* --------------------------------------------------------- init validation */
{
  const env = freshEnv();
  const init = (limit) => call(env, 'POST', '/api/upload/init', { body: { size: 100, chunkSize: CHUNK, ttl: 3600, limit } });
  // Older CLI copies send `--limit -1` unchecked; it has always meant unlimited.
  const negative = await init(-1);
  check('init: negative limit (old CLI) still accepted as unlimited', negative.status === 200
    && (await env.META.get(`u:${negative.data.id}`, 'json')).limit === 0);
  check('init: negative limit logs a compat warning', logs.some((l) => l.level === 'warn' && l.text.includes('negative download limit')));
  const negFraction = await init(-0.5);
  check('init: negative fraction limit accepted as unlimited', negFraction.status === 200
    && (await env.META.get(`u:${negFraction.data.id}`, 'json')).limit === 0);
  const fraction = await init(1.5);
  check('init: fractional limit (old CLI, unchecked --limit) truncated as before', fraction.status === 200
    && (await env.META.get(`u:${fraction.data.id}`, 'json')).limit === 1);
  check('init: non-numeric limit -> 400', (await init('one')).status === 400);
  const nullLimit = await init(null);
  check('init: null limit (old CLI with a bad flag) still accepted', nullLimit.status === 200);
  const pending = await env.META.get(`u:${nullLimit.data.id}`, 'json');
  check('init: null limit means unlimited', pending.limit === 0);
  const missing = await call(env, 'POST', '/api/upload/init', { body: { size: 100, chunkSize: CHUNK } });
  check('init: absent limit accepted', missing.status === 200);
  const numeric = await init('5');
  check('init: numeric string limit still accepted', numeric.status === 200
    && (await env.META.get(`u:${numeric.data.id}`, 'json')).limit === 5);
  check('init: huge limit is clamped, not rejected', (await env.META.get(`u:${(await init(5e9)).data.id}`, 'json')).limit === 1e6);
  check('init: pending record has a safety TTL', env.META.data.get(`u:${numeric.data.id}`).expiration > 0);
  check('init: oversize file -> 413', (await call(env, 'POST', '/api/upload/init', { body: { size: 6e9, chunkSize: CHUNK } })).status === 413);
  const small = (size) => call(env, 'POST', '/api/upload/init', { body: { size, chunkSize: 1 << 20 } });
  check('init: 1 MiB chunks for a one-part file accepted', (await small(1000)).status === 200);
  check('init: 1 MiB chunks for a multi-part file -> 400 (R2 would refuse at complete)',
    (await small((1 << 20) + 17)).status === 400);
  check('init: chunk under 1 MiB -> 400', (await call(env, 'POST', '/api/upload/init', { body: { size: 10, chunkSize: 1000 } })).status === 400);

  const flaky = freshEnv();
  flaky.META.failPut = (key) => key.startsWith('u:');
  const failed = await call(flaky, 'POST', '/api/upload/init', { body: { size: 100, chunkSize: CHUNK } });
  const states = [...flaky.BUCKET.uploads.values()].map((u) => u.state);
  check('init: failed pending write -> 500 and the multipart upload is aborted', failed.status === 500 && states.join() === 'aborted');
}

/* ------------------------------------------------------------------ config */
{
  const bad = await call(freshEnv({ MAX_SIZE_MB: '-5' }), 'GET', '/api/config');
  check('config: negative MAX_SIZE_MB falls back to 5120', bad.data.maxSizeMB === 5120);
  check('config: bad MAX_SIZE_MB logs a warning', logs.some((l) => l.level === 'warn' && l.text.includes('MAX_SIZE_MB')));
  check('config: typo MAX_SIZE_MB falls back to 5120', (await call(freshEnv({ MAX_SIZE_MB: '5GB' }), 'GET', '/api/config')).data.maxSizeMB === 5120);
  check('config: fractional MAX_SIZE_MB is kept', (await call(freshEnv({ MAX_SIZE_MB: '0.5' }), 'GET', '/api/config')).data.maxSizeMB === 0.5);
  check('config: unset MAX_SIZE_MB defaults to 5120', (await call(freshEnv({ MAX_SIZE_MB: undefined }), 'GET', '/api/config')).data.maxSizeMB === 5120);

  const noKv = await call(freshEnv({ META: undefined }), 'GET', '/api/f/aaaaaaaaaaaaaaaa');
  check('config: missing META binding -> 503 naming it', noKv.status === 503 && noKv.data.error.includes('META'));
  const noBucket = await call(freshEnv({ BUCKET: undefined }), 'POST', '/api/upload/init', { body: { size: 1, chunkSize: CHUNK } });
  check('config: missing BUCKET binding -> 503 naming it', noBucket.status === 503 && noBucket.data.error.includes('BUCKET'));
  const noAssets = await call(freshEnv({ ASSETS: undefined }), 'GET', '/f/aaaaaaaaaaaaaaaa');
  check('config: missing ASSETS binding -> 503 naming it', noAssets.status === 503 && noAssets.data.error.includes('ASSETS'));
  check('config: /api/config works without storage bindings', (await call(freshEnv({ META: undefined, BUCKET: undefined }), 'GET', '/api/config')).status === 200);
}

/* ------------------------------------------------------- part validation */
{
  const env = freshEnv();
  const { init } = await upload(env, bytesOf(200), { complete: false });
  const base = `/api/upload/part?id=${init.data.id}&uploadId=${init.data.uploadId}`;
  check('part: number past the end of the file -> 400', (await call(env, 'PUT', `${base}&part=2`, { body: bytesOf(10) })).status === 400);
  const declared = await call(env, 'PUT', `${base}&part=1`, { body: bytesOf(10), headers: { 'content-length': String(CIPHER_CHUNK + 1) } });
  check('part: declared content-length over one chunk -> 413 before reading', declared.status === 413);
  check('part: empty body -> 413', (await call(env, 'PUT', `${base}&part=1`, { body: new Uint8Array(0) })).status === 413);
  check('part: unknown upload -> 404', (await call(env, 'PUT', `/api/upload/part?id=${init.data.id}&uploadId=other&part=1`, { body: bytesOf(10) })).status === 404);
}

/* --------------------------------------------------- complete validation */
{
  const env = freshEnv();
  const bytes = bytesOf(CIPHER_CHUNK + 50);
  const { init, parts } = await upload(env, bytes, { complete: false });
  check('complete: duplicate part -> 400', (await completeWith(env, init, [parts[0], parts[0], parts[1]])).status === 400);
  check('complete: fractional part number -> 400', (await completeWith(env, init, [{ ...parts[0], partNumber: 1.5 }, parts[1]])).status === 400);
  check('complete: part number out of range -> 400', (await completeWith(env, init, [parts[0], { ...parts[1], partNumber: 3 }])).status === 400);
  check('complete: null part -> 400, not 500', (await completeWith(env, init, [null, parts[1]])).status === 400);
  check('complete: empty etag -> 400', (await completeWith(env, init, [parts[0], { ...parts[1], etag: '' }])).status === 400);
  check('complete: non-string etag -> 400', (await completeWith(env, init, [parts[0], { ...parts[1], etag: 7 }])).status === 400);
  check('complete: non-base64url header -> 400', (await completeWith(env, init, parts, '<script>')).status === 400);
  check('complete: upload still pending after rejected attempts', env.META.data.has(`u:${init.data.id}`));
  const ok = await completeWith(env, init, parts);
  check('complete: valid parts accepted', ok.status === 200 && ok.data.url === `https://share.example/f/${init.data.id}` && ok.data.deleteToken);
  const record = await env.META.get(`f:${init.data.id}`, 'json');
  check('complete: record stores the verified size', record.size === bytes.length);
  check('complete: pending record removed', !env.META.data.has(`u:${init.data.id}`));
}
{
  const env = freshEnv();
  const bytes = bytesOf(300);
  const { init, parts } = await upload(env, bytes, { declare: 500, complete: false });
  const res = await completeWith(env, init, parts);
  check('complete: size mismatch -> 400', res.status === 400 && /size/.test(res.data.error));
  check('complete: size mismatch deletes the object and pending record',
    !env.BUCKET.objects.has(init.data.id) && !env.META.data.has(`u:${init.data.id}`) && !env.META.data.has(`f:${init.data.id}`));
}
{
  const env = freshEnv();
  const { init, parts } = await upload(env, bytesOf(100), { complete: false });
  const key = `u:${init.data.id}`;
  const pending = JSON.parse(env.META.data.get(key).value);
  env.META.data.get(key).value = JSON.stringify({ ...pending, expires: Date.now() - 1000 });
  const res = await completeWith(env, init, parts);
  check('complete: upload that outlived its expiry -> 410', res.status === 410);
  check('complete: expired upload is aborted, no link created',
    env.BUCKET.uploads.get(init.data.uploadId).state === 'aborted' && !env.META.data.has(`f:${init.data.id}`) && !env.META.data.has(key));
}
{
  const env = freshEnv();
  env.META.failPut = (key) => key.startsWith('f:');
  const { init, done } = await upload(env, bytesOf(100));
  check('complete: failed record write -> retryable 503', done.status === 503);
  check('complete: failed record write drops the R2 object', !env.BUCKET.objects.has(init.data.id));
}

/* -------------------------------------------------- downloads and limits */
async function share(env, bytes, limit, auth) {
  const { done } = await upload(env, bytes, { limit, auth });
  return done.data;
}

{
  const env = freshEnv();
  const bytes = bytesOf(1000);
  const { id } = await share(env, bytes, 3);
  const meta = await call(env, 'GET', `/api/f/${id}`);
  check('meta: remaining starts at the limit', meta.data.remaining === 3);
  check('meta: reports server time', typeof meta.data.now === 'number' && Math.abs(meta.data.now - Date.now()) < 5000);
  check('meta: share page fields unchanged', ['id', 'size', 'chunk', 'header', 'protected', 'expires'].every((k) => k in meta.data));

  const first = await call(env, 'GET', `/api/d/${id}`);
  const got = new Uint8Array(await first.response.arrayBuffer());
  check('download: bytes match', first.status === 200 && Buffer.compare(Buffer.from(got), Buffer.from(bytes)) === 0);
  check('download: x-downloads-remaining counts down', first.headers.get('x-downloads-remaining') === '2');
  check('download: count persisted', (await call(env, 'GET', `/api/f/${id}`)).data.remaining === 2);
}
{
  const env = freshEnv();
  const { id } = await share(env, bytesOf(500), 1);
  const ctx = makeCtx();
  const response = await worker.fetch(new Request(`https://share.example/api/d/${id}`), env, ctx);
  check('burn: first download served', response.status === 200);
  check('burn: record deleted before the response is returned', !env.META.data.has(`f:${id}`));
  const tomb = env.META.data.get(`x:${id}`);
  check('burn: tombstone written with {at} metadata and a TTL', tomb && typeof tomb.metadata?.at === 'number' && tomb.expiration > 0);
  await response.arrayBuffer();
  await ctx.settle();
  check('burn: second download -> 404', (await call(env, 'GET', `/api/d/${id}`)).status === 404);
  check('burn: meta -> 404', (await call(env, 'GET', `/api/f/${id}`)).status === 404);
}
{
  const env = freshEnv();
  const { id } = await share(env, bytesOf(500), 1);
  env.META.failPut = (key) => key.startsWith('x:');
  const res = await call(env, 'GET', `/api/d/${id}`);
  check('burn: a failed burn fails closed (500, no bytes)', res.status === 500 && res.data?.error === 'internal error');
}
{
  const env = freshEnv();
  const { id } = await share(env, bytesOf(500), 2);
  // A stale KV read elsewhere that still shows a spent record must not serve it.
  const key = `f:${id}`;
  const record = JSON.parse(env.META.data.get(key).value);
  env.META.data.get(key).value = JSON.stringify({ ...record, downloads: 2 });
  const gets = env.BUCKET.gets;
  const res = await call(env, 'GET', `/api/d/${id}`);
  check('limit: spent record -> 404 without touching R2', res.status === 404 && env.BUCKET.gets === gets);
}
{
  const env = freshEnv();
  const { id } = await share(env, bytesOf(500), 0);
  const before = env.META.writes();
  const a = await call(env, 'GET', `/api/d/${id}`);
  const b = await call(env, 'GET', `/api/d/${id}`);
  check('unlimited: downloads served', a.status === 200 && b.status === 200 && a.headers.get('x-downloads-remaining') === 'unlimited');
  check('unlimited: no KV write per download', env.META.writes() === before);
  check('unlimited: meta remaining is null', (await call(env, 'GET', `/api/f/${id}`)).data.remaining === null);
}
{
  const env = freshEnv();
  const { id } = await share(env, bytesOf(700), 1);
  const head = await call(env, 'HEAD', `/api/d/${id}`);
  check('HEAD: answers with headers only', head.status === 200 && head.headers.get('content-length') === '700'
    && (await head.response.arrayBuffer()).byteLength === 0);
  check('HEAD: does not spend a download', (await call(env, 'GET', `/api/f/${id}`)).data.remaining === 1
    && env.META.data.has(`f:${id}`) && env.BUCKET.gets === 0);
}

/* -------------------------------------------------------- revoke / expiry */
{
  const env = freshEnv();
  const { id, deleteToken } = await share(env, bytesOf(100), 0);
  check('revoke: wrong token -> 403', (await call(env, 'DELETE', `/api/f/${id}`, { headers: { 'x-delete-token': 'nope' } })).status === 403);
  const ok = await call(env, 'DELETE', `/api/f/${id}`, { headers: { 'x-delete-token': deleteToken } });
  check('revoke: right token -> 200', ok.status === 200);
  check('revoke: record and object gone', !env.META.data.has(`f:${id}`) && !env.BUCKET.objects.has(id));
  check('revoke: link dead', (await call(env, 'GET', `/api/d/${id}`)).status === 404);
}
{
  const env = freshEnv();
  const { id } = await share(env, bytesOf(100), 0);
  const key = `f:${id}`;
  const record = JSON.parse(env.META.data.get(key).value);
  env.META.data.get(key).value = JSON.stringify({ ...record, expires: Date.now() - 1 });
  const writes = env.META.writes();
  check('expiry: expired meta -> 404', (await call(env, 'GET', `/api/f/${id}`)).status === 404);
  check('expiry: expired download -> 404', (await call(env, 'GET', `/api/d/${id}`)).status === 404);
  check('expiry: reads write nothing to KV', env.META.writes() === writes && !env.META.data.has(`x:${id}`));
}

/* ------------------------------------------------------------- throttling */
{
  const seen = [];
  const limiter = (allow) => ({ async limit({ key }) { seen.push(key); return { success: allow(key) }; } });
  const env = freshEnv({ DOWNLOAD_LIMIT: limiter((key) => !key.includes(':meta:')) });
  const { id } = await share(env, bytesOf(100), 0);
  const headers = { 'cf-connecting-ip': '203.0.113.9' };
  check('throttle: meta GET limited by DOWNLOAD_LIMIT', (await call(env, 'GET', `/api/f/${id}`, { headers })).status === 429);
  check('throttle: revoke not throttled (it needs the delete token)', (await call(env, 'DELETE', `/api/f/${id}`, { headers })).status === 403);
  check('throttle: downloads keep their own counter', (await call(env, 'GET', `/api/d/${id}`, { headers })).status === 200);
  check('throttle: keys are distinct',
    seen.includes('DOWNLOAD_LIMIT:meta:203.0.113.9') && seen.includes('DOWNLOAD_LIMIT:203.0.113.9'));
}

/* ------------------------------------------------------------ errors/logs */
{
  const env = freshEnv();
  env.BUCKET.get = async () => { throw new Error('boom'); };
  const { id } = await share(env, bytesOf(100), 0);
  logs.length = 0;
  const res = await call(env, 'GET', `/api/d/${id}`, { headers: { 'cf-ray': '8abc123-LHR' } });
  check('500: generic message plus ray id', res.status === 500 && res.data.error === 'internal error' && res.data.ray === '8abc123-LHR');
  const line = logs.find((l) => l.level === 'error');
  let entry = null;
  try { entry = JSON.parse(line.text); } catch {}
  check('500: structured log with ray, method and route', entry?.ray === '8abc123-LHR' && entry.method === 'GET' && entry.route === '/api/d/:id');
  check('500: share id kept out of the log', !line.text.includes(id));
}

/* ------------------------------------------------------ download counter */
const counterEnv = (extra = {}) => {
  const env = freshEnv(extra);
  env.COUNTER = new FakeDONamespace(DownloadCounter, env);
  return env;
};
const counterOf = (env, id) => env.COUNTER.objects.get(id)?.state.storage;

{
  const env = counterEnv();
  const { id } = await share(env, bytesOf(500), 1);
  const ctx = makeCtx();
  const responses = await Promise.all(
    Array.from({ length: 6 }, () => worker.fetch(new Request(`https://share.example/api/d/${id}`), env, ctx)),
  );
  await Promise.all(responses.map((r) => r.arrayBuffer()));
  await ctx.settle();
  const statuses = responses.map((r) => r.status).sort();
  check('counter: six racing downloads of a one-read link -> exactly one 200', statuses.join() === '200,404,404,404,404,404');
  check('counter: winner still burns the KV record and writes a tombstone', !env.META.data.has(`f:${id}`) && env.META.data.has(`x:${id}`));
  check('counter: object holds the final count', counterOf(env, id).data.get('count') === 1);
}
{
  const env = counterEnv();
  const { id } = await share(env, bytesOf(500), 3);
  const key = `f:${id}`;
  const record = JSON.parse(env.META.data.get(key).value);
  env.META.data.get(key).value = JSON.stringify({ ...record, downloads: 2 }); // spent two before the binding existed
  const res = await call(env, 'GET', `/api/d/${id}`);
  check('counter: seeded from the KV count (one of three left)', res.status === 200 && res.headers.get('x-downloads-remaining') === '0');
  check('counter: seeded object counts to the limit', counterOf(env, id).data.get('count') === 3);
  check('counter: reaching the limit burns the KV record', !env.META.data.has(key) && env.META.data.has(`x:${id}`));
  // A stale KV read elsewhere still showing the record must not get a second read.
  env.META.data.set(key, { value: JSON.stringify({ ...record, downloads: 2 }), metadata: null, expiration: null });
  check('counter: stale KV record refused by the counter',
    (await call(env, 'GET', `/api/d/${id}`)).status === 404 && counterOf(env, id).data.get('count') === 3);
  check('counter: alarm set at expiry plus a margin', counterOf(env, id).alarm === record.expires + 3600e3);
  await env.COUNTER.objects.get(id).instance.alarm();
  check('counter: alarm clears its storage', counterOf(env, id).data.size === 0);
}
{
  const env = counterEnv();
  const { id } = await share(env, bytesOf(300), 0);
  await call(env, 'GET', `/api/d/${id}`);
  await call(env, 'GET', `/api/d/${id}`);
  const limited = await share(env, bytesOf(300), 2);
  await call(env, 'HEAD', `/api/d/${limited.id}`);
  check('counter: unlimited shares and HEAD never call the counter', env.COUNTER.calls.length === 0);
}
{
  const env = counterEnv();
  const { id, deleteToken } = await share(env, bytesOf(300), 2);
  await call(env, 'GET', `/api/d/${id}`);
  check('counter: count persisted in KV for meta', (await call(env, 'GET', `/api/f/${id}`)).data.remaining === 1);
  await call(env, 'DELETE', `/api/f/${id}`, { headers: { 'x-delete-token': deleteToken } });
  check('counter: revoke clears the object and its alarm', counterOf(env, id).data.size === 0 && counterOf(env, id).alarm === null);
}
{
  // Same scenario with and without the binding: same answers.
  const run = async (env) => {
    const { id } = await share(env, bytesOf(400), 2);
    const out = [];
    for (let i = 0; i < 3; i++) {
      const r = await call(env, 'GET', `/api/d/${id}`);
      out.push(`${r.status}:${r.headers.get('x-downloads-remaining')}`);
    }
    out.push(String((await call(env, 'GET', `/api/f/${id}`)).status));
    return out.join();
  };
  const plain = await run(freshEnv());
  check('counter: no binding behaves exactly as before', plain === '200:1,200:0,404:null,404');
  check('counter: binding gives the same answers', (await run(counterEnv())) === plain);
}
{
  const env = freshEnv();
  env.COUNTER = { idFromName: (n) => n, get: () => ({ fetch: async () => { throw new Error('counter down'); } }) };
  const { id } = await share(env, bytesOf(300), 1);
  const res = await call(env, 'GET', `/api/d/${id}`);
  check('counter: an unreachable counter fails closed (500, nothing spent)', res.status === 500
    && JSON.parse(env.META.data.get(`f:${id}`).value).downloads === 0 && !env.META.data.has(`x:${id}`));
}
{
  // Removed, used, and bound again: downloads counted only in KV meanwhile still count.
  const env = counterEnv();
  const { id } = await share(env, bytesOf(300), 3);
  check('counter rebind: first download claimed', (await call(env, 'GET', `/api/d/${id}`)).status === 200 && counterOf(env, id).data.get('count') === 1);
  const counter = env.COUNTER;
  delete env.COUNTER;
  check('counter rebind: download without the binding counted in KV', (await call(env, 'GET', `/api/d/${id}`)).headers.get('x-downloads-remaining') === '1');
  env.COUNTER = counter;
  const third = await call(env, 'GET', `/api/d/${id}`);
  check('counter rebind: object catches up with KV (last download)', third.status === 200 && third.headers.get('x-downloads-remaining') === '0'
    && counterOf(env, id).data.get('count') === 3);
  // A KV read elsewhere that still shows two downloads must not get a fourth.
  const record = { id, size: 300, chunk: CHUNK, header: HEADER, expires: Date.now() + 3600e3, limit: 3, downloads: 1 };
  env.META.data.set(`f:${id}`, { value: JSON.stringify(record), metadata: null, expiration: null });
  check('counter rebind: limit holds against a stale KV record', (await call(env, 'GET', `/api/d/${id}`)).status === 404);
}
{
  // R2 fails after the record loaded: nothing is spent, so a retry still works.
  const env = counterEnv();
  const { id } = await share(env, bytesOf(300), 1);
  const realGet = env.BUCKET.get.bind(env.BUCKET);
  env.BUCKET.get = async () => { throw new Error('R2 down (injected)'); };
  const failed = await call(env, 'GET', `/api/d/${id}`);
  check('counter: a failed R2 read spends nothing', failed.status === 500 && counterOf(env, id) === undefined
    && env.META.data.has(`f:${id}`));
  env.BUCKET.get = realGet;
  const retry = await call(env, 'GET', `/api/d/${id}`);
  check('counter: retry after a failed R2 read is served', retry.status === 200 && retry.headers.get('x-downloads-remaining') === '0');
}
{
  // The counter claimed the last download, then the KV burn failed: serve it, do not waste it.
  const env = counterEnv();
  const bytes = bytesOf(300);
  const { id } = await share(env, bytes, 1);
  env.META.failPut = (key) => key.startsWith('x:');
  const res = await call(env, 'GET', `/api/d/${id}`);
  check('counter: claimed download served though the KV burn failed', res.status === 200
    && Buffer.compare(await bodyOf(res), Buffer.from(bytes)) === 0 && counterOf(env, id).data.get('count') === 1);
  check('counter: burn failure logged', logs.some((l) => l.text.includes('"step":"burn"')));
  env.META.failPut = null;
  check('counter: and the link is still spent', (await call(env, 'GET', `/api/d/${id}`)).status === 404);
}
{
  const ns = new FakeDONamespace(DownloadCounter);
  const stub = ns.get(ns.idFromName('aaaaaaaaaaaaaaaa'));
  const bad = await stub.fetch('https://counter/claim', { method: 'POST', body: JSON.stringify({ limit: 0, seed: 0, expires: Date.now() }) });
  check('counter: claim without a positive limit -> 400', bad.status === 400);
  const claim = (seed) => stub.fetch('https://counter/claim', { method: 'POST', body: JSON.stringify({ limit: 2, seed, expires: Date.now() + 1e6 }) }).then((r) => r.json());
  const spent = await claim(5);
  check('counter: seed at or past the limit refuses and is remembered', spent.ok === false && ns.object('aaaaaaaaaaaaaaaa').state.storage.data.get('count') === 2);
  check('counter: unknown path -> 404', (await stub.fetch('https://counter/nope', { method: 'POST' })).status === 404);
}

/* ---------------------------------------------------------- download auth */
const authKey = (seed) => Buffer.from(bytesOf(32, seed)).toString('base64url');
const verifierOf = (key) => createHash('sha256').update(Buffer.from(key, 'base64url')).digest('base64url');
const KEY = authKey(7);
const VERIFIER = verifierOf(KEY);

{
  const env = freshEnv();
  const { id } = await share(env, bytesOf(300), 3, VERIFIER);
  check('auth: verifier stored on the record', (await env.META.get(`f:${id}`, 'json')).auth === VERIFIER);
  check('auth: meta says auth true', (await call(env, 'GET', `/api/f/${id}`)).data.auth === true);

  const gets = env.BUCKET.gets;
  const wrong = await call(env, 'GET', `/api/d/${id}`, { headers: { 'x-ef-auth': authKey(8) } });
  check('auth: wrong key -> 403', wrong.status === 403);
  const garbled = await call(env, 'GET', `/api/d/${id}`, { headers: { 'x-ef-auth': 'not-a-key' } });
  check('auth: malformed key -> 403', garbled.status === 403);
  const headWrong = await call(env, 'HEAD', `/api/d/${id}`, { headers: { 'x-ef-auth': authKey(8) } });
  check('auth: HEAD with a wrong key -> 403', headWrong.status === 403);
  check('auth: refusals spend nothing and never touch R2',
    (await call(env, 'GET', `/api/f/${id}`)).data.remaining === 3 && env.BUCKET.gets === gets);

  const right = await call(env, 'GET', `/api/d/${id}`, { headers: { 'x-ef-auth': KEY } });
  check('auth: right key -> 200 and counted', right.status === 200 && right.headers.get('x-downloads-remaining') === '2');
  const bare = await call(env, 'GET', `/api/d/${id}`);
  check('auth: no header allowed by default (old clients)', bare.status === 200 && bare.headers.get('x-downloads-remaining') === '1');

  env.DOWNLOAD_AUTH = 'enforce';
  const refused = await call(env, 'GET', `/api/d/${id}`);
  check('auth: no header under DOWNLOAD_AUTH=enforce -> 401', refused.status === 401);
  check('auth: 401 spends nothing', (await call(env, 'GET', `/api/f/${id}`)).data.remaining === 1);
  check('auth: right key still works under enforce', (await call(env, 'GET', `/api/d/${id}`, { headers: { 'x-ef-auth': KEY } })).status === 200);
}
{
  const env = freshEnv({ DOWNLOAD_AUTH: 'enforce' });
  const { id } = await share(env, bytesOf(300), 0);
  check('auth: legacy record has no auth field, meta auth false',
    !('auth' in (await env.META.get(`f:${id}`, 'json'))) && (await call(env, 'GET', `/api/f/${id}`)).data.auth === false);
  check('auth: legacy record not challenged under enforce', (await call(env, 'GET', `/api/d/${id}`)).status === 200);
  check('auth: legacy record ignores a presented key', (await call(env, 'GET', `/api/d/${id}`, { headers: { 'x-ef-auth': KEY } })).status === 200);
}
{
  const env = freshEnv();
  for (const [label, auth] of [['too short', VERIFIER.slice(1)], ['too long', `${VERIFIER}A`], ['padded', `${VERIFIER.slice(0, 42)}=`],
    ['non-string', 12345], ['object', { v: VERIFIER }]]) {
    const { init, done } = await upload(env, bytesOf(100), { auth });
    check(`auth: ${label} verifier -> 400, upload still pending`, done.status === 400 && env.META.data.has(`u:${init.data.id}`));
  }
  const nullAuth = await upload(env, bytesOf(100), { auth: null });
  check('auth: null verifier means none', nullAuth.done.status === 200 && !('auth' in (await env.META.get(`f:${nullAuth.init.data.id}`, 'json'))));
}
{
  check('config: downloadAuth optional by default', (await call(freshEnv(), 'GET', '/api/config')).data.downloadAuth === 'optional');
  check('config: downloadAuth enforce', (await call(freshEnv({ DOWNLOAD_AUTH: 'enforce' }), 'GET', '/api/config')).data.downloadAuth === 'enforce');
  check('config: any other DOWNLOAD_AUTH value is optional', (await call(freshEnv({ DOWNLOAD_AUTH: 'Enforce ' }), 'GET', '/api/config')).data.downloadAuth === 'optional');
}

/* ------------------------------------------------------- ranges / resume */
const TICKET_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const withClock = async (offset, fn) => {
  const real = Date.now;
  Date.now = () => real() + offset;
  try { return await fn(); } finally { Date.now = real; }
};

{
  const env = freshEnv();
  const bytes = bytesOf(3000);
  const { id } = await share(env, bytes, 0);
  const open = await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=100-' } });
  check('range: bytes=N- -> 206 with content-range and length', open.status === 206
    && open.headers.get('content-range') === 'bytes 100-2999/3000' && open.headers.get('content-length') === '2900'
    && open.headers.get('accept-ranges') === 'bytes');
  check('range: bytes=N- body', Buffer.compare(await bodyOf(open), Buffer.from(bytes.subarray(100))) === 0);
  check('range: ranged R2 get', env.BUCKET.lastRange?.offset === 100 && env.BUCKET.lastRange?.length === 2900);
  const closed = await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=100-199' } });
  check('range: bytes=N-M -> exact slice', closed.status === 206 && closed.headers.get('content-range') === 'bytes 100-199/3000'
    && Buffer.compare(await bodyOf(closed), Buffer.from(bytes.subarray(100, 200))) === 0);
  const clamped = await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=2990-99999' } });
  check('range: end past the file is clamped', clamped.status === 206 && clamped.headers.get('content-range') === 'bytes 2990-2999/3000'
    && (await bodyOf(clamped)).length === 10);
  for (const range of ['bytes=3000-', 'bytes=5-2', 'bytes=-100', 'bytes=0-1,5-6', 'items=0-1', 'bytes=x-']) {
    const res = await call(env, 'GET', `/api/d/${id}`, { headers: { range } });
    check(`range: ${range} -> 416`, res.status === 416 && res.headers.get('content-range') === 'bytes */3000');
  }
  const whole = await call(env, 'GET', `/api/d/${id}`);
  check('range: plain GET advertises accept-ranges', whole.status === 200 && whole.headers.get('accept-ranges') === 'bytes');
  const head = await call(env, 'HEAD', `/api/d/${id}`, { headers: { range: 'bytes=5-' } });
  check('range: HEAD advertises accept-ranges, ignores Range, no ticket', head.status === 200
    && head.headers.get('accept-ranges') === 'bytes' && head.headers.get('content-length') === '3000' && !head.headers.has('x-resume-ticket'));
  check('ticket: issued on a download', TICKET_SHAPE.test(whole.headers.get('x-resume-ticket') || ''));
}
{
  const env = freshEnv();
  const { id } = await share(env, bytesOf(300), 2);
  check('range: 416 spends nothing', (await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=300-' } })).status === 416
    && (await call(env, 'GET', `/api/f/${id}`)).data.remaining === 2);
  const counted = await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=10-' } });
  check('range: without a ticket counts as a download', counted.status === 206 && counted.headers.get('x-downloads-remaining') === '1'
    && TICKET_SHAPE.test(counted.headers.get('x-resume-ticket') || ''));
  const ticket = counted.headers.get('x-resume-ticket');
  const writes = env.META.writes();
  const gets = env.META.ops.filter(([op]) => op === 'get').length;
  const resumed = await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=50-', 'x-resume-ticket': ticket } });
  check('ticket: resume -> 206 with the right slice', resumed.status === 206 && resumed.headers.get('content-range') === 'bytes 50-299/300'
    && Buffer.compare(await bodyOf(resumed), Buffer.from(bytesOf(300).subarray(50))) === 0);
  check('ticket: resume neither loads nor counts the record',
    env.META.writes() === writes && env.META.ops.filter(([op]) => op === 'get').length === gets && !resumed.headers.has('x-downloads-remaining'));
  const fresh = resumed.headers.get('x-resume-ticket');
  check('ticket: resume returns a fresh ticket', TICKET_SHAPE.test(fresh || ''));
  check('ticket: fresh ticket works too', (await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=0-', 'x-resume-ticket': fresh } })).status === 206);
  check('ticket: count unchanged after resumes', (await call(env, 'GET', `/api/f/${id}`)).data.remaining === 1);
  const past = await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=300-', 'x-resume-ticket': ticket } });
  check('ticket: range past the end -> 416', past.status === 416 && past.headers.get('content-range') === 'bytes */300');
  const noRange = await call(env, 'GET', `/api/d/${id}`, { headers: { 'x-resume-ticket': ticket } });
  check('ticket: without a Range header it is a counted download', noRange.status === 200 && noRange.headers.get('x-downloads-remaining') === '0');
}
{
  const env = freshEnv();
  const bytes = bytesOf(500);
  const { id } = await share(env, bytes, 1);
  const first = await call(env, 'GET', `/api/d/${id}`);
  const ticket = first.headers.get('x-resume-ticket');
  check('ticket: burn download carries a ticket', first.status === 200 && TICKET_SHAPE.test(ticket || '') && !env.META.data.has(`f:${id}`));
  const resumed = await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=200-', 'x-resume-ticket': ticket } });
  check('ticket: resumes a burned link inside the grace period', resumed.status === 206
    && Buffer.compare(await bodyOf(resumed), Buffer.from(bytes.subarray(200))) === 0);
  check('ticket: burned link without a ticket stays dead', (await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=200-' } })).status === 404);
  const late = await withClock(11 * 60e3, () => call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=200-', 'x-resume-ticket': ticket } }));
  check('ticket: expired ticket on a burned link -> 404', late.status === 404);
}
{
  const env = freshEnv();
  const a = await share(env, bytesOf(300), 5);
  const b = await share(env, bytesOf(300, 9), 5);
  const ticket = (await call(env, 'GET', `/api/d/${a.id}`)).headers.get('x-resume-ticket');
  const [payload, mac] = ticket.split('.');
  // The first character, not the last: the last one of a 32-byte MAC carries padding bits.
  const flip = (s) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
  const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(payload, 'base64url')), exp: Date.now() + 864e5 })).toString('base64url');
  const cases = [
    ['forged payload', `${forged}.${mac}`, a.id, 4],
    ['flipped MAC', `${payload}.${flip(mac)}`, a.id, 4],
    ['garbage', 'not a ticket', a.id, 4],
    ['another share\'s ticket', ticket, b.id, 5],
  ];
  for (const [label, t, id, left] of cases) {
    const res = await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=0-', 'x-resume-ticket': t } });
    check(`ticket: ${label} -> 410, nothing spent`, res.status === 410 && (await call(env, 'GET', `/api/f/${id}`)).data.remaining === left);
  }
  const expired = await withClock(11 * 60e3, () => call(env, 'GET', `/api/d/${a.id}`, { headers: { range: 'bytes=0-', 'x-resume-ticket': ticket } }));
  check('ticket: expired ticket -> 410, nothing spent', expired.status === 410 && (await call(env, 'GET', `/api/f/${a.id}`)).data.remaining === 4);
  const renew = await withClock(11 * 60e3, () => call(env, 'GET', `/api/d/${a.id}`, { headers: { range: 'bytes=0-0', 'x-resume-ticket': ticket } }));
  check('ticket: expired renewal -> 410, nothing spent', renew.status === 410 && (await call(env, 'GET', `/api/f/${a.id}`)).data.remaining === 4);
  const unlimited = await share(env, bytesOf(300), 0);
  const plain = await call(env, 'GET', `/api/d/${unlimited.id}`, { headers: { range: 'bytes=10-', 'x-resume-ticket': 'not a ticket' } });
  check('ticket: a bad ticket on an unlimited share still gets its range', plain.status === 206
    && plain.headers.get('content-range') === 'bytes 10-299/300');
}
{
  // Offline guessing: the MAC is not computable from UPLOAD_TOKEN alone.
  const env = freshEnv();
  const { id } = await share(env, bytesOf(300), 2);
  const ticket = (await call(env, 'GET', `/api/d/${id}`)).headers.get('x-resume-ticket');
  const [payload, mac] = ticket.split('.');
  const { createHmac } = await import('node:crypto');
  const derived = createHmac('sha256', TOKEN).update('ephemeral-files/v1/resume-ticket').digest();
  check('ticket: MAC is not derivable from UPLOAD_TOKEN alone', createHmac('sha256', derived).update(payload).digest('base64url') !== mac);
  // With TICKET_SECRET the key is fixed by configuration; changing it invalidates tickets.
  const pinned = freshEnv({ TICKET_SECRET: 'secret-one-0123456789abcdefghijklmn' });
  const p = await share(pinned, bytesOf(300), 3);
  const t1 = (await call(pinned, 'GET', `/api/d/${p.id}`)).headers.get('x-resume-ticket');
  check('ticket: TICKET_SECRET tickets resume', (await call(pinned, 'GET', `/api/d/${p.id}`, { headers: { range: 'bytes=0-', 'x-resume-ticket': t1 } })).status === 206);
  pinned.TICKET_SECRET = 'secret-two-0123456789abcdefghijklmn';
  check('ticket: a changed TICKET_SECRET invalidates tickets',
    (await call(pinned, 'GET', `/api/d/${p.id}`, { headers: { range: 'bytes=0-', 'x-resume-ticket': t1 } })).status === 410);
}
{
  // Forward progress: replaying a ticket chain at the same offset dies after a
  // few reissues; moving forward a chunk at a time keeps it going.
  const env = freshEnv();
  const bytes = bytesOf(CIPHER_CHUNK * 2 + 100);
  const { id } = await share(env, bytes, 2);
  let ticket = (await call(env, 'GET', `/api/d/${id}`)).headers.get('x-resume-ticket');
  const resume = async (range, t) => call(env, 'GET', `/api/d/${id}`, { headers: { range, 'x-resume-ticket': t } });
  let res = await resume(`bytes=${CIPHER_CHUNK}-`, ticket);
  check('ticket progress: a chunk forward resumes', res.status === 206);
  ticket = res.headers.get('x-resume-ticket');
  let statuses = [];
  for (let i = 0; i < 9; i++) {
    res = await resume('bytes=0-', ticket);
    statuses.push(res.status);
    if (res.status === 206) ticket = res.headers.get('x-resume-ticket');
  }
  check('ticket progress: 8 reissues without progress, then 410', statuses.join() === '206,206,206,206,206,206,206,206,410');
  check('ticket progress: refusal spends nothing', (await call(env, 'GET', `/api/f/${id}`)).data.remaining === 1);
  res = await resume(`bytes=${CIPHER_CHUNK * 2}-`, ticket);
  check('ticket progress: moving forward a chunk resets the count', res.status === 206);
}
{
  const env = freshEnv();
  const { id } = await share(env, bytesOf(300), 3);
  const ticket = (await call(env, 'GET', `/api/d/${id}`)).headers.get('x-resume-ticket');
  delete env.UPLOAD_TOKEN;
  const res = await call(env, 'GET', `/api/d/${id}`);
  check('ticket: none issued without UPLOAD_TOKEN', res.status === 200 && !res.headers.has('x-resume-ticket'));
  const old = await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=0-', 'x-resume-ticket': ticket } });
  check('ticket: not honoured without UPLOAD_TOKEN (410, nothing spent)', old.status === 410 && (await call(env, 'GET', `/api/f/${id}`)).data.remaining === 1);
  env.UPLOAD_TOKEN = TOKEN;
  const { id: other } = await share(env, bytesOf(300), 3);
  env.UPLOAD_TOKEN = 'a-rotated-token-0123456789';
  const t2 = (await call(env, 'GET', `/api/d/${other}`)).headers.get('x-resume-ticket');
  env.UPLOAD_TOKEN = TOKEN;
  const rotated = await call(env, 'GET', `/api/d/${other}`, { headers: { range: 'bytes=0-', 'x-resume-ticket': t2 } });
  check('ticket: a rotated UPLOAD_TOKEN invalidates tickets (410, nothing spent)', rotated.status === 410
    && (await call(env, 'GET', `/api/f/${other}`)).data.remaining === 2);
}
{
  const env = freshEnv();
  const { id } = await share(env, bytesOf(300), 0, VERIFIER);
  const keyed = (await call(env, 'GET', `/api/d/${id}`, { headers: { 'x-ef-auth': KEY } })).headers.get('x-resume-ticket');
  const bare = (await call(env, 'GET', `/api/d/${id}`)).headers.get('x-resume-ticket');
  env.DOWNLOAD_AUTH = 'enforce';
  check('ticket: issued with the key, resumes under enforce without it',
    (await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=0-', 'x-resume-ticket': keyed } })).status === 206);
  check('ticket: issued without the key, refused once enforce is on',
    (await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=0-', 'x-resume-ticket': bare } })).status === 401);
}
{
  const env = counterEnv();
  const bytes = bytesOf(400);
  const { id } = await share(env, bytes, 1);
  const first = await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=0-' } });
  check('range + counter: counted ranged download burns', first.status === 206 && !env.META.data.has(`f:${id}`) && counterOf(env, id).data.get('count') === 1);
  const calls = env.COUNTER.calls.length;
  const resumed = await call(env, 'GET', `/api/d/${id}`, { headers: { range: 'bytes=100-', 'x-resume-ticket': first.headers.get('x-resume-ticket') } });
  check('range + counter: resume skips the counter', resumed.status === 206 && env.COUNTER.calls.length === calls
    && Buffer.compare(await bodyOf(resumed), Buffer.from(bytes.subarray(100))) === 0);
}

/* ------------------------------------------------------------------ sweep */
const kvPut = (env, key, value, metadata) => env.META.data.set(key, { value, metadata: metadata ?? null, expiration: null });
const sid = (prefix, n) => `${prefix}${String(n).padStart(15, '0')}`; // 16-char ids, sorted by prefix

{
  const env = freshEnv();
  const now = Date.now();
  // Phase 1: expired objects, more than one R2 page.
  for (let i = 0; i < 1100; i++) env.BUCKET.objects.set(sid('e', i), { bytes: bytesOf(1), customMetadata: { expires: String(now - 1000) } });
  env.BUCKET.objects.set(sid('k', 1), { bytes: bytesOf(1), customMetadata: { expires: String(now + 3600e3) } });
  // Phase 2: 1200 fresh tombstones sort first, so the old ones are only on page two.
  for (let i = 0; i < 1200; i++) kvPut(env, `x:${sid('a', i)}`, '1', { at: now });
  for (let i = 0; i < 300; i++) {
    const id = sid('z', i);
    env.BUCKET.objects.set(id, { bytes: bytesOf(1), customMetadata: { expires: String(now + 3600e3) } });
    kvPut(env, `x:${id}`, '1', i % 2 ? { at: now - 3600e3 } : undefined); // metadata-less = pre-change = old
  }
  // Phase 3: 1001 young pending uploads ahead of 5 stale ones.
  for (let i = 0; i < 1001; i++) kvPut(env, `u:${sid('A', i)}`, '{}', { created: now });
  const stale = [];
  for (let i = 0; i < 5; i++) {
    const { uploadId } = await env.BUCKET.createMultipartUpload(sid('Z', i));
    stale.push(uploadId);
    kvPut(env, `u:${sid('Z', i)}`, JSON.stringify({ id: sid('Z', i), uploadId }), { created: now - 7 * 3600e3 });
  }

  await worker.scheduled({}, env, makeCtx());
  const keys = [...env.META.data.keys()];
  check('sweep: expired objects deleted across R2 pages', ![...env.BUCKET.objects.keys()].some((k) => k.startsWith('e')));
  check('sweep: unexpired object kept', env.BUCKET.objects.has(sid('k', 1)));
  check('sweep: old tombstones past the first KV page collected', !keys.some((k) => k.startsWith('x:z')));
  check('sweep: their objects deleted', ![...env.BUCKET.objects.keys()].some((k) => k.startsWith('z')));
  check('sweep: tombstones inside the grace period kept', keys.filter((k) => k.startsWith('x:a')).length === 1200);
  check('sweep: stale uploads past the first KV page aborted',
    stale.every((u) => env.BUCKET.uploads.get(u).state === 'aborted') && !keys.some((k) => k.startsWith('u:Z')));
  check('sweep: young uploads kept', keys.filter((k) => k.startsWith('u:A')).length === 1001);
  check('sweep: logs a line per phase', ['expired', 'tombstones', 'pending'].every((p) => logs.some((l) => l.text.includes(`"phase":"${p}"`))));
}
{
  const env = freshEnv();
  const now = Date.now();
  env.BUCKET.failList = true;
  env.BUCKET.objects.set(sid('z', 1), { bytes: bytesOf(1), customMetadata: {} });
  kvPut(env, `x:${sid('z', 1)}`, '1');
  const { uploadId } = await env.BUCKET.createMultipartUpload(sid('Z', 1));
  kvPut(env, `u:${sid('Z', 1)}`, JSON.stringify({ id: sid('Z', 1), uploadId }), { created: now - 7 * 3600e3 });
  let rejected = false;
  try { await worker.scheduled({}, env, makeCtx()); } catch { rejected = true; }
  check('sweep: a failed phase marks the run as failed', rejected);
  check('sweep: later phases still ran',
    !env.META.data.has(`x:${sid('z', 1)}`) && !env.BUCKET.objects.has(sid('z', 1)) && env.BUCKET.uploads.get(uploadId).state === 'aborted');
}

/* ---------------------------------------------------------------- headers */
{
  const headersFile = readFileSync(new URL('../public/_headers', import.meta.url), 'utf8');
  const csp = headersFile.match(/^\s*Content-Security-Policy:\s*(.+)$/m)?.[1].trim();
  const page = await call(freshEnv(), 'GET', '/f/aaaaaaaaaaaaaaaa');
  check('headers: share page CSP equals public/_headers', page.status === 200 && page.headers.get('content-security-policy') === csp);
  const hsts = headersFile.match(/^\s*Strict-Transport-Security:\s*(.+)$/m)?.[1].trim();
  check('headers: HSTS matches public/_headers and has no includeSubDomains',
    page.headers.get('strict-transport-security') === hsts && !hsts.includes('includeSubDomains'));
  for (const name of ['Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy', 'Permissions-Policy', 'X-Frame-Options', 'Referrer-Policy']) {
    const want = headersFile.match(new RegExp(`^\\s*${name}:\\s*(.+)$`, 'm'))?.[1].trim();
    check(`headers: ${name} matches public/_headers`, page.headers.get(name) === want);
  }
}

report(failures ? `\n${failures} failure(s)` : '\nall checks passed');
process.exit(failures ? 1 : 0);
