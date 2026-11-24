/**
 * The init / parts / complete upload sequence, shared by the browser app and
 * the CLI. Plain fetch, no DOM: it runs unchanged in browsers and Node 24.
 *
 *   uploadFile(file, opts) -> Promise<{ id, url, expires, deleteToken, linkKey }>
 *     file      anything with { name, type, size, slice(start, end) } (File, Blob-backed object)
 *     opts.baseUrl          origin to talk to, '' for same-origin (default '')
 *     opts.token            upload token, sent as a Bearer header
 *     opts.ttl              seconds, or a function returning seconds that is
 *                           re-read on every init attempt (bundles shrink it)
 *     opts.limit            download limit, 0 = unlimited
 *     opts.password         optional second factor, null for none
 *     opts.salt             optional 16-byte salt passed to beginEncrypt
 *     opts.auth             register the download verifier (box.auth) with the
 *                           share so downloads must prove the link key; default
 *                           true, and skipped when crypto.js predates it
 *     opts.signal           AbortSignal; cancels init and parts, never complete
 *     opts.parallel         part uploads in flight (default PARALLEL)
 *     opts.onProgress(sentCipherBytes, cipherSize)   after each part lands
 *     opts.onBeforeComplete()  once every part has landed, just before the
 *                           completion call; the last point a cancel is honoured
 *     Throws the AbortSignal's reason (name 'AbortError') on cancel, and an
 *     ApiError (with .status, 0 = network) otherwise. On any failure before
 *     completion the parts are aborted server-side, best effort.
 *     `url` is what the server reports; it is built from the request's Host,
 *     so a browser should prefer `${location.origin}/f/${id}`.
 *
 *   request(url, options) -> parsed JSON body; throws ApiError on non-2xx or
 *     a network failure, rethrows aborts untouched.
 *   deleteShare(baseUrl, id, deleteToken) -> true when the share is gone,
 *     whether this call deleted it (2xx) or it was already gone (404).
 *   abortUpload(baseUrl, token, id, uploadId) -> best effort, never throws.
 *   withRetry(fn, { signal, attempts, when = retryable }) -> fn() retried
 *     with capped exponential backoff and jitter while when(err) holds.
 *   retryable(err) -> network errors, 429 and 5xx; every other 4xx is final.
 *   ApiError, PARALLEL, ATTEMPTS
 *
 * Complete is deliberately not cancellable: aborting it mid-flight can leave
 * the share created server-side with its delete token never received.
 */
import { CHUNK, beginEncrypt } from './crypto.js';

export const PARALLEL = 3;  // part uploads in flight
export const ATTEMPTS = 9;  // per request; ~45-90 s of backoff, enough to outlast a 60 s rate-limit window
const BACKOFF_BASE = 500;   // ms
const BACKOFF_CAP = 30000;  // ms
const ABORT_WAIT = 3000;    // ms to wait for the best-effort abort before giving up on it

export class ApiError extends Error {
  constructor(message, status, retryAfter = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;          // 0 when the server was never reached
    this.retryAfter = retryAfter;  // seconds, when the server said
  }
}

const aborted = (signal) => signal?.reason ?? new DOMException('cancelled', 'AbortError');

export async function request(url, options = {}) {
  let response;
  try {
    response = await fetch(url, options);
  } catch (err) {
    if (options.signal?.aborted) throw aborted(options.signal);
    if (err?.name === 'AbortError') throw err;
    throw new ApiError('cannot reach the server', 0);
  }
  const data = await response.json().catch(() => ({}));
  if (options.signal?.aborted) throw aborted(options.signal);
  if (!response.ok) {
    const after = Number(response.headers.get('retry-after'));
    throw new ApiError(data.error || `request failed (${response.status})`, response.status,
      Number.isFinite(after) && after > 0 ? after : null);
  }
  return data;
}

export const retryable = (err) =>
  err instanceof ApiError && (err.status === 0 || err.status === 429 || err.status >= 500);

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(aborted(signal));
    const onAbort = () => { clearTimeout(timer); reject(aborted(signal)); };
    const timer = setTimeout(() => { signal?.removeEventListener('abort', onAbort); resolve(); }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** Capped exponential backoff with jitter (50-100% of the step), so parallel
    workers and several tabs do not retry in lockstep. */
export async function withRetry(fn, { signal, attempts = ATTEMPTS, when = retryable } = {}) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (signal?.aborted) throw aborted(signal);
      if (!when(err) || attempt >= attempts - 1) throw err;
      const step = Math.min(BACKOFF_CAP, BACKOFF_BASE * 2 ** attempt);
      const wait = Math.max(step * (0.5 + Math.random() / 2), Math.min((err.retryAfter || 0) * 1000, BACKOFF_CAP));
      await sleep(wait, signal);
    }
  }
}

const bearer = (token, extra = {}) => (token ? { ...extra, authorization: `Bearer ${token}` } : extra);

/** Tells the server to drop the parts now rather than at the next sweep.
    No signal (the caller's is usually already aborted) and keepalive, so it
    still goes out if the page is closing. */
export async function abortUpload(baseUrl, token, id, uploadId) {
  const sent = fetch(`${baseUrl}/api/upload/abort`, {
    method: 'POST',
    headers: bearer(token, { 'content-type': 'application/json' }),
    body: JSON.stringify({ id, uploadId }),
    keepalive: true,
  }).catch(() => {});
  let timer;
  await Promise.race([sent, new Promise((r) => { timer = setTimeout(r, ABORT_WAIT); })]);
  clearTimeout(timer);
}

export async function deleteShare(baseUrl, id, deleteToken, { attempts = 3 } = {}) {
  try {
    await withRetry(() => request(`${baseUrl}/api/f/${id}`, {
      method: 'DELETE', headers: { 'x-delete-token': deleteToken },
    }), { attempts });
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return true; // already gone is still gone
    throw err;
  }
  return true;
}

export async function uploadFile(file, opts = {}) {
  const {
    baseUrl = '', token = '', ttl, limit, password = null, salt, signal,
    parallel = PARALLEL, onProgress, onBeforeComplete, auth = true,
  } = opts;
  const box = await beginEncrypt(file, password, salt ? { salt } : {});
  const jsonHeaders = bearer(token, { 'content-type': 'application/json' });
  if (signal?.aborted) throw aborted(signal);

  const init = await withRetry(() => request(`${baseUrl}/api/upload/init`, {
    method: 'POST',
    headers: jsonHeaders,
    body: JSON.stringify({ size: box.cipherSize, chunkSize: CHUNK, ttl: typeof ttl === 'function' ? ttl() : ttl, limit }),
    signal,
  }), { signal });

  // One controller per file: a part that fails for good stops its siblings
  // instead of letting them push the rest of the file into a dead upload.
  const local = new AbortController();
  const relay = () => local.abort(aborted(signal));
  if (signal?.aborted) relay();
  else signal?.addEventListener('abort', relay, { once: true });

  const parts = new Array(box.chunks);
  let sent = 0;
  let next = 0;
  const partUrl = (n) =>
    `${baseUrl}/api/upload/part?id=${init.id}&uploadId=${encodeURIComponent(init.uploadId)}&part=${n}`;

  const worker = async () => {
    try {
      while (next < box.chunks && !local.signal.aborted) {
        const index = next++;
        const sealed = await box.chunk(index);
        const result = await withRetry(() => request(partUrl(index + 1), {
          method: 'PUT', body: sealed, headers: bearer(token), signal: local.signal,
        }), { signal: local.signal });
        parts[index] = { partNumber: index + 1, etag: result.etag };
        sent += sealed.length;
        onProgress?.(sent, box.cipherSize);
      }
    } catch (err) {
      local.abort(err);
      throw err;
    }
  };

  try {
    // Promise.all rejects with the first real error; siblings then stop on
    // the local abort and their AbortErrors are ignored.
    await Promise.all(Array.from({ length: Math.min(parallel, box.chunks) }, worker));
    if (local.signal.aborted) throw aborted(signal);
  } catch (err) {
    await abortUpload(baseUrl, token, init.id, init.uploadId);
    throw signal?.aborted ? aborted(signal) : err;
  } finally {
    signal?.removeEventListener('abort', relay);
  }

  onBeforeComplete?.();
  // Complete is not idempotent: only a request that never got an answer is
  // repeated, and a failure here does not abort (the share may exist).
  const done = await withRetry(() => request(`${baseUrl}/api/upload/complete`, {
    method: 'POST',
    headers: jsonHeaders,
    body: JSON.stringify({
      id: init.id, uploadId: init.uploadId, parts, header: box.header, protected: Boolean(password),
      // Optional and additive: Workers that predate it ignore the field.
      ...(auth && typeof box.auth === 'string' ? { auth: box.auth } : {}),
    }),
  }), { attempts: 3, when: (err) => err instanceof ApiError && err.status === 0 });

  return { id: done.id, url: done.url, expires: done.expires, deleteToken: done.deleteToken, linkKey: box.linkKey };
}
