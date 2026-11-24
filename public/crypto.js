/**
 * Browser-side encryption. Nothing in this file ever talks to the network.
 *
 * Layout
 *   key material  linkKey (32 random bytes, lives in the URL fragment)
 *                 + optional PBKDF2(password) -> HKDF-SHA256 -> AES-256-GCM key
 *   header        salt(16) || nonceBase(8) || GCM(meta JSON)   [stored in KV]
 *   body          GCM(chunk 0) || GCM(chunk 1) || ...          [stored in R2]
 *
 * Every chunk is sealed with nonce = nonceBase || u32be(index) and
 * additional data = u32be(index) || isLast, so a chunk cannot be reordered,
 * dropped, duplicated or swapped between files without the tag failing. The
 * header carries the expected chunk count, so truncation is caught too.
 *
 * Meta JSON is {n: name, t: type, s: size, c: chunks} plus, since uploads
 * started recording it, k: plaintext chunk size. Headers without k are 8 MiB.
 * New headers are padded with trailing spaces (JSON.parse ignores them) so
 * their length says less about the name and type.
 *
 * Download auth (optional, server-side only): authKey = HKDF-SHA256(linkKey,
 * no salt, info 'ephemeral-files/v1/auth'); the uploader hands the Worker
 * sha256(authKey) and downloaders prove the link key by sending authKey. It is
 * a separate HKDF output, so it reveals nothing about the AES key, and it
 * ignores password and salt so the server can check it on its own.
 */

/**
 * Marker media types. They are sealed inside the header like any other media
 * type, so the server never sees them; they only tell a client to render a
 * share as text, or as a list of files, instead of handing it straight to the
 * browser's downloader.
 */
export const NOTE_TYPE = 'application/x-ephemeral-note+text';
export const BUNDLE_TYPE = 'application/x-ephemeral-bundle+json';

export const CHUNK = 8 << 20; // 8 MiB of plaintext per chunk
export const TAG = 16;        // AES-GCM tag, appended to each chunk
const MAX_CHUNK = 64 << 20;   // matches the Worker's MAX_CHUNK
const PBKDF2_ITERATIONS = 600000;
const HEADER_BUCKET = 256;    // meta JSON is padded up to a multiple of this
// The Worker caps the base64url header at 4096 chars = 3072 bytes, of which
// salt + nonceBase + tag take 40; never pad past what it would accept.
const MAX_META = 3072 - 40;
const INFO = new TextEncoder().encode('ephemeral-files/v1');
const AUTH_INFO = new TextEncoder().encode('ephemeral-files/v1/auth');

const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function b64urlEncode(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(text) {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function u32be(n) {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}

const nonce = (base, index) => concat(base, u32be(index));
const aad = (index, isLast) => concat(u32be(index), new Uint8Array([isLast ? 1 : 0]));

const validChunk = (n) => Number.isSafeInteger(n) && n > 0 && n <= MAX_CHUNK;

/**
 * PBKDF2 output, memoised in memory by salt + password so a bundle whose
 * members share one salt pays for the stretch once. Never persisted; bounded
 * so a long-lived tab does not keep every password it has seen.
 */
const stretched = new Map();
function stretch(password, salt) {
  const id = b64urlEncode(salt) + ':' + password;
  let pending = stretched.get(id);
  if (!pending) {
    pending = (async () => {
      const base = await crypto.subtle.importKey('raw', utf8.encode(password), 'PBKDF2', false, ['deriveBits']);
      return new Uint8Array(
        await crypto.subtle.deriveBits(
          { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
          base,
          256,
        ),
      );
    })();
    pending.catch(() => stretched.delete(id));
    if (stretched.size >= 16) stretched.delete(stretched.keys().next().value);
    stretched.set(id, pending);
  }
  return pending;
}

/**
 * Both factors are required: the link key alone or the password alone derives
 * a different key and every tag fails. A password is a real second factor,
 * not a check the server could be talked out of.
 */
async function deriveKey(linkKey, password, salt) {
  let material = linkKey;
  if (password) material = concat(linkKey, await stretch(password, salt));
  const hkdf = await crypto.subtle.importKey('raw', material, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: INFO },
    hkdf,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * The download credential for a link key (b64url string or raw bytes):
 * { authKey, verifier }, both base64url (43 chars). Downloaders send authKey
 * as x-ef-auth; the uploader registers verifier = sha256(authKey) as `auth`.
 */
export async function deriveAuth(linkKey) {
  const raw = typeof linkKey === 'string' ? b64urlDecode(linkKey) : linkKey;
  const hkdf = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
  const authKey = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: AUTH_INFO }, hkdf, 256),
  );
  const verifier = new Uint8Array(await crypto.subtle.digest('SHA-256', authKey));
  return { authKey: b64urlEncode(authKey), verifier: b64urlEncode(verifier) };
}

/**
 * Where to resume a body after `verified` chunks decrypted and were handed on:
 * the ciphertext byte offset of chunk `verified` (each chunk is chunkSize + TAG
 * except the last, which never needs resuming past). Pass the same number as
 * decryptStream's startChunk.
 */
export function resumeOffset(verified, chunkSize = CHUNK) {
  if (!Number.isSafeInteger(verified) || verified < 0 || !validChunk(chunkSize)) throw new Error('bad resume point');
  return verified * (chunkSize + TAG);
}

const seal = (key, base, index, isLast, plaintext) =>
  crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce(base, index), additionalData: aad(index, isLast) },
    key,
    plaintext,
  );

const open = (key, base, index, isLast, ciphertext) =>
  crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce(base, index), additionalData: aad(index, isLast) },
    key,
    ciphertext,
  );

/** Trailing 0x20 bytes up to the next bucket, counted in encoded bytes. */
function padMeta(json) {
  const raw = utf8.encode(json);
  const target = Math.min(Math.ceil(raw.length / HEADER_BUCKET) * HEADER_BUCKET, Math.max(raw.length, MAX_META));
  if (target === raw.length) return raw;
  const out = new Uint8Array(target).fill(0x20);
  out.set(raw);
  return out;
}

/**
 * Everything the uploader needs before streaming chunks. Index 0 is the header.
 *
 * opts.salt (16 bytes) lets the members of one bundle share a salt, so with a
 * password the PBKDF2 stretch runs once; each member still has its own link
 * key and nonce base, so the AES keys stay distinct. opts.chunkSize exists for
 * tests and third-party clients: shipped clients keep CHUNK, because older
 * cached readers ignore k and assume 8 MiB.
 */
export async function beginEncrypt(file, password, opts = {}) {
  const salt = opts.salt ?? randomBytes(16);
  if (!(salt instanceof Uint8Array) || salt.length !== 16) throw new Error('salt must be 16 bytes');
  const chunkSize = opts.chunkSize ?? CHUNK;
  if (!validChunk(chunkSize)) throw new Error('bad chunk size');

  const linkKey = randomBytes(32);
  const nonceBase = randomBytes(8);
  const key = await deriveKey(linkKey, password, salt);
  const chunks = Math.max(1, Math.ceil(file.size / chunkSize));

  const meta = padMeta(JSON.stringify({ n: file.name, t: file.type || '', s: file.size, c: chunks, k: chunkSize }));
  const header = new Uint8Array(await seal(key, nonceBase, 0, true, meta));
  const { verifier } = await deriveAuth(linkKey);

  return {
    key,
    nonceBase,
    chunks,
    chunkSize,
    salt,
    linkKey: b64urlEncode(linkKey),
    header: b64urlEncode(concat(salt, nonceBase, header)),
    auth: verifier, // optional `auth` for /api/upload/complete; see deriveAuth
    cipherSize: file.size + chunks * TAG,
    async chunk(index) {
      const start = index * chunkSize;
      const slice = file.slice(start, Math.min(start + chunkSize, file.size));
      const isLast = index === chunks - 1;
      return new Uint8Array(await seal(key, nonceBase, index + 1, isLast, await slice.arrayBuffer()));
    },
  };
}

/**
 * Decrypt the header with the link key (+ password). A wrong key or password
 * shows up here as a tag failure, before a single byte of body is fetched.
 */
export async function openHeader(headerB64, linkKeyB64, password) {
  const raw = b64urlDecode(headerB64);
  const salt = raw.subarray(0, 16);
  const nonceBase = raw.subarray(16, 24);
  const sealed = raw.subarray(24);
  const key = await deriveKey(b64urlDecode(linkKeyB64), password, salt);
  const meta = JSON.parse(fromUtf8.decode(await open(key, nonceBase, 0, true, sealed)));
  const chunkSize = meta.k ?? CHUNK; // absent in headers written before k existed
  if (!validChunk(chunkSize)) throw new Error('bad chunk size');
  return { key, nonceBase, name: meta.n, type: meta.t, size: meta.s, chunks: meta.c, chunkSize };
}

/**
 * Decrypt the body stream chunk by chunk, handing each verified plaintext
 * chunk to `onChunk`. Nothing is trusted until its tag verifies.
 *
 * opts.startChunk resumes: `body` must begin at resumeOffset(startChunk,
 * chunkSize), and decryption carries on with that chunk's index (so its nonce
 * and the final-chunk flag still bind it to its place; a body from the wrong
 * offset fails its tag). Progress and the return value stay absolute, counting
 * the startChunk chunks already delivered. Default 0 reads the whole body.
 */
export async function decryptStream(body, opened, onChunk, onProgress, opts = {}) {
  const chunkSize = opened.chunkSize ?? CHUNK;
  const { chunks, size } = opened;
  // c and s are authenticated, so this only fails on a hostile or broken
  // uploader; checking first keeps every expected length within one chunk.
  if (!validChunk(chunkSize) || !Number.isSafeInteger(size) || size < 0
    || chunks !== Math.max(1, Math.ceil(size / chunkSize))) throw new Error('file is corrupt or truncated');
  const startChunk = opts.startChunk ?? 0;
  if (!Number.isSafeInteger(startChunk) || startChunk < 0 || startChunk >= chunks) throw new Error('bad resume point');

  const lengthOf = (i) => (i === chunks - 1 ? size - i * chunkSize : chunkSize) + TAG;
  // One buffer, filled in place: each network byte is copied exactly once.
  // Reusing it is safe because each open() is awaited before refilling.
  const buffer = new Uint8Array(lengthOf(startChunk)); // no later chunk is longer
  const reader = body.getReader();
  let index = startChunk;
  let fill = 0;
  let expected = lengthOf(startChunk);
  let plainBytes = startChunk * chunkSize;

  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      for (let at = 0; at < value.length;) {
        if (index === chunks) throw new Error('file is corrupt or truncated'); // bytes past the last chunk
        const n = Math.min(expected - fill, value.length - at);
        buffer.set(value.subarray(at, at + n), fill);
        fill += n;
        at += n;
        if (fill < expected) continue;

        const isLast = index === chunks - 1;
        const plain = new Uint8Array(await open(opened.key, opened.nonceBase, index + 1, isLast, buffer.subarray(0, expected)));
        index += 1;
        fill = 0;
        if (!isLast) expected = lengthOf(index);
        plainBytes += plain.length;
        await onChunk(plain);
        onProgress?.(plainBytes);
      }
    }
  } catch (error) {
    reader.cancel().catch(() => {}); // stop downloading what can no longer be used
    throw error;
  }

  if (index !== chunks) throw new Error('file is truncated');
  return plainBytes;
}

/* ------------------------------------------------------- receiving keys
 *
 * Agent-to-human sharing. A person creates a receiving key (ECDH P-256) on a
 * device they control; its private half never leaves that device. A sender
 * (an AI agent, a script) holds only the public half, as a string
 * 'efpk1.<base64url raw point>'.
 *
 * The share itself is encrypted exactly as before, under a random link key.
 * Instead of putting that link key in the fragment, the sender seals it to
 * each recipient and puts the sealed form there:
 *
 *   #r1.<ephemeral public key>.<kid>.<wrapped>[.<kid>.<wrapped>...]
 *
 *   shared  ECDH(ephemeral private, recipient public)
 *   kek     HKDF-SHA256(shared, salt = epk || recipient raw,
 *                       info 'ephemeral-files/v1/recipient')     AES-256-GCM
 *   wrapped GCM(kek, iv = 0^12, aad = 'r1' || kid, link key)     48 bytes
 *   kid     first 8 bytes of SHA-256(recipient raw)              11 chars
 *
 * Each kek is used once (fresh ephemeral key per share), so a fixed IV is
 * safe. The link is therefore no secret on its own: whoever sends it, logs it
 * or reads it in a transcript cannot derive the link key, and so cannot
 * decrypt the share or, on a deployment that enforces download keys, spend a
 * view. Only a holder of a matching private key can.
 */

export const RECIPIENT_PREFIX = 'efpk1.';
const SEALED_PREFIX = 'r1.';
const RECIPIENT_INFO = utf8.encode('ephemeral-files/v1/recipient');
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
const B64URL = /^[A-Za-z0-9_-]+$/;
const MAX_RECIPIENTS = 8;

/** True for a fragment produced by sealLinkKey (the part after '#'). */
export const isSealed = (fragment) => typeof fragment === 'string' && fragment.startsWith(SEALED_PREFIX);

async function kidOf(raw) {
  return b64urlEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', raw)).subarray(0, 8));
}

/** 'efpk1.<b64url>' -> { raw, kid, key }. Throws on anything that is not a
    valid uncompressed P-256 point (importKey checks the point is on the curve). */
export async function parseRecipient(text) {
  const value = String(text ?? '').trim();
  const body = value.startsWith(RECIPIENT_PREFIX) ? value.slice(RECIPIENT_PREFIX.length) : '';
  if (body.length !== 87 || !B64URL.test(body)) throw new Error('not a receiving key (expected efpk1.<87 characters>)');
  const raw = b64urlDecode(body);
  if (raw.length !== 65 || raw[0] !== 4) throw new Error('not a receiving key');
  let key;
  try {
    key = await crypto.subtle.importKey('raw', raw, ECDH, true, []);
  } catch {
    throw new Error('not a receiving key (the point is not on P-256)');
  }
  return { raw, kid: await kidOf(raw), key, text: RECIPIENT_PREFIX + body };
}

/**
 * A new receiving key pair. `extractable` applies to the private half only:
 * the browser keeps it false (stored as a CryptoKey in IndexedDB, it can be
 * used but never read out); a CLI keystore needs true to write it to a file.
 * Returns { privateKey, publicKey, raw, kid, text }.
 */
export async function generateRecipient({ extractable = false } = {}) {
  const pair = await crypto.subtle.generateKey(ECDH, extractable, ['deriveBits']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, raw, kid: await kidOf(raw), text: RECIPIENT_PREFIX + b64urlEncode(raw) };
}

async function kek(privateKey, publicKey, epkRaw, recipientRaw) {
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
  const hkdf = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: concat(epkRaw, recipientRaw), info: RECIPIENT_INFO },
    hkdf,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

const wrapParams = (kid) => ({ name: 'AES-GCM', iv: new Uint8Array(12), additionalData: concat(utf8.encode('r1'), b64urlDecode(kid)) });

/**
 * Seal a link key (base64url, as beginEncrypt returns it) to one or more
 * recipients (strings or parseRecipient results). Returns the fragment to use
 * in place of the link key: `${origin}/f/${id}#${sealed}`.
 */
export async function sealLinkKey(linkKeyB64, recipients) {
  const list = await Promise.all([].concat(recipients).map((r) => (typeof r === 'string' ? parseRecipient(r) : r)));
  if (!list.length) throw new Error('no recipients');
  if (list.length > MAX_RECIPIENTS) throw new Error(`at most ${MAX_RECIPIENTS} recipients`);
  const linkKey = b64urlDecode(linkKeyB64);
  if (linkKey.length !== 32) throw new Error('bad link key');
  const eph = await crypto.subtle.generateKey(ECDH, false, ['deriveBits']);
  const epkRaw = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const parts = [SEALED_PREFIX.slice(0, -1), b64urlEncode(epkRaw)];
  const seen = new Set();
  for (const r of list) {
    if (seen.has(r.kid)) continue;
    seen.add(r.kid);
    const key = await kek(eph.privateKey, r.key, epkRaw, r.raw);
    parts.push(r.kid, b64urlEncode(new Uint8Array(await crypto.subtle.encrypt(wrapParams(r.kid), key, linkKey))));
  }
  return parts.join('.');
}

/** The sealed fragment's parts: { epk, entries: [{ kid, wrapped }] }. Throws if malformed. */
export function parseSealed(fragment) {
  if (!isSealed(fragment)) throw new Error('not a sealed link');
  const parts = fragment.split('.');
  const [, epk, ...rest] = parts;
  const ok = epk && epk.length === 87 && B64URL.test(epk) && rest.length >= 2 && rest.length % 2 === 0
    && rest.length / 2 <= MAX_RECIPIENTS
    && rest.every((p, i) => B64URL.test(p) && p.length === (i % 2 === 0 ? 11 : 64));
  if (!ok) throw new Error('this sealed link is malformed; copy the whole link');
  const entries = [];
  for (let i = 0; i < rest.length; i += 2) entries.push({ kid: rest[i], wrapped: rest[i + 1] });
  return { epk, entries };
}

/** The kids a sealed fragment was sealed to, so a client can look for a matching key. */
export const sealedKids = (fragment) => parseSealed(fragment).entries.map((e) => e.kid);

/**
 * Recover the link key (base64url) from a sealed fragment with one receiving
 * key: { privateKey, raw } where raw is its public point. Throws when the
 * fragment was not sealed to this key or was altered.
 */
export async function openSealedLinkKey(fragment, recipient) {
  const { epk, entries } = parseSealed(fragment);
  const kid = await kidOf(recipient.raw);
  const entry = entries.find((e) => e.kid === kid);
  if (!entry) throw new Error('this link was not sealed to this receiving key');
  const epkRaw = b64urlDecode(epk);
  let ephPublic;
  try {
    ephPublic = await crypto.subtle.importKey('raw', epkRaw, ECDH, false, []);
  } catch {
    throw new Error('this sealed link is malformed; copy the whole link');
  }
  const key = await kek(recipient.privateKey, ephPublic, epkRaw, recipient.raw);
  try {
    return b64urlEncode(new Uint8Array(await crypto.subtle.decrypt(wrapParams(kid), key, b64urlDecode(entry.wrapped))));
  } catch {
    throw new Error('this sealed link does not open with this receiving key; copy the whole link');
  }
}
