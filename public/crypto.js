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
const PBKDF2_ITERATIONS = 600000;
const INFO = new TextEncoder().encode('ephemeral-files/v1');

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

/**
 * Both factors are required: the link key alone or the password alone derives
 * a different key and every tag fails. A password is a real second factor,
 * not a check the server could be talked out of.
 */
async function deriveKey(linkKey, password, salt) {
  let material = linkKey;
  if (password) {
    const base = await crypto.subtle.importKey('raw', utf8.encode(password), 'PBKDF2', false, ['deriveBits']);
    const stretched = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
        base,
        256,
      ),
    );
    material = concat(linkKey, stretched);
  }
  const hkdf = await crypto.subtle.importKey('raw', material, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: INFO },
    hkdf,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
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

/** Everything the uploader needs before streaming chunks. Index 0 is the header. */
export async function beginEncrypt(file, password) {
  const linkKey = randomBytes(32);
  const salt = randomBytes(16);
  const nonceBase = randomBytes(8);
  const key = await deriveKey(linkKey, password, salt);
  const chunks = Math.max(1, Math.ceil(file.size / CHUNK));

  const meta = utf8.encode(JSON.stringify({ n: file.name, t: file.type || '', s: file.size, c: chunks }));
  const header = new Uint8Array(await seal(key, nonceBase, 0, true, meta));

  return {
    key,
    nonceBase,
    chunks,
    linkKey: b64urlEncode(linkKey),
    header: b64urlEncode(concat(salt, nonceBase, header)),
    cipherSize: file.size + chunks * TAG,
    async chunk(index) {
      const start = index * CHUNK;
      const slice = file.slice(start, Math.min(start + CHUNK, file.size));
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
  return { key, nonceBase, name: meta.n, type: meta.t, size: meta.s, chunks: meta.c };
}

/**
 * Decrypt the body stream chunk by chunk, handing each verified plaintext
 * chunk to `onChunk`. Nothing is trusted until its tag verifies.
 */
export async function decryptStream(body, opened, onChunk, onProgress) {
  const cipherChunk = CHUNK + TAG;
  const reader = body.getReader();
  let buffer = new Uint8Array(0);
  let index = 0;
  let done = false;
  let plainBytes = 0;

  const flush = async (force) => {
    while (index < opened.chunks) {
      const isLast = index === opened.chunks - 1;
      const expected = isLast ? Math.min(cipherChunk, opened.size - index * CHUNK + TAG) : cipherChunk;
      if (buffer.length < expected) {
        if (!force) return;
        throw new Error('file is truncated');
      }
      const plain = new Uint8Array(await open(opened.key, opened.nonceBase, index + 1, isLast, buffer.subarray(0, expected)));
      buffer = buffer.slice(expected);
      index += 1;
      plainBytes += plain.length;
      await onChunk(plain);
      onProgress?.(plainBytes);
    }
  };

  while (!done) {
    const { value, done: finished } = await reader.read();
    done = finished;
    if (value) {
      buffer = concat(buffer, value);
      await flush(false);
    }
  }
  await flush(true);

  if (index !== opened.chunks || buffer.length) throw new Error('file is corrupt or truncated');
  return plainBytes;
}
