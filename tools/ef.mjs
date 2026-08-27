#!/usr/bin/env node
/**
 * Command-line client. Same encryption as the browser, same wire format -
 * files shared from the CLI open in the browser and vice versa.
 *
 *   node tools/ef.mjs put ./backup.tar.gz --host https://files.example.com \
 *        --ttl 3600 --limit 1 --password secret
 *   node tools/ef.mjs put - --name .env < .env      # or --text 'KEY=value'
 *   node tools/ef.mjs get 'https://files.example.com/f/abc...#key' -o ./backup.tar.gz
 *   node tools/ef.mjs get 'https://…#key' > .env    # text prints to stdout
 *
 * The key is only ever in the fragment, so it never reaches the server - not
 * in the URL it sees, not in its logs.
 */
import { basename } from 'node:path';
import { openAsBlob, createWriteStream } from 'node:fs';
import { Writable } from 'node:stream';
import { CHUNK, NOTE_TYPE, beginEncrypt, openHeader, decryptStream } from '../public/crypto.js';

const args = process.argv.slice(2);
const command = args.shift();

function flag(...names) {
  for (const name of names) {
    const i = args.indexOf(name);
    if (i !== -1) return args.splice(i, 2)[1];
  }
  return undefined;
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks);
}

async function request(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `${response.status} ${response.statusText}`);
  return data;
}

async function put() {
  const host = (flag('--host', '-h') || process.env.EF_HOST || 'http://localhost:8787').replace(/\/$/, '');
  const ttl = Number(flag('--ttl') || 86400);
  const limit = Number(flag('--limit') || 0);
  const password = flag('--password', '-p') || null;
  const token = flag('--token') || process.env.EF_TOKEN || '';
  if (!token) throw new Error('an upload token is required: pass --token or set EF_TOKEN');
  const text = flag('--text');
  const name = flag('--name');
  const path = args.shift();
  if (text === undefined && !path) {
    throw new Error(
      'usage: ef put <file|-> [--text s] [--name n] [--host url] [--ttl s] [--limit n] [--password p]',
    );
  }

  // `-` or --text shares text: same encryption, same wire format, marked with
  // NOTE_TYPE inside the header so the browser shows it instead of saving it.
  const isNote = text !== undefined || path === '-';
  const blob = isNote ? new Blob([text ?? (await readStdin())]) : await openAsBlob(path);
  const file = {
    name: name || (isNote ? 'note.txt' : basename(path)),
    type: isNote ? NOTE_TYPE : '',
    size: blob.size,
    slice: (a, b) => blob.slice(a, b),
  };

  const box = await beginEncrypt(file, password);
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;

  const init = await request(`${host}/api/upload/init`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ size: box.cipherSize, chunkSize: CHUNK, ttl, limit }),
  });

  const parts = [];
  for (let i = 0; i < box.chunks; i++) {
    const sealed = await box.chunk(i);
    const part = await request(
      `${host}/api/upload/part?id=${init.id}&uploadId=${encodeURIComponent(init.uploadId)}&part=${i + 1}`,
      { method: 'PUT', body: sealed, headers: { authorization: `Bearer ${token}` } },
    );
    parts.push({ partNumber: i + 1, etag: part.etag });
    process.stderr.write(`\ruploaded ${i + 1}/${box.chunks} chunk(s)`);
  }
  process.stderr.write('\n');

  const done = await request(`${host}/api/upload/complete`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      id: init.id, uploadId: init.uploadId, parts, header: box.header, protected: Boolean(password),
    }),
  });

  console.error(`expires ${new Date(done.expires).toISOString()} · delete token ${done.deleteToken}`);
  console.log(`${done.url}#${box.linkKey}`);
}

async function get() {
  const password = flag('--password', '-p') || null;
  const out = flag('--out', '-o');
  const link = args.shift();
  if (!link) throw new Error("usage: ef get '<link>' [-o file] [--password p]");

  const url = new URL(link);
  const linkKey = url.hash.slice(1);
  if (!linkKey) throw new Error('link is missing its key (the part after #)');
  const id = url.pathname.split('/').pop();

  const meta = await request(`${url.origin}/api/f/${id}`);
  let opened;
  try {
    opened = await openHeader(meta.header, linkKey, password);
  } catch {
    // A tag failure here is indistinguishable from a wrong key by design, and
    // WebCrypto's own message says nothing useful about which one it was.
    throw new Error(
      meta.protected
        ? 'wrong password, or this link is not valid for this share'
        : 'this link is not valid for this share',
    );
  }
  // Text goes to stdout unless a file was asked for, so `ef get … > .env` and
  // `$(ef get …)` work; `-o -` forces it for a file share too.
  const toStdout = out === '-' || (opened.type === NOTE_TYPE && !out);
  const target = out || basename(opened.name) || id;

  const response = await fetch(`${url.origin}/api/d/${id}`);
  if (!response.ok) throw new Error(`download failed (${response.status})`);

  const sink = toStdout
    ? Writable.toWeb(process.stdout).getWriter()
    : Writable.toWeb(createWriteStream(target)).getWriter();
  await decryptStream(response.body, opened, (chunk) => sink.write(chunk), (done) => {
    if (!toStdout) process.stderr.write(`\rdecrypted ${done}/${opened.size} bytes`);
  });
  await sink.close();
  if (toStdout) {
    console.error('verified');
  } else {
    process.stderr.write('\n');
    console.error(`verified and saved to ${target}`);
  }
}

try {
  if (command === 'put') await put();
  else if (command === 'get') await get();
  else {
    console.error('usage: ef <put|get> ...  (see the header of this file)');
    process.exit(2);
  }
} catch (err) {
  console.error(`error: ${err.message}`);
  process.exit(1);
}
