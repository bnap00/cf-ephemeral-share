/**
 * End-to-end checks for tools/ef.mjs: the real Worker fetch handler behind a
 * node:http server, with in-memory KV and R2, and the CLI run as a child
 * process exactly as a user would run it. No dependencies.
 */
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, readdir, mkdir, rm as rmrf } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import worker from '../src/index.js';
import { BUNDLE_TYPE, randomBytes, deriveAuth } from '../public/crypto.js';
import { uploadFile } from '../public/upload.js';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const EF = join(root, 'tools', 'ef.mjs');
// Makes the child believe stderr is a terminal, to exercise the interactive no-clobber path.
const AS_TTY = 'data:text/javascript,process.stderr.isTTY=true';

let failures = 0;
const check = (name, condition, detail = '') => {
  if (!condition) failures += 1;
  process.stdout.write(`${condition ? 'ok  ' : 'FAIL'} ${name}${!condition && detail ? `\n     ${detail}` : ''}\n`);
};

/* ------------------------------------------------------------------ fakes */

class FakeKV {
  data = new Map();
  async get(key, type) {
    const e = this.data.get(key);
    if (!e || (e.expiration && e.expiration * 1000 <= Date.now())) return null;
    return (type === 'json' || type?.type === 'json') ? JSON.parse(e.value) : e.value;
  }
  async put(key, value, options = {}) {
    this.data.set(key, {
      value: String(value),
      metadata: options.metadata ?? null,
      expiration: options.expirationTtl ? Math.floor(Date.now() / 1000) + options.expirationTtl : null,
    });
  }
  async delete(key) { this.data.delete(key); }
  async list({ prefix = '' } = {}) {
    return { keys: [...this.data.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })), list_complete: true };
  }
}

class FakeR2 {
  objects = new Map();
  uploads = new Map();
  inits = 0;
  aborted = 0;
  async createMultipartUpload(key, options = {}) {
    this.inits += 1;
    const uploadId = `upload-${this.inits}`;
    this.uploads.set(uploadId, { key, parts: new Map(), meta: options.customMetadata ?? {}, state: 'open' });
    return this.resumeMultipartUpload(key, uploadId);
  }
  resumeMultipartUpload(key, uploadId) {
    const r2 = this;
    const u = () => {
      const up = r2.uploads.get(uploadId);
      if (!up || up.key !== key || up.state !== 'open') throw new Error('no such upload');
      return up;
    };
    return {
      key,
      uploadId,
      async uploadPart(partNumber, value) {
        const bytes = new Uint8Array(value);
        const etag = `etag-${partNumber}-${bytes.length}`;
        u().parts.set(partNumber, { bytes, etag });
        return { partNumber, etag };
      },
      async complete(parts) {
        const up = u();
        const chunks = parts.map(({ partNumber, etag }) => {
          const p = up.parts.get(partNumber);
          if (!p || p.etag !== etag) throw new Error('bad part');
          return p.bytes;
        });
        // Real R2: every part but the last must be at least 5 MiB.
        if (chunks.slice(0, -1).some((c) => c.length < 5 << 20)) throw new Error('EntityTooSmall');
        const bytes = Buffer.concat(chunks);
        up.state = 'completed';
        r2.objects.set(key, { bytes, meta: up.meta });
        return { key, size: bytes.length };
      },
      async abort() { u().state = 'aborted'; r2.aborted += 1; },
    };
  }
  async get(key, options = {}) {
    const o = this.objects.get(key);
    if (!o) return null;
    const { offset = 0, length = o.bytes.length - offset } = options.range ?? {};
    return { key, size: o.bytes.length, body: new Response(o.bytes.subarray(offset, offset + length)).body };
  }
  async head(key) {
    const o = this.objects.get(key);
    return o ? { key, size: o.bytes.length } : null;
  }
  async delete(keys) { for (const k of [].concat(keys)) this.objects.delete(k); }
  async list() { return { objects: [], truncated: false }; }
}

const TOKEN = 'cli-test-upload-token-0123456789';
const env = {
  META: new FakeKV(),
  BUCKET: new FakeR2(),
  ASSETS: { fetch: async () => new Response('<!doctype html>', { headers: { 'content-type': 'text/html' } }) },
  UPLOAD_TOKEN: TOKEN,
  MAX_SIZE_MB: '5120',
};

let onPart = null; // test hook: runs before a part upload reaches the Worker
// Test hook: (req, n) for the n-th body download since it was set -> null, or
// { at: bytes, clean } to cut that response after `at` body bytes: by
// resetting the connection, or (clean) by ending a body sent without a length.
let cutDownload = null;
let downloadsSeen = 0;
const downloads = []; // every /api/d request: { method, range, ticket, auth, status }
const server = createServer((req, res) => handle(req, res).catch(() => res.destroy()));
async function handle(req, res) {
  if (onPart && req.url.startsWith('/api/upload/part')) await onPart();
  const isDownload = req.url.startsWith('/api/d/');
  const body = [];
  for await (const c of req) body.push(c);
  const hasBody = req.method !== 'GET' && req.method !== 'HEAD';
  const request = new Request(`http://${req.headers.host}${req.url}`, {
    method: req.method,
    headers: Object.entries(req.headers).filter(([, v]) => typeof v === 'string'),
    body: hasBody ? Buffer.concat(body) : undefined,
  });
  const response = await worker.fetch(request, env, { waitUntil() {} });
  const headers = Object.fromEntries(response.headers);
  let cut = null;
  if (isDownload) {
    downloads.push({
      method: req.method, range: req.headers.range, ticket: req.headers['x-resume-ticket'],
      auth: req.headers['x-ef-auth'], status: response.status,
    });
    if (req.method === 'GET' && response.body && cutDownload) cut = cutDownload(req, ++downloadsSeen);
    if (cut?.clean) delete headers['content-length'];
  }
  res.writeHead(response.status, headers);
  let sent = 0;
  if (response.body) {
    for await (const c of response.body) {
      if (cut && sent + c.length > cut.at) {
        res.write(c.subarray(0, cut.at - sent));
        await response.body.cancel().catch(() => {});
        if (cut.clean) return void res.end();
        await new Promise((r) => setTimeout(r, 50)); // let the partial bytes reach the client first
        return void res.destroy();
      }
      sent += c.length;
      res.write(c);
    }
  }
  res.end();
}
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const HOST = `http://127.0.0.1:${server.address().port}`;

/* ---------------------------------------------------------------- helpers */

const work = await mkdtemp(join(tmpdir(), 'ef-cli-'));

function ef(args, { input, cwd = work, envExtra = {}, tty = false, spawned } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [...(tty ? ['--import', AS_TTY] : []), EF, ...args], {
      cwd,
      env: { PATH: process.env.PATH, EF_HOST: HOST, EF_TOKEN: TOKEN, ...envExtra },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const out = [];
    const err = [];
    child.stdout.on('data', (c) => out.push(c));
    child.stderr.on('data', (c) => err.push(c));
    child.stdin.end(input ?? '');
    spawned?.(child);
    child.on('close', (code) => resolve({
      code, stdout: Buffer.concat(out), out: Buffer.concat(out).toString(), err: Buffer.concat(err).toString(),
    }));
  });
}

const LINK = /^http:\/\/127\.0\.0\.1:\d+\/f\/([A-Za-z0-9]{16,32})#([A-Za-z0-9_-]{43})\n$/;
const idOf = (link) => link.match(/\/f\/([A-Za-z0-9]+)/)[1];
const partFiles = async (dir) => (await readdir(dir)).filter((n) => n.endsWith('.part'));
const fresh = async (name) => { const d = join(work, name); await mkdir(d, { recursive: true }); return d; };

/* ------------------------------------------------------------------ tests */

try {
  // File round trip, multi-part (two 8 MiB chunks) so the parallel pool runs.
  const big = randomBytes(1 << 16);
  const payload = Buffer.alloc((8 << 20) + 12345);
  for (let i = 0; i < payload.length; i += big.length) payload.set(big.subarray(0, Math.min(big.length, payload.length - i)), i);
  await writeFile(join(work, 'payload.bin'), payload);
  let r = await ef(['put', 'payload.bin', '--ttl', '3600']);
  check('put file: exit 0', r.code === 0, r.err);
  check('put file: link built from the host used', LINK.test(r.out) && r.out.startsWith(`${HOST}/f/`), r.out);
  check('put file: progress counts chunks', r.err.includes('uploaded 2/2 chunk(s)'), r.err);
  check('put file: states password and limit', r.err.includes('password: no · downloads: unlimited'), r.err);
  check('put file: delete token line kept', /expires \S+ · delete token [A-Za-z0-9]{32}/.test(r.err), r.err);
  const fileLink = r.out.trim();
  const fileDelete = r.err.match(/delete token (\S+)/)[1];

  const d1 = await fresh('get1');
  r = await ef(['get', fileLink, '-o', 'copy.bin'], { cwd: d1 });
  check('get file -o: exit 0', r.code === 0, r.err);
  check('get file -o: bytes match', Buffer.compare(await readFile(join(d1, 'copy.bin')), payload) === 0);
  check('get file -o: no temp file left', (await partFiles(d1)).length === 0);

  r = await ef(['get', fileLink.replace('#', '/#')], { cwd: d1 });
  check('get with trailing slash, implicit name', r.code === 0 && Buffer.compare(await readFile(join(d1, 'payload.bin')), payload) === 0, r.err);

  // Notes: --text (value starting with -- is fine), and stdin.
  r = await ef(['put', '--text', '--not-a-flag KEY=value', '--limit', '2']);
  check('put --text: exit 0', r.code === 0, r.err);
  const noteLink = r.out.trim();
  r = await ef(['get', noteLink]);
  check('get note: printed to stdout exactly', r.code === 0 && r.out === '--not-a-flag KEY=value', JSON.stringify(r.out) + r.err);
  r = await ef(['put', '-', '--name', '.env'], { input: 'A=1\nB=2\n' });
  check('put - (stdin note): exit 0', r.code === 0, r.err);
  r = await ef(['get', r.out.trim()]);
  check('get stdin note', r.out === 'A=1\nB=2\n', JSON.stringify(r.out));

  // Password shares, three ways to give the password.
  r = await ef(['put', '--text', 'secret', '--password', 'hunter2']);
  check('put --password: says yes', r.code === 0 && r.err.includes('password: yes'), r.err);
  const pwLink = r.out.trim();
  r = await ef(['get', pwLink]);
  check('get without password fails', r.code === 1 && r.err.includes('wrong password'), r.err);
  r = await ef(['get', pwLink, '-p', 'hunter2']);
  check('get -p', r.code === 0 && r.out === 'secret', r.err);
  r = await ef(['get', pwLink], { envExtra: { EF_PASSWORD: 'hunter2' } });
  check('get with EF_PASSWORD', r.code === 0 && r.out === 'secret', r.err);
  r = await ef(['get', pwLink, '--password-stdin'], { input: 'hunter2\n' });
  check('get --password-stdin', r.code === 0 && r.out === 'secret', r.err);
  r = await ef(['put', 'payload.bin', '--password-stdin', '--limit', '1'], { input: 'pw from stdin\n' });
  check('put --password-stdin', r.code === 0 && r.err.includes('password: yes · downloads: 1'), r.err);
  const d2 = await fresh('get2');
  const r2 = await ef(['get', r.out.trim(), '-o', 'x.bin', '--password-stdin'], { cwd: d2, input: 'pw from stdin' });
  check('get --password-stdin (no newline)', r2.code === 0 && Buffer.compare(await readFile(join(d2, 'x.bin')), payload) === 0, r2.err);

  // Flag errors: nothing reaches the server.
  const initsBefore = env.BUCKET.inits;
  for (const [args, msg, extra] of [
    [['put', 'payload.bin', '--ttl'], '--ttl needs a value'],
    [['put', 'payload.bin', '--limit'], '--limit needs a value'],
    [['put', 'payload.bin', '--password'], '--password needs a value'],
    [['put', 'payload.bin', '-p'], '-p needs a value'],
    [['put', 'payload.bin', '--password', ''], '--password is empty'],
    [['put', 'payload.bin', '--ttl', 'abc'], '--ttl must be a number of seconds from 60 to 2592000'],
    [['put', 'payload.bin', '--ttl', ''], '--ttl must be a number of seconds from 60 to 2592000'],
    [['put', 'payload.bin', '--ttl', '-5'], '--ttl must be a number of seconds from 60 to 2592000'],
    [['put', 'payload.bin', '--ttl', '0'], '--ttl must be a number of seconds from 60 to 2592000'],
    [['put', 'payload.bin', '--limit', ''], '--limit must be a whole number'],
    [['put', 'payload.bin', '--limit', 'abc'], '--limit must be a whole number'],
    [['put', 'payload.bin', '--limit', '-1'], '--limit must be a whole number'],
    [['put', 'payload.bin', '--limit', '0.5'], '--limit must be a whole number'],
    [['put', '-', '--password-stdin'], 'cannot be used with'],
    [['put', 'payload.bin'], 'EF_PASSWORD is set but empty', { EF_PASSWORD: '' }],
    [['get', noteLink, '-o'], '-o needs a value'],
    [['put', 'payload.bin', '--host', 'http://example.invalid', '--require-https'], 'refusing to send the upload token'],
    [['put', 'payload.bin', '--host', 'http://example.invalid'], 'refusing to send the upload token', { EF_REQUIRE_HTTPS: '1' }],
  ]) {
    r = await ef(args, { envExtra: extra });
    check(`error: ${args.slice(2).join(' ') || JSON.stringify(extra)}`, r.code === 1 && r.err.includes(msg), r.err);
  }
  check('flag errors start no upload', env.BUCKET.inits === initsBefore);

  // Values the Worker has always adjusted are adjusted the same way, with a warning.
  for (const [args, warning, shown] of [
    [['--ttl', '59'], '--ttl 59 is not a whole number from 60 to 2592000; using 60', 'downloads: unlimited'],
    [['--ttl', '0.5'], 'using 60', 'downloads: unlimited'],
    [['--ttl', '3600.5'], 'using 3600', 'downloads: unlimited'],
    [['--ttl', '2592001'], 'using 2592000', 'downloads: unlimited'],
    [['--limit', '1.5'], '--limit 1.5 is not a whole number; using 1', 'downloads: 1'],
  ]) {
    r = await ef(['put', 'payload.bin', ...args]);
    check(`adjusted: ${args.join(' ')} warns and uploads`, r.code === 0 && r.err.includes(`warning: ${args[0]} ${args[1]} is not a whole number`) && r.err.includes(warning)
      && r.err.includes(shown) && /\/f\/[A-Za-z0-9]{16,32}#/.test(r.out), r.err);
  }

  // http to a non-loopback name warns and carries on (0.0.0.0 reaches this machine on Linux).
  r = await ef(['put', '--text', 'w', '--host', HOST.replace('127.0.0.1', '0.0.0.0')]);
  check('http non-loopback: warns, still uploads', r.code === 0 && r.err.includes('CLEARTEXT') && r.out.startsWith('http://0.0.0.0:'), r.err);
  r = await ef(['put', '--text', 'w']);
  check('http loopback: no warning', r.code === 0 && !r.err.includes('CLEARTEXT'), r.err);

  // No-clobber for implicit names.
  r = await ef(['put', '--text', 'new contents', '--name', 'notes.txt', '--limit', '1']);
  const burnNote = r.out.trim();
  // A note goes to stdout unless -o is given, so use a file share for the implicit-name path.
  await writeFile(join(work, 'report.txt'), 'fresh report');
  r = await ef(['put', 'report.txt', '--limit', '1']);
  const reportLink = r.out.trim();
  const d3 = await fresh('clobber');
  await writeFile(join(d3, 'report.txt'), 'precious');
  r = await ef(['get', reportLink], { cwd: d3, tty: true });
  check('terminal: existing file refused', r.code === 1 && r.err.includes('already exists'), r.err);
  check('terminal: existing file untouched', (await readFile(join(d3, 'report.txt'), 'utf8')) === 'precious');
  check('terminal: refusal spent no view', (await ef(['get', reportLink, '-o', '-'])).stdout.toString() === 'fresh report');
  r = await ef(['put', 'report.txt']);
  const reportLink2 = r.out.trim();
  r = await ef(['get', reportLink2], { cwd: d3 });
  check('script: overwrites with a warning', r.code === 0 && r.err.includes('warning: overwriting')
    && (await readFile(join(d3, 'report.txt'), 'utf8')) === 'fresh report', r.err);
  await writeFile(join(d3, 'report.txt'), 'precious');
  r = await ef(['get', reportLink2, '--force'], { cwd: d3, tty: true });
  check('terminal --force overwrites', r.code === 0 && (await readFile(join(d3, 'report.txt'), 'utf8')) === 'fresh report', r.err);
  await writeFile(join(d3, 'report.txt'), 'precious');
  r = await ef(['get', reportLink2, '-o', 'report.txt'], { cwd: d3, tty: true });
  check('explicit -o overwrites silently', r.code === 0 && !r.err.includes('warning')
    && (await readFile(join(d3, 'report.txt'), 'utf8')) === 'fresh report', r.err);
  r = await ef(['get', reportLink2, '-o', join(d3, 'missing-dir', 'x')], { cwd: d3 });
  check('unwritable -o fails', r.code === 1, r.err);
  const once = (await ef(['put', 'report.txt', '--limit', '1'])).out.trim();
  r = await ef(['get', once, '-o', join(d3, 'missing-dir', 'x')], { cwd: d3 });
  check('unwritable -o spends no view', r.code === 1 && (await ef(['get', once, '-o', '-'])).out === 'fresh report', r.err);

  // Ctrl-C mid-upload: exits 130 and tells the server to drop the parts.
  const abortedBefore = env.BUCKET.aborted;
  let child;
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  let firstPart;
  const partSeen = new Promise((resolve) => { firstPart = resolve; });
  onPart = async () => { firstPart(); await held; };
  const pending = ef(['put', 'payload.bin'], { spawned: (c) => { child = c; } });
  await partSeen;
  child.kill('SIGINT');
  setTimeout(release, 300);
  r = await pending;
  onPart = null;
  check('SIGINT: exit 130, says cancelled', r.code === 130 && r.err.includes('cancelled'), `${r.code} ${r.err}`);
  check('SIGINT: upload aborted server-side', env.BUCKET.aborted === abortedBefore + 1
    && ![...env.META.data.keys()].some((k) => k.startsWith('u:')));

  // Burn after read.
  r = await ef(['get', burnNote]);
  check('limit 1: first read', r.code === 0 && r.out === 'new contents', r.err);
  r = await ef(['get', burnNote]);
  check('limit 1: second read refused', r.code === 1 && r.err.includes('not found'), r.err);

  // A tampered body: error, no output file, no temp file.
  r = await ef(['put', 'payload.bin']);
  const tamperedId = idOf(r.out);
  env.BUCKET.objects.get(tamperedId).bytes[(8 << 20) + 100] ^= 1; // second chunk
  const d4 = await fresh('tamper');
  r = await ef(['get', r.out.trim(), '-o', 'out.bin'], { cwd: d4 });
  check('tampered: fails', r.code === 1, r.err);
  check('tampered: nothing left on disk', (await readdir(d4)).length === 0, (await readdir(d4)).join(','));

  // Hostile names are sanitised for the terminal and the filesystem.
  await writeFile(join(work, 'plain.txt'), 'x');
  r = await ef(['put', 'plain.txt', '--name', '../evil\x1b[31mred\x07.txt']);
  const d5 = await fresh('names');
  r = await ef(['get', r.out.trim()], { cwd: d5 });
  check('hostile name: saved inside cwd, controls stripped', r.code === 0 && (await readdir(d5)).join() === 'evil_[31mred_.txt', (await readdir(d5)).join());
  check('hostile name: no escape codes printed', !/[\x00-\x08\x0b-\x1f]/.test(r.err.replace(/\r/g, '')), JSON.stringify(r.err));

  // Bad links.
  r = await ef(['get', `${HOST}/f/short#key`]);
  check('bad link id refused', r.code === 1 && r.err.includes('not a share link'), r.err);
  r = await ef(['get', fileLink.split('#')[0]]);
  check('link without key refused', r.code === 1 && r.err.includes('missing its key'), r.err);

  // rm.
  r = await ef(['rm', fileLink, '--token', 'wrong-token']);
  check('rm wrong token fails', r.code === 1 && r.err.includes('bad delete token'), r.err);
  r = await ef(['rm', fileLink, '--token']);
  check('rm --token with no value', r.code === 1 && r.err.includes('--token needs a value'), r.err);
  r = await ef(['rm', fileLink, '--token', fileDelete]);
  check('rm by link', r.code === 0 && r.err.includes('deleted'), r.err);
  r = await ef(['get', fileLink, '-o', '-']);
  check('rm: link is dead', r.code === 1 && r.err.includes('not found'), r.err);
  r = await ef(['rm', fileLink, '--token', fileDelete]);
  check('rm twice: already gone, exit 0', r.code === 0 && r.err.includes('not found'), r.err);
  r = await ef(['put', '--text', 'bye']);
  const byeId = idOf(r.out);
  r = await ef(['rm', byeId, '--token', r.err.match(/delete token (\S+)/)[1]]);
  check('rm by bare id + EF_HOST', r.code === 0 && r.err.includes('deleted') && !env.META.data.has(`f:${byeId}`), r.err);

  // Bundles, built the way the app builds them, with one password throughout.
  const pw = 'bundle-pw';
  const salt = randomBytes(16);
  const blobFile = (name, text, type = '') => {
    const b = new Blob([text]);
    return { name, type, size: b.size, slice: (a, z) => b.slice(a, z) };
  };
  const opts = { baseUrl: HOST, token: TOKEN, ttl: 3600, limit: 0, password: pw, salt };
  const members = [];
  for (const [name, text] of [['a.txt', 'alpha'], ['a.txt', 'alpha two'], ['../b\x1b.txt', 'beta'], ['c.txt', 'gamma']]) {
    const up = await uploadFile(blobFile(name, text), opts);
    members.push({ id: up.id, key: up.linkKey, name, size: text.length, type: '' });
  }
  const index = await uploadFile(blobFile('4 files', JSON.stringify({ v: 1, files: members }), BUNDLE_TYPE), { ...opts, limit: 2 });
  const bundleLink = `${HOST}/f/${index.id}#${index.linkKey}`;
  r = await ef(['get', bundleLink, '-o', '-', '-p', pw]);
  check('bundle -o - refused', r.code === 1 && r.err.includes('multi-file'), r.err);
  const d6 = await fresh('bundle');
  await writeFile(join(d6, 'c.txt'), 'already here');
  r = await ef(['get', bundleLink, '-o', join(d6, 'out'), '-p', pw], { cwd: d6 });
  check('bundle into a new -o dir', r.code === 0 && r.err.includes("spends one of that file's own views"), r.err);
  const got = (await readdir(join(d6, 'out'))).sort();
  check('bundle: members saved, duplicates numbered, no index file', got.join('|') === 'a (2).txt|a.txt|b_.txt|c.txt', got.join('|'));
  check('bundle: contents', (await readFile(join(d6, 'out', 'a (2).txt'), 'utf8')) === 'alpha two'
    && (await readFile(join(d6, 'out', 'b_.txt'), 'utf8')) === 'beta');
  r = await ef(['get', bundleLink, '-p', pw], { cwd: d6 });
  check('bundle into cwd never clobbers', r.code === 0 && (await readFile(join(d6, 'c.txt'), 'utf8')) === 'already here'
    && (await readFile(join(d6, 'c (2).txt'), 'utf8')) === 'gamma', r.err);
  check('bundle: index burned after its limit', (await ef(['get', bundleLink, '-p', pw], { cwd: d6 })).code === 1);
  check('bundle: no stray files', (await partFiles(d6)).length === 0 && !(await readdir(d6)).some((n) => n.includes('files')));

  // Download auth: put registers sha256(authKey); every download proves the key.
  const keyOf = (link) => link.split('#')[1];
  const recordOf = (link) => JSON.parse(env.META.data.get(`f:${idOf(link)}`)?.value ?? 'null');
  const remainingOf = async (link) => (await (await fetch(`${HOST}/api/f/${idOf(link)}`)).json()).remaining;
  r = await ef(['put', 'payload.bin', '--limit', '3']);
  const authLink = r.out.trim();
  const authOf = await deriveAuth(keyOf(authLink));
  check('auth: put stores the verifier', recordOf(authLink)?.auth === authOf.verifier, JSON.stringify(recordOf(authLink)));
  downloads.length = 0;
  const d7 = await fresh('auth');
  r = await ef(['get', authLink, '-o', 'a.bin'], { cwd: d7 });
  check('auth: get works', r.code === 0 && Buffer.compare(await readFile(join(d7, 'a.bin')), payload) === 0, r.err);
  check('auth: get sends x-ef-auth', downloads.length === 1 && downloads[0].auth === authOf.authKey, JSON.stringify(downloads));
  r = await ef(['put', '--text', 'noted']);
  check('auth: notes carry it too', recordOf(r.out.trim())?.auth === (await deriveAuth(keyOf(r.out.trim()))).verifier);

  // DOWNLOAD_AUTH=enforce: the CLI still gets everything; a request without
  // the key, or with a wrong one, is refused and spends nothing.
  env.DOWNLOAD_AUTH = 'enforce';
  try {
    r = await ef(['get', authLink, '-o', 'b.bin'], { cwd: d7 });
    check('enforce: get file works', r.code === 0 && Buffer.compare(await readFile(join(d7, 'b.bin')), payload) === 0, r.err);
    const limited = (await ef(['put', '--text', 'enforced', '--limit', '2'])).out.trim();
    const bare = await fetch(`${HOST}/api/d/${idOf(limited)}`);
    check('enforce: no header is 401', bare.status === 401);
    const wrong = await fetch(`${HOST}/api/d/${idOf(limited)}`, { headers: { 'x-ef-auth': authOf.authKey } });
    check('enforce: wrong key is 403', wrong.status === 403);
    check('enforce: refusals spend nothing', (await remainingOf(limited)) === 2);
    r = await ef(['get', limited]);
    check('enforce: get note works', r.code === 0 && r.out === 'enforced' && (await remainingOf(limited)) === 1, r.err);
    // Shares uploaded without auth (older clients) are never challenged.
    const old = await uploadFile(blobFile('old.txt', 'from before'), { baseUrl: HOST, token: TOKEN, ttl: 3600, limit: 0, auth: false });
    const oldLink = `${HOST}/f/${old.id}#${old.linkKey}`;
    r = await ef(['get', oldLink, '-o', '-']);
    check('enforce: share without auth still opens', r.code === 0 && r.out === 'from before' && !recordOf(oldLink).auth, r.err);
    // A bundle: the index and every member prove their own key.
    const bundleOpts = { baseUrl: HOST, token: TOKEN, ttl: 3600, limit: 1 };
    const parts = [];
    for (const [name, text] of [['x.txt', 'ex'], ['y.txt', 'why']]) {
      const up = await uploadFile(blobFile(name, text), bundleOpts);
      parts.push({ id: up.id, key: up.linkKey, name, size: text.length, type: '' });
    }
    const idx = await uploadFile(blobFile('2 files', JSON.stringify({ v: 1, files: parts }), BUNDLE_TYPE), bundleOpts);
    downloads.length = 0;
    const d8 = await fresh('enforce-bundle');
    r = await ef(['get', `${HOST}/f/${idx.id}#${idx.linkKey}`], { cwd: d8 });
    check('enforce: bundle works', r.code === 0 && (await readFile(join(d8, 'y.txt'), 'utf8')) === 'why', r.err);
    const expected = await Promise.all([idx.linkKey, ...parts.map((p) => p.key)].map(async (k) => (await deriveAuth(k)).authKey));
    check('enforce: bundle index and members each send their own key',
      downloads.length === 3 && downloads.every((d, i) => d.auth === expected[i] && d.status === 200), JSON.stringify(downloads));
  } finally {
    delete env.DOWNLOAD_AUTH;
  }

  // Resume: a cut connection continues from the last verified chunk under the
  // Worker's ticket, into the same temp file, without spending a second view.
  const CHUNK0 = (8 << 20) + 16; // ciphertext length of a full first chunk
  const fast = { EF_RESUME_BACKOFF_MS: '20' };
  const resumeAt = (cuts) => { downloadsSeen = 0; downloads.length = 0; cutDownload = (_req, n) => cuts[n - 1] ?? null; };
  try {
    // Reset mid first chunk: resumes from 0, one view spent.
    const two = (await ef(['put', 'payload.bin', '--limit', '2'])).out.trim();
    resumeAt([{ at: 3 << 20 }]);
    const d9 = await fresh('resume');
    r = await ef(['get', two, '-o', 'r.bin'], { cwd: d9, envExtra: fast });
    check('resume (reset): exit 0, bytes match', r.code === 0 && Buffer.compare(await readFile(join(d9, 'r.bin')), payload) === 0, r.err);
    check('resume (reset): says so', r.err.includes('resuming (attempt 1 of 5)'), r.err);
    check('resume (reset): ranged, ticketed, authenticated', downloads.length === 2 && !downloads[0].range
      && downloads[1].range === 'bytes=0-' && Boolean(downloads[1].ticket) && downloads[1].status === 206
      && downloads.every((d) => d.auth === downloads[0].auth), JSON.stringify(downloads));
    check('resume (reset): one view spent', (await remainingOf(two)) === 1);
    check('resume (reset): no temp file left', (await partFiles(d9)).length === 0);

    // Burn after read, clean early end after the first chunk: resumes at the
    // chunk boundary even though the link is already burned.
    const burn = (await ef(['put', 'payload.bin', '--limit', '1'])).out.trim();
    resumeAt([{ at: CHUNK0 + 1000, clean: true }]);
    r = await ef(['get', burn, '-o', 'burn.bin'], { cwd: d9, envExtra: fast });
    check('resume burned: exit 0, bytes match', r.code === 0 && Buffer.compare(await readFile(join(d9, 'burn.bin')), payload) === 0, r.err);
    check('resume burned: from the chunk boundary', downloads.length === 2 && downloads[1].range === `bytes=${CHUNK0}-`
      && downloads[1].status === 206, JSON.stringify(downloads));
    check('resume burned: link is dead, object awaits the sweep', !env.META.data.has(`f:${idOf(burn)}`)
      && env.META.data.has(`x:${idOf(burn)}`) && env.BUCKET.objects.has(idOf(burn)));
    cutDownload = null;
    r = await ef(['get', burn, '-o', '-']);
    check('resume burned: no second read', r.code === 1 && r.err.includes('not found'), r.err);

    // Text to stdout resumes too.
    const note = (await ef(['put', '--text', 'resumed to stdout', '--limit', '1'])).out.trim();
    resumeAt([{ at: 5 }]);
    r = await ef(['get', note], { envExtra: fast });
    check('resume to stdout', r.code === 0 && r.out === 'resumed to stdout' && downloads.length === 2, r.err);

    // A tag failure after a resume is final: no further requests.
    const bad = (await ef(['put', 'payload.bin'])).out.trim();
    env.BUCKET.objects.get(idOf(bad)).bytes[CHUNK0 + 100] ^= 1;
    resumeAt([{ at: 1000 }]);
    const d10 = await fresh('resume-bad');
    r = await ef(['get', bad, '-o', 'bad.bin'], { cwd: d10, envExtra: fast });
    check('resume tampered: fails, not retried', r.code === 1 && downloads.length === 2, `${downloads.length} ${r.err}`);
    check('resume tampered: nothing left on disk', (await readdir(d10)).length === 0);

    // Retries are bounded: a connection that always drops gives up after 5.
    const flaky = (await ef(['put', 'payload.bin'])).out.trim();
    resumeAt(Array(10).fill({ at: 1000 }));
    r = await ef(['get', flaky, '-o', 'flaky.bin'], { cwd: d10, envExtra: fast });
    check('resume bounded: gives up after 5 reconnects', r.code === 1 && downloads.length === 6
      && r.err.includes('connection dropped'), `${downloads.length} ${r.err}`);
    check('resume bounded: nothing left on disk', (await readdir(d10)).length === 0);

    // Without tickets (no UPLOAD_TOKEN on the Worker): a limited share is not
    // retried, since that would spend another view; an unlimited one resumes
    // with Range alone.
    const limitedNoTicket = (await ef(['put', 'payload.bin', '--limit', '2'])).out.trim();
    const unlimitedNoTicket = (await ef(['put', 'payload.bin'])).out.trim();
    delete env.UPLOAD_TOKEN;
    try {
      resumeAt([{ at: CHUNK0 + 1000 }]);
      r = await ef(['get', limitedNoTicket, '-o', 'nt.bin'], { cwd: d10, envExtra: fast });
      check('no ticket, limited: fails without a second request', r.code === 1 && downloads.length === 1
        && r.err.includes('connection dropped'), `${downloads.length} ${r.err}`);
      check('no ticket, limited: one view spent, nothing on disk', (await remainingOf(limitedNoTicket)) === 1
        && (await readdir(d10)).length === 0);
      resumeAt([{ at: CHUNK0 + 1000 }]);
      r = await ef(['get', unlimitedNoTicket, '-o', 'nt.bin'], { cwd: d10, envExtra: fast });
      check('no ticket, unlimited: resumes by Range alone', r.code === 0 && downloads.length === 2
        && downloads[1].range === `bytes=${CHUNK0}-` && !downloads[1].ticket
        && Buffer.compare(await readFile(join(d10, 'nt.bin')), payload) === 0, `${JSON.stringify(downloads)} ${r.err}`);
    } finally {
      env.UPLOAD_TOKEN = TOKEN;
    }
  } finally {
    cutDownload = null;
  }

  // Usage.
  r = await ef(['frobnicate']);
  check('unknown command: exit 2', r.code === 2);
} finally {
  server.close();
  await rmrf(work, { recursive: true, force: true });
}

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log('\nall cli checks passed');
