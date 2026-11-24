/**
 * Proves the wire format round-trips and that tampering is caught.
 * Run with: node test/roundtrip.mjs
 */
import { createHash, hkdfSync, createECDH, createDecipheriv } from 'node:crypto';
import {
  CHUNK, TAG, beginEncrypt, openHeader, decryptStream, deriveAuth, resumeOffset, b64urlDecode, b64urlEncode, randomBytes,
  generateRecipient, parseRecipient, sealLinkKey, openSealedLinkKey, isSealed, sealedKids, parseSealed,
} from '../public/crypto.js';

let failures = 0;
const check = (name, condition) => {
  console.log(`${condition ? 'ok  ' : 'FAIL'} ${name}`);
  if (!condition) failures += 1;
};

async function expectThrow(name, fn) {
  try {
    await fn();
    check(name, false);
  } catch {
    check(name, true);
  }
}

const streamOf = (bytes, step = 7777) =>
  new ReadableStream({
    start(controller) {
      // Deliberately ragged reads: the decryptor must reassemble chunks itself.
      for (let i = 0; i < bytes.length; i += step) controller.enqueue(bytes.subarray(i, i + step));
      controller.close();
    },
  });

function joined(chunks) {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let at = 0;
  for (const c of chunks) { out.set(c, at); at += c.length; }
  return out;
}

async function encrypt(file, password, opts) {
  const box = await beginEncrypt(file, password, opts);
  const parts = [];
  for (let i = 0; i < box.chunks; i++) parts.push(await box.chunk(i));
  return { box, parts, body: joined(parts) };
}

async function decrypt(header, body, linkKey, password, step) {
  const opened = await openHeader(header, linkKey, password);
  const out = [];
  await decryptStream(streamOf(body, step), opened, (c) => out.push(c));
  return { opened, bytes: joined(out) };
}

const same = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
const pattern = (size) => {
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) out[i] = (i * 7 + 3) & 255;
  return out;
};

async function run(label, size, password) {
  const plaintext = new Uint8Array(size);
  crypto.getRandomValues(plaintext.subarray(0, Math.min(size, 65536)));
  for (let i = 65536; i < size; i++) plaintext[i] = i & 255;
  const file = new File([plaintext], 'notes ünïcode.tar.gz', { type: 'application/gzip' });

  const { box, body } = await encrypt(file, password);
  check(`${label}: ciphertext length`, body.length === size + box.chunks * TAG);

  const { opened, bytes } = await decrypt(box.header, body, box.linkKey, password);
  check(`${label}: filename survives`, opened.name === 'notes ünïcode.tar.gz');
  check(`${label}: media type survives`, opened.type === 'application/gzip');
  check(`${label}: plaintext matches`, Buffer.compare(Buffer.from(bytes), Buffer.from(plaintext)) === 0);

  await expectThrow(`${label}: wrong link key rejected`, () =>
    openHeader(box.header, box.linkKey.slice(0, -2) + 'AA', password));

  const flipped = body.slice();
  flipped[Math.max(0, flipped.length - 20)] ^= 1; // hits the tag on tiny files
  await expectThrow(`${label}: tampered byte rejected`, () =>
    decrypt(box.header, flipped, box.linkKey, password));

  await expectThrow(`${label}: truncated body rejected`, () =>
    decrypt(box.header, body.subarray(0, body.length - 1), box.linkKey, password));
}

await run('small', 1024, null);
await run('empty', 0, null);
await run('multi-chunk', CHUNK * 2 + 4096, null);
await run('password', 4096, 'correct horse battery staple');

// A password-protected file must not open with the link alone, and vice versa.
{
  const file = new File([new Uint8Array(64)], 'x.bin');
  const { box } = await encrypt(file, 'hunter2');
  await expectThrow('password: link alone is not enough', () => openHeader(box.header, box.linkKey, null));
  await expectThrow('password: wrong password rejected', () => openHeader(box.header, box.linkKey, 'hunter3'));

  const other = await encrypt(file, null);
  await expectThrow('password: key from another file rejected', () =>
    openHeader(box.header, other.box.linkKey, 'hunter2'));
}

// Known-answer vectors, produced once by the pre-k, pre-padding crypto.js and
// committed. Every link already shared looks like this; it must open forever.
const LEGACY = [
  {
    name: 'fixture.txt',
    size: 100,
    password: null,
    linkKey: 'FwAVsqYDDcCYvEQKVG16KdB77FA5hN1v49TbALlT5a0',
    header: '04F1ZXhtZDB2GwLUbqKS1S4O4keOp1pj80DGtuZ3ApqKXl_N6Cd8zc9KGR1zI6xuzloX9v_6DLnOKrrYrJAg6c-BkR4ps9NkIU4jX-zKrL1HlQiKswL8G2DfH07Q2aL-HbcasvpzCZA',
    body: 'vT0iR6ni1MQkPuPYKtFw7KKBaMoS5jjBCjd5_xucyYrOn9wbNL0B0EEV1sP5O6MRaJovGo1OuXpc_D4nJu1avYS-dvhHdPnrAjAU9ibMxXpIDG1H3wE7Hx8J7xwR_SeuQnVLQVrwSRhTfgQKBURt8IxBGf4',
  },
  {
    name: 'pässwörd.bin',
    size: 300,
    password: 'hunter2',
    linkKey: 'PxJ81VYhqtq9SSFFHvQvs_UR5w6s6SdKxLwnBOZxeMU',
    header: 'Vg8y8pJq6dqKCL_ti6ARTStWix4uOedgUCPzhtFW7tzY6IJLnK0l4AFunQfDRCBRnqgqZeBCTg8xbO9PJFt_aGNPr8LqZKMZRiXcEG1a7JAcjtfAhanyNiXehve6-OaKFDvGUhJSzhnZhu0',
    body: 'Nxs0pCCxS0QZ3tDsr0r0A0dFovShmK5oKAoYPk5RDl92I5spnYY2ypTY9j5s8AY3rbr6MMjDsUYBQO3k1vmUeTPgsRYzmopP-gHdoSRuMhXE7cdy4Pwlx5kKhiE8nDZ_eX4m_oxz8J0etdbS_COwoE_WIG-RcEYdClA-UYjKgWqraHG1rm01Bba6ZYqUkG3eI__pJTKeVHhskGFm5j-MLA3956NWbsXKVrryqF0XxxkuEJ_3M3L5o0FBrA8fMK_m6CzdRC5Zp0FxktC1X512HMC4C0nhF0J5Bbcwm5KHD6RKUBa4WzYA5Rp7fuly5sQ-ZrojXJRYLEsDR3uPImaeW32qPPcvA03LmiXr5ZBE5LObI4bU4UCDWO1zrHStShU70gqqbvItWfPR3hw1bcDvd-GZqc--8U13kXocfQ',
  },
];

for (const v of LEGACY) {
  const label = `legacy ${v.password ? 'password' : 'plain'}`;
  const { opened, bytes } = await decrypt(v.header, b64urlDecode(v.body), v.linkKey, v.password);
  check(`${label}: header opens`, opened.name === v.name && opened.type === 'application/octet-stream' && opened.size === v.size);
  check(`${label}: missing k means 8 MiB`, opened.chunkSize === CHUNK);
  check(`${label}: plaintext matches`, same(bytes, pattern(v.size)));
  // A caller holding an opened object from before chunkSize existed.
  const { chunkSize, ...bare } = opened;
  const out = [];
  await decryptStream(streamOf(b64urlDecode(v.body)), bare, (c) => out.push(c));
  check(`${label}: opened without chunkSize decrypts`, same(joined(out), pattern(v.size)));
  await expectThrow(`${label}: wrong key rejected`, () => openHeader(v.header, v.linkKey.slice(0, -2) + 'AA', v.password));
}

// A stale reader (old app.js / CLI) just JSON.parses the meta and ignores
// fields it does not know. Re-implemented here so the check does not depend
// on the current code.
async function legacyMeta(headerB64, linkKeyB64) {
  const raw = b64urlDecode(headerB64);
  const salt = raw.subarray(0, 16);
  const hkdf = await crypto.subtle.importKey('raw', b64urlDecode(linkKeyB64), 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('ephemeral-files/v1') },
    hkdf, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const iv = new Uint8Array(12);
  iv.set(raw.subarray(16, 24));
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: new Uint8Array([0, 0, 0, 0, 1]) }, key, raw.subarray(24));
  return { length: plain.byteLength, meta: JSON.parse(new TextDecoder().decode(plain)) };
}

// New headers: k recorded, meta padded to a 256-byte bucket, still readable by old code.
{
  const { box } = await encrypt(new File([pattern(10)], 'a.txt', { type: 'text/plain' }), null);
  const { length, meta } = await legacyMeta(box.header, box.linkKey);
  check('padded header: meta is a multiple of 256 bytes', length % 256 === 0 && length > 0);
  check('padded header: old-style JSON.parse reads it', meta.n === 'a.txt' && meta.t === 'text/plain' && meta.s === 10 && meta.c === 1);
  check('padded header: k is recorded', meta.k === CHUNK);
  const opened = await openHeader(box.header, box.linkKey, null);
  check('padded header: opens', opened.name === 'a.txt' && opened.chunkSize === CHUNK);

  const wide = await encrypt(new File([pattern(1)], 'ü'.repeat(200) + '.bin'), null);
  check('padded header: bucket counts encoded bytes', (await legacyMeta(wide.box.header, wide.box.linkKey)).length % 256 === 0);

  const long = await encrypt(new File([pattern(1)], 'x'.repeat(2990)), null);
  check('padded header: long names stay under the Worker cap', long.box.header.length <= 4096);
  check('padded header: long name opens', (await openHeader(long.box.header, long.box.linkKey, null)).name.length === 2990);
}

// Small chunk size carried in k: exact boundaries, ragged and tiny reads.
for (const size of [0, 1, 1023, 1024, 1025, 2048, 3072, 3073]) {
  const plaintext = pattern(size);
  const { box, body } = await encrypt(new File([plaintext], 'k.bin'), null, { chunkSize: 1024 });
  check(`k=1024 size ${size}: chunk count`, box.chunks === Math.max(1, Math.ceil(size / 1024)) && body.length === size + box.chunks * TAG);
  for (const step of [1, 3, 1040, 1 << 20]) {
    const { opened, bytes } = await decrypt(box.header, body, box.linkKey, null, step);
    check(`k=1024 size ${size} reads of ${step}: plaintext matches`, opened.chunkSize === 1024 && same(bytes, plaintext));
  }
}
{
  const { box, body } = await encrypt(new File([pattern(CHUNK)], 'exact.bin'), null);
  check('exact CHUNK: one chunk', box.chunks === 1);
  check('exact CHUNK: plaintext matches', same((await decrypt(box.header, body, box.linkKey, null, 65536)).bytes, pattern(CHUNK)));
}
await expectThrow('chunk size 0 refused on upload', () => beginEncrypt(new File([], 'x'), null, { chunkSize: 0 }));
await expectThrow('chunk size over 64 MiB refused on upload', () => beginEncrypt(new File([], 'x'), null, { chunkSize: (64 << 20) + 1 }));

// Chunk-level tampering on a 3-chunk body.
{
  const { box, parts, body } = await encrypt(new File([pattern(2500)], 'r.bin'), null, { chunkSize: 1024 });
  const bad = {
    'reordered chunks': [parts[1], parts[0], parts[2]],
    'duplicated chunk': [parts[0], parts[0], parts[2]],
    'dropped middle chunk': [parts[0], parts[2]],
    'dropped last chunk': [parts[0], parts[1]],
    'repeated last chunk': [parts[0], parts[1], parts[2], parts[2]],
    'trailing garbage': [body, new Uint8Array([0])],
    'empty body': [],
  };
  for (const [name, pieces] of Object.entries(bad)) {
    await expectThrow(`k=1024: ${name} rejected`, () => decrypt(box.header, joined(pieces), box.linkKey, null, 100));
  }
  const opened = await openHeader(box.header, box.linkKey, null);
  await expectThrow('k=1024: chunk size swapped for default rejected', () =>
    decryptStream(streamOf(body), { ...opened, chunkSize: CHUNK }, () => {}));
  await expectThrow('opened with absurd chunk size rejected', () =>
    decryptStream(streamOf(body), { ...opened, chunkSize: 65 << 20 }, () => {}));
}

// One salt shared across a bundle: PBKDF2 runs once, keys stay distinct.
{
  const salt = randomBytes(16);
  const pw = 'bundle password';
  let t = performance.now();
  const a = await encrypt(new File([pattern(50)], 'a.bin'), pw, { salt });
  const cold = performance.now() - t;
  t = performance.now();
  const b = await encrypt(new File([pattern(60)], 'b.bin'), pw, { salt });
  const warm = performance.now() - t;
  check('shared salt: both headers carry it', same(b64urlDecode(a.box.header).subarray(0, 16), salt) && same(b64urlDecode(b.box.header).subarray(0, 16), salt));
  check('shared salt: link keys differ', a.box.linkKey !== b.box.linkKey);
  check('shared salt: second stretch is memoised', warm < cold / 2);
  check('shared salt: a opens', same((await decrypt(a.box.header, a.body, a.box.linkKey, pw)).bytes, pattern(50)));
  check('shared salt: b opens', same((await decrypt(b.box.header, b.body, b.box.linkKey, pw)).bytes, pattern(60)));
  await expectThrow('shared salt: wrong password still rejected', () => openHeader(a.box.header, a.box.linkKey, 'nope'));
  await expectThrow('shared salt: link key of a sibling rejected', () => openHeader(a.box.header, b.box.linkKey, pw));
  const openedA = await openHeader(a.box.header, a.box.linkKey, pw);
  await expectThrow('shared salt: sibling body rejected', () => decryptStream(streamOf(b.body), { ...openedA, size: 60 }, () => {}));
  await expectThrow('bad salt length refused', () => beginEncrypt(new File([], 'x'), null, { salt: new Uint8Array(8) }));
}

// Download auth: derived from the link key alone, re-derived here with
// node:crypto so the label and layout are pinned independently of crypto.js.
{
  const independent = (linkKeyB64) => {
    const authKey = Buffer.from(hkdfSync('sha256', b64urlDecode(linkKeyB64), new Uint8Array(0), 'ephemeral-files/v1/auth', 32));
    return { authKey: b64urlEncode(authKey), verifier: b64urlEncode(createHash('sha256').update(authKey).digest()) };
  };
  const shape = /^[A-Za-z0-9_-]{43}$/;
  for (const v of LEGACY) {
    const got = await deriveAuth(v.linkKey);
    const want = independent(v.linkKey);
    check(`auth: legacy ${v.password ? 'password' : 'plain'} key derives the pinned values`, got.authKey === want.authKey && got.verifier === want.verifier);
  }
  const file = new File([pattern(100)], 'auth.bin');
  const plain = await encrypt(file, null);
  const pw = await encrypt(file, 'hunter2');
  const a1 = await deriveAuth(plain.box.linkKey);
  const a2 = await deriveAuth(plain.box.linkKey);
  check('auth: stable for a key', a1.authKey === a2.authKey && a1.verifier === a2.verifier);
  check('auth: 43 base64url chars each', shape.test(a1.authKey) && shape.test(a1.verifier));
  check('auth: raw bytes and b64url agree', (await deriveAuth(b64urlDecode(plain.box.linkKey))).verifier === a1.verifier);
  check('auth: verifier is sha256(authKey)', a1.verifier === b64urlEncode(createHash('sha256').update(b64urlDecode(a1.authKey)).digest()));
  check('auth: authKey is not the link key or the verifier', a1.authKey !== plain.box.linkKey && a1.authKey !== a1.verifier);
  check('auth: box carries the verifier', plain.box.auth === a1.verifier);
  check('auth: password box verifier is the link-key-only value', pw.box.auth === (await deriveAuth(pw.box.linkKey)).verifier);
  check('auth: differs across keys', plain.box.auth !== pw.box.auth);
  const salt = randomBytes(16);
  const s1 = await encrypt(file, 'x', { salt });
  const s2 = await encrypt(file, 'x', { salt });
  check('auth: bundle members sharing a salt still differ', s1.box.auth !== s2.box.auth);
  check('auth: header/body unchanged by auth (still opens)', same((await decrypt(pw.box.header, pw.body, pw.box.linkKey, 'hunter2')).bytes, pattern(100)));
}

// Resume: a fresh body starting at a chunk boundary continues where the last
// verified chunk left off, with absolute progress.
{
  const size = 5 * 1024 + 300; // 6 chunks, short last one
  const plaintext = pattern(size);
  const { box, parts, body } = await encrypt(new File([plaintext], 'resume.bin'), null, { chunkSize: 1024 });
  const opened = await openHeader(box.header, box.linkKey, null);
  check('resume: offsets are chunk boundaries', resumeOffset(0, 1024) === 0 && resumeOffset(3, 1024) === 3 * 1040 && resumeOffset(2) === 2 * (CHUNK + TAG));
  check('resume: offset matches the parts', parts.slice(0, 4).reduce((n, p) => n + p.length, 0) === resumeOffset(4, 1024));
  for (const bad of [-1, 1.5, NaN, '2']) await expectThrow(`resume: offset of ${String(bad)} chunks refused`, () => resumeOffset(bad, 1024));
  await expectThrow('resume: offset with bad chunk size refused', () => resumeOffset(1, 0));

  for (let s = 0; s < box.chunks; s++) {
    for (const step of [1, 333, 1 << 20]) {
      const out = [];
      let last = -1;
      const total = await decryptStream(streamOf(body.subarray(resumeOffset(s, 1024)), step), opened, (c) => out.push(c), (n) => { last = n; }, { startChunk: s });
      check(`resume at chunk ${s} reads of ${step}: rest of plaintext`, same(joined(out), plaintext.subarray(s * 1024)) && total === size && last === size);
    }
  }
  check('resume: explicit startChunk 0 is a full read', same(joined(await (async () => {
    const out = []; await decryptStream(streamOf(body), opened, (c) => out.push(c), undefined, { startChunk: 0 }); return out;
  })()), plaintext));

  // Interrupted mid-stream, then resumed from the verified count.
  {
    const cut = resumeOffset(3, 1024) + 500;
    let pulls = 0;
    const broken = new ReadableStream({
      pull(controller) {
        if (pulls++ === 0) controller.enqueue(body.subarray(0, cut));
        else controller.error(new Error('connection reset'));
      },
    });
    const out = [];
    let failed = false;
    try { await decryptStream(broken, opened, (c) => out.push(c)); } catch { failed = true; }
    check('resume: interrupted read fails after 3 chunks', failed && out.length === 3);
    await decryptStream(streamOf(body.subarray(resumeOffset(out.length, 1024))), opened, (c) => out.push(c), undefined, { startChunk: out.length });
    check('resume: interrupted then resumed matches', same(joined(out), plaintext));
  }

  const resumeFrom = (bytes, startChunk) => decryptStream(streamOf(bytes, 100), opened, () => {}, undefined, { startChunk });
  await expectThrow('resume: body one chunk ahead rejected', () => resumeFrom(body.subarray(resumeOffset(3, 1024)), 2));
  await expectThrow('resume: body one chunk behind rejected', () => resumeFrom(body.subarray(resumeOffset(1, 1024)), 2));
  await expectThrow('resume: body off a boundary rejected', () => resumeFrom(body.subarray(resumeOffset(2, 1024) + 16), 2));
  await expectThrow('resume: offset computed with the wrong chunk size rejected', () => resumeFrom(body.subarray(resumeOffset(1, 1000)), 1));
  await expectThrow('resume: reordered chunks rejected', () => resumeFrom(joined([parts[2], parts[4], parts[3], parts[5]]), 2));
  await expectThrow('resume: last chunk replayed early rejected', () => resumeFrom(joined([parts[5]]), 4));
  await expectThrow('resume: truncated resumed body rejected', () => resumeFrom(joined([parts[3], parts[4]]), 3));
  await expectThrow('resume: trailing garbage rejected', () => resumeFrom(joined([parts[5], new Uint8Array([0])]), 5));
  await expectThrow('resume: empty resumed body rejected', () => resumeFrom(new Uint8Array(0), 5));
  for (const bad of [-1, 6, 7, 0.5, '1']) await expectThrow(`resume: startChunk ${String(bad)} refused`, () => resumeFrom(body, bad));

  // Legacy single-chunk fixtures accept the options argument too.
  const v = LEGACY[0];
  const lo = await openHeader(v.header, v.linkKey, v.password);
  const out = [];
  await decryptStream(streamOf(b64urlDecode(v.body)), lo, (c) => out.push(c), undefined, { startChunk: 0 });
  check('resume: legacy fixture with startChunk 0 decrypts', same(joined(out), pattern(v.size)));
  await expectThrow('resume: legacy fixture startChunk 1 refused', () => decryptStream(streamOf(b64urlDecode(v.body)), lo, () => {}, undefined, { startChunk: 1 }));
}

/* Receiving keys: a link key sealed to recipients opens with each of their
   private keys and nothing else, and the format matches the documented
   construction (checked with node:crypto, independently of WebCrypto). */
{
  const alice = await generateRecipient();
  const bob = await generateRecipient();
  const eve = await generateRecipient();
  const linkKey = b64urlEncode(randomBytes(32));
  const sealed = await sealLinkKey(linkKey, [alice.text, bob.text]);
  check('sealed: recognised', isSealed(sealed) && !isSealed(linkKey));
  check('sealed: lists both recipients', JSON.stringify(sealedKids(sealed)) === JSON.stringify([alice.kid, bob.kid]));
  check('sealed: fragment is URL-safe', /^[A-Za-z0-9_.-]+$/.test(sealed));
  check('sealed: alice opens it', (await openSealedLinkKey(sealed, alice)) === linkKey);
  check('sealed: bob opens it', (await openSealedLinkKey(sealed, bob)) === linkKey);
  await expectThrow('sealed: eve cannot', () => openSealedLinkKey(sealed, eve));
  check('sealed: the link key appears nowhere in it', !sealed.includes(linkKey));
  const again = await sealLinkKey(linkKey, [alice.text]);
  check('sealed: fresh ephemeral key every time', again.split('.')[1] !== sealed.split('.')[1]);
  check('sealed: duplicate recipients collapse', sealedKids(await sealLinkKey(linkKey, [alice.text, alice.text])).length === 1);

  // Tampering: a flipped wrapped byte, a swapped ephemeral key, an entry moved to another kid.
  const parts = sealed.split('.');
  const flip = (s) => (s[5] === 'A' ? `${s.slice(0, 5)}B${s.slice(6)}` : `${s.slice(0, 5)}A${s.slice(6)}`);
  await expectThrow('sealed: altered wrapped key rejected', () => openSealedLinkKey([...parts.slice(0, 3), flip(parts[3]), ...parts.slice(4)].join('.'), alice));
  await expectThrow('sealed: swapped ephemeral key rejected', () => openSealedLinkKey([parts[0], again.split('.')[1], ...parts.slice(2)].join('.'), alice));
  await expectThrow('sealed: entry relabelled to another kid rejected', () => openSealedLinkKey([parts[0], parts[1], bob.kid, parts[3]].join('.'), bob));
  for (const bad of ['r1.', 'r1.x.y.z', `${sealed}.extra`, sealed.slice(0, -1), parts.slice(0, 3).join('.')]) {
    await expectThrow(`sealed: malformed '${bad.slice(0, 12)}…' rejected`, () => parseSealed(bad));
  }
  for (const bad of ['', 'efpk1.', 'efpk2.' + alice.text.slice(6), alice.text.slice(0, -1), `efpk1.${'A'.repeat(87)}`]) {
    await expectThrow(`recipient: '${bad.slice(0, 10)}…' rejected`, () => parseRecipient(bad));
  }
  check('recipient: round trips its own text', (await parseRecipient(` ${alice.text} `)).kid === alice.kid);

  // Independent implementation of the documented construction.
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  const raw = new Uint8Array(ecdh.getPublicKey());
  const mine = await parseRecipient(`efpk1.${b64urlEncode(raw)}`);
  const s2 = (await sealLinkKey(linkKey, [mine])).split('.');
  const epk = b64urlDecode(s2[1]);
  const kid = b64urlEncode(createHash('sha256').update(raw).digest().subarray(0, 8));
  const shared = ecdh.computeSecret(epk);
  const kek = Buffer.from(hkdfSync('sha256', shared, Buffer.concat([epk, raw]), 'ephemeral-files/v1/recipient', 32));
  const wrapped = b64urlDecode(s2[3]);
  const d = createDecipheriv('aes-256-gcm', kek, Buffer.alloc(12));
  d.setAAD(Buffer.concat([Buffer.from('r1'), b64urlDecode(kid)]));
  d.setAuthTag(wrapped.subarray(32));
  const unwrapped = Buffer.concat([d.update(wrapped.subarray(0, 32)), d.final()]);
  check('sealed: kid is sha256(raw)[0:8]', s2[2] === kid);
  check('sealed: matches the documented construction', b64urlEncode(unwrapped) === linkKey);
}

console.log(failures ? `\n${failures} failure(s)` : '\nall checks passed');
process.exit(failures ? 1 : 0);
