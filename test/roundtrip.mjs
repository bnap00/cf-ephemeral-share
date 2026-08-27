/**
 * Proves the wire format round-trips and that tampering is caught.
 * Run with: node test/roundtrip.mjs
 */
import { CHUNK, TAG, beginEncrypt, openHeader, decryptStream } from '../public/crypto.js';

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

const streamOf = (bytes) =>
  new ReadableStream({
    start(controller) {
      // Deliberately ragged reads: the decryptor must reassemble chunks itself.
      for (let i = 0; i < bytes.length; i += 7777) controller.enqueue(bytes.subarray(i, i + 7777));
      controller.close();
    },
  });

function joined(chunks) {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let at = 0;
  for (const c of chunks) { out.set(c, at); at += c.length; }
  return out;
}

async function encrypt(file, password) {
  const box = await beginEncrypt(file, password);
  const parts = [];
  for (let i = 0; i < box.chunks; i++) parts.push(await box.chunk(i));
  return { box, body: joined(parts) };
}

async function decrypt(header, body, linkKey, password, expected) {
  const opened = await openHeader(header, linkKey, password);
  const out = [];
  await decryptStream(streamOf(body), opened, (c) => out.push(c));
  return { opened, bytes: joined(out) };
}

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

console.log(failures ? `\n${failures} failure(s)` : '\nall checks passed');
process.exit(failures ? 1 : 0);
