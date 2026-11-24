import { chromium } from 'playwright';
import { writeFileSync, readFileSync, mkdirSync } from 'node:fs';

/**
 * Browser end-to-end test. Needs a dev server on :8787 with UPLOAD_TOKEN set
 * to the value below (put it in .dev.vars), plus `npm i -D playwright`.
 *
 *   npx wrangler dev --local     # in one shell
 *   node test/ui.mjs             # in another
 *
 * Set CHROMIUM=/path/to/chrome to use a browser Playwright did not install,
 * and EF_TEST_HOST=http://127.0.0.1:<port> when the dev server is elsewhere.
 */

const H = (process.env.EF_TEST_HOST || 'http://127.0.0.1:8787').replace(/\/+$/, '');
const TOKEN = 'test-token-do-not-use-in-production';
const SP = process.env.SP || new URL('../.tmp', import.meta.url).pathname;
let failed = 0;
const pass = (m) => console.log(`ok   ${m}`);
const fail = (m) => { console.log(`FAIL ${m}`); failed = 1; };

/* Links carry whatever hostname the Worker thinks it is serving, which under
   `wrangler dev` is the configured route, not 127.0.0.1. Keep the path and the
   key fragment; point them back at the dev server. */
const local = (link) => { const u = new URL(link); return `${H}${u.pathname}${u.hash}`; };
const cipherUrl = (link) => local(link).split('#')[0].replace('/f/', '/api/d/');

mkdirSync(`${SP}/dl`, { recursive: true });
const payload = Buffer.from('the quick brown fox '.repeat(5000)); // ~100 KB
writeFileSync(`${SP}/ui-input.txt`, payload);

const browser = await chromium.launch(
  process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {},
);
const ctx = await browser.newContext({ acceptDownloads: true });
const page = await ctx.newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(e.message));
page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });

// --- gate
await page.goto(H);
await page.waitForSelector('[data-view="gate"]:not([hidden])');
pass('locked gate is shown to an unauthenticated owner');
await page.fill('#gate-token', 'nope');
await page.click('#gate-unlock');
await page.waitForFunction(() => document.querySelector('#gate-status').textContent.includes('invalid'));
pass('wrong upload token is rejected in the UI');

await page.fill('#gate-token', TOKEN);
await page.check('#gate-remember');
await page.click('#gate-unlock');
await page.waitForSelector('[data-view="upload"]:not([hidden])');
pass('correct token unlocks the upload view');

// --- upload with a generated password
await page.setInputFiles('#file', `${SP}/ui-input.txt`);
await page.waitForFunction(() => document.querySelector('#drop-label').textContent === 'ui-input.txt');
pass('chosen file is shown');
await page.selectOption('#ttl', '3600');
await page.selectOption('#limit', '5');
await page.click('#generate');
const password = await page.inputValue('#password');
if (password.length >= 12) pass(`password generator produced ${password.length} chars`); else fail('weak generated password');

await page.click('#send');
await page.waitForSelector('[data-view="result"]:not([hidden])', { timeout: 30000 });
const link = await page.inputValue('#link');
pass('upload completed and produced a link');
if (link.includes('#') && link.split('#')[1].length > 20) pass('link carries the key in the fragment'); else fail('no key fragment');
if (await page.isVisible('#result-password')) pass('password is surfaced to share separately'); else fail('password not surfaced');

// --- recipient, in a clean browser context with no token and no storage
const guest = await browser.newContext({ acceptDownloads: true });
// Every ciphertext request a recipient page makes, with the headers it sent.
const cipherRequests = [];
guest.on('request', (r) => {
  if (new URL(r.url()).pathname.startsWith('/api/d/')) cipherRequests.push({ url: r.url(), headers: r.headers() });
});
const AUTH_HEADER = /^[A-Za-z0-9_-]{43}$/;
const allAuthed = (list) => list.length > 0 && list.every((r) => AUTH_HEADER.test(r.headers['x-ef-auth'] || ''));
const rpage = await guest.newPage();
rpage.on('pageerror', (e) => errors.push(`recipient: ${e.message}`));
await rpage.goto(local(link));
await rpage.waitForSelector('#unlock-row:not([hidden])');
pass('recipient with no token gets the password prompt');

await rpage.fill('#unlock-password', 'wrong');
await rpage.click('#unlock');
await rpage.waitForFunction(() => document.querySelector('#file-status').textContent.includes('wrong password'));
pass('wrong password is rejected client-side');

await rpage.fill('#unlock-password', password);
await rpage.click('#unlock');
await rpage.waitForSelector('#get:not([hidden])');
const shownName = await rpage.textContent('#file-name');
if (shownName === 'ui-input.txt') pass('filename decrypts only after unlocking'); else fail(`filename wrong: ${shownName}`);

// Path 1: the save picker. Headless Chromium rejects it with AbortError, which
// is exactly what a user cancelling the dialog produces - it must read as a
// cancel, not as a failed download.
await rpage.click('#get');
await rpage.waitForFunction(() => document.querySelector('#file-status').textContent === 'cancelled');
if (!(await rpage.isDisabled('#get'))) pass('cancelling the save dialog cancels cleanly and stays retryable');
else fail('download button left disabled after a cancel');

// Path 2: no save picker, but OPFS: the file is staged on disk, then handed
// to the browser's downloader. The probe records that the staging path ran.
await rpage.evaluate(() => {
  delete window.showSaveFilePicker;
  const original = FileSystemFileHandle.prototype.createWritable;
  FileSystemFileHandle.prototype.createWritable = function (...args) {
    window.stagedWrites = (window.stagedWrites || 0) + 1;
    return original.apply(this, args);
  };
});
const [download] = await Promise.all([
  rpage.waitForEvent('download', { timeout: 30000 }),
  rpage.click('#get'),
]);
await download.saveAs(`${SP}/dl/out.txt`);
const got = readFileSync(`${SP}/dl/out.txt`);
if (Buffer.compare(got, payload) === 0) pass('downloaded bytes match the original exactly'); else fail('bytes differ');
if (download.suggestedFilename() === 'ui-input.txt') pass('browser saves under the real filename'); else fail('wrong save name');
if (await rpage.evaluate(() => window.stagedWrites) === 1) pass('without a save picker the file is staged on disk (OPFS)');
else fail('OPFS staging path was not used');
const stagedEntries = await rpage.evaluate(async () => {
  const dir = await (await navigator.storage.getDirectory()).getDirectoryHandle('ephemeral-downloads');
  const names = [];
  for await (const name of dir.keys()) names.push(name);
  return names;
});
if (stagedEntries.length === 1) pass('the staged copy sits in its own OPFS directory until the copy-out delay passes');
else fail(`staged entries: ${stagedEntries.join()}`);
if (allAuthed(cipherRequests)) pass('every download request carries x-ef-auth');
else fail(`download without x-ef-auth: ${JSON.stringify(cipherRequests.map((r) => r.headers['x-ef-auth'] ?? null))}`);

// Path 3: no createWritable either (older Safari): the in-memory Blob path.
// The page leaves #get disabled after a finished download (so a stray second
// click cannot spend another view); re-enable it to drive the next path.
await rpage.evaluate(() => {
  window.stagedWrites = 0;
  delete FileSystemFileHandle.prototype.createWritable;
  document.querySelector('#get').disabled = false;
});
const [memoryDownload] = await Promise.all([
  rpage.waitForEvent('download', { timeout: 30000 }),
  rpage.click('#get'),
]);
await memoryDownload.saveAs(`${SP}/dl/out-memory.txt`);
if (Buffer.compare(readFileSync(`${SP}/dl/out-memory.txt`), payload) === 0 && await rpage.evaluate(() => window.stagedWrites) === 0) {
  pass('without createWritable the in-memory fallback still saves the exact bytes');
} else fail('in-memory fallback failed');

// --- owner side: recent list and revoke
await page.click('#again');
await page.waitForSelector('[data-view="upload"]:not([hidden])');
await page.waitForSelector('#recent-wrap:not([hidden])');
pass('recent links list is populated');
// Revoking takes a second click to confirm.
await page.click('.recent .link-button');
if (await page.textContent('.recent .link-button') === 'confirm delete') pass('revoke asks for confirmation first');
else fail('revoke did not ask for confirmation');
await page.click('.recent .link-button');
await page.waitForFunction(() => document.querySelectorAll('.recent li').length === 0);
pass('owner can revoke a link from the recent list');
const after = await fetch(cipherUrl(link));
if (after.status === 404) pass('revoked link is dead for recipients'); else fail(`revoked link still ${after.status}`);

// --- text mode: paste a secret, read it inline, watch it burn
await page.click('#mode-text');
await page.waitForSelector('#text-pane:not([hidden])');
if (await page.inputValue('#limit') === '1') pass('text defaults to burn after read'); else fail('text did not default to a single read');

const secret = 'API_KEY=sk-test-not-a-real-key\nDB_URL=postgres://user:pw@host/db\n';
await page.fill('#text', secret);
await page.fill('#text-name', '.env');
// The second factor has to hold for text exactly as it does for a file: the
// password is folded into the key, so the link alone must open nothing.
await page.click('#generate');
const textPassword = await page.inputValue('#password');
await page.click('#send');
await page.waitForSelector('[data-view="result"]:not([hidden])', { timeout: 30000 });
const textLink = await page.inputValue('#link');
pass('pasted text uploads and produces a link');

const tpage = await guest.newPage();
tpage.on('pageerror', (e) => errors.push(`text recipient: ${e.message}`));
await tpage.goto(local(textLink));
await tpage.waitForSelector('#unlock-row:not([hidden])');
pass('a password-protected text share asks for the password');

await tpage.fill('#unlock-password', 'wrong');
await tpage.click('#unlock');
await tpage.waitForFunction(() => document.querySelector('#file-status').textContent.includes('wrong password'));
pass('wrong password is rejected before any text is fetched');
const afterGuess = await fetch(`${H}/api/f/${new URL(textLink).pathname.split('/').pop()}`);
if ((await afterGuess.json()).remaining === 1) pass('a wrong guess does not spend the one read'); else fail('a wrong password spent a read');

await tpage.fill('#unlock-password', textPassword);
await tpage.click('#unlock');
await tpage.waitForSelector('#get:not([hidden])');
if (await tpage.textContent('#get') === 'Reveal text') pass('text share offers a reveal, not a download'); else fail('text share still offers a download');
if (await tpage.isHidden('#note-wrap')) pass('text stays unread until asked for'); else fail('text was revealed without a click');

await tpage.click('#get');
await tpage.waitForSelector('#note-wrap:not([hidden])');
const revealed = await tpage.textContent('#note-text');
if (revealed === secret) pass('revealed text matches the original byte for byte'); else fail(`text differs: ${JSON.stringify(revealed)}`);
if (await tpage.textContent('#file-name') === '.env') pass('the name given to the text survives'); else fail('text name wrong');

const burned = await fetch(cipherUrl(textLink));
if (burned.status === 404) pass('burn after read really burns the text'); else fail(`text link still ${burned.status}`);

// --- a dropped connection resumes under the ticket instead of failing
// Just over one 8 MiB chunk, burn after read: the first response is cut off
// after the first chunk, so the only way to finish is a ticketed resume, and
// a resume that were counted would find the link already burned.
const big = Buffer.alloc((8 << 20) + 300000);
for (let i = 0; i < big.length; i++) big[i] = (i * 31 + (i >> 13)) & 255;
writeFileSync(`${SP}/ui-big.bin`, big);
await page.goto(H);
await page.waitForSelector('[data-view="upload"]:not([hidden])');
await page.click('#mode-files');
await page.setInputFiles('#file', `${SP}/ui-big.bin`);
await page.selectOption('#limit', '1');
await page.click('#send');
await page.waitForSelector('[data-view="result"]:not([hidden])', { timeout: 60000 });
const bigLink = await page.inputValue('#link');

const dpage = await guest.newPage();
dpage.on('pageerror', (e) => errors.push(`resume recipient: ${e.message}`));
const firstChunk = (8 << 20) + 16;
const seenRanges = [];
let cut = false;
await dpage.route('**/api/d/**', async (route) => {
  const headers = route.request().headers();
  seenRanges.push({ range: headers.range || null, ticket: Boolean(headers['x-resume-ticket']), auth: AUTH_HEADER.test(headers['x-ef-auth'] || '') });
  if (cut || headers.range) return route.continue();
  cut = true;
  const real = await route.fetch();
  const body = await real.body();
  // A clean but short body, as when a connection closes mid-transfer.
  await route.fulfill({ status: real.status(), headers: real.headers(), body: body.subarray(0, firstChunk + 4096) });
});
await dpage.goto(local(bigLink));
await dpage.waitForSelector('#get:not([hidden])');
await dpage.evaluate(() => { delete window.showSaveFilePicker; });
const [bigDownload] = await Promise.all([
  dpage.waitForEvent('download', { timeout: 60000 }),
  dpage.click('#get'),
]);
await bigDownload.saveAs(`${SP}/dl/big.bin`);
if (Buffer.compare(readFileSync(`${SP}/dl/big.bin`), big) === 0) pass('a download cut off mid-stream resumes and finishes byte for byte');
else fail('resumed download differs from the original');
if (seenRanges.length === 2 && seenRanges[0].range === null && seenRanges[1].range === `bytes=${firstChunk}-` && seenRanges[1].ticket) {
  pass('the resume asks for the first unverified chunk, with the resume ticket');
} else fail(`resume requests: ${JSON.stringify(seenRanges)}`);
if (seenRanges.every((r) => r.auth)) pass('the resumed request carries x-ef-auth too'); else fail('resume without x-ef-auth');
await dpage.waitForFunction(() => document.querySelector('#file-status').textContent.startsWith('done'));
pass('the resumed download reports done');
if ((await fetch(cipherUrl(bigLink))).status === 404) pass('the resume did not need a second download of a burn-after-read link');
else fail('burn-after-read link still live after the resumed download');

// --- bundle with a single view: the file list must not load until asked for
const memberA = Buffer.from('alpha '.repeat(2000));
const memberB = Buffer.from([0, 1, 2, 254, 255, 0xc3, 0x28]); // not UTF-8 on purpose
writeFileSync(`${SP}/ui-a.txt`, memberA);
writeFileSync(`${SP}/ui-b.bin`, memberB);
await page.goto(H);
await page.waitForSelector('[data-view="upload"]:not([hidden])');
await page.setInputFiles('#file', [`${SP}/ui-a.txt`, `${SP}/ui-b.bin`]);
await page.waitForFunction(() => document.querySelector('#drop-label').textContent === '2 files selected');
await page.selectOption('#limit', '1');
await page.click('#send');
await page.waitForSelector('[data-view="result"]:not([hidden])', { timeout: 30000 });
const bundleLink = await page.inputValue('#link');
if (new URL(bundleLink).origin === H) pass('share link is built from the page origin'); else fail(`link origin ${new URL(bundleLink).origin}`);
pass('two files upload as a bundle');

const bpage = await guest.newPage();
bpage.on('pageerror', (e) => errors.push(`bundle recipient: ${e.message}`));
await bpage.goto(local(bundleLink));
await bpage.waitForSelector('#get:not([hidden])');
if (await bpage.textContent('#get') === 'Show files') pass('a limited bundle offers "Show files"'); else fail('no Show files button');
if (await bpage.isVisible('#burn-note')) pass('the last view of the list is announced'); else fail('no burn note on a single-view bundle');
if (await bpage.isHidden('#bundle-list-wrap')) pass('the file list stays unloaded until asked for'); else fail('file list loaded on page load');
const bundleId = new URL(bundleLink).pathname.split('/').pop();
if ((await (await fetch(`${H}/api/f/${bundleId}`)).json()).remaining === 1) pass('opening the page did not spend the only view');
else fail('opening a bundle page spent its view');

// No pickers: every member goes through the OPFS staging sink.
await bpage.evaluate(() => { delete window.showSaveFilePicker; delete window.showDirectoryPicker; });
const bundleRequestsFrom = cipherRequests.length;
await bpage.click('#get');
await bpage.waitForSelector('#bundle-list-wrap:not([hidden])');
const rows = await bpage.$$eval('#bundle-list li .recent-name', (els) => els.map((el) => el.textContent));
if (rows.join() === 'ui-a.txt,ui-b.bin') pass('file list shows both members'); else fail(`file list: ${rows.join()}`);

const bundleDownloads = [];
bpage.on('download', (d) => bundleDownloads.push(d));
await bpage.click('#bundle-download-all');
await bpage.waitForFunction(() => document.querySelector('#file-status').textContent.startsWith('2 of 2 saved'), null, { timeout: 30000 });
pass('"Download all" reports 2 of 2 saved');
for (let i = 0; i < 50 && bundleDownloads.length < 2; i++) await new Promise((r) => setTimeout(r, 100));
const byName = {};
for (const d of bundleDownloads) {
  await d.saveAs(`${SP}/dl/${d.suggestedFilename()}`);
  byName[d.suggestedFilename()] = readFileSync(`${SP}/dl/${d.suggestedFilename()}`);
}
if (byName['ui-a.txt'] && Buffer.compare(byName['ui-a.txt'], memberA) === 0
  && byName['ui-b.bin'] && Buffer.compare(byName['ui-b.bin'], memberB) === 0) pass('every member downloads byte for byte');
else fail(`bundle downloads: ${Object.keys(byName).join()}`);
const savedLabels = await bpage.$$eval('#bundle-list li button', (els) => els.map((el) => el.textContent));
if (savedLabels.every((t) => t === 'saved')) pass('each row shows its own outcome'); else fail(`row labels: ${savedLabels.join()}`);
const bundleRequests = cipherRequests.slice(bundleRequestsFrom);
if (bundleRequests.length === 3 && allAuthed(bundleRequests)
  && new Set(bundleRequests.map((r) => r.headers['x-ef-auth'])).size === 3) pass('the bundle index and each member send their own x-ef-auth');
else fail(`bundle requests: ${bundleRequests.length}, auth ${JSON.stringify(bundleRequests.map((r) => r.headers['x-ef-auth'] ?? null))}`);
if ((await fetch(cipherUrl(bundleLink))).status === 404) pass('the single-view file list burned after showing'); else fail('bundle index still live');

// --- agent -> human: a receiving key made in the browser, a link sealed to it by the CLI
const { spawnSync } = await import('node:child_process');
const kctx = await browser.newContext();
const kpage = await kctx.newPage();
kpage.on('pageerror', (e) => errors.push(e.message));
await kpage.goto(`${H}/keys`);
await kpage.waitForSelector('[data-view="keys"]:not([hidden])');
pass('/keys opens without an upload token');
await kpage.fill('#key-label', 'ui laptop');
await kpage.click('#key-create');
await kpage.waitForSelector('#key-list li');
const publicKey = await kpage.inputValue('#key-list li input');
if (/^efpk1\.[A-Za-z0-9_-]{87}$/.test(publicKey)) pass('a receiving key is created and its public half shown'); else fail(`public key: ${publicKey}`);
const extractable = await kpage.evaluate(async () => (await (await import('/keys.js')).listKeys())[0].privateKey.extractable);
if (extractable === false) pass('the private half is non-extractable'); else fail('private key is extractable');

const cliSend = (input) => spawnSync(process.execPath, [new URL('../tools/ef.mjs', import.meta.url).pathname, 'send', '-', '--to', publicKey, '--name', 'agent.env'], {
  input, encoding: 'utf8', env: { PATH: process.env.PATH, EF_HOST: H, EF_TOKEN: TOKEN, EF_CONFIG: `${SP}/no-config.json` },
});
const sent = cliSend('API_KEY=sealed-by-an-agent\n');
const sealedLink = sent.stdout.trim();
if (sent.status === 0 && /#r1\./.test(sealedLink)) pass('the CLI sealed a link to the browser key'); else fail(`ef send: ${sent.stderr}`);

await kpage.goto(local(sealedLink));
await kpage.waitForSelector('#get:not([hidden])');
if ((await kpage.textContent('#sealed-note')).includes('ui laptop')) pass('the share page says which receiving key opened it'); else fail('no sealed note');
await kpage.click('#get');
await kpage.waitForSelector('#note-wrap:not([hidden])');
if ((await kpage.textContent('#note-text')) === 'API_KEY=sealed-by-an-agent\n') pass('the sealed text decrypts in the browser that holds the key');
else fail(`sealed note: ${await kpage.textContent('#note-text')}`);

// Another browser, with no key: refused before anything is fetched or spent.
const other = cliSend('second secret');
const octx = await browser.newContext();
const opage = await octx.newPage();
const otherRequests = [];
opage.on('request', (r) => { if (/^\/api\/[fd]\//.test(new URL(r.url()).pathname)) otherRequests.push(new URL(r.url()).pathname); });
await opage.goto(local(other.stdout.trim()));
await opage.waitForFunction(() => document.querySelector('#file-status').textContent.includes('receiving key'));
if (!(await opage.isVisible('#sealed-help'))) fail('no help link for a missing key'); else pass('a browser without the key is told where to open it');
if (otherRequests.length === 0) pass('no share metadata or ciphertext is requested without the key'); else fail(`requests: ${otherRequests}`);
await octx.close();
await kctx.close();

// The deliberate bad-token attempt logs an expected 401; anything else is a bug.
const unexpected = errors.filter((e) => !e.includes('401'));
if (unexpected.length) { console.log('page errors:', unexpected); failed = 1; }
else pass('no unexpected console or page errors');
await browser.close();
console.log(failed ? '\nUI failures' : '\nall UI checks passed');
process.exit(failed);
