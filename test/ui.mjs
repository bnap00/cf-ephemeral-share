import { chromium } from 'playwright';
import { writeFileSync, readFileSync, mkdirSync } from 'node:fs';

/**
 * Browser end-to-end test. Needs a dev server on :8787 with UPLOAD_TOKEN set
 * to the value below (put it in .dev.vars), plus `npm i -D playwright`.
 *
 *   npx wrangler dev --local     # in one shell
 *   node test/ui.mjs             # in another
 *
 * Set CHROMIUM=/path/to/chrome to use a browser Playwright did not install.
 */

const H = 'http://127.0.0.1:8787';
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

// Path 2: the Blob fallback every browser without the picker takes.
await rpage.evaluate(() => { delete window.showSaveFilePicker; });
const [download] = await Promise.all([
  rpage.waitForEvent('download', { timeout: 30000 }),
  rpage.click('#get'),
]);
await download.saveAs(`${SP}/dl/out.txt`);
const got = readFileSync(`${SP}/dl/out.txt`);
if (Buffer.compare(got, payload) === 0) pass('downloaded bytes match the original exactly'); else fail('bytes differ');
if (download.suggestedFilename() === 'ui-input.txt') pass('browser saves under the real filename'); else fail('wrong save name');

// --- owner side: recent list and revoke
await page.click('#again');
await page.waitForSelector('[data-view="upload"]:not([hidden])');
await page.waitForSelector('#recent-wrap:not([hidden])');
pass('recent links list is populated');
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

// The deliberate bad-token attempt logs an expected 401; anything else is a bug.
const unexpected = errors.filter((e) => !e.includes('401'));
if (unexpected.length) { console.log('page errors:', unexpected); failed = 1; }
else pass('no unexpected console or page errors');
await browser.close();
console.log(failed ? '\nUI failures' : '\nall UI checks passed');
process.exit(failed);
