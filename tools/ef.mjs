#!/usr/bin/env node
/**
 * Command-line client. Same encryption as the browser, same wire format -
 * files shared from the CLI open in the browser and vice versa.
 *
 *   node tools/ef.mjs put ./backup.tar.gz --host https://files.example.com \
 *        --ttl 3600 --limit 1 --password-stdin < pw.txt   # or EF_PASSWORD, --password p
 *   node tools/ef.mjs put - --name .env < .env      # or --text 'KEY=value'
 *   node tools/ef.mjs get 'https://files.example.com/f/abc...#key' -o ./backup.tar.gz
 *   node tools/ef.mjs get 'https://…#key' > .env    # text prints to stdout
 *   node tools/ef.mjs get 'https://…#key' -o ./dir  # a multi-file share fills a directory
 *   node tools/ef.mjs rm 'https://…/f/abc...' --token <deleteToken>   # or a bare id + --host
 *
 * Agent-to-human (see the README, "Sending from agents"):
 *   ef send ./report.pdf --to alice              # sealed to alice's receiving key, 1 read
 *   some-command | ef send - --name db.env       # stdin, never echoed
 *   ef send --from-env DB_PASSWORD --name db-password --json
 *   ef send --generate 32 --name new-api-secret  # a fresh secret only the recipient ever sees
 *   ef recipient add alice efpk1.…   ef recipient list   ef recipient rm alice
 *   ef keygen --label laptop                     # a receiving key for this terminal
 *   ef config set host https://files.example.com
 *   ef config set token - < token.txt            # never on the command line
 *   ef config show
 *
 * Environment: EF_HOST, EF_TOKEN (upload token), EF_PASSWORD, EF_CONFIG (the
 * config file, default $XDG_CONFIG_HOME/ef/config.json or ~/.config/ef/config.json),
 * and EF_REQUIRE_HTTPS=1 (same as --require-https: refuse to send a token over
 * plain http to anything but this machine). Flags beat the environment, which
 * beats the config file.
 *
 * The key is only ever in the fragment, so it never reaches the server - not
 * in the URL it sees, not in its logs. Uploads register a verifier derived
 * from it and downloads send x-ef-auth (another one-way derivation of it), so
 * a leaked id alone cannot spend a view. A download whose connection drops
 * resumes from the last verified chunk under the Worker's x-resume-ticket,
 * without spending a second view.
 */
import { basename, dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { openAsBlob, unlinkSync, readFileSync as readFileSyncImpl } from 'node:fs';
import { open, lstat, stat, rename, unlink, chmod, mkdir, readFile, writeFile, readdir } from 'node:fs/promises';
import { randomBytes as nodeRandomBytes } from 'node:crypto';
import { Writable } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import {
  CHUNK, NOTE_TYPE, BUNDLE_TYPE, openHeader, decryptStream, deriveAuth, resumeOffset,
  isSealed, sealedKids, sealLinkKey, openSealedLinkKey, parseRecipient, generateRecipient,
  b64urlEncode,
} from '../public/crypto.js';
import { uploadFile, request, withRetry, ApiError } from '../public/upload.js';

const ID = /^[A-Za-z0-9]{16,32}$/;               // what the Worker accepts as an id
const SHARE_PATH = /^\/f\/([A-Za-z0-9]{16,32})\/?$/; // the app's own link pattern
const LINK_KEY = /^[A-Za-z0-9_-]{16,128}$/;       // as app.js checks bundle member keys
const MAX_INDEX = 16 << 20;                        // a bundle index is a few KB of JSON
const RESUME_ATTEMPTS = 5;                         // reconnects in a row without a new verified chunk
// ms, doubled per attempt, with jitter. EF_RESUME_BACKOFF_MS exists for tests.
const RESUME_BACKOFF = /^\d{1,6}$/.test(process.env.EF_RESUME_BACKOFF_MS || '') ? Number(process.env.EF_RESUME_BACKOFF_MS) : 1000;
const TICKET_LIFE = 9 * 60e3;                      // the Worker's resume tickets last 10 minutes
const TICKET_REFRESH = 4 * 60e3;                   // renewed this often while a limited download streams

const args = process.argv.slice(2);
const command = args.shift();

class UsageError extends Error {}

/** A value flag. Absent -> undefined; given last with nothing after it is an
    error. The value itself is never inspected: `--text '--x'` is a fine note. */
function flag(...names) {
  for (const name of names) {
    const i = args.indexOf(name);
    if (i === -1) continue;
    if (i === args.length - 1) throw new UsageError(`${name} needs a value`);
    return args.splice(i, 2)[1];
  }
  return undefined;
}

/** A switch with no value. */
function has(...names) {
  let found = false;
  for (const name of names) {
    for (let i; (i = args.indexOf(name)) !== -1;) {
      args.splice(i, 1);
      found = true;
    }
  }
  return found;
}

const MIN_TTL = 60;
const MAX_TTL = 30 * 86400;

/** A value flag read as a number: undefined when absent, NaN when empty or garbled. */
function numberFlag(name) {
  const raw = flag(name);
  if (raw === undefined) return undefined;
  return { raw, n: raw.trim() === '' ? NaN : Number(raw) };
}

/** --ttl in seconds. Values the Worker has always adjusted (a fraction, under
    a minute, over 30 days) are adjusted the same way, with a warning. An empty,
    garbled, zero or negative one is refused: it used to become "1 day" without
    a word, which can keep a share alive far longer than meant. */
function ttlFlag() {
  const value = numberFlag('--ttl');
  if (!value) return 86400;
  const { raw, n } = value;
  if (!Number.isFinite(n) || n <= 0) {
    throw new UsageError(`--ttl must be a number of seconds from ${MIN_TTL} to ${MAX_TTL}, got '${raw}'`);
  }
  const ttl = Math.min(Math.max(Math.trunc(n), MIN_TTL), MAX_TTL);
  if (ttl !== n) console.error(`warning: --ttl ${raw} is not a whole number from ${MIN_TTL} to ${MAX_TTL}; using ${ttl}`);
  return ttl;
}

/** --limit. A fraction of 1 or more is truncated, as it always was, with a
    warning. Anything that used to turn into "unlimited" by accident (empty,
    garbled, negative, a fraction under 1) is refused. */
function limitFlag() {
  const value = numberFlag('--limit');
  if (!value) return 0;
  const { raw, n } = value;
  if (!Number.isFinite(n) || n < 0 || (n > 0 && n < 1)) {
    throw new UsageError(`--limit must be a whole number of 0 or more (0 for unlimited), got '${raw}'`);
  }
  const limit = Math.trunc(n);
  if (limit !== n) console.error(`warning: --limit ${raw} is not a whole number; using ${limit}`);
  return limit;
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks);
}

/** Takes the password flags out of args; resolve later with password(). */
const passwordFlags = () => ({ given: flag('--password', '-p'), fromStdin: has('--password-stdin') });

/** --password, then --password-stdin, then EF_PASSWORD. An empty password is
    an error rather than "no password": `--password "$UNSET"` must not quietly
    produce a share that opens with the link alone. */
async function password({ given, fromStdin }, { stdinTaken = false } = {}) {
  if (given !== undefined) {
    if (given === '') throw new UsageError('--password is empty; leave the flag out to share without a password');
    return given;
  }
  if (fromStdin) {
    if (stdinTaken) throw new UsageError("--password-stdin cannot be used with 'put -', which reads the note from stdin");
    const text = (await readStdin()).toString('utf8').replace(/\r?\n$/, '');
    if (text === '') throw new UsageError('--password-stdin read an empty password');
    return text;
  }
  const env = process.env.EF_PASSWORD;
  if (env !== undefined) {
    if (env === '') throw new UsageError('EF_PASSWORD is set but empty; unset it to go without a password');
    return env;
  }
  return null;
}

/** Sender-chosen names reach the terminal: no control or bidi characters. */
const printable = (s) => String(s).replace(/[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '?');

/** A sender-chosen name as a file in the chosen directory, never a path. */
function safeName(name) {
  const base = basename(String(name ?? '').replace(/[\x00-\x1f\x7f-\x9f]/g, '_'));
  return base === '.' || base === '..' ? '' : base;
}

function hostFrom(value) {
  const raw = (value || process.env.EF_HOST || config().host || 'http://localhost:8787').replace(/\/+$/, '');
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new UsageError(`--host must be a URL such as https://files.example.com, got '${raw}'`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new UsageError('--host must be an http(s) URL');
  return raw;
}

const loopback = (hostname) =>
  hostname === 'localhost' || hostname.endsWith('.localhost') || /^127(\.\d{1,3}){3}$/.test(hostname)
  || hostname === '[::1]' || hostname === '::1';

/** A token sent over plain http to another machine can be read on the way.
    Warn by default (LAN and dev hosts over http keep working); refuse when
    asked to. */
function checkTransport(host, what, strict) {
  const url = new URL(host);
  if (url.protocol === 'https:' || loopback(url.hostname)) return;
  if (strict) {
    throw new UsageError(`refusing to send the ${what} to ${url.origin} over plain http (--require-https / EF_REQUIRE_HTTPS is set)`);
  }
  console.error(
    `\nWARNING: ${url.origin} is not https - the ${what} is sent in CLEARTEXT and anyone on the path can read it.\n` +
    '         Use an https:// host, or set EF_REQUIRE_HTTPS=1 (or --require-https) to refuse instead.\n',
  );
}

const strictHttps = () => has('--require-https') || /^(1|true|yes)$/i.test(process.env.EF_REQUIRE_HTTPS || '');

/** Ctrl-C: the first press cancels cleanly (the upload is aborted server-side,
    a partial download is removed); a second one quits at once. */
const interrupt = new AbortController();
let interrupts = 0;
let onInterrupt = () => {};
let cancellable = false; // false while nothing watches the signal, e.g. reading stdin
process.on('SIGINT', () => {
  interrupts += 1;
  if (interrupts > 1 || !cancellable) process.exit(130);
  onInterrupt();
  interrupt.abort(new DOMException('cancelled', 'AbortError'));
});

async function put() {
  const host = hostFrom(flag('--host', '-h'));
  const ttl = ttlFlag();
  const limit = limitFlag();
  const passFlags = passwordFlags();
  const token = flag('--token') || process.env.EF_TOKEN || config().token || '';
  if (!token) throw new Error('an upload token is required: pass --token, set EF_TOKEN, or run `ef config set token -`');
  const to = await recipientsFrom(flags('--to'), { fallback: false });
  const text = flag('--text');
  const name = flag('--name');
  const strict = strictHttps();
  const path = args.shift();
  if (text === undefined && !path) {
    throw new UsageError(
      'usage: ef put <file|-> [--text s] [--name n] [--host url] [--ttl s] [--limit n]\n' +
      '              [--password p | --password-stdin] [--to recipient]... [--require-https]',
    );
  }
  checkTransport(host, 'upload token', strict);
  const pass = await password(passFlags, { stdinTaken: text === undefined && path === '-' });

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

  const chunks = Math.max(1, Math.ceil(file.size / CHUNK));
  let landed = 0;
  let completing = false;
  onInterrupt = () => {
    if (completing) console.error('\nfinishing: the share is being created; press Ctrl-C again to quit anyway');
  };
  cancellable = true;
  const done = await uploadFile(file, {
    baseUrl: host,
    token,
    ttl,
    limit,
    password: pass,
    auth: true, // registers the download verifier; Workers that predate it ignore it
    signal: interrupt.signal,
    onProgress: () => process.stderr.write(`\ruploaded ${++landed}/${chunks} chunk(s)`),
    onBeforeComplete: () => { completing = true; },
  });
  process.stderr.write('\n');

  console.error(`password: ${pass ? 'yes' : 'no'} · downloads: ${limit || 'unlimited'}${to.length ? ` · sealed to ${to.map((r) => r.name).join(', ')}` : ''}`);
  console.error(`expires ${new Date(done.expires).toISOString()} · delete token ${done.deleteToken}`);
  // Built from the host actually used rather than the Worker's idea of it,
  // which follows whatever Host header reached it.
  const fragment = to.length ? await sealLinkKey(done.linkKey, to) : done.linkKey;
  console.log(`${host}/f/${done.id}#${fragment}`);
}

/* ------------------------------------------------------- config and keys */

/** Every value of a repeatable flag, e.g. --to a --to b. */
function flags(name) {
  const out = [];
  for (let v; (v = flag(name)) !== undefined;) out.push(v);
  return out;
}

const configDir = () => (process.env.EF_CONFIG
  ? dirname(process.env.EF_CONFIG)
  : join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'ef'));
const configPath = () => process.env.EF_CONFIG || join(configDir(), 'config.json');
const keysDir = () => join(configDir(), 'keys');

let loadedConfig = null;
/** The config file, read once: { host, token, recipients: { name: 'efpk1…' }, default }.
    A missing file is an empty config; a broken one is an error, never ignored. */
function config() {
  if (loadedConfig) return loadedConfig;
  loadedConfig = {};
  let text;
  try {
    text = readFileSyncQuiet(configPath());
  } catch (err) {
    throw new Error(`cannot read ${configPath()}: ${err.message}`);
  }
  if (text === null) return loadedConfig;
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) loadedConfig = parsed;
    else throw new Error('not an object');
  } catch (err) {
    throw new Error(`${configPath()} is not valid JSON (${err.message})`);
  }
  return loadedConfig;
}

function readFileSyncQuiet(path) {
  try {
    return readFileSyncImpl(path, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

/** Written owner-only, via a temp file, so a crash never leaves half a config. */
async function saveConfig(next) {
  await mkdir(configDir(), { recursive: true, mode: 0o700 });
  const temp = `${configPath()}.${nodeRandomBytes(4).toString('hex')}.tmp`;
  await writeFile(temp, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  await rename(temp, configPath());
  loadedConfig = next;
}

/** The token is a bearer credential: say so if the file holding it is readable by others. */
async function warnIfOpen() {
  if (process.platform === 'win32' || !config().token) return;
  const st = await stat(configPath()).catch(() => null);
  if (st && (st.mode & 0o077)) console.error(`warning: ${configPath()} holds the upload token and is readable by other users; run chmod 600 on it`);
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * --to values (names from the config, or efpk1.… keys) -> [{ name, kid, raw, key }].
 * With none given and `fallback`, the config's `default` (a name or a list),
 * else its only recipient. Parsed before anything is uploaded.
 */
async function recipientsFrom(given, { fallback }) {
  const known = config().recipients && typeof config().recipients === 'object' ? config().recipients : {};
  let wanted = given;
  if (!wanted.length && fallback) {
    const def = config().default;
    if (def) wanted = [].concat(def);
    else if (Object.keys(known).length === 1) wanted = Object.keys(known);
  }
  if (wanted.length > 8) throw new UsageError('at most 8 recipients');
  const out = [];
  for (const value of wanted) {
    const text = value.startsWith('efpk1.') ? value : known[value];
    if (!text) {
      const names = Object.keys(known);
      throw new UsageError(`unknown recipient '${printable(value)}'${names.length ? ` (known: ${names.join(', ')})` : '; add one with `ef recipient add <name> efpk1.…`'}`);
    }
    try {
      const r = await parseRecipient(text);
      out.push({ ...r, name: value.startsWith('efpk1.') ? r.kid : value });
    } catch (err) {
      throw new UsageError(`recipient '${printable(value.startsWith('efpk1.') ? value.slice(0, 16) + '…' : value)}': ${err.message}`);
    }
  }
  return out;
}

async function recipientCmd() {
  const sub = args.shift();
  const cfg = { ...config() };
  const recipients = { ...(cfg.recipients || {}) };
  if (sub === 'add') {
    const asDefault = has('--default');
    const [name, key] = [args.shift(), args.shift()];
    if (!name || !key) throw new UsageError('usage: ef recipient add <name> <efpk1.…> [--default]');
    if (!NAME.test(name) || name.startsWith('efpk1.')) throw new UsageError('a recipient name is letters, digits, . _ - (up to 64), not starting with efpk1.');
    const r = await parseRecipient(key).catch((err) => { throw new UsageError(err.message); });
    if (recipients[name] && recipients[name] !== r.text) {
      throw new UsageError(`recipient '${name}' already exists with a different key; pick another name, or \`ef recipient rm ${name}\` first`);
    }
    recipients[name] = r.text;
    const makeDefault = asDefault || (!cfg.default && Object.keys(recipients).length === 1);
    await saveConfig({ ...cfg, recipients, ...(makeDefault ? { default: name } : {}) });
    console.error(`added ${name} (id ${r.kid})${makeDefault ? ', the default recipient' : ''}`);
  } else if (sub === 'rm') {
    const name = args.shift();
    if (!name || !recipients[name]) throw new UsageError(`usage: ef recipient rm <name>; known: ${Object.keys(recipients).join(', ') || 'none'}`);
    delete recipients[name];
    const next = { ...cfg, recipients };
    if (next.default === name) delete next.default;
    await saveConfig(next);
    console.error(`removed ${name}`);
  } else if (sub === 'list' || sub === undefined) {
    const names = Object.keys(recipients);
    if (!names.length) console.error('no recipients; add one with `ef recipient add <name> efpk1.…`');
    for (const name of names) {
      const r = await parseRecipient(recipients[name]).catch(() => null);
      console.log(`${name}${cfg.default === name ? ' (default)' : ''}\t${r ? `id ${r.kid}` : 'INVALID KEY'}`);
    }
  } else {
    throw new UsageError('usage: ef recipient <add|rm|list> ...');
  }
}

async function configCmd() {
  const sub = args.shift();
  const cfg = { ...config() };
  if (sub === 'show' || sub === undefined) {
    const shown = { ...cfg, ...(cfg.token ? { token: `<set, ${cfg.token.length} chars>` } : {}) };
    console.log(JSON.stringify({ file: configPath(), ...shown }, null, 2));
    await warnIfOpen();
    return;
  }
  if (sub !== 'set') throw new UsageError('usage: ef config <show | set host <url> | set token - | set default <name>>');
  const [key, value] = [args.shift(), args.shift()];
  if (key === 'host') {
    if (!value) throw new UsageError('usage: ef config set host https://files.example.com');
    const host = hostFrom(value);
    await saveConfig({ ...cfg, host });
    console.error(`host set to ${host}`);
  } else if (key === 'token') {
    // Never from argv: it would sit in shell history, the process list and
    // any agent transcript that shows the command.
    if (value !== '-') throw new UsageError('pass the token on stdin: ef config set token - < token.txt');
    const token = (await readStdin()).toString('utf8').trim();
    if (!token) throw new UsageError('read an empty token from stdin');
    await saveConfig({ ...cfg, token });
    console.error('token saved');
  } else if (key === 'default') {
    if (!value || !cfg.recipients?.[value]) throw new UsageError('usage: ef config set default <recipient name>');
    await saveConfig({ ...cfg, default: value });
    console.error(`default recipient is ${value}`);
  } else {
    throw new UsageError('usage: ef config set <host|token|default> ...');
  }
}

/** A receiving key for this terminal, so `ef get` can open links sealed to it.
    The private half is a JWK in keys/<kid>.json, owner-only. Anything that can
    read that file (an agent on this machine included) can open those links. */
async function keygen() {
  const label = flag('--label') || 'terminal';
  const r = await generateRecipient({ extractable: true });
  const jwk = await crypto.subtle.exportKey('jwk', r.privateKey);
  await mkdir(keysDir(), { recursive: true, mode: 0o700 });
  await writeFile(join(keysDir(), `${r.kid}.json`), `${JSON.stringify({ label, created: Date.now(), public: r.text, jwk })}\n`, { mode: 0o600, flag: 'wx' });
  console.error(`receiving key '${printable(label)}' (id ${r.kid}) saved in ${keysDir()}`);
  console.error('give the public key below to the sender: ef recipient add <name> <key>');
  console.log(r.text);
}

/** The link key of a sealed fragment, from a key in this terminal's keystore. */
async function unsealWithLocalKeys(fragment) {
  const kids = sealedKids(fragment);
  for (const kid of kids) {
    let stored;
    try {
      stored = JSON.parse(await readFile(join(keysDir(), `${kid}.json`), 'utf8'));
    } catch (err) {
      if (err.code === 'ENOENT') continue;
      throw new Error(`cannot read receiving key ${kid}: ${err.message}`);
    }
    const privateKey = await crypto.subtle.importKey('jwk', stored.jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const { raw } = await parseRecipient(stored.public);
    return openSealedLinkKey(fragment, { privateKey, raw });
  }
  const local = (await readdir(keysDir()).catch(() => [])).filter((n) => n.endsWith('.json')).length;
  throw new Error(`this link is sealed to a receiving key that is not on this machine (sealed to ${kids.join(', ')}; ${local} key(s) in ${keysDir()}). Open it in the browser that holds the key.`);
}

/**
 * Agent-safe sending. Same encryption and wire format as `put`, with defaults
 * chosen so whoever runs it (typically an AI agent) never needs to see, type
 * or print the content, and the link it prints is useless to it:
 *   - sealed to a receiving key unless --unsealed; refuses to run without one
 *   - one read, one day, unless told otherwise
 *   - content only from a file path, stdin, an environment variable, or
 *     generated here; never from argv (--text, --password are refused)
 *   - https required for anything but this machine
 *   - prints the link (or --json) and nothing derived from the content
 */
async function send() {
  for (const banned of ['--text', '--password', '-p']) {
    if (args.includes(banned)) {
      throw new UsageError(`${banned} is not accepted by 'ef send': it puts a secret on the command line, where shell history, the process list and agent transcripts keep it. Pipe it on stdin, use --from-env, or --generate.`);
    }
  }
  const host = hostFrom(flag('--host', '-h'));
  const ttlGiven = args.includes('--ttl');
  const ttl = ttlGiven ? ttlFlag() : 86400;
  const limitGiven = args.includes('--limit');
  const limit = limitGiven ? limitFlag() : 1;
  const token = flag('--token') || process.env.EF_TOKEN || config().token || '';
  const name = flag('--name');
  const fromEnv = flag('--from-env');
  const generate = flag('--generate');
  const unsealed = has('--unsealed');
  const asJson = has('--json');
  const toGiven = flags('--to');
  const path = args.shift();
  if (args.length) throw new UsageError(`unexpected argument '${printable(args[0])}'`);

  const sources = [path !== undefined, fromEnv !== undefined, generate !== undefined].filter(Boolean).length;
  if (sources !== 1) {
    throw new UsageError(
      'usage: ef send <file | -> | --from-env VAR | --generate <bytes>\n' +
      '               [--to recipient]... [--name n] [--ttl s] [--limit n] [--json] [--unsealed]',
    );
  }
  if (!token) throw new Error('no upload token configured: the human runs `ef config set token - < token.txt` (or sets EF_TOKEN)');
  if (unsealed && toGiven.length) throw new UsageError('--unsealed and --to contradict each other');
  const to = unsealed ? [] : await recipientsFrom(toGiven, { fallback: true });
  if (!unsealed && !to.length) {
    throw new UsageError(
      `no receiving key configured. Ask the person to open ${host}/keys, create a receiving key and run\n` +
      '  ef recipient add <name> efpk1.…\n' +
      'where this runs. (--unsealed sends a plain link instead: anyone who sees it, including this transcript, can open it.)',
    );
  }
  checkTransport(host, 'upload token', true);
  await warnIfOpen();

  let blob;
  let fileName = name;
  let isNote = true;
  if (generate !== undefined) {
    const n = generate === '' ? NaN : Number(generate);
    if (!Number.isInteger(n) || n < 16 || n > 1024) throw new UsageError('--generate takes a number of random bytes from 16 to 1024');
    blob = new Blob([b64urlEncode(new Uint8Array(nodeRandomBytes(n)))]);
    fileName ||= 'generated-secret.txt';
  } else if (fromEnv !== undefined) {
    const value = process.env[fromEnv];
    if (value === undefined || value === '') throw new UsageError(`environment variable ${printable(fromEnv)} is not set or empty`);
    blob = new Blob([value]);
    fileName ||= `${fromEnv}.txt`;
  } else if (path === '-') {
    if (process.stdin.isTTY) throw new UsageError("'ef send -' reads the content from stdin; pipe it in");
    blob = new Blob([await readStdin()]);
    if (!blob.size) throw new UsageError('stdin was empty; nothing to send');
    fileName ||= 'secret.txt';
  } else {
    const st = await stat(path).catch(() => null);
    if (!st) throw new UsageError(`${printable(path)} does not exist`);
    if (st.isDirectory()) throw new UsageError(`${printable(path)} is a directory; archive it first (tar czf x.tgz dir) and send the archive`);
    blob = await openAsBlob(path);
    fileName ||= basename(path);
    isNote = false;
  }

  const file = { name: fileName, type: isNote ? NOTE_TYPE : '', size: blob.size, slice: (a, b) => blob.slice(a, b) };
  cancellable = true;
  const done = await uploadFile(file, { baseUrl: host, token, ttl, limit, password: null, auth: true, signal: interrupt.signal });
  const fragment = to.length ? await sealLinkKey(done.linkKey, to) : done.linkKey;
  const link = `${host}/f/${done.id}#${fragment}`;
  const summary = {
    link,
    id: done.id,
    sealed: to.length > 0,
    recipients: to.map((r) => ({ name: r.name, kid: r.kid })),
    kind: isNote ? 'text' : 'file',
    size: file.size,
    downloads: limit || 'unlimited',
    expires: new Date(done.expires).toISOString(),
    deleteToken: done.deleteToken,
  };
  if (asJson) {
    console.log(JSON.stringify(summary));
    return;
  }
  console.error(`${summary.sealed ? `sealed to ${to.map((r) => r.name).join(', ')}` : 'NOT sealed: anyone holding this link can open it'} · ${summary.kind}, ${file.size} bytes · downloads: ${summary.downloads} · expires ${summary.expires}`);
  console.error(`revoke early: ef rm ${host}/f/${done.id} --token ${done.deleteToken}`);
  console.log(link);
}

function parseLink(link) {
  let url;
  try {
    url = new URL(link);
  } catch {
    throw new UsageError("that is not a share link; expected 'https://host/f/<id>#<key>'");
  }
  const match = url.pathname.match(SHARE_PATH);
  if (!match) throw new UsageError("that is not a share link; expected 'https://host/f/<id>#<key>'");
  return { origin: url.origin, id: match[1], linkKey: url.hash.slice(1) };
}

const fetchMeta = (origin, id) =>
  withRetry(() => request(`${origin}/api/f/${id}`, { signal: interrupt.signal }), { signal: interrupt.signal, attempts: 4 });

async function openShare(meta, linkKey, pass) {
  try {
    return await openHeader(meta.header, linkKey, pass);
  } catch {
    // A tag failure here is indistinguishable from a wrong key by design, and
    // WebCrypto's own message says nothing useful about which one it was.
    throw new Error(
      meta.protected
        ? 'wrong password, or this link is not valid for this share'
        : pass
          ? 'this share has no password, or this link is not valid for it; try without --password/EF_PASSWORD'
          : 'this link is not valid for this share',
    );
  }
}

/** Spends one view: never retried, since a retry may cost a second one. */
async function download(url, headers) {
  let response;
  try {
    response = await fetch(url, { headers, signal: interrupt.signal });
  } catch (err) {
    if (interrupt.signal.aborted) throw interrupt.signal.reason;
    throw new Error(`download failed: ${err.message}`);
  }
  if (!response.ok) throw await refused(response);
  return response;
}

async function refused(response) {
  const data = await response.json().catch(() => ({}));
  return new Error(`download failed (${response.status}${data.error ? `: ${data.error}` : ''})`);
}

/** x-ef-auth for a link key: proves the key without revealing it. Workers
    that predate it ignore the header, as do shares uploaded without auth. */
async function authHeaders(linkKey) {
  const { authKey } = await deriveAuth(linkKey);
  return { 'x-ef-auth': authKey };
}

/** The Worker's x-resume-ticket, opaque except for a best-effort read of its
    expiry (in server time; `skew` = server - local) so a resume is never sent
    on one the Worker would count as a new download. */
function readTicket(response, previous, skew) {
  const value = response.headers.get('x-resume-ticket');
  if (!value) return previous;
  let until = Date.now() + TICKET_LIFE;
  try {
    const exp = JSON.parse(Buffer.from(value.split('.')[0], 'base64url').toString('utf8')).exp;
    if (Number.isFinite(exp)) until = Math.min(until, exp - skew - 30e3);
  } catch { /* opaque after all: the local estimate stands */ }
  return { value, until };
}

/** Passes `body` through, noting whether the network side broke or ended it,
    so a dropped connection is told apart from a bad tag or a failed write. */
function watched(body, seen) {
  const reader = body.getReader();
  return new ReadableStream({
    async pull(controller) {
      let step;
      try {
        step = await reader.read();
      } catch (err) {
        seen.broken = true;
        throw err;
      }
      if (step.done) { seen.ended = true; controller.close(); } else controller.enqueue(step.value);
    },
    cancel: (reason) => reader.cancel(reason).catch(() => {}),
  }, { highWaterMark: 0 });
}

const DROPPED = 'the connection dropped before the download finished; try again';

/**
 * Downloads and decrypts the body of `id`, handing each verified chunk to
 * `write` (awaited). The first request spends one view. If the connection
 * drops after that, the body is re-requested from the first chunk that has not
 * verified (Range + the ticket of the counted request, which the Worker serves
 * without counting again), up to RESUME_ATTEMPTS times in a row with backoff;
 * the sink just carries on. A limited share without a live ticket is not
 * retried, since that would spend another view; an unlimited one resumes with
 * Range alone, which costs nothing. A bad tag or a failed write is final.
 */
async function fetchBody(origin, id, opened, write, { key, meta, onProgress } = {}) {
  const url = `${origin}/api/d/${id}`;
  const auth = await authHeaders(key);
  const limited = meta?.remaining != null;
  const skew = Number.isFinite(meta?.now) ? meta.now - Date.now() : 0;
  let response = await download(url, auth);

  let ticket = readTicket(response, null, skew);
  const live = () => Boolean(ticket) && Date.now() < ticket.until;
  let verified = 0; // chunks decrypted and written
  let streak = 0;   // reconnects since the last newly verified chunk

  // A ticket only lasts minutes; a long limited download renews it with a
  // one-byte ticketed request (served uncounted) so a late drop can resume.
  // It asks for the byte where a resume would start: the Worker lets a ticket
  // chain that makes no progress through the file lapse.
  let renewing = false;
  const keepAlive = limited ? setInterval(async () => {
    if (renewing || !live()) return;
    renewing = true;
    try {
      const at = resumeOffset(verified, opened.chunkSize);
      const res = await fetch(url, {
        headers: { ...auth, range: `bytes=${at}-${at}`, 'x-resume-ticket': ticket.value }, signal: interrupt.signal,
      });
      await res.body?.cancel().catch(() => {});
      if (res.status === 206) ticket = readTicket(res, ticket, skew);
    } catch { /* the current ticket still stands */ } finally {
      renewing = false;
    }
  }, TICKET_REFRESH) : null;
  keepAlive?.unref();

  const reconnect = async () => {
    for (;;) {
      if (streak >= RESUME_ATTEMPTS || (limited && !live())) throw new Error(DROPPED);
      streak += 1;
      process.stderr.write(`\nconnection lost; resuming (attempt ${streak} of ${RESUME_ATTEMPTS})\n`);
      await delay(RESUME_BACKOFF * 2 ** (streak - 1) * (0.5 + Math.random() / 2), undefined, { signal: interrupt.signal });
      if (limited && !live()) throw new Error(DROPPED);
      const offset = resumeOffset(verified, opened.chunkSize);
      const headers = { ...auth, range: `bytes=${offset}-` };
      if (live()) headers['x-resume-ticket'] = ticket.value;
      let res;
      try {
        res = await fetch(url, { headers, signal: interrupt.signal });
      } catch {
        if (interrupt.signal.aborted) throw interrupt.signal.reason;
        continue;
      }
      // Only the exact continuation will do; a 200 is a Worker that ignored
      // the range, and its whole body would fail at the resume offset.
      if (res.status === 206 && (res.headers.get('content-range') || '').startsWith(`bytes ${offset}-`)) {
        ticket = readTicket(res, ticket, skew);
        return res;
      }
      if (res.status === 429 || res.status >= 500) {
        await res.body?.cancel().catch(() => {});
        continue;
      }
      if (res.ok) {
        await res.body?.cancel().catch(() => {});
        throw new Error('the connection dropped and this server cannot resume downloads; try again');
      }
      if (res.status === 404) throw new Error('the connection dropped and this share can no longer be resumed');
      throw await refused(res);
    }
  };

  try {
    for (;;) {
      const seen = {};
      const before = verified;
      try {
        await decryptStream(watched(response.body, seen), opened, async (chunk) => {
          await write(chunk);
          verified += 1;
        }, onProgress, verified ? { startChunk: verified } : undefined);
        return;
      } catch (err) {
        if (interrupt.signal.aborted) throw interrupt.signal.reason;
        const dropped = seen.broken || (seen.ended && err?.message === 'file is truncated');
        if (!dropped) throw err;
        if (verified === opened.chunks) return; // every chunk landed before the drop
        if (verified > before) streak = 0;
        response = await reconnect();
      }
    }
  } finally {
    clearInterval(keepAlive);
  }
}

/**
 * The sink, opened before the download is requested so an unwritable path
 * fails without spending a view. Regular files are written to a temp file in
 * the same directory and renamed into place only once every chunk verified,
 * so a failure never leaves a truncated file under the final name. Anything
 * else that already exists (/dev/null, a FIFO, a symlink) is written in place
 * as before, and never removed.
 */
async function openSink(target) {
  const existing = await lstat(target).catch(() => null);
  if (existing?.isDirectory()) throw new Error(`${printable(target)} is a directory`);
  if (existing && !existing.isFile()) {
    const handle = await open(target, 'w');
    return {
      write: (chunk) => handle.write(chunk),
      commit: () => handle.close(),
      discard: () => handle.close().catch(() => {}),
    };
  }
  const temp = join(dirname(target), `.${basename(target)}.${nodeRandomBytes(4).toString('hex')}.part`);
  const handle = await open(temp, 'wx');
  let live = true;
  const discard = async () => {
    if (!live) return;
    live = false;
    await handle.close().catch(() => {});
    await unlink(temp).catch(() => {});
  };
  return {
    temp,
    write: async (chunk) => { await handle.write(chunk); },
    async commit() {
      await handle.close();
      if (existing) await chmod(temp, existing.mode & 0o7777).catch(() => {});
      await rename(temp, target);
      live = false;
    },
    discard,
  };
}

/** Download + verify into a sink; the partial temp file goes on any failure or
    Ctrl-C, and a resumed download carries on writing into the same one. */
async function saveTo(target, origin, id, opened, { progress = true, key, meta } = {}) {
  const sink = await openSink(target);
  onInterrupt = () => { if (sink.temp) unlinkSyncQuiet(sink.temp); };
  try {
    await fetchBody(origin, id, opened, (chunk) => sink.write(chunk), {
      key,
      meta,
      onProgress: (done) => { if (progress) process.stderr.write(`\rdecrypted ${done}/${opened.size} bytes`); },
    });
    await sink.commit();
  } catch (err) {
    await sink.discard();
    throw err;
  } finally {
    onInterrupt = () => {};
  }
}

function unlinkSyncQuiet(path) {
  try { unlinkSync(path); } catch {}
}

/** Implicit target already there: a person at a terminal is asked to choose;
    a script keeps today's overwrite, with a warning it can log. */
async function guardImplicit(target, force) {
  if (force) return;
  const existing = await stat(target).catch(() => null);
  if (!existing) return;
  if (existing.isDirectory()) throw new Error(`${printable(target)} is a directory; pass -o <file>`);
  if (process.stderr.isTTY) {
    throw new Error(`${printable(target)} already exists; pass -o <file> to choose another name, or --force to overwrite it`);
  }
  console.error(`warning: overwriting existing ${printable(target)} (pass -o <file> to choose the name)`);
}

async function get() {
  const out = flag('--out', '-o');
  const passFlags = passwordFlags();
  const force = has('--force', '-f');
  const link = args.shift();
  if (!link) throw new UsageError("usage: ef get '<link>' [-o file|dir|-] [--force] [--password p | --password-stdin]");
  const pass = await password(passFlags);
  cancellable = true;

  const parsed = parseLink(link);
  const { origin, id } = parsed;
  let { linkKey } = parsed;
  if (!linkKey) throw new Error('link is missing its key (the part after #)');
  if (isSealed(linkKey)) linkKey = await unsealWithLocalKeys(linkKey);
  if (!LINK_KEY.test(linkKey)) throw new Error('the key after # is malformed; copy the whole link');

  const meta = await fetchMeta(origin, id);
  const opened = await openShare(meta, linkKey, pass);

  if (opened.type === BUNDLE_TYPE) return getBundle({ origin, id, linkKey, opened, out, force, pass, meta });

  // Text goes to stdout unless a file was asked for, so `ef get … > .env` and
  // `$(ef get …)` work; `-o -` forces it for a file share too.
  const toStdout = out === '-' || (opened.type === NOTE_TYPE && !out);
  if (toStdout) {
    const sink = Writable.toWeb(process.stdout).getWriter();
    await fetchBody(origin, id, opened, (chunk) => sink.write(chunk), { key: linkKey, meta });
    await sink.close();
    console.error('verified');
    return;
  }

  const target = out || safeName(opened.name) || id;
  if (!out) await guardImplicit(target, force);
  await saveTo(target, origin, id, opened, { key: linkKey, meta });
  process.stderr.write('\n');
  console.error(`verified and saved to ${printable(target)}`);
}

/** Same checks as the browser's parseManifest: the index is sender-written
    JSON, so nothing from it goes into a URL or a path unchecked. */
function parseManifest(bytes) {
  let manifest;
  try {
    manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new Error('the file list of this share is unreadable');
  }
  if (!manifest || manifest.v !== 1 || !Array.isArray(manifest.files) || !manifest.files.length) {
    throw new Error(manifest?.v !== 1 ? 'this share uses a newer file-list format; update ef' : 'the file list of this share is malformed');
  }
  return manifest.files.map((f) => {
    const ok = f && typeof f.id === 'string' && ID.test(f.id)
      && typeof f.key === 'string' && LINK_KEY.test(f.key)
      && typeof f.name === 'string'
      && Number.isSafeInteger(f.size) && f.size >= 0;
    if (!ok) throw new Error('the file list of this share is malformed');
    return { id: f.id, key: f.key, name: f.name, size: f.size };
  });
}

/** `name.ext` -> `name (2).ext`, skipping names taken on disk or earlier in this bundle. */
async function freeName(dir, name, taken, force) {
  const dot = name.lastIndexOf('.');
  const [stem, ext] = dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, ''];
  for (let n = 1; ; n++) {
    const candidate = n === 1 ? name : `${stem} (${n})${ext}`;
    if (taken.has(candidate)) continue;
    if (!force && (await lstat(join(dir, candidate)).catch(() => null))) continue;
    taken.add(candidate);
    return candidate;
  }
}

/**
 * A multi-file share: its index lists each member's own id and key. The index
 * stays in memory (it holds every member's key) and each member is fetched,
 * verified and saved on its own. Existing files are never overwritten unless
 * --force: the index view is already spent by then, so refusing would lose it.
 */
async function getBundle({ origin, id, linkKey, opened, out, force, pass, meta }) {
  if (out === '-') throw new UsageError('this link is a multi-file share; use -o <directory> instead of -o -');
  if (!Number.isSafeInteger(opened.size) || opened.size > MAX_INDEX) throw new Error('the file list of this share is too large');
  const dir = out || '.';
  // Before the index is spent: a bad -o costs nothing.
  const existing = await stat(dir).catch(() => null);
  if (existing && !existing.isDirectory()) throw new Error(`${printable(dir)} is not a directory; a multi-file share needs -o <directory>`);
  if (!existing) await mkdir(dir, { recursive: true });

  if (meta.remaining === 1) console.error('note: this is the last view of the file list; the link dies once it is read');
  const parts = [];
  await fetchBody(origin, id, opened, (chunk) => { parts.push(chunk); }, { key: linkKey, meta });
  const members = parseManifest(Buffer.concat(parts));

  console.error(`${members.length} files; fetching each one spends one of that file's own views`);
  const taken = new Set();
  let saved = 0;
  for (const [i, member] of members.entries()) {
    const label = `[${i + 1}/${members.length}] ${printable(member.name || member.id)}`;
    try {
      const name = await freeName(dir, safeName(member.name) || member.id, taken, force);
      const target = join(dir, name);
      const memberMeta = await fetchMeta(origin, member.id);
      const memberOpened = await openShare(memberMeta, member.key, pass);
      await saveTo(target, origin, member.id, memberOpened, { progress: false, key: member.key, meta: memberMeta });
      saved += 1;
      console.error(`${label}: verified and saved to ${printable(target)}`);
    } catch (err) {
      if (interrupt.signal.aborted) throw err;
      console.error(`${label}: failed: ${err.message}`);
    }
  }
  if (saved !== members.length) throw new Error(`${saved} of ${members.length} files saved`);
  console.error(`all ${members.length} files saved to ${printable(dir)}`);
}

async function rm() {
  const hostFlag = flag('--host', '-h');
  const token = flag('--token');
  const strict = strictHttps();
  const target = args.shift();
  if (!target || !token) throw new UsageError("usage: ef rm '<link>|<id>' --token <deleteToken> [--host url]");

  let origin;
  let id;
  if (ID.test(target)) {
    origin = hostFrom(hostFlag);
    id = target;
  } else {
    ({ origin, id } = parseLink(target));
  }
  checkTransport(origin, 'delete token', strict);
  cancellable = true;

  try {
    await withRetry(() => request(`${origin}/api/f/${id}`, {
      method: 'DELETE', headers: { 'x-delete-token': token }, signal: interrupt.signal,
    }), { signal: interrupt.signal, attempts: 4 });
  } catch (err) {
    // Gone is gone: deleting twice, or after expiry, is not a failure.
    if (err instanceof ApiError && err.status === 404) {
      console.error('not found: already deleted, expired or burned');
      return;
    }
    throw err;
  }
  console.error('deleted');
}

try {
  if (command === 'put') await put();
  else if (command === 'send') await send();
  else if (command === 'get') await get();
  else if (command === 'rm') await rm();
  else if (command === 'recipient') await recipientCmd();
  else if (command === 'keygen') await keygen();
  else if (command === 'config') await configCmd();
  else {
    console.error('usage: ef <put|send|get|rm|recipient|keygen|config> ...  (see the header of this file)');
    process.exit(2);
  }
} catch (err) {
  if (interrupt.signal.aborted) {
    console.error('\ncancelled');
    process.exit(130);
  }
  console.error(`error: ${err.message}`);
  process.exit(1);
}
