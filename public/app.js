import { CHUNK, TAG, NOTE_TYPE, BUNDLE_TYPE, openHeader, decryptStream, randomBytes, b64urlEncode, b64urlDecode } from './crypto.js';
// Newer exports (deriveAuth, resumeOffset) are read off the namespace: a stale
// cached crypto.js without them then costs those features, not the whole app.
import * as cryptoModule from './crypto.js';
import { uploadFile, deleteShare, request as api } from './upload.js';

const $ = (sel) => document.querySelector(sel);
const DEFAULT_NOTE_NAME = 'note.txt';
const MEMBER_ID = /^[A-Za-z0-9]{16,32}$/;  // what the Worker accepts as an id
const LINK_KEY = /^[A-Za-z0-9_-]{16,128}$/;
// Past this, the in-memory download fallback risks taking the tab down with it.
const LARGE_IN_MEMORY = 1 << 30;
const RESUME_ATTEMPTS = 5;        // reconnects in a row without a new verified chunk
const RESUME_BACKOFF = 1000;      // ms, doubled per attempt, with jitter
const TICKET_LIFE = 9 * 60e3;     // the Worker's resume tickets last 10 minutes
const TICKET_REFRESH = 4 * 60e3;  // renewed this often while a limited download streams
const TEMP_DIR = 'ephemeral-downloads'; // OPFS staging for browsers without a save picker
const TEMP_KEEP = 10 * 60e3;      // the browser is still copying out of it after the hand-off
const TEMP_SWEEP = 3600e3;        // leftovers older than this are removed at boot
const TEMP_STALE = TEMP_KEEP + 5 * 60e3; // a finished copy this long past its hand-off is removed at boot

/* A share of 2+ files is just a small JSON index - itself uploaded, encrypted
   and linked exactly like any other file - listing the id/key/name/size/type
   of each member (BUNDLE_TYPE). Pasted text is the same trick with one file
   and no index (NOTE_TYPE): both markers ride inside the encrypted header, so
   the Worker never learned a thing about either and a single file still
   uploads byte-for-byte as it always did. */

const state = {
  files: [], mode: 'files', limitTouched: false,
  aborter: null, opened: null, meta: null, password: null, note: null, noteBytes: null,
  config: null, shareId: null, linkKey: null, clockOffset: 0, busy: 0, expired: false,
};

/* Storage can be disabled, full or blocked outright (reading the property
   throws), and none of that may cost an upload or a link. */
function store(kind) {
  try { return window[kind] || null; } catch { return null; }
}
function readKey(kind, key) {
  try { return store(kind)?.getItem(key) ?? null; } catch { return null; }
}
function writeKey(kind, key, value) {
  try { store(kind).setItem(key, value); return true; } catch { return false; }
}
function removeKey(kind, key) {
  try { store(kind)?.removeItem(key); } catch { /* nothing to remove */ }
}

/* The upload token is a bearer credential: kept in sessionStorage by default,
   promoted to localStorage only if the owner asks to be remembered. Memory
   covers a browser that refuses both. */
let tokenInMemory = '';
const tokenStore = {
  get: () => tokenInMemory || readKey('sessionStorage', 'upload-token') || readKey('localStorage', 'upload-token') || '',
  remembered: () => Boolean(readKey('localStorage', 'upload-token')),
  set(token, remember) {
    tokenInMemory = token;
    writeKey(remember ? 'localStorage' : 'sessionStorage', 'upload-token', token);
  },
  clear() {
    tokenInMemory = '';
    removeKey('sessionStorage', 'upload-token');
    removeKey('localStorage', 'upload-token');
  },
};

/* --------------------------------------------------------------- format */

function bytes(n) {
  if (!Number.isFinite(n)) return '--';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

function countdown(ms) {
  if (ms <= 0) return 'expired';
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

/** Bidi isolation for sender-chosen names inside plain text, so a
    right-to-left override cannot visually disguise an extension. */
const isolate = (name) => `\u2068${name}\u2069`;

function bdi(text) {
  const el = document.createElement('bdi');
  el.textContent = text;
  return el;
}

function show(view) {
  for (const el of document.querySelectorAll('[data-view]')) {
    el.hidden = el.dataset.view !== view;
  }
}

function status(el, message, kind = '') {
  el.textContent = message;
  el.className = `status ${kind}`;
  el.setAttribute('role', kind === 'error' ? 'alert' : 'status');
}

/** Width through the CSSOM (allowed by style-src 'self'), value for assistive tech. */
function setProgress(bar, pct, text) {
  const value = Math.max(0, Math.min(100, pct));
  bar.style.width = `${value}%`;
  bar.parentElement.setAttribute('aria-valuenow', String(Math.round(value)));
  if (text !== undefined) bar.parentElement.nextElementSibling.textContent = text;
}

function contrastInk(hex) {
  const channels = hex.slice(1).match(/.{2}/g).map((part) => parseInt(part, 16) / 255);
  const [r, g, b] = channels.map((channel) => (
    channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
  ));
  const luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b;
  return (luminance + 0.05) / 0.05 > 1.05 / (luminance + 0.05) ? '#0d1117' : '#ffffff';
}

function applyBrand(brand) {
  if (!brand) return;

  $('#brand-name').textContent = brand.name;
  document.title = brand.name;
  $('meta[name="apple-mobile-web-app-title"]').content = brand.name;

  for (const [selector, text] of [['#brand-tagline', brand.tagline], ['#brand-footer', brand.footer]]) {
    const element = $(selector);
    element.textContent = text;
    element.hidden = !text;
  }

  const logo = $('#brand-logo');
  if (brand.logo) {
    logo.src = brand.logo;
    logo.hidden = false;
    logo.addEventListener('error', () => { logo.hidden = true; }, { once: true });
  }

  const root = document.documentElement.style;
  root.setProperty('--brand-accent-light', brand.accent);
  root.setProperty('--brand-accent-dark', brand.accentDark);
  root.setProperty('--brand-accent-ink-light', contrastInk(brand.accent));
  root.setProperty('--brand-accent-ink-dark', contrastInk(brand.accentDark));
}

async function loadConfig() {
  try {
    state.config = await api('/api/config');
    applyBrand(state.config.brand);
  } catch { /* the static defaults keep the offline shell usable */ }
}

/* --------------------------------------------------------------- upload */

const totalSize = (files) => files.reduce((n, f) => n + f.size, 0);

/** Mirrors the Worker's check on the ciphertext size; no config, no opinion. */
function tooBig(size) {
  const mb = state.config?.maxSizeMB;
  if (!Number.isFinite(mb)) return false;
  return size + Math.max(1, Math.ceil(size / CHUNK)) * TAG > mb * 1024 * 1024;
}
const limitText = () => bytes(state.config.maxSizeMB * 1024 * 1024);

function renderPicked() {
  const files = state.files;
  const list = $('#file-list');
  list.replaceChildren();
  list.hidden = files.length <= 1;

  if (files.length > 1) {
    files.forEach((file, index) => {
      const row = document.createElement('li');
      const name = document.createElement('span');
      name.className = 'file-list-name';
      name.append(bdi(file.name));
      const size = document.createElement('span');
      size.className = 'file-list-size';
      size.textContent = bytes(file.size);
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'link-button';
      remove.textContent = 'remove';
      remove.setAttribute('aria-label', `remove ${file.name}`);
      remove.addEventListener('click', () => { state.files.splice(index, 1); renderPicked(); });
      row.append(name, size, remove);
      list.append(row);
    });
  }

  const label = $('#drop-label');
  if (files.length === 0) {
    label.textContent = 'Drop one or more files, or click to choose';
    $('#drop-size').textContent = '';
    $('#drop').classList.remove('has-file');
  } else if (files.length === 1) {
    label.replaceChildren(bdi(files[0].name));
    $('#drop-size').textContent = bytes(files[0].size);
    $('#drop').classList.add('has-file');
  } else {
    label.textContent = `${files.length} files selected`;
    $('#drop-size').textContent = `${bytes(totalSize(files))} total`;
    $('#drop').classList.add('has-file');
  }

  syncSend();
}

/* ----------------------------------------------------------------- text */

/** The pasted text as a File, so it walks the exact same encrypt-and-upload
    path as anything dropped on the dropzone. NOTE_TYPE is what tells the
    recipient's browser to show it instead of saving it. */
function textFiles() {
  const body = $('#text').value;
  if (!body) return [];
  const name = $('#text-name').value.trim() || DEFAULT_NOTE_NAME;
  return [new File([body], name, { type: NOTE_TYPE })];
}

function syncSend() {
  $('#send').disabled = state.mode === 'text' ? !$('#text').value : state.files.length === 0;
}

const TABS = ['#mode-files', '#mode-text'];

function setMode(mode) {
  state.mode = mode;
  $('#files-pane').hidden = mode !== 'files';
  $('#text-pane').hidden = mode !== 'text';
  for (const [button, on] of [[$('#mode-files'), mode === 'files'], [$('#mode-text'), mode === 'text']]) {
    button.classList.toggle('is-on', on);
    button.setAttribute('aria-selected', String(on));
    button.tabIndex = on ? 0 : -1; // roving tabindex: one stop for the tablist, arrows inside it
  }
  // A pasted secret is usually meant for one pair of eyes, so text defaults to
  // burn-after-read - unless the owner has already picked a limit themselves.
  if (!state.limitTouched) $('#limit').value = mode === 'text' ? '1' : '0';
  syncSend();
}

function wireText() {
  $('#mode-files').addEventListener('click', () => setMode('files'));
  $('#mode-text').addEventListener('click', () => { setMode('text'); $('#text').focus(); });
  for (const selector of TABS) {
    $(selector).addEventListener('keydown', (e) => {
      const at = TABS.indexOf(selector);
      const to = { ArrowRight: at + 1, ArrowDown: at + 1, ArrowLeft: at - 1, ArrowUp: at - 1, Home: 0, End: TABS.length - 1 }[e.key];
      if (to === undefined) return;
      e.preventDefault();
      const target = $(TABS[(to + TABS.length) % TABS.length]);
      setMode(target.id === 'mode-text' ? 'text' : 'files');
      target.focus();
    });
  }
  $('#limit').addEventListener('change', () => { state.limitTouched = true; });
  // Encoding a multi-megabyte paste on every keystroke is wasted work; the
  // Send button still follows each keystroke.
  let sizeTimer = null;
  $('#text').addEventListener('input', () => {
    syncSend();
    clearTimeout(sizeTimer);
    sizeTimer = setTimeout(() => {
      const size = new Blob([$('#text').value]).size;
      $('#text-size').textContent = size ? bytes(size) : '';
    }, 150);
  });
}

/** Picking or dropping adds to the current selection (skipping exact repeats)
    rather than replacing it, so files can be gathered one drop at a time.
    Folders and files over the limit are turned away here, before anything
    is encrypted, rather than failing halfway through a bundle. */
function pickFiles(fileList, folders = 0) {
  const incoming = Array.from(fileList || []);
  const seen = new Set(state.files.map((f) => `${f.name}:${f.size}:${f.lastModified}`));
  const oversized = [];
  for (const file of incoming) {
    if (tooBig(file.size)) { oversized.push(file.name); continue; }
    const key = `${file.name}:${file.size}:${file.lastModified}`;
    if (seen.has(key)) continue;
    seen.add(key);
    state.files.push(file);
  }

  const problems = [];
  if (folders) problems.push(`${folders === 1 ? 'a folder was' : `${folders} folders were`} skipped - folders cannot be shared, zip them first`);
  if (oversized.length) {
    const which = oversized.length === 1 ? isolate(oversized[0]) : `${oversized.length} files`;
    problems.push(`${which} skipped - over the ${limitText()} limit per file`);
  }
  if (problems.length) status($('#upload-status'), problems.join('; '), 'error');
  else if (incoming.length) status($('#upload-status'), '');
  renderPicked();
}

function wireDropzone() {
  const drop = $('#drop');
  const input = $('#file');

  drop.addEventListener('click', () => input.click());
  drop.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });
  input.addEventListener('change', () => { pickFiles(input.files); input.value = ''; });

  for (const type of ['dragenter', 'dragover']) {
    drop.addEventListener(type, (e) => { e.preventDefault(); drop.classList.add('over'); });
  }
  for (const type of ['dragleave', 'drop']) {
    drop.addEventListener(type, (e) => { e.preventDefault(); drop.classList.remove('over'); });
  }
  drop.addEventListener('drop', (e) => {
    // A dropped folder shows up in `files` as a File that cannot be read; only
    // the entry API (valid during this event only) can tell it apart.
    const items = Array.from(e.dataTransfer.items || []).filter((item) => item.kind === 'file');
    if (!items.length || typeof items[0].webkitGetAsEntry !== 'function') {
      pickFiles(e.dataTransfer.files);
      return;
    }
    const files = [];
    let folders = 0;
    for (const item of items) {
      if (item.webkitGetAsEntry()?.isDirectory) { folders += 1; continue; }
      const file = item.getAsFile();
      if (file) files.push(file);
    }
    pickFiles(files, folders);
  });
}

/** Link for the page the owner is on, not for whatever Host the Worker saw. */
const shareLink = (result) => `${location.origin}/f/${result.id}#${result.linkKey}`;

const cancelled = (signal) => signal.reason ?? new DOMException('cancelled', 'AbortError');

/** Uploads every member, then the index. If anything fails or is cancelled,
    the members already live are deleted with their own tokens; any that
    cannot be are kept in the recent list so the owner can still revoke them. */
async function uploadBundle(files, { ttl, limit, password, signal, onProgress, onBeforeComplete }) {
  const token = tokenStore.get();
  // One salt for the whole bundle, so with a password the PBKDF2 stretch runs
  // once per side instead of once per file. Each member still gets its own
  // link key. Without a password there is nothing to save, and distinct
  // salts keep the members' headers from visibly matching one another.
  const salt = password ? randomBytes(16) : undefined;
  const started = Date.now(); // before the first init, so elapsed is never underestimated
  const totalPlain = totalSize(files) || 1;
  const members = [];
  const uploaded = [];
  let plainDoneBefore = 0;

  try {
    for (const file of files) {
      if (signal.aborted) throw cancelled(signal);
      const result = await uploadFile(file, {
        token, ttl, limit, password, salt, signal,
        onProgress: (sent, total) => {
          const thisPlain = Math.min(file.size, (sent / total) * file.size);
          onProgress(plainDoneBefore + thisPlain, totalPlain, `file ${members.length + 1}/${files.length}`);
        },
      });
      uploaded.push({ id: result.id, token: result.deleteToken, expires: result.expires });
      plainDoneBefore += file.size;
      members.push({ id: result.id, key: result.linkKey, name: file.name, size: file.size, type: file.type || '' });
    }
    if (signal.aborted) throw cancelled(signal);

    // The index is shared with recipients, so it carries only what opens each
    // member file - never the delete tokens, which stay owner-side.
    const manifestBody = JSON.stringify({ v: 1, files: members });
    const manifestFile = new File([manifestBody], `${files.length} files`, { type: BUNDLE_TYPE });
    // The first member's clock started earliest; the index must not outlive it
    // and point at a dead file. Re-read on each init retry. If too little of
    // the expiry is left, fail (the catch below removes the members) rather
    // than hand out a link that is already dying.
    const indexTtl = () => {
      const left = ttl - Math.ceil((Date.now() - started) / 1000) - 2;
      if (left < 60) throw new Error('the upload took longer than the chosen expiry - choose a longer one');
      return left;
    };
    indexTtl();
    const manifest = await uploadFile(manifestFile, {
      token, ttl: indexTtl, limit, password, salt, signal, onBeforeComplete,
    });
    return { manifest, memberTokens: uploaded.map(({ id, token: t }) => ({ id, token: t })) };
  } catch (err) {
    if (uploaded.length) {
      status($('#upload-status'), `removing the ${uploaded.length} file(s) already uploaded...`);
      const results = await Promise.allSettled(uploaded.map((m) => deleteShare('', m.id, m.token)));
      const left = uploaded.filter((_, i) => results[i].status === 'rejected');
      if (left.length) {
        remember({
          id: left[0].id,
          name: `unfinished upload (${left.length} file${left.length === 1 ? '' : 's'})`,
          expires: Math.max(...left.map((m) => m.expires)),
          token: left[0].token,
          members: left.slice(1).map(({ id, token: t }) => ({ id, token: t })),
        });
        renderRecent();
        const why = signal.aborted ? 'cancelled' : err.message || 'upload failed';
        throw Object.assign(new Error(`${why} - ${left.length} uploaded file(s) could not be removed; delete them from your recent links`), { leftover: true });
      }
    }
    throw err;
  }
}

async function upload() {
  if (state.aborter) return;
  const isNote = state.mode === 'text';
  // A snapshot: the list on screen must not change under the loop.
  const files = isNote ? textFiles() : [...state.files];
  if (!files.length) return;
  const oversized = files.find((f) => tooBig(f.size));
  if (oversized) {
    status($('#upload-status'), `${isolate(oversized.name)} is over the ${limitText()} limit per file`, 'error');
    return;
  }

  const ttl = Number($('#ttl').value);
  const limit = Number($('#limit').value);
  // NFC on top of the long-standing trim: what the recipient types is NFC on
  // every mainstream platform, and older readers still match it.
  const password = $('#password').value.trim().normalize('NFC') || null;

  const bar = $('#progress-bar');
  const controller = new AbortController();
  const signal = controller.signal;
  state.aborter = controller;
  $('#compose').inert = true;
  $('#send').hidden = true;
  $('#cancel').hidden = false;
  $('#cancel').disabled = false;
  $('#progress').hidden = false;
  setProgress(bar, 0, '0%');
  status($('#upload-status'), password ? 'deriving key, then encrypting and uploading...' : 'encrypting and uploading...');

  const started = Date.now();
  const onProgress = (done, total, suffix = '') => {
    const pct = Math.min(100, (done / total) * 100);
    const rate = done / Math.max((Date.now() - started) / 1000, 0.001);
    setProgress(bar, pct, `${Math.round(pct)}% · ${bytes(rate)}/s${suffix ? ` · ${suffix}` : ''}`);
  };
  // Past this point the share is being created; cancelling the completion
  // call could leave it live with its delete token never received.
  const onBeforeComplete = () => {
    $('#cancel').disabled = true;
    status($('#upload-status'), 'finishing...');
  };

  try {
    if (files.length === 1) {
      const file = files[0];
      const result = await uploadFile(file, {
        token: tokenStore.get(), ttl, limit, password, signal, onProgress, onBeforeComplete,
      });
      // The link first: it is the one thing that cannot be recovered later.
      showResult(shareLink(result), result.expires, password, 1, isNote);
      const kept = remember({ id: result.id, name: file.name, expires: result.expires, token: result.deleteToken });
      if (!kept) noteNotRemembered();
    } else {
      const { manifest, memberTokens } = await uploadBundle(files, {
        ttl, limit, password, signal, onProgress, onBeforeComplete,
      });
      showResult(shareLink(manifest), manifest.expires, password, files.length);
      const kept = remember({
        id: manifest.id,
        name: `${files.length} files`,
        expires: manifest.expires,
        token: manifest.deleteToken,
        members: memberTokens,
      });
      if (!kept) noteNotRemembered();
    }
  } catch (err) {
    if (signal.aborted && !err.leftover) status($('#upload-status'), 'cancelled');
    else status($('#upload-status'), err.message || 'upload failed', 'error');
    $('#progress').hidden = true;
    $('#send').hidden = false;
  } finally {
    $('#cancel').hidden = true;
    $('#compose').inert = false;
    state.aborter = null;
  }
}

function cancelUpload() {
  if (!state.aborter || $('#cancel').disabled) return;
  state.aborter.abort();
  $('#cancel').disabled = true;
  status($('#upload-status'), 'cancelling...');
}

function showResult(link, expires, password, count = 1, isNote = false) {
  show('result');
  $('#link').value = link;
  $('#result-password').hidden = !password;
  if (password) $('#password-out').value = password;
  const what = isNote ? 'this text' : count > 1 ? `these ${count} files` : 'the file';
  $('#result-note').textContent = password
    ? `Expires in ${countdown(expires - Date.now())}. Send the password over a different channel than the link.`
    : `Expires in ${countdown(expires - Date.now())}. Anyone with this link can open ${what}.`;
  $('#link').focus();
  $('#link').select();
}

function noteNotRemembered() {
  $('#result-note').textContent +=
    ' This browser would not save it to your recent links, so it cannot be deleted early from here.';
}

/* ------------------------------------------------- local record of links */

const readRecent = () => {
  try {
    const list = JSON.parse(readKey('localStorage', 'recent') || '[]');
    return Array.isArray(list) ? list : [];
  } catch { return []; }
};
const writeRecent = (list) => writeKey('localStorage', 'recent', JSON.stringify(list));

/** Only what is needed to revoke later - never the key, which stays in the link.
    Unexpired entries are never dropped: each holds the only delete token. */
function remember(entry) {
  const recent = readRecent().filter((e) => e.id !== entry.id && e.expires > Date.now());
  recent.unshift(entry);
  return writeRecent(recent);
}

function renderRecent() {
  const list = $('#recent');
  const all = readRecent();
  const items = all.filter((e) => e.expires > Date.now());
  if (items.length !== all.length) writeRecent(items);
  list.replaceChildren();
  $('#recent-wrap').hidden = items.length === 0;

  for (const item of items) {
    const row = document.createElement('li');
    const name = document.createElement('span');
    name.className = 'recent-name';
    name.append(bdi(item.name));
    const left = document.createElement('span');
    left.className = 'recent-time';
    left.textContent = countdown(item.expires - Date.now());
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'link-button';
    const label = (text) => {
      button.textContent = text;
      button.setAttribute('aria-label', `${text} ${item.name}`);
    };
    label('delete');
    // Revoking is irreversible, so it takes a second click to confirm.
    let armed = null;
    button.addEventListener('click', async () => {
      if (!armed) {
        label('confirm delete');
        armed = setTimeout(() => { armed = null; label('delete'); }, 4000);
        return;
      }
      clearTimeout(armed);
      armed = null;
      button.disabled = true;
      label('deleting...');
      // Bundles carry their member files' own delete tokens alongside the
      // index's; older single-file entries have no `members` and just skip this.
      const targets = [{ id: item.id, token: item.token }, ...(item.members || [])];
      const results = await Promise.allSettled(targets.map(({ id, token }) => deleteShare('', id, token)));
      const failed = results.find((r) => r.status === 'rejected');
      if (failed) {
        // The entry (and so every token) stays; a retry treats the ones that
        // did go through as already gone.
        status($('#upload-status'), `could not delete ${isolate(item.name)}: ${failed.reason?.message || 'request failed'} - try again`, 'error');
        button.disabled = false;
        label('delete');
        return;
      }
      writeRecent(readRecent().filter((e) => e.id !== item.id));
      renderRecent();
    });
    row.append(name, left, button);
    list.append(row);
  }
}

/* ------------------------------------------------------------- download */

/* A Blob URL lives on this origin. If a browser ignores `download` and
   navigates to it, only types that cannot carry markup or script are safe to
   label as themselves; everything else is opaque bytes, like the Worker
   serves it. The filename still tells the OS what the file is. */
const INERT_TYPE = /^(image\/(png|jpeg|gif|webp|avif)|video\/[a-z0-9.+-]+|audio\/[a-z0-9.+-]+|application\/pdf|text\/plain(;\s*charset=utf-8)?)$/i;
const blobType = (type) => (INERT_TYPE.test(String(type || '').trim()) ? type.trim() : 'application/octet-stream');

function fileSink(writable, onAbort) {
  return {
    write: (chunk) => writable.write(chunk),
    close: () => writable.close(),
    abort: async () => {
      await writable.abort().catch(() => {});
      await onAbort?.();
    },
  };
}

/** Gives a finished Blob to the browser's own downloader under `name`. */
function handOver(blob, name, keep, cleanup) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); cleanup?.(); }, keep);
}

function memorySink(name, type, size, why = 'This browser cannot stream to disk') {
  if (size > LARGE_IN_MEMORY) {
    const last = state.meta?.remaining === 1 ? ' This link has no downloads left after this one.' : '';
    const ok = window.confirm(
      `${why}, so all ${bytes(size)} will be held in memory until it is saved, which can crash the tab.${last} Continue?`,
    );
    if (!ok) throw new DOMException('cancelled', 'AbortError');
  }
  const parts = [];
  return {
    write: (chunk) => { parts.push(chunk); },
    close: () => {
      const blob = new Blob(parts, { type: blobType(type) });
      parts.length = 0;
      handOver(blob, name, 60000);
    },
    abort: () => { parts.length = 0; },
  };
}

/* Without a save picker, the origin private file system (OPFS) still lets
   the decrypted file go to disk instead of memory: it is written to a temp
   entry, then handed over as a disk-backed File through the same <a download>
   as the memory path. Entries are named <base36 ms>-<random> so the boot
   sweep can tell an abandoned one from a download still in flight. */
const diskStaging = () => typeof navigator.storage?.getDirectory === 'function'
  && typeof window.FileSystemFileHandle === 'function'
  && typeof window.FileSystemFileHandle.prototype.createWritable === 'function';

const tempDir = async (create) => (await navigator.storage.getDirectory()).getDirectoryHandle(TEMP_DIR, { create });

// Partial plaintext of downloads still being written. A page that is going
// away for good drops them (best effort: the removal may not finish), so a
// closed tab does not leave them for the next visit's sweep.
const stagingNow = new Set();
window.addEventListener('pagehide', (event) => {
  if (event.persisted) return; // kept in the back/forward cache: may still finish
  for (const abort of stagingNow) abort();
});
const isQuota = (err) => err?.name === 'QuotaExceededError';
const OUT_OF_STORAGE = 'The browser ran out of storage for this download';

/** { sink } on disk, or { why } to say why the memory path is taken instead. */
async function stagedSink(name, type, size) {
  if (!diskStaging()) return {};
  try {
    const estimate = await navigator.storage.estimate?.().catch(() => null);
    if (Number.isFinite(estimate?.quota) && Number.isFinite(estimate?.usage)
      && estimate.quota - estimate.usage < size + (16 << 20)) {
      return { why: 'There is not enough free browser storage to stage this file on disk' };
    }
    const dir = await tempDir(true);
    const entry = `${Date.now().toString(36)}-${b64urlEncode(randomBytes(9))}`;
    const handle = await dir.getFileHandle(entry, { create: true });
    let writable;
    try {
      writable = await handle.createWritable();
    } catch (err) {
      await dir.removeEntry(entry).catch(() => {});
      throw err;
    }
    let removed = false;
    const remove = () => {
      if (removed) return undefined;
      removed = true;
      return dir.removeEntry(entry).catch(() => {});
    };
    const abort = async () => {
      stagingNow.delete(abort);
      await writable.abort().catch(() => {});
      await remove();
    };
    stagingNow.add(abort);
    return {
      sink: {
        write: (chunk) => writable.write(chunk),
        close: async () => {
          stagingNow.delete(abort);
          await writable.close();
          // A slice keeps the File disk-backed while relabelling it with an
          // allowlisted type; the entry outlives the copy the browser makes.
          const file = await handle.getFile();
          handOver(file.slice(0, file.size, blobType(type)), name, TEMP_KEEP, remove);
        },
        abort,
        // Storage filled up mid-download: drop the partial copy and carry on
        // in memory (fetchAndDecrypt restarts the body under its ticket).
        fallback: async () => {
          await abort();
          return memorySink(name, type, size, OUT_OF_STORAGE);
        },
      },
    };
  } catch (err) {
    return isQuota(err) ? { why: OUT_OF_STORAGE } : {};
  }
}

/** Temp entries a closed tab never got to remove. Aged by last write, not
    by creation: a finished file is written at its hand-off, so another tab
    never removes one the browser may still be copying (TEMP_KEEP), but does
    remove it soon after (TEMP_STALE). An entry with nothing in it yet is
    still being written or was abandoned mid-way: it gets TEMP_SWEEP, and a
    download still writing it holds a lock that makes removal fail anyway. */
async function sweepStaged() {
  if (!diskStaging()) return;
  try {
    const dir = await tempDir(false);
    const stale = [];
    for await (const [entry, handle] of dir.entries()) {
      let at = parseInt(entry.split('-')[0], 36);
      let size = 0;
      if (handle.kind === 'file') {
        try {
          const file = await handle.getFile();
          at = Math.max(at || 0, file.lastModified);
          size = file.size;
        } catch { /* unreadable: fall back to the name's timestamp */ }
      }
      const age = Date.now() - at;
      if (!(age < (size > 0 ? TEMP_STALE : TEMP_SWEEP))) stale.push(entry);
    }
    await Promise.all(stale.map((entry) => dir.removeEntry(entry, { recursive: true }).catch(() => {})));
  } catch { /* nothing staged yet, or no OPFS in this context */ }
}

async function save(name, type, size) {
  // Stream straight to disk where the browser allows it: a picked file, else
  // a staged OPFS file; only then assemble it in memory (warning first when
  // that is risky).
  if (window.showSaveFilePicker) {
    try {
      const handle = await window.showSaveFilePicker({ suggestedName: name });
      return fileSink(await handle.createWritable());
    } catch (err) {
      if (err.name === 'AbortError') throw err;
    }
  }
  const staged = await stagedSink(name, type, size);
  return staged.sink ?? memorySink(name, type, size, staged.why);
}

/** A name the File System Access API will accept, never one that exists. */
function safeName(name) {
  const cleaned = String(name).replace(/[\\/\u0000-\u001f]/g, '_').trim();
  return !cleaned || cleaned === '.' || cleaned === '..' ? 'file' : cleaned;
}
function numbered(name, n) {
  const dot = name.lastIndexOf('.');
  return dot > 0 ? `${name.slice(0, dot)} (${n})${name.slice(dot)}` : `${name} (${n})`;
}

async function directorySink(dir, name, used) {
  const base = safeName(name);
  for (let n = 1; n <= 1000; n += 1) {
    const candidate = n === 1 ? base : numbered(base, n);
    if (used.has(candidate)) continue;
    // Never overwrite something already in the folder the user picked. Only
    // "no such entry" frees a name and a folder of that name takes it; any
    // other error (permission gone, name refused) is not about this name.
    const exists = await dir.getFileHandle(candidate).then(() => true, (err) => {
      if (err.name === 'NotFoundError') return false;
      if (err.name === 'TypeMismatchError') return true;
      throw err;
    });
    if (exists) continue;
    used.add(candidate);
    const handle = await dir.getFileHandle(candidate, { create: true });
    return fileSink(await handle.createWritable(), () => dir.removeEntry(candidate).catch(() => {}));
  }
  throw new Error('too many files with this name in the chosen folder');
}

class FetchError extends Error {}

/* Downloads prove the link key with x-ef-auth (a separate HKDF output of the
   key, never the key itself). Derived once per key; with a crypto.js too old
   to derive it no header is sent, which the Worker allows unless its owner
   enforces it, and then answers 401. */
const authCache = new Map();
function authHeaders(linkKey) {
  if (!linkKey || typeof cryptoModule.deriveAuth !== 'function') return Promise.resolve({});
  if (!authCache.has(linkKey)) {
    authCache.set(linkKey, cryptoModule.deriveAuth(linkKey).then(({ authKey }) => ({ 'x-ef-auth': authKey }), () => ({})));
  }
  return authCache.get(linkKey);
}

function refusal(status) {
  if (status === 401) return 'this link needs an up-to-date page - reload the page and try again (nothing was used up)';
  if (status === 403) return 'this link is not valid for this file';
  if (status === 429) return 'too many requests - wait a moment and try again';
  return 'this link has expired';
}

const DROPPED = 'the connection dropped before the download finished - try again';

/** The Worker's x-resume-ticket, opaque except for a best-effort read of its
    expiry so a resume is never sent on one that would be counted afresh. */
function readTicket(response, previous) {
  const value = response.headers.get('x-resume-ticket');
  if (!value) return previous;
  let until = Date.now() + TICKET_LIFE;
  try {
    const exp = JSON.parse(new TextDecoder().decode(b64urlDecode(value.split('.')[0]))).exp;
    if (Number.isFinite(exp)) until = Math.min(until, exp - state.clockOffset - 30e3);
  } catch { /* opaque after all: the local estimate stands */ }
  return { value, until };
}

/** Passes `body` through, noting whether the network side broke or ended it,
    so a dropped connection is told apart from a bad tag or a full disk. */
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

const pause = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

/** Fetches the ciphertext body for `id` and decrypts it against `opened`
    (from openHeader), reporting progress as it goes. Shared by the single-file
    download and by each member of a bundle. `key` is the link key the auth
    header is derived from; `limited` says whether a fresh request would spend
    a download.

    If the connection drops, the body is re-requested from the first chunk
    that has not verified yet (Range + the x-resume-ticket of the counted
    request, which the Worker serves without counting again), a few times
    with backoff; progress and the sink carry on where they were. Without a
    usable ticket a limited share is not retried, since that would spend
    another download. */
async function fetchAndDecrypt(id, opened, sink, onProgress, { key = state.linkKey, limited = true } = {}) {
  const url = `/api/d/${id}`;
  const auth = await authHeaders(key);
  let response;
  try {
    response = await fetch(url, { headers: auth });
  } catch {
    await sink.abort?.();
    throw new FetchError('cannot reach the server - check your connection and try again');
  }
  if (!response.ok) {
    await sink.abort?.();
    throw new FetchError(refusal(response.status));
  }
  forgetKeyIfSpent(id);

  const resumable = typeof cryptoModule.resumeOffset === 'function';
  const started = Date.now();
  let ticket = readTicket(response, null);
  const ticketLive = () => Boolean(ticket) && Date.now() < ticket.until;
  let verified = 0; // chunks decrypted and accepted by the sink
  let streak = 0;   // reconnects since the last newly verified chunk
  const statusEl = $('#file-status');

  // A ticket only lasts minutes; a long limited download renews it with a
  // one-byte ticketed request (served uncounted) so a late drop can resume.
  // It asks for the byte where a resume would start: the Worker lets a ticket
  // chain that makes no progress through the file lapse.
  let renewing = false;
  const keepAlive = resumable && limited ? setInterval(async () => {
    if (renewing || !ticketLive()) return;
    renewing = true;
    try {
      const at = cryptoModule.resumeOffset(verified, opened.chunkSize);
      const res = await fetch(url, { headers: { ...auth, range: `bytes=${at}-${at}`, 'x-resume-ticket': ticket.value } });
      res.body?.cancel().catch(() => {});
      if (res.status === 206) ticket = readTicket(res, ticket);
    } catch { /* the current ticket still stands */ } finally {
      renewing = false;
    }
  }, TICKET_REFRESH) : null;

  const reconnect = async () => {
    const before = { text: statusEl.textContent, kind: statusEl.classList.contains('ok') ? 'ok' : '' };
    for (;;) {
      if (streak >= RESUME_ATTEMPTS) throw new FetchError(DROPPED);
      if (limited && !ticketLive()) throw new FetchError(DROPPED);
      streak += 1;
      status(statusEl, `connection lost - resuming (attempt ${streak} of ${RESUME_ATTEMPTS})...`);
      await pause(RESUME_BACKOFF * 2 ** (streak - 1) * (0.5 + Math.random() / 2));
      if (limited && !ticketLive()) throw new FetchError(DROPPED);
      const offset = cryptoModule.resumeOffset(verified, opened.chunkSize);
      const headers = { ...auth, range: `bytes=${offset}-` };
      if (ticketLive()) headers['x-resume-ticket'] = ticket.value;
      let res;
      try {
        res = await fetch(url, { headers });
      } catch {
        continue;
      }
      // Only the exact continuation will do; a 200 is a Worker that ignored
      // the range, and its whole body would fail at the resume offset.
      if (res.status === 206 && (res.headers.get('content-range') || '').startsWith(`bytes ${offset}-`)) {
        ticket = readTicket(res, ticket);
        status(statusEl, before.text, before.kind);
        return res;
      }
      res.body?.cancel().catch(() => {});
      if (res.status === 429 || res.status >= 500) continue;
      throw new FetchError(res.status === 404 ? 'the connection dropped and this file can no longer be resumed' : refusal(res.status));
    }
  };

  try {
    for (;;) {
      const seen = {};
      const before = verified;
      let sinkError = null;
      try {
        await decryptStream(watched(response.body, seen), opened, async (chunk) => {
          try {
            await sink.write(chunk);
          } catch (err) {
            sinkError = err;
            throw err;
          }
          verified += 1;
        }, (done) => onProgress?.(done, opened.size, started), verified ? { startChunk: verified } : undefined);
        await sink.close();
        return;
      } catch (err) {
        if (sinkError && isQuota(sinkError) && sink.fallback && resumable && (!limited || ticketLive())) {
          // The staged copy hit the storage quota: start over in memory, under
          // the same ticket, so this costs no second download.
          sink = await sink.fallback();
          verified = 0;
          streak = 0;
          status(statusEl, 'browser storage is full - downloading again into memory...');
          response = await reconnect();
          continue;
        }
        if (sinkError && isQuota(sinkError)) throw new Error(`${OUT_OF_STORAGE.toLowerCase()} - free some disk space and try again`);
        const dropped = seen.broken || (seen.ended && err?.message === 'file is truncated');
        if (!dropped || !resumable) throw err;
        if (verified === opened.chunks) { // every chunk landed before the drop
          await sink.close();
          return;
        }
        if (verified > before) streak = 0;
        response = await reconnect();
      }
    }
  } catch (err) {
    await sink.abort?.();
    throw err;
  } finally {
    clearInterval(keepAlive);
  }
}

/** The share in the address bar: its key for x-ef-auth, and whether a
    fresh request for it is counted. */
const shareOptions = () => ({ key: state.linkKey, limited: state.meta?.remaining !== null });

/** Once the last read of this share has been handed out the key is useless,
    so it need not sit in the address bar any longer. Live links keep it:
    reloading or forwarding them must still work. */
function forgetKeyIfSpent(id) {
  if (id === state.shareId && state.meta?.remaining === 1 && location.hash) {
    history.replaceState(null, '', location.pathname);
  }
}

const memoryCollector = (parts) => ({ write: (chunk) => { parts.push(chunk); }, close: () => {} });
const joined = async (parts) => new Uint8Array(await new Blob(parts).arrayBuffer());

/** Exact bytes first, then the forms a paste or another OS commonly produces.
    Existing shares were made with the exact value, so it is always tried first. */
function passwordCandidates(raw) {
  if (!raw) return [null];
  return [...new Set([raw, raw.trim(), raw.normalize('NFC'), raw.trim().normalize('NFC')])].filter(Boolean);
}

async function unlock(id, linkKey) {
  if ($('#unlock').disabled) return;
  const candidates = passwordCandidates($('#unlock-password').value);
  $('#unlock').disabled = true;
  status($('#file-status'), candidates[0] ? 'deriving key...' : 'decrypting...');
  let opened = null;
  for (const password of candidates) {
    try {
      opened = await openHeader(state.meta.header, linkKey, password);
      state.password = password; // reused to open each member header if this turns out to be a bundle
      break;
    } catch { /* next candidate */ }
  }
  $('#unlock').disabled = false;
  if (state.expired) return;
  if (!opened) {
    status($('#file-status'), state.meta.protected ? 'wrong password' : 'this link is not valid for this file', 'error');
    return;
  }
  state.opened = opened;
  status($('#file-status'), '');
  $('#unlock-row').hidden = true;

  if (opened.type === BUNDLE_TYPE && state.meta.remaining === null) {
    // Unlimited: looking at the list costs nothing, so show it straight away.
    // If that fetch fails, fall through to the "Show files" button to retry.
    if (await showBundle(id)) return;
    if (state.expired) return;
  }

  if (opened.type === BUNDLE_TYPE) {
    $('#file-name').textContent = 'several files';
    $('#file-size').textContent = '\u2014';
  } else {
    $('#file-name').replaceChildren(bdi(opened.name));
    $('#file-size').textContent = bytes(opened.size);
  }
  // Text and limited file lists are still fetched on a click, never on page
  // load: a link preview or a scanner opening the page must not spend a view.
  if (opened.type === NOTE_TYPE) $('#get').textContent = 'Reveal text';
  if (opened.type === BUNDLE_TYPE) $('#get').textContent = 'Show files';
  if (state.meta.remaining === 1) {
    $('#burn-note').textContent = {
      [NOTE_TYPE]: 'This is the only read left. Copy what you need before you close the page - the link dies the moment you reveal it.',
      [BUNDLE_TYPE]: 'The file list can be opened only once. Download what you need before you close the page - the link dies the moment the list is shown.',
    }[opened.type] ?? 'This is the only download left. The link dies as soon as it starts.';
    $('#burn-note').hidden = false;
  }
  $('#get').hidden = false;
  $('#get').focus();
}

/** Decrypts a text share into the page rather than onto the disk. It is small
    by construction, so it is assembled in memory and never touches a sink.
    The verified bytes are kept: saving writes exactly what was shared. */
async function reveal(id) {
  $('#get').disabled = true;
  state.busy += 1;
  status($('#file-status'), 'downloading and decrypting...');
  try {
    const parts = [];
    await fetchAndDecrypt(id, state.opened, memoryCollector(parts), undefined, shareOptions());
    state.noteBytes = await joined(parts);
    let text = null;
    try {
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(state.noteBytes);
    } catch { /* not UTF-8: offered as a file instead */ }
    state.note = text;
    $('#note-text').textContent = text ?? '';
    $('#note-text').hidden = text === null;
    $('#note-copy').hidden = text === null;
    $('#note-wrap').hidden = false;
    $('#get').hidden = true;
    $('#burn-note').hidden = true;
    if (text === null) status($('#file-status'), 'decrypted and verified, but this share is not text - save it as a file', 'ok');
    else status($('#file-status'), 'decrypted and verified', 'ok');
  } catch (err) {
    status($('#file-status'), err.message || 'this link has expired', 'error');
    $('#get').disabled = false;
  } finally {
    state.busy -= 1;
    afterBusy();
  }
}

async function saveNote() {
  if (!state.noteBytes) return;
  try {
    const type = state.note === null ? 'application/octet-stream' : 'text/plain;charset=utf-8';
    const sink = await save(state.opened.name, type, state.noteBytes.length);
    await sink.write(state.noteBytes);
    await sink.close();
  } catch (err) {
    if (err.name !== 'AbortError') status($('#file-status'), err.message || 'could not save', 'error');
  }
}

/** The index is sender-written JSON: check its shape before a single id is
    put into a URL. `type` may be '' in every index ever written. */
function parseManifest(raw) {
  const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  if (!manifest || manifest.v !== 1 || !Array.isArray(manifest.files) || !manifest.files.length) {
    throw new Error('bad manifest');
  }
  return manifest.files.map((f) => {
    const ok = f && typeof f.id === 'string' && MEMBER_ID.test(f.id)
      && typeof f.key === 'string' && LINK_KEY.test(f.key)
      && typeof f.name === 'string'
      && Number.isSafeInteger(f.size) && f.size >= 0
      && (f.type === undefined || f.type === null || typeof f.type === 'string');
    if (!ok) throw new Error('bad manifest');
    return { id: f.id, key: f.key, name: f.name, size: f.size, type: f.type || '' };
  });
}

async function showBundle(id) {
  state.busy += 1;
  status($('#file-status'), 'loading file list...');
  let members;
  try {
    const parts = [];
    await fetchAndDecrypt(id, state.opened, memoryCollector(parts), undefined, shareOptions());
    members = parseManifest(await joined(parts));
  } catch (err) {
    status($('#file-status'), err instanceof FetchError ? err.message : 'this bundle is corrupt or truncated', 'error');
    state.busy -= 1;
    afterBusy();
    return false;
  }
  state.busy -= 1; // the list is rendered before an expiry that waited on it clears it
  status($('#file-status'), '');
  $('#file-name').textContent = `${members.length} files`;
  $('#file-size').textContent = bytes(members.reduce((n, f) => n + f.size, 0));
  renderBundleList(members);
  afterBusy();
  return true;
}

async function showFiles(id) {
  $('#get').disabled = true;
  if (await showBundle(id)) {
    $('#get').hidden = true;
  } else {
    $('#get').disabled = false;
  }
}

function renderBundleList(members) {
  const wrap = $('#bundle-list-wrap');
  const list = $('#bundle-list');
  list.replaceChildren();
  wrap.hidden = false;

  const rows = members.map((member) => {
    const row = document.createElement('li');
    const name = document.createElement('span');
    name.className = 'recent-name';
    name.append(bdi(member.name));
    const size = document.createElement('span');
    size.className = 'recent-time';
    size.textContent = bytes(member.size);
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'link-button';
    row.append(name, size, button);
    list.append(row);

    const entry = {
      member,
      saved: false,
      running: null, // a row-click download in progress, so "Download all" waits for it
      set(text, busy = false) {
        button.textContent = text;
        button.setAttribute('aria-label', `${text} ${member.name}`);
        button.disabled = busy || entry.saved;
      },
    };
    entry.set('download');
    button.addEventListener('click', () => {
      entry.set('downloading...', true);
      // Ask for the destination inside the click, while the browser still
      // counts it as a user gesture; the header is opened afterwards.
      const early = save(member.name, member.type, member.size);
      early.catch(() => {});
      entry.running = (async () => {
        try {
          await downloadMember(member, () => early);
          entry.saved = true;
          entry.set('saved');
        } catch (err) {
          early.then((sink) => sink.abort?.(), () => {});
          entry.set(err.name === 'AbortError' ? 'download' : 'retry');
          if (err.name !== 'AbortError') status($('#file-status'), `${isolate(member.name)}: ${err.message || 'download failed'}`, 'error');
        }
      })().finally(() => { entry.running = null; });
    });
    return entry;
  });

  const all = $('#bundle-download-all');
  all.onclick = async () => {
    all.disabled = true;
    // One folder prompt for the whole set where the browser offers it; the
    // per-file save picker would lose its user gesture after the first file.
    let dir = null;
    if (window.showDirectoryPicker) {
      try {
        dir = await window.showDirectoryPicker({ mode: 'readwrite' });
      } catch (err) {
        if (err.name === 'AbortError') { all.disabled = false; return; }
      }
    }
    const used = new Set();
    let failed = 0;
    for (const entry of rows) {
      // A row click may already be fetching this one: wait for it, never
      // fetch it a second time (a limited member would then count as failed).
      if (entry.running) await entry.running;
      if (entry.saved) continue;
      entry.set('downloading...', true);
      const { member } = entry;
      try {
        await downloadMember(member, dir
          ? () => directorySink(dir, member.name, used)
          : () => save(member.name, member.type, member.size));
        entry.saved = true;
        entry.set('saved');
      } catch (err) {
        if (err.name !== 'AbortError') failed += 1;
        entry.set(err.name === 'AbortError' ? 'download' : 'retry');
      }
    }
    const saved = rows.filter((entry) => entry.saved).length;
    status($('#file-status'), `${saved} of ${rows.length} saved${failed ? ` - ${failed} failed, use retry on those rows` : ''}`,
      saved === rows.length ? 'ok' : 'error');
    all.disabled = saved === rows.length;
  };
}

/** `sinkFor()` is called once the member's header has opened, so a broken
    member never leaves an empty file behind in a picked folder. */
async function downloadMember(member, sinkFor) {
  const bar = $('#file-progress-bar');
  state.busy += 1;
  $('#file-progress').hidden = false;
  setProgress(bar, 0, '0%');
  status($('#file-status'), `downloading ${isolate(member.name)}...`);
  try {
    const memberMeta = await api(`/api/f/${member.id}`).catch((err) => {
      throw new FetchError(err.status === 404 ? 'this file has expired or was already downloaded' : err.message);
    });
    const opened = await openHeader(memberMeta.header, member.key, state.password);
    const sink = await sinkFor(opened);
    await fetchAndDecrypt(member.id, opened, sink, (done, size, started) => {
      const pct = size ? (done / size) * 100 : 100;
      const rate = done / Math.max((Date.now() - started) / 1000, 0.001);
      setProgress(bar, pct, `${Math.round(pct)}% · ${bytes(rate)}/s`);
    }, { key: member.key, limited: memberMeta.remaining !== null });
    status($('#file-status'), `${isolate(member.name)} - done`, 'ok');
  } finally {
    $('#file-progress').hidden = true;
    state.busy -= 1;
    afterBusy();
  }
}

async function download(id) {
  if (state.opened.type === NOTE_TYPE) return reveal(id);
  if (state.opened.type === BUNDLE_TYPE) return showFiles(id);

  const bar = $('#file-progress-bar');
  $('#get').disabled = true;
  state.busy += 1;
  $('#file-progress').hidden = false;
  setProgress(bar, 0, '0%');
  status($('#file-status'), 'downloading and decrypting...');

  try {
    const sink = await save(state.opened.name, state.opened.type, state.opened.size);
    await fetchAndDecrypt(id, state.opened, sink, (done, size, started) => {
      const pct = size ? (done / size) * 100 : 100;
      const rate = done / Math.max((Date.now() - started) / 1000, 0.001);
      setProgress(bar, pct, `${Math.round(pct)}% · ${bytes(rate)}/s`);
    }, shareOptions());
    status($('#file-status'), 'done - verified and saved', 'ok');
  } catch (err) {
    if (err.name === 'AbortError') status($('#file-status'), 'cancelled');
    else status($('#file-status'), err.message || 'download failed', 'error');
    $('#get').disabled = false;
  } finally {
    $('#file-progress').hidden = true;
    state.busy -= 1;
    afterBusy();
  }
}

/** Meta plus an estimate of the server's clock, so the countdown and the
    expired state follow the Worker rather than a wrong device clock. */
async function fetchMeta(id) {
  let response;
  try {
    response = await fetch(`/api/f/${id}`);
  } catch {
    throw new Error('cannot reach the server - check your connection and reload');
  }
  const received = Date.now();
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `request failed (${response.status})`);
  // Older Workers have no `now`; the Date header is coarser but always there.
  const serverNow = Number.isFinite(data.now) ? data.now : Date.parse(response.headers.get('date') || '');
  state.clockOffset = Number.isFinite(serverNow) ? serverNow - received : 0;
  return data;
}

/** Expiry is shown in place, never by reloading: a reload re-requests the
    page in a loop when the clock is off and kills a download mid-stream.
    A download already running is left to finish; afterBusy() returns here. */
function expireInPlace() {
  state.expired = true;
  if (state.busy) return;
  // A finished download keeps its "saved" line; a revealed note is wiped, as
  // the old reload did, so its status must not suggest it is still there.
  const finished = $('#file-status').classList.contains('ok') && !state.noteBytes;
  state.note = null;
  state.noteBytes = null;
  state.opened = null;
  state.password = null;
  state.linkKey = null;
  $('#note-text').textContent = '';
  $('#bundle-list').replaceChildren();
  for (const sel of ['#note-wrap', '#get', '#unlock-row', '#burn-note', '#bundle-list-wrap', '#file-progress', '#file-card']) {
    $(sel).hidden = true;
  }
  status($('#file-status'),
    finished ? `${$('#file-status').textContent} - this link has now expired` : 'this link has expired',
    finished ? 'ok' : 'error');
}

function afterBusy() {
  if (state.expired && !state.busy) expireInPlace();
}

function startCountdown() {
  const timer = setInterval(() => tick(), 1000);
  const tick = () => {
    const left = state.meta.expires - (Date.now() + state.clockOffset);
    $('#file-expiry').textContent = countdown(left);
    if (left <= 0) {
      clearInterval(timer);
      expireInPlace();
    }
  };
  tick();
}

async function fileView(id) {
  show('file');
  state.shareId = id;
  const linkKey = location.hash.slice(1);
  state.linkKey = linkKey; // kept for x-ef-auth after a spent link drops it from the address bar
  if (!linkKey) {
    status($('#file-status'), 'this link is missing its key - open the original link again, including the part after #', 'error');
    return;
  }

  try {
    state.meta = await fetchMeta(id);
  } catch (err) {
    $('#file-card').hidden = true;
    status($('#file-status'), err.message, 'error');
    return;
  }

  $('#file-card').hidden = false;
  $('#file-remaining').textContent =
    state.meta.remaining === null ? 'unlimited' : `${state.meta.remaining} left`;
  $('#get').addEventListener('click', () => download(id));
  $('#note-copy').addEventListener('click', (e) => copyText(state.note, e.currentTarget, () => {
    getSelection()?.selectAllChildren($('#note-text'));
  }));
  $('#note-save').addEventListener('click', saveNote);
  startCountdown();
  if (state.expired) return;

  if (state.meta.protected) {
    $('#unlock-row').hidden = false;
    $('#unlock-password').focus();
    $('#unlock').addEventListener('click', () => unlock(id, linkKey));
    $('#unlock-password').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(id, linkKey); });
  } else {
    await unlock(id, linkKey);
  }
}

/* ----------------------------------------------------------------- boot */

async function unlockGate(token, remember) {
  await api('/api/auth', { headers: { authorization: `Bearer ${token}` } });
  tokenStore.set(token, remember);
}

function gateMessage(err) {
  if (err.status === 0) return 'cannot reach the server - check your connection and press Unlock to retry';
  if (err.status === 429) return `${err.message} - wait a minute, then press Unlock`;
  return err.message || 'invalid upload token';
}

const isStandalone = () =>
  window.matchMedia?.('(display-mode: standalone)').matches || window.navigator.standalone === true;

/** `retry` is a remembered token whose check failed for a reason other than
    being wrong (offline, rate limited, server error): it is kept, and Unlock
    with an empty field tries it again. */
function gateView(configReady, retry = null) {
  show('gate');
  const input = $('#gate-token');
  // Installed as an app: there is no tab to close, so default to remembering
  // the token in localStorage rather than re-prompting on every launch. A
  // browser tab still defaults to session-only unless the box is checked.
  $('#gate-remember').checked = retry ? retry.remember : isStandalone();
  if (retry) status($('#gate-status'), gateMessage(retry.error), 'error');
  input.focus();
  const attempt = async () => {
    const typed = input.value.trim();
    const token = typed || retry?.token;
    if (!token) return;
    $('#gate-unlock').disabled = true;
    status($('#gate-status'), 'checking...');
    try {
      await unlockGate(token, $('#gate-remember').checked);
      uploadView(configReady);
    } catch (err) {
      if (!typed && err.status === 401) { tokenStore.clear(); retry = null; }
      status($('#gate-status'), gateMessage(err), 'error');
      input.select();
    } finally {
      $('#gate-unlock').disabled = false;
    }
  };
  $('#gate-unlock').addEventListener('click', attempt);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') attempt(); });
}

function generatePassword() {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  let out = '';
  for (const b of bytes) out += b.toString(36).padStart(2, '0');
  return out.slice(0, 20);
}

function forgetDevice(withRecent) {
  tokenStore.clear();
  if (withRecent) removeKey('localStorage', 'recent');
  location.reload();
}

function wireLock() {
  const choice = $('#lock-choice');
  $('#lock').addEventListener('click', () => {
    if (!choice) { forgetDevice(false); return; } // an older cached page without the choice
    choice.hidden = false;
    $('#lock').hidden = true;
    $('#lock-token').focus();
  });
  if (!choice) return;
  $('#lock-token').addEventListener('click', () => forgetDevice(false));
  $('#lock-all').addEventListener('click', () => forgetDevice(true));
  $('#lock-keep').addEventListener('click', () => {
    choice.hidden = true;
    $('#lock').hidden = false;
    $('#lock').focus();
  });
}

async function uploadView(configReady) {
  show('upload');
  wireDropzone();
  wireText();
  wireLock();
  renderRecent();
  $('#send').addEventListener('click', upload);
  $('#cancel').addEventListener('click', cancelUpload);
  $('#generate').addEventListener('click', () => { $('#password').value = generatePassword(); });
  $('#copy').addEventListener('click', () => copy($('#link'), $('#copy')));
  $('#copy-password').addEventListener('click', () => copy($('#password-out'), $('#copy-password')));
  $('#again').addEventListener('click', () => location.assign('/'));

  await configReady;
  if (state.config) {
    $('#limit-note').textContent = `up to ${limitText()} per file`;
  }
}

const copyTimers = new WeakMap();

/** Says "copied" only when the clipboard took it; otherwise selects the text
    so a manual copy is one keystroke away. */
async function copyText(text, button, onFail) {
  button.dataset.label ??= button.textContent;
  let ok = false;
  try {
    await navigator.clipboard.writeText(text);
    ok = true;
  } catch {
    onFail?.();
  }
  button.textContent = ok ? 'copied' : 'selected - copy it manually';
  clearTimeout(copyTimers.get(button));
  copyTimers.set(button, setTimeout(() => { button.textContent = button.dataset.label; }, ok ? 1500 : 4000));
}

const copy = (field, button) => copyText(field.value, button, () => { field.focus(); field.select(); });

function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => { /* offline shell is a nicety, not a requirement */ });
  });
}

async function main() {
  registerServiceWorker();
  sweepStaged(); // in the background: nothing below waits on it
  // Branding and the size limit are not needed to start: fetch them alongside
  // the view's own first request instead of in front of it.
  const configReady = loadConfig();
  const match = location.pathname.match(/^\/f\/([A-Za-z0-9]{16,32})\/?$/);
  if (match) return fileView(match[1]);

  // Recipients never see the gate; only the owner's own device does.
  const token = tokenStore.get();
  if (token) {
    const remember = tokenStore.remembered();
    try {
      await unlockGate(token, remember);
      return uploadView(configReady);
    } catch (err) {
      // Only the server saying "wrong token" makes it stale. Offline, a rate
      // limit or an outage must not sign the owner out.
      if (err.status === 401) tokenStore.clear();
      else return gateView(configReady, { token, remember, error: err });
    }
  }
  gateView(configReady);
}

main();
