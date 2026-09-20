import { CHUNK, TAG, NOTE_TYPE, BUNDLE_TYPE, beginEncrypt, openHeader, decryptStream } from './crypto.js';

const $ = (sel) => document.querySelector(sel);
const PARALLEL = 3;      // in-flight part uploads
const RETRIES = 3;       // per part, with backoff
const DEFAULT_NOTE_NAME = 'note.txt';

/* A share of 2+ files is just a small JSON index - itself uploaded, encrypted
   and linked exactly like any other file - listing the id/key/name/size/type
   of each member (BUNDLE_TYPE). Pasted text is the same trick with one file
   and no index (NOTE_TYPE): both markers ride inside the encrypted header, so
   the Worker never learned a thing about either and a single file still
   uploads byte-for-byte as it always did. */

const state = {
  files: [], mode: 'files', limitTouched: false,
  aborter: null, opened: null, meta: null, password: null, note: null,
  config: null,
};

/* The upload token is a bearer credential: kept in sessionStorage by default,
   promoted to localStorage only if the owner asks to be remembered. */
const tokenStore = {
  get: () => sessionStorage.getItem('upload-token') || localStorage.getItem('upload-token') || '',
  set(token, remember) {
    (remember ? localStorage : sessionStorage).setItem('upload-token', token);
  },
  clear() {
    sessionStorage.removeItem('upload-token');
    localStorage.removeItem('upload-token');
  },
};

const authHeaders = (extra = {}) => {
  const token = tokenStore.get();
  return token ? { ...extra, authorization: `Bearer ${token}` } : extra;
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

function show(view) {
  for (const el of document.querySelectorAll('[data-view]')) {
    el.hidden = el.dataset.view !== view;
  }
}

function status(el, message, kind = '') {
  el.textContent = message;
  el.className = `status ${kind}`;
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `request failed (${response.status})`);
  return data;
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

function renderPicked() {
  const files = state.files;
  const list = $('#file-list');
  list.innerHTML = '';
  list.hidden = files.length <= 1;

  if (files.length > 1) {
    files.forEach((file, index) => {
      const row = document.createElement('li');
      const name = document.createElement('span');
      name.className = 'file-list-name';
      name.textContent = file.name;
      const size = document.createElement('span');
      size.className = 'file-list-size';
      size.textContent = bytes(file.size);
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'link-button';
      remove.textContent = 'remove';
      remove.addEventListener('click', () => { state.files.splice(index, 1); renderPicked(); });
      row.append(name, size, remove);
      list.append(row);
    });
  }

  if (files.length === 0) {
    $('#drop-label').textContent = 'Drop one or more files, or click to choose';
    $('#drop-size').textContent = '';
    $('#drop').classList.remove('has-file');
  } else if (files.length === 1) {
    $('#drop-label').textContent = files[0].name;
    $('#drop-size').textContent = bytes(files[0].size);
    $('#drop').classList.add('has-file');
  } else {
    $('#drop-label').textContent = `${files.length} files selected`;
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

function setMode(mode) {
  state.mode = mode;
  $('#files-pane').hidden = mode !== 'files';
  $('#text-pane').hidden = mode !== 'text';
  for (const [button, on] of [[$('#mode-files'), mode === 'files'], [$('#mode-text'), mode === 'text']]) {
    button.classList.toggle('is-on', on);
    button.setAttribute('aria-selected', String(on));
  }
  // A pasted secret is usually meant for one pair of eyes, so text defaults to
  // burn-after-read - unless the owner has already picked a limit themselves.
  if (!state.limitTouched) $('#limit').value = mode === 'text' ? '1' : '0';
  syncSend();
  if (mode === 'text') $('#text').focus();
}

function wireText() {
  $('#mode-files').addEventListener('click', () => setMode('files'));
  $('#mode-text').addEventListener('click', () => setMode('text'));
  $('#limit').addEventListener('change', () => { state.limitTouched = true; });
  $('#text').addEventListener('input', () => {
    const size = new Blob([$('#text').value]).size;
    $('#text-size').textContent = size ? bytes(size) : '';
    syncSend();
  });
}

/** Picking or dropping adds to the current selection (skipping exact repeats)
    rather than replacing it, so files can be gathered one drop at a time. */
function pickFiles(fileList) {
  const incoming = Array.from(fileList || []);
  if (!incoming.length) return;
  const seen = new Set(state.files.map((f) => `${f.name}:${f.size}:${f.lastModified}`));
  for (const file of incoming) {
    const key = `${file.name}:${file.size}:${file.lastModified}`;
    if (seen.has(key)) continue;
    seen.add(key);
    state.files.push(file);
  }
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
  drop.addEventListener('drop', (e) => pickFiles(e.dataTransfer.files));
}

async function putPart(id, uploadId, partNumber, body, signal) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await api(`/api/upload/part?id=${id}&uploadId=${encodeURIComponent(uploadId)}&part=${partNumber}`, {
        method: 'PUT', body, headers: authHeaders(), signal,
      });
    } catch (err) {
      if (signal.aborted || attempt >= RETRIES - 1) throw err;
      await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
    }
  }
}

/** Encrypts and uploads one file through the same init/part/complete pipeline
    regardless of whether it ends up as the sole shared file or one member of
    a bundle. `onProgress(sentBytes, cipherSize)` fires per part; `onBeforeComplete`
    fires once every part has landed, just before the completion call. */
async function uploadFile(file, { ttl, limit, password, signal, onProgress, onBeforeComplete }) {
  const box = await beginEncrypt(file, password);
  const jsonHeaders = authHeaders({ 'content-type': 'application/json' });

  const init = await api('/api/upload/init', {
    method: 'POST',
    headers: jsonHeaders,
    body: JSON.stringify({ size: box.cipherSize, chunkSize: CHUNK, ttl, limit }),
    signal,
  });

  const parts = new Array(box.chunks);
  let sent = 0;
  let next = 0;

  const worker = async () => {
    while (next < box.chunks && !signal.aborted) {
      const index = next++;
      const sealed = await box.chunk(index);
      const result = await putPart(init.id, init.uploadId, index + 1, sealed, signal);
      parts[index] = { partNumber: index + 1, etag: result.etag };
      sent += sealed.length;
      onProgress?.(sent, box.cipherSize);
    }
  };
  await Promise.all(Array.from({ length: Math.min(PARALLEL, box.chunks) }, worker));
  if (signal.aborted) throw new Error('cancelled');

  onBeforeComplete?.();
  const done = await api('/api/upload/complete', {
    method: 'POST',
    headers: jsonHeaders,
    body: JSON.stringify({
      id: init.id,
      uploadId: init.uploadId,
      parts,
      header: box.header,
      protected: Boolean(password),
    }),
  });

  return { id: done.id, url: done.url, expires: done.expires, deleteToken: done.deleteToken, linkKey: box.linkKey };
}

async function upload() {
  const files = state.mode === 'text' ? textFiles() : state.files;
  if (!files.length) return;
  const isNote = state.mode === 'text';

  const ttl = Number($('#ttl').value);
  const limit = Number($('#limit').value);
  const password = $('#password').value.trim() || null;

  const bar = $('#progress-bar');
  const controller = new AbortController();
  const signal = controller.signal;
  state.aborter = controller;
  $('#send').hidden = true;
  $('#cancel').hidden = false;
  $('#progress').hidden = false;
  status($('#upload-status'), password ? 'deriving key...' : 'encrypting...');

  try {
    if (files.length === 1) {
      const file = files[0];
      const started = Date.now();
      status($('#upload-status'), 'encrypting and uploading...');
      const result = await uploadFile(file, {
        ttl, limit, password, signal,
        onProgress: (sent, total) => {
          const pct = Math.min(100, (sent / total) * 100);
          bar.style.width = `${pct}%`;
          const rate = sent / Math.max((Date.now() - started) / 1000, 0.001);
          $('#progress-text').textContent = `${Math.round(pct)}% · ${bytes(rate)}/s`;
        },
        onBeforeComplete: () => status($('#upload-status'), 'finishing...'),
      });

      remember({ id: result.id, name: file.name, expires: result.expires, token: result.deleteToken });
      showResult(`${result.url}#${result.linkKey}`, result.expires, password, 1, isNote);
    } else {
      status($('#upload-status'), 'encrypting and uploading...');
      const started = Date.now();
      const totalPlain = totalSize(files) || 1;
      const members = [];
      const memberTokens = [];
      let plainDoneBefore = 0;

      for (const file of files) {
        if (signal.aborted) throw new Error('cancelled');
        const result = await uploadFile(file, {
          ttl, limit, password, signal,
          onProgress: (sent, total) => {
            const thisPlain = Math.min(file.size, (sent / total) * file.size);
            const pct = Math.min(100, ((plainDoneBefore + thisPlain) / totalPlain) * 100);
            bar.style.width = `${pct}%`;
            const rate = (plainDoneBefore + thisPlain) / Math.max((Date.now() - started) / 1000, 0.001);
            $('#progress-text').textContent = `${Math.round(pct)}% · ${bytes(rate)}/s · file ${members.length + 1}/${files.length}`;
          },
        });
        plainDoneBefore += file.size;
        members.push({ id: result.id, key: result.linkKey, name: file.name, size: file.size, type: file.type || '' });
        memberTokens.push({ id: result.id, token: result.deleteToken });
      }

      status($('#upload-status'), 'finishing...');
      // The index is shared with recipients, so it carries only what opens each
      // member file - never the delete tokens, which stay owner-side below.
      const manifestBody = JSON.stringify({ v: 1, files: members });
      const manifestFile = new File([manifestBody], `${files.length} files`, { type: BUNDLE_TYPE });
      const manifest = await uploadFile(manifestFile, { ttl, limit, password, signal });

      remember({
        id: manifest.id,
        name: `${files.length} files`,
        expires: manifest.expires,
        token: manifest.deleteToken,
        members: memberTokens,
      });
      showResult(`${manifest.url}#${manifest.linkKey}`, manifest.expires, password, files.length);
    }
  } catch (err) {
    status($('#upload-status'), err.message || 'upload failed', 'error');
    $('#progress').hidden = true;
    $('#send').hidden = false;
  } finally {
    $('#cancel').hidden = true;
    state.aborter = null;
  }
}

function cancelUpload() {
  state.aborter?.abort();
  status($('#upload-status'), 'cancelled');
  $('#progress').hidden = true;
  $('#send').hidden = false;
  $('#cancel').hidden = true;
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

/* ------------------------------------------------- local record of links */

const readRecent = () => {
  try { return JSON.parse(localStorage.getItem('recent') || '[]'); } catch { return []; }
};

/** Only what is needed to revoke later - never the key, which stays in the link. */
function remember(entry) {
  const recent = readRecent().filter((e) => e.id !== entry.id && e.expires > Date.now());
  recent.unshift(entry);
  localStorage.setItem('recent', JSON.stringify(recent.slice(0, 20)));
  renderRecent();
}

function renderRecent() {
  const list = $('#recent');
  const items = readRecent().filter((e) => e.expires > Date.now());
  localStorage.setItem('recent', JSON.stringify(items));
  list.innerHTML = '';
  $('#recent-wrap').hidden = items.length === 0;

  for (const item of items) {
    const row = document.createElement('li');
    const name = document.createElement('span');
    name.className = 'recent-name';
    name.textContent = item.name;
    const left = document.createElement('span');
    left.className = 'recent-time';
    left.textContent = countdown(item.expires - Date.now());
    const button = document.createElement('button');
    button.className = 'link-button';
    button.textContent = 'delete';
    button.addEventListener('click', async () => {
      button.disabled = true;
      // Bundles carry their member files' own delete tokens alongside the
      // index's; older single-file entries have no `members` and just skip this.
      const targets = [{ id: item.id, token: item.token }, ...(item.members || [])];
      await Promise.all(targets.map(({ id, token }) =>
        api(`/api/f/${id}`, { method: 'DELETE', headers: { 'x-delete-token': token } }).catch(() => {
          /* already gone is still gone */
        }),
      ));
      localStorage.setItem('recent', JSON.stringify(readRecent().filter((e) => e.id !== item.id)));
      renderRecent();
    });
    row.append(name, left, button);
    list.append(row);
  }
}

/* ------------------------------------------------------------- download */

async function save(name, type) {
  // Stream straight to disk where the browser allows it; otherwise assemble a
  // Blob, which browsers back with disk storage for large files.
  if (window.showSaveFilePicker) {
    try {
      const handle = await window.showSaveFilePicker({ suggestedName: name });
      const writable = await handle.createWritable();
      return { write: (chunk) => writable.write(chunk), close: () => writable.close() };
    } catch (err) {
      if (err.name === 'AbortError') throw err;
    }
  }
  const parts = [];
  return {
    write: (chunk) => { parts.push(chunk); },
    close: () => {
      const url = URL.createObjectURL(new Blob(parts, { type: type || 'application/octet-stream' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    },
  };
}

/** Fetches the ciphertext body for `id` and decrypts it against `opened`
    (from openHeader), reporting progress as it goes. Shared by the single-file
    download and by each member of a bundle. */
async function fetchAndDecrypt(id, opened, sink, onProgress) {
  const response = await fetch(`/api/d/${id}`);
  if (!response.ok) throw new Error('this link has expired');
  const started = Date.now();
  await decryptStream(response.body, opened, sink.write, (done) => onProgress?.(done, opened.size, started));
  await sink.close();
}

async function unlock(id, linkKey) {
  const password = $('#unlock-password').value || null;
  status($('#file-status'), password ? 'deriving key...' : 'decrypting...');
  try {
    state.opened = await openHeader(state.meta.header, linkKey, password);
  } catch {
    status($('#file-status'), state.meta.protected ? 'wrong password' : 'this link is not valid for this file', 'error');
    return;
  }
  state.password = password; // reused to open each member header if this turns out to be a bundle
  status($('#file-status'), '');
  $('#unlock-row').hidden = true;

  if (state.opened.type === BUNDLE_TYPE) {
    await showBundle(id);
  } else {
    $('#file-name').textContent = state.opened.name;
    $('#file-size').textContent = bytes(state.opened.size);
    // Text is still fetched on a click, never on page load: a link preview or
    // a scanner opening the page must not spend a burn-after-read view.
    if (state.opened.type === NOTE_TYPE) $('#get').textContent = 'Reveal text';
    if (state.meta.remaining === 1) {
      $('#burn-note').textContent = state.opened.type === NOTE_TYPE
        ? 'This is the only read left. Copy what you need before you close the page - the link dies the moment you reveal it.'
        : 'This is the only download left. The link dies as soon as it starts.';
      $('#burn-note').hidden = false;
    }
    $('#get').hidden = false;
    $('#get').focus();
  }
}

/** Decrypts a text share into the page rather than onto the disk. It is small
    by construction, so it is assembled in memory and never touches a sink. */
async function reveal(id) {
  $('#get').disabled = true;
  status($('#file-status'), 'downloading and decrypting...');
  try {
    const parts = [];
    await fetchAndDecrypt(id, state.opened, { write: (chunk) => parts.push(chunk), close: () => {} });
    state.note = new TextDecoder().decode(await new Blob(parts).arrayBuffer());
    $('#note-text').textContent = state.note;
    $('#note-wrap').hidden = false;
    $('#get').hidden = true;
    status($('#file-status'), 'decrypted and verified', 'ok');
  } catch (err) {
    status($('#file-status'), err.message || 'this link has expired', 'error');
    $('#get').disabled = false;
  }
}

async function saveNote() {
  try {
    const sink = await save(state.opened.name, 'text/plain;charset=utf-8');
    await sink.write(new TextEncoder().encode(state.note));
    await sink.close();
  } catch (err) {
    if (err.name !== 'AbortError') status($('#file-status'), err.message || 'could not save', 'error');
  }
}

async function showBundle(id) {
  status($('#file-status'), 'loading file list...');
  let manifest;
  try {
    const parts = [];
    await fetchAndDecrypt(id, state.opened, { write: (chunk) => parts.push(chunk), close: () => {} });
    manifest = JSON.parse(new TextDecoder().decode(await new Blob(parts).arrayBuffer()));
  } catch {
    status($('#file-status'), 'this bundle is corrupt or truncated', 'error');
    return;
  }
  status($('#file-status'), '');
  $('#file-name').textContent = `${manifest.files.length} files`;
  $('#file-size').textContent = bytes(manifest.files.reduce((n, f) => n + f.size, 0));
  renderBundleList(manifest.files);
}

function renderBundleList(members) {
  const wrap = $('#bundle-list-wrap');
  const list = $('#bundle-list');
  list.innerHTML = '';
  wrap.hidden = false;

  for (const member of members) {
    const row = document.createElement('li');
    const name = document.createElement('span');
    name.className = 'recent-name';
    name.textContent = member.name;
    const size = document.createElement('span');
    size.className = 'recent-time';
    size.textContent = bytes(member.size);
    const button = document.createElement('button');
    button.className = 'link-button';
    button.textContent = 'download';
    button.addEventListener('click', async () => {
      button.disabled = true;
      const original = button.textContent;
      button.textContent = 'downloading...';
      try {
        await downloadMember(member);
        button.textContent = 'done';
      } catch (err) {
        button.textContent = err.name === 'AbortError' ? original : 'retry';
        button.disabled = false;
      }
    });
    row.append(name, size, button);
    list.append(row);
  }

  const all = $('#bundle-download-all');
  all.addEventListener('click', async () => {
    all.disabled = true;
    for (const member of members) {
      try { await downloadMember(member); } catch { /* keep going; each row shows its own outcome */ }
    }
    all.disabled = false;
  });
}

async function downloadMember(member) {
  const bar = $('#file-progress-bar');
  $('#file-progress').hidden = false;
  status($('#file-status'), `downloading ${member.name}...`);
  try {
    const memberMeta = await api(`/api/f/${member.id}`);
    const opened = await openHeader(memberMeta.header, member.key, state.password);
    const sink = await save(opened.name, opened.type);
    await fetchAndDecrypt(member.id, opened, sink, (done, size, started) => {
      const pct = size ? (done / size) * 100 : 100;
      bar.style.width = `${pct}%`;
      const rate = done / Math.max((Date.now() - started) / 1000, 0.001);
      $('#file-progress-text').textContent = `${Math.round(pct)}% · ${bytes(rate)}/s`;
    });
    status($('#file-status'), `${member.name} - done`, 'ok');
  } finally {
    $('#file-progress').hidden = true;
  }
}

async function download(id) {
  if (state.opened.type === NOTE_TYPE) return reveal(id);

  const bar = $('#file-progress-bar');
  $('#get').disabled = true;
  $('#file-progress').hidden = false;
  status($('#file-status'), 'downloading and decrypting...');

  try {
    const sink = await save(state.opened.name, state.opened.type);
    await fetchAndDecrypt(id, state.opened, sink, (done, size, started) => {
      const pct = size ? (done / size) * 100 : 100;
      bar.style.width = `${pct}%`;
      const rate = done / Math.max((Date.now() - started) / 1000, 0.001);
      $('#file-progress-text').textContent = `${Math.round(pct)}% · ${bytes(rate)}/s`;
    });
    status($('#file-status'), 'done - verified and saved', 'ok');
  } catch (err) {
    if (err.name === 'AbortError') status($('#file-status'), 'cancelled');
    else status($('#file-status'), err.message || 'download failed', 'error');
    $('#get').disabled = false;
  } finally {
    $('#file-progress').hidden = true;
  }
}

async function fileView(id) {
  show('file');
  const linkKey = location.hash.slice(1);
  if (!linkKey) {
    status($('#file-status'), 'this link is missing its key - copy the whole link, including the part after #', 'error');
    return;
  }

  try {
    state.meta = await api(`/api/f/${id}`);
  } catch (err) {
    $('#file-card').hidden = true;
    status($('#file-status'), err.message, 'error');
    return;
  }

  $('#file-card').hidden = false;
  const tick = () => {
    const left = state.meta.expires - Date.now();
    $('#file-expiry').textContent = countdown(left);
    if (left <= 0) location.reload();
  };
  tick();
  setInterval(tick, 1000);
  $('#file-remaining').textContent =
    state.meta.remaining === null ? 'unlimited' : `${state.meta.remaining} left`;

  if (state.meta.protected) {
    $('#unlock-row').hidden = false;
    $('#unlock-password').focus();
    $('#unlock').addEventListener('click', () => unlock(id, linkKey));
    $('#unlock-password').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(id, linkKey); });
  } else {
    await unlock(id, linkKey);
  }
  $('#get').addEventListener('click', () => download(id));
  $('#note-copy').addEventListener('click', (e) => copyText(state.note, e.currentTarget));
  $('#note-save').addEventListener('click', saveNote);
}

/* ----------------------------------------------------------------- boot */

async function unlockGate(token, remember) {
  const response = await fetch('/api/auth', { headers: { authorization: `Bearer ${token}` } });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || 'invalid upload token');
  }
  tokenStore.set(token, remember);
}

const isStandalone = () =>
  window.matchMedia?.('(display-mode: standalone)').matches || window.navigator.standalone === true;

function gateView() {
  show('gate');
  const input = $('#gate-token');
  // Installed as an app: there is no tab to close, so default to remembering
  // the token in localStorage rather than re-prompting on every launch. A
  // browser tab still defaults to session-only unless the box is checked.
  $('#gate-remember').checked = isStandalone();
  input.focus();
  const attempt = async () => {
    const token = input.value.trim();
    if (!token) return;
    $('#gate-unlock').disabled = true;
    status($('#gate-status'), 'checking...');
    try {
      await unlockGate(token, $('#gate-remember').checked);
      uploadView();
    } catch (err) {
      status($('#gate-status'), err.message, 'error');
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

async function uploadView() {
  show('upload');
  wireDropzone();
  wireText();
  renderRecent();
  $('#send').addEventListener('click', upload);
  $('#cancel').addEventListener('click', cancelUpload);
  $('#generate').addEventListener('click', () => { $('#password').value = generatePassword(); });
  $('#lock').addEventListener('click', () => { tokenStore.clear(); location.reload(); });
  $('#copy').addEventListener('click', () => copy($('#link'), $('#copy')));
  $('#copy-password').addEventListener('click', () => copy($('#password-out'), $('#copy-password')));
  $('#again').addEventListener('click', () => location.assign('/'));

  if (state.config) {
    $('#limit-note').textContent = `up to ${bytes(state.config.maxSizeMB * 1024 * 1024)} per file`;
  }
}

async function copyText(text, button, onFail) {
  await navigator.clipboard.writeText(text).catch(() => onFail?.());
  const original = button.textContent;
  button.textContent = 'copied';
  setTimeout(() => { button.textContent = original; }, 1500);
}

const copy = (field, button) => copyText(field.value, button, () => field.select());

function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => { /* offline shell is a nicety, not a requirement */ });
  });
}

async function main() {
  registerServiceWorker();
  await loadConfig();
  const match = location.pathname.match(/^\/f\/([A-Za-z0-9]{16,32})\/?$/);
  if (match) return fileView(match[1]);

  // Recipients never see the gate; only the owner's own device does.
  const token = tokenStore.get();
  if (token) {
    try {
      await unlockGate(token, Boolean(localStorage.getItem('upload-token')));
      return uploadView();
    } catch {
      tokenStore.clear(); // stale or revoked
    }
  }
  gateView();
}

main();
