/**
 * Receiving keys kept by this browser, for links an agent sealed to this
 * person (see "receiving keys" in crypto.js).
 *
 * Each record is { kid, label, created, raw, text, privateKey }. privateKey is
 * a non-extractable CryptoKey: IndexedDB stores it by structured clone, so
 * pages of this origin can use it to open a sealed link but nothing, this
 * code included, can read its bytes out. Clearing the site's data deletes it,
 * and links sealed only to it can then never be opened.
 */
import { generateRecipient, sealedKids, openSealedLinkKey } from './crypto.js';

const DB = 'ephemeral-keys';
const STORE = 'recipients';

function openDb() {
  return new Promise((resolve, reject) => {
    let req;
    try {
      req = indexedDB.open(DB, 1);
    } catch (err) {
      reject(err);
      return;
    }
    req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: 'kid' });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('this browser cannot store keys (private window?)'));
    req.onblocked = () => reject(new Error('key storage is busy in another tab; close it and retry'));
  });
}

async function tx(mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      const result = fn(t.objectStore(STORE));
      t.oncomplete = () => resolve(result.result ?? result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error || new Error('aborted'));
    });
  } finally {
    db.close();
  }
}

export const keystoreAvailable = () => typeof indexedDB !== 'undefined';

export async function listKeys() {
  const all = await tx('readonly', (s) => s.getAll());
  return (all || []).sort((a, b) => b.created - a.created);
}

export async function createKey(label) {
  const r = await generateRecipient({ extractable: false });
  const record = {
    kid: r.kid,
    label: String(label || '').trim().slice(0, 60) || 'this browser',
    created: Date.now(),
    raw: r.raw,
    text: r.text,
    privateKey: r.privateKey,
  };
  await tx('readwrite', (s) => s.put(record));
  // Ask the browser not to evict the key under storage pressure. Best effort:
  // a refusal still leaves the key usable until the site's data is cleared.
  navigator.storage?.persist?.().catch(() => {});
  return record;
}

export const deleteKey = (kid) => tx('readwrite', (s) => s.delete(kid));

/**
 * The link key of a sealed fragment, using whichever local key it was sealed
 * to. Resolves { linkKey, record } or { linkKey: null, reason } when no key on
 * this device matches.
 */
export async function unsealHere(fragment) {
  const kids = sealedKids(fragment); // throws on a malformed fragment
  let keys;
  try {
    keys = await listKeys();
  } catch {
    return { linkKey: null, reason: 'storage' };
  }
  const record = keys.find((k) => kids.includes(k.kid));
  if (!record) return { linkKey: null, reason: 'nokey', kids };
  return { linkKey: await openSealedLinkKey(fragment, record), record };
}
