#!/usr/bin/env node
/**
 * One-off PWA icon generator - no image dependencies, just Node's built-in
 * zlib for the PNG IDAT stream. Draws a padlock (matching public/favicon.svg)
 * on a solid accent-colour square, at every size the manifest references.
 *
 * Run with: node tools/gen-icons.mjs
 */
import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const OUT_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'icons');
mkdirSync(OUT_DIR, { recursive: true });

const BG = [0x1f, 0x6f, 0xeb, 255];   // --accent
const FG = [0xff, 0xff, 0xff, 255];  // white padlock
const SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

/* --------------------------------------------------------------- crc32 */

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const typeBuf = Buffer.from(type, 'ascii');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

function encodePNG(width, height, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type: RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // no per-row filter
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }
  const idat = deflateSync(raw, { level: 9 });

  return Buffer.concat([
    SIGNATURE,
    chunk('IHDR', ihdr),
    chunk('IDAT', idat),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/* ------------------------------------------------------------- drawing */

function roundedRectMask(x, y, rx0, ry0, rx1, ry1, radius) {
  const cx = Math.min(Math.max(x, rx0 + radius), rx1 - radius);
  const cy = Math.min(Math.max(y, ry0 + radius), ry1 - radius);
  if (x < rx0 || x > rx1 || y < ry0 || y > ry1) return false;
  const dx = x - cx;
  const dy = y - cy;
  return dx * dx + dy * dy <= radius * radius;
}

/** Draws the icon into an S x S RGBA buffer. `pad` is the fraction of each
 *  edge left empty (maskable icons need a safe zone; regular ones look
 *  better with a little breathing room too). */
function draw(size, { pad = 0.18, rounded = true } = {}) {
  const buf = Buffer.alloc(size * size * 4);
  const bgRadius = rounded ? size * 0.22 : 0;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 4;
      const inBg = rounded ? roundedRectMask(x, y, 0, 0, size - 1, size - 1, bgRadius) : true;
      const color = inBg ? BG : [0, 0, 0, 0];
      buf[i] = color[0]; buf[i + 1] = color[1]; buf[i + 2] = color[2]; buf[i + 3] = color[3];
    }
  }

  // Padlock geometry, in the padded content box.
  const box = size * (1 - pad * 2);
  const left = size * pad;
  const cx = size / 2;
  const shackleCy = left + box * 0.34;
  const rOut = box * 0.26;
  const rIn = box * 0.15;
  const legTop = shackleCy;
  const legBottom = left + box * 0.46;
  const bodyTop = left + box * 0.42;
  const bodyBottom = left + box * 0.92;
  const bodyLeft = cx - box * 0.36;
  const bodyRight = cx + box * 0.36;
  const bodyRadius = box * 0.1;
  const keyholeCx = cx;
  const keyholeCy = bodyTop + (bodyBottom - bodyTop) * 0.38;
  const keyholeR = box * 0.07;

  const setFg = (x, y) => {
    if (x < 0 || y < 0 || x >= size || y >= size) return;
    const i = (y * size + x) * 4;
    buf[i] = FG[0]; buf[i + 1] = FG[1]; buf[i + 2] = FG[2]; buf[i + 3] = FG[3];
  };
  const setBg = (x, y) => {
    if (x < 0 || y < 0 || x >= size || y >= size) return;
    const i = (y * size + x) * 4;
    buf[i] = BG[0]; buf[i + 1] = BG[1]; buf[i + 2] = BG[2]; buf[i + 3] = BG[3];
  };

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const dx = x - cx;
      const dy = y - shackleCy;
      const dist = Math.hypot(dx, dy);

      // Shackle arch: upper half of an annulus, plus two straight legs
      // dropping from the arch ends down to the body.
      const inArch = y <= shackleCy && dist >= rIn && dist <= rOut;
      const inLeftLeg = x >= cx - rOut && x <= cx - rIn && y >= legTop && y <= legBottom;
      const inRightLeg = x >= cx + rIn && x <= cx + rOut && y >= legTop && y <= legBottom;
      if (inArch || inLeftLeg || inRightLeg) setFg(x, y);

      // Body.
      if (roundedRectMask(x, y, bodyLeft, bodyTop, bodyRight, bodyBottom, bodyRadius)) setFg(x, y);
    }
  }

  // Keyhole cutout, drawn last so it punches through the body.
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const dx = x - keyholeCx;
      const dy = y - keyholeCy;
      const inCircle = dx * dx + dy * dy <= keyholeR * keyholeR;
      const inStem = Math.abs(dx) <= keyholeR * 0.4 && y >= keyholeCy && y <= keyholeCy + keyholeR * 1.6;
      if (inCircle || inStem) setBg(x, y);
    }
  }

  return buf;
}

const targets = [
  { name: 'icon-192.png', size: 192, opts: {} },
  { name: 'icon-512.png', size: 512, opts: {} },
  { name: 'icon-maskable-512.png', size: 512, opts: { pad: 0.26, rounded: false } },
  { name: 'apple-touch-icon.png', size: 180, opts: { rounded: false } }, // iOS applies its own mask
];

for (const { name, size, opts } of targets) {
  const png = encodePNG(size, size, draw(size, opts));
  writeFileSync(join(OUT_DIR, name), png);
  console.log(`wrote ${name} (${size}x${size}, ${png.length} bytes)`);
}
