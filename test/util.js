'use strict';
/* Shared helpers for the X-SHATTER test suite (not a test file itself). */
const zlib = require('node:zlib');
const { makeChunk, paethPredictor } = require('../src/png');

/** Deterministic RGBA pattern image — no randomness, stable across runs. */
function makePatternImage(w, h) {
  const data = Buffer.alloc(w * h * 4);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const i = (y * w + x) * 4;
      data[i] = (x * 37 + y * 11) & 0xff;
      data[i + 1] = (x * 91 + y * 53 + 7) & 0xff;
      data[i + 2] = (x * 13 + y * 97 + 42) & 0xff;
      data[i + 3] = (x * 17 + y * 23 + 128) & 0xff; // varying alpha too
    }
  }
  return { width: w, height: h, data };
}

/** Forward PNG filter (for building test files with filter types 1-4). */
function filterRow(type, cur, prev, bpp) {
  const out = Buffer.alloc(cur.length);
  for (let i = 0; i < cur.length; i++) {
    const a = i >= bpp ? cur[i - bpp] : 0;
    const b = prev[i];
    const c = i >= bpp ? prev[i - bpp] : 0;
    let f;
    switch (type) {
      case 0: f = 0; break;
      case 1: f = a; break;
      case 2: f = b; break;
      case 3: f = (a + b) >> 1; break;
      case 4: f = paethPredictor(a, b, c); break;
      default: throw new Error('bad filter');
    }
    out[i] = (cur[i] - f) & 0xff;
  }
  return out;
}

/**
 * Build a minimal PNG with full control: bitDepth 8, chosen colorType,
 * chosen filter type per file, optional extra chunks (inserted before IDAT).
 * pixelRows: array of Buffer rows in native (unfiltered, unpacked) form.
 */
function buildRawPng(w, h, colorType, filterType, pixelRows, extraChunks) {
  const bpp = { 0: 1, 2: 3, 6: 4 }[colorType];
  const stride = w * bpp;
  const raw = Buffer.alloc(h * (stride + 1));
  let prev = Buffer.alloc(stride);
  for (let y = 0; y < h; y++) {
    raw[y * (stride + 1)] = filterType;
    filterRow(filterType, pixelRows[y], prev, bpp).copy(raw, y * (stride + 1) + 1);
    prev = pixelRows[y];
  }
  const comp = zlib.deflateSync(raw);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = colorType; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const parts = [sig, makeChunk('IHDR', ihdr)];
  for (const ch of extraChunks || []) parts.push(makeChunk(ch.type, ch.data));
  parts.push(makeChunk('IDAT', comp));
  parts.push(makeChunk('IEND', Buffer.alloc(0)));
  return Buffer.concat(parts);
}

/** Split a pattern image into native RGB rows (for colorType 2 test files). */
function rgbRows(img) {
  const rows = [];
  for (let y = 0; y < img.height; y++) {
    const row = Buffer.alloc(img.width * 3);
    for (let x = 0; x < img.width; x++) {
      const s = (y * img.width + x) * 4, d = x * 3;
      row[d] = img.data[s]; row[d + 1] = img.data[s + 1]; row[d + 2] = img.data[s + 2];
    }
    rows.push(row);
  }
  return rows;
}

/** Split a pattern image into native grayscale rows (luma of RGB). */
function grayRows(img) {
  const rows = [];
  for (let y = 0; y < img.height; y++) {
    const row = Buffer.alloc(img.width);
    for (let x = 0; x < img.width; x++) {
      const s = (y * img.width + x) * 4;
      row[x] = Math.round(0.299 * img.data[s] + 0.587 * img.data[s + 1] + 0.114 * img.data[s + 2]);
    }
    rows.push(row);
  }
  return rows;
}

function rgbaRows(img) {
  const rows = [];
  for (let y = 0; y < img.height; y++) {
    rows.push(img.data.subarray(y * img.width * 4, (y + 1) * img.width * 4));
  }
  return rows;
}

module.exports = { makePatternImage, buildRawPng, rgbRows, grayRows, rgbaRows };
