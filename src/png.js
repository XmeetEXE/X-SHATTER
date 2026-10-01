'use strict';
/*
 * X-SHATTER PNG codec — pure JavaScript, zero dependencies.
 *
 * Decodes 8-bit PNGs (color types 0 = grayscale, 2 = RGB, 6 = RGBA,
 * non-interlaced only) into raw RGBA pixel buffers, and encodes raw
 * RGBA buffers back into valid PNG files.
 */

const zlib = require('node:zlib');

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/* ---------------- CRC32 (ISO 3309) ---------------- */

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/* ---------------- Chunk handling ---------------- */

function makeChunk(type, data) {
  if (type.length !== 4) throw new Error('Chunk type must be exactly 4 ASCII chars.');
  const td = Buffer.from(type, 'ascii');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([td, data])), 0);
  return Buffer.concat([len, td, data, crc]);
}

function parseChunks(buf) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
  if (buf.length < 8 || !buf.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new Error('Not a PNG file: bad signature.');
  }
  const chunks = [];
  let off = 8;
  let seenIEND = false;
  while (off + 8 <= buf.length) {
    const len = buf.readUInt32BE(off);
    const type = buf.toString('ascii', off + 4, off + 8);
    if (off + 12 + len > buf.length) throw new Error('Not a PNG file: truncated chunk.');
    const data = buf.subarray(off + 8, off + 8 + len);
    const want = buf.readUInt32BE(off + 8 + len);
    const got = crc32(buf.subarray(off + 4, off + 8 + len));
    if (want !== got) throw new Error(`Not a PNG file: CRC mismatch in ${type} chunk.`);
    chunks.push({ type, data: Buffer.from(data) });
    off += 12 + len;
    if (type === 'IEND') { seenIEND = true; break; }
  }
  if (!seenIEND) throw new Error('Not a PNG file: missing IEND.');
  return chunks;
}

/** Build the data payload of a tEXt chunk: keyword NUL text (latin1). */
function textChunkData(keyword, text) {
  return Buffer.concat([
    Buffer.from(keyword, 'latin1'),
    Buffer.from([0]),
    Buffer.from(text, 'latin1'),
  ]);
}

/* ---------------- Filtering ---------------- */

function paethPredictor(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  if (pb <= pc) return b;
  return c;
}

const BYTES_PER_PIXEL = { 0: 1, 2: 3, 6: 4 };

function decodePng(buf) {
  const chunks = parseChunks(buf);
  const ihdr = chunks.find((c) => c.type === 'IHDR');
  if (!ihdr || ihdr.data.length !== 13) throw new Error('Not a PNG file: missing or bad IHDR.');

  const width = ihdr.data.readUInt32BE(0);
  const height = ihdr.data.readUInt32BE(4);
  const bitDepth = ihdr.data[8];
  const colorType = ihdr.data[9];
  const interlace = ihdr.data[12];

  if (width === 0 || height === 0) throw new Error('Not a PNG file: zero dimension.');
  if (bitDepth !== 8) throw new Error(`Unsupported PNG: ${bitDepth}-bit depth (only 8-bit supported).`);
  if (!(colorType in BYTES_PER_PIXEL)) throw new Error(`Unsupported PNG: color type ${colorType}.`);
  if (interlace !== 0) throw new Error('Unsupported PNG: interlaced images are not supported.');

  const bpp = BYTES_PER_PIXEL[colorType];
  const idat = Buffer.concat(chunks.filter((c) => c.type === 'IDAT').map((c) => c.data));
  if (idat.length === 0) throw new Error('Not a PNG file: missing IDAT.');

  let raw;
  try {
    raw = zlib.inflateSync(idat);
  } catch {
    throw new Error('Not a PNG file: IDAT decompression failed.');
  }

  const stride = width * bpp;
  if (raw.length !== height * (stride + 1)) throw new Error('Not a PNG file: IDAT size mismatch.');

  const pixels = Buffer.alloc(width * height * bpp);
  let prev = Buffer.alloc(stride);
  for (let y = 0; y < height; y++) {
    const f = raw[y * (stride + 1)];
    const row = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    const cur = pixels.subarray(y * stride, (y + 1) * stride);
    switch (f) {
      case 0: // None
        row.copy(cur);
        break;
      case 1: // Sub
        for (let i = 0; i < stride; i++) cur[i] = (row[i] + (i >= bpp ? cur[i - bpp] : 0)) & 0xff;
        break;
      case 2: // Up
        for (let i = 0; i < stride; i++) cur[i] = (row[i] + prev[i]) & 0xff;
        break;
      case 3: // Average
        for (let i = 0; i < stride; i++) {
          const a = i >= bpp ? cur[i - bpp] : 0;
          cur[i] = (row[i] + ((a + prev[i]) >> 1)) & 0xff;
        }
        break;
      case 4: // Paeth
        for (let i = 0; i < stride; i++) {
          const a = i >= bpp ? cur[i - bpp] : 0;
          const b = prev[i];
          const c = i >= bpp ? prev[i - bpp] : 0;
          cur[i] = (row[i] + paethPredictor(a, b, c)) & 0xff;
        }
        break;
      default:
        throw new Error(`Not a PNG file: unknown filter type ${f}.`);
    }
    prev = Buffer.from(cur);
  }

  // Normalize everything to RGBA.
  let rgba;
  if (colorType === 6) {
    rgba = pixels;
  } else {
    rgba = Buffer.alloc(width * height * 4);
    for (let i = 0, j = 0; i < pixels.length; j += 4) {
      if (colorType === 0) {
        const v = pixels[i++];
        rgba[j] = v; rgba[j + 1] = v; rgba[j + 2] = v; rgba[j + 3] = 255;
      } else { // color type 2
        rgba[j] = pixels[i++]; rgba[j + 1] = pixels[i++]; rgba[j + 2] = pixels[i++]; rgba[j + 3] = 255;
      }
    }
  }
  return { width, height, data: rgba };
}

function encodePng(width, height, rgba, extraChunks) {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0) {
    throw new Error('encodePng: bad dimensions.');
  }
  if (!Buffer.isBuffer(rgba) || rgba.length !== width * height * 4) {
    throw new Error('encodePng: pixel buffer size mismatch.');
  }
  const stride = width * 4;
  const raw = Buffer.alloc(height * (stride + 1));
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter type 0 (None) on every scanline
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const comp = zlib.deflateSync(raw);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type: RGBA
  ihdr[10] = 0; // compression method
  ihdr[11] = 0; // filter method
  ihdr[12] = 0; // interlace: none

  const parts = [PNG_SIGNATURE, makeChunk('IHDR', ihdr)];
  for (const ch of extraChunks || []) parts.push(makeChunk(ch.type, ch.data));
  for (let o = 0; o < comp.length; o += 32768) {
    parts.push(makeChunk('IDAT', comp.subarray(o, o + 32768)));
  }
  parts.push(makeChunk('IEND', Buffer.alloc(0)));
  return Buffer.concat(parts);
}

module.exports = {
  PNG_SIGNATURE,
  crc32,
  makeChunk,
  parseChunks,
  textChunkData,
  paethPredictor,
  decodePng,
  encodePng,
};
