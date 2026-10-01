'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  crc32, makeChunk, parseChunks, decodePng, encodePng, textChunkData, paethPredictor,
} = require('../src/png');
const { makePatternImage, buildRawPng, rgbRows, grayRows, rgbaRows } = require('./util');

test('paeth predictor matches known values', () => {
  assert.equal(paethPredictor(0, 0, 0), 0);
  assert.equal(paethPredictor(10, 20, 30), 10); // p=-20 → pa smallest
  assert.equal(paethPredictor(10, 20, 5), 20);  // p=25 → pb smallest
  assert.equal(paethPredictor(5, 20, 10), 20);  // p=15 → pb == pc, b wins
  assert.equal(paethPredictor(100, 100, 100), 100);
});

test('crc32 matches the standard check value', () => {
  assert.equal(crc32(Buffer.from('123456789', 'ascii')), 0xcbf43926);
});

test('encode/decode round-trip is byte-identical (RGBA)', () => {
  const img = makePatternImage(9, 7);
  const png = encodePng(img.width, img.height, img.data);
  const back = decodePng(png);
  assert.equal(back.width, 9);
  assert.equal(back.height, 7);
  assert.deepEqual(back.data, img.data);
});

for (const filterType of [0, 1, 2, 3, 4]) {
  test(`unfiltering works for filter type ${filterType}`, () => {
    const img = makePatternImage(6, 5);
    const png = buildRawPng(img.width, img.height, 6, filterType, rgbaRows(img));
    const back = decodePng(png);
    assert.deepEqual(back.data, img.data);
  });
}

test('grayscale (color type 0) converts to RGBA with full alpha', () => {
  const img = makePatternImage(5, 4);
  const png = buildRawPng(img.width, img.height, 0, 2, grayRows(img));
  const back = decodePng(png);
  assert.equal(back.data.length, img.width * img.height * 4);
  const rows = grayRows(img);
  for (let y = 0; y < img.height; y++) {
    for (let x = 0; x < img.width; x++) {
      const i = (y * img.width + x) * 4;
      const v = rows[y][x];
      assert.equal(back.data[i], v);
      assert.equal(back.data[i + 1], v);
      assert.equal(back.data[i + 2], v);
      assert.equal(back.data[i + 3], 255);
    }
  }
});

test('RGB (color type 2) converts to RGBA with full alpha', () => {
  const img = makePatternImage(5, 4);
  const png = buildRawPng(img.width, img.height, 2, 4, rgbRows(img));
  const back = decodePng(png);
  for (let y = 0; y < img.height; y++) {
    for (let x = 0; x < img.width; x++) {
      const i = (y * img.width + x) * 4;
      const s = (y * img.width + x) * 4;
      assert.equal(back.data[i], img.data[s]);
      assert.equal(back.data[i + 1], img.data[s + 1]);
      assert.equal(back.data[i + 2], img.data[s + 2]);
      assert.equal(back.data[i + 3], 255);
    }
  }
});

test('multi-IDAT files decode correctly', () => {
  // incompressible random pixels -> deflate output exceeds the 32k IDAT split
  const crypto = require('node:crypto');
  const w = 256, h = 256;
  const data = crypto.randomBytes(w * h * 4);
  const png = encodePng(w, h, data); // encoder splits IDAT at 32k
  const chunks = parseChunks(png);
  assert.ok(chunks.filter((c) => c.type === 'IDAT').length > 1, 'expected multiple IDAT chunks');
  assert.deepEqual(decodePng(png).data, data);
});

test('bad signature is rejected', () => {
  assert.throws(() => decodePng(Buffer.from('not a png file at all')), /bad signature/);
});

test('CRC mismatch is rejected', () => {
  const img = makePatternImage(4, 4);
  const png = Buffer.from(encodePng(img.width, img.height, img.data));
  png[20] ^= 0x01; // corrupt a byte inside IHDR data
  assert.throws(() => decodePng(png), /CRC mismatch/);
});

test('interlaced images are rejected with a clear error', () => {
  const img = makePatternImage(4, 4);
  const png = Buffer.from(encodePng(img.width, img.height, img.data));
  // IHDR is the first chunk: data starts at offset 16, interlace byte at 16+12
  png[16 + 12] = 1;
  // fix the CRC so we reach the interlace check (recompute over type+data)
  const typeAndData = png.subarray(12, 16 + 13);
  const c = crc32(typeAndData);
  png.writeUInt32BE(c, 16 + 13);
  assert.throws(() => decodePng(png), /interlaced/);
});

test('unknown filter type is rejected', () => {
  const img = makePatternImage(4, 4);
  const png = buildRawPng(img.width, img.height, 6, 0, rgbaRows(img));
  // flip the first scanline's filter byte 0 -> 7, then fix IDAT CRC
  const chunks = parseChunks(png);
  const idatIdx = chunks.findIndex((c) => c.type === 'IDAT');
  void idatIdx;
  // easier: rebuild via zlib — decode IDAT, patch, re-encode chunk manually
  const zlib = require('node:zlib');
  const raw = zlib.inflateSync(chunks.find((c) => c.type === 'IDAT').data);
  raw[0] = 7;
  const sig = png.subarray(0, 8);
  const parts = [sig];
  for (const ch of chunks) {
    if (ch.type === 'IDAT') parts.push(makeChunk('IDAT', zlib.deflateSync(raw)));
    else if (ch.type !== 'IEND') parts.push(makeChunk(ch.type, ch.data));
  }
  parts.push(makeChunk('IEND', Buffer.alloc(0)));
  assert.throws(() => decodePng(Buffer.concat(parts)), /unknown filter type 7/);
});

test('textChunkData builds keyword NUL text payloads', () => {
  const d = textChunkData('X-Shatter', 'aGVsbG8');
  assert.deepEqual(d.subarray(0, 10), Buffer.from('X-Shatter\0', 'latin1'));
  assert.equal(d.subarray(10).toString('latin1'), 'aGVsbG8');
});
