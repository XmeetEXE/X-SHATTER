'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const shatter = require('../src/shatter');
const { encodePng, parseChunks, makeChunk, textChunkData } = require('../src/png');
const { makePatternImage, buildRawPng, rgbRows, grayRows, rgbaRows } = require('./util');

const PASS = 'correct horse battery staple';

function headerOf(pngBuf) {
  const chunks = parseChunks(pngBuf);
  const kw = Buffer.from('X-Shatter', 'latin1');
  const t = chunks.find((c) => c.type === 'tEXt' && c.data.subarray(0, kw.length).equals(kw));
  const b64 = t.data.subarray(kw.length + 1).toString('latin1');
  return { chunks, header: JSON.parse(Buffer.from(b64, 'base64url').toString('utf8')), t };
}

test('round-trip RGBA image: decrypt(encrypt(x)) is pixel-identical', () => {
  const img = makePatternImage(11, 8);
  const file = shatter.encryptPixels(img.data, img.width, img.height, PASS);
  const back = shatter.decryptPixels(file, PASS);
  assert.equal(back.width, img.width);
  assert.equal(back.height, img.height);
  assert.deepEqual(back.data, img.data);
});

test('round-trip RGB input image', () => {
  const img = makePatternImage(7, 6);
  const png = buildRawPng(img.width, img.height, 2, 1, rgbRows(img));
  const decoded = shatter.decodePng(png);
  const file = shatter.encryptPixels(decoded.data, decoded.width, decoded.height, PASS);
  assert.deepEqual(shatter.decryptPixels(file, PASS).data, decoded.data);
});

test('round-trip grayscale input image', () => {
  const img = makePatternImage(7, 6);
  const png = buildRawPng(img.width, img.height, 0, 3, grayRows(img));
  const decoded = shatter.decodePng(png);
  const file = shatter.encryptPixels(decoded.data, decoded.width, decoded.height, PASS);
  assert.deepEqual(shatter.decryptPixels(file, PASS).data, decoded.data);
});

test('1x1 image round-trips', () => {
  const data = Buffer.from([1, 2, 3, 4]);
  const file = shatter.encryptPixels(data, 1, 1, PASS);
  assert.deepEqual(shatter.decryptPixels(file, PASS).data, data);
});

test('wrong passphrase -> authentication error', () => {
  const img = makePatternImage(8, 8);
  const file = shatter.encryptPixels(img.data, img.width, img.height, PASS);
  assert.throws(() => shatter.decryptPixels(file, 'wrong passphrase'), new RegExp(shatter.ERR_AUTH));
});

test('flipping one byte in IDAT -> authentication failure', () => {
  const img = makePatternImage(8, 8);
  const file = shatter.encryptPixels(img.data, img.width, img.height, PASS);
  const chunks = parseChunks(file);
  const parts = [file.subarray(0, 8)];
  let flipped = false;
  for (const ch of chunks) {
    if (ch.type === 'IDAT' && !flipped) {
      const d = Buffer.from(ch.data);
      d[Math.floor(d.length / 2)] ^= 0x01;
      flipped = true;
      parts.push(makeChunk('IDAT', d));
    } else {
      parts.push(makeChunk(ch.type, ch.data));
    }
  }
  assert.ok(flipped);
  assert.throws(() => shatter.decryptPixels(Buffer.concat(parts), PASS), new RegExp(shatter.ERR_AUTH));
});

test('tampering with w/h in the tEXt header -> authentication failure (AAD)', () => {
  const img = makePatternImage(8, 8);
  const file = shatter.encryptPixels(img.data, img.width, img.height, PASS);
  const { chunks, header, t } = headerOf(file);
  header.w = 16; // lie about dimensions
  const text = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const parts = [file.subarray(0, 8)];
  for (const ch of chunks) {
    if (ch === t) parts.push(makeChunk('tEXt', textChunkData('X-Shatter', text)));
    else parts.push(makeChunk(ch.type, ch.data));
  }
  assert.throws(() => shatter.decryptPixels(Buffer.concat(parts), PASS), new RegExp(shatter.ERR_AUTH));
});

test('tampering with the GCM tag -> authentication failure', () => {
  const img = makePatternImage(8, 8);
  const file = shatter.encryptPixels(img.data, img.width, img.height, PASS);
  const { chunks, header, t } = headerOf(file);
  const tag = Buffer.from(header.tag, 'base64url');
  tag[0] ^= 0x01;
  header.tag = tag.toString('base64url');
  const text = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const parts = [file.subarray(0, 8)];
  for (const ch of chunks) {
    if (ch === t) parts.push(makeChunk('tEXt', textChunkData('X-Shatter', text)));
    else parts.push(makeChunk(ch.type, ch.data));
  }
  assert.throws(() => shatter.decryptPixels(Buffer.concat(parts), PASS), new RegExp(shatter.ERR_AUTH));
});

test('decrypting a normal PNG -> clean "not a SHATTER file" error', () => {
  const img = makePatternImage(6, 6);
  const png = encodePng(img.width, img.height, img.data);
  assert.throws(() => shatter.decryptPixels(png, PASS), new RegExp(shatter.ERR_NOT_SHATTER));
  assert.throws(() => shatter.infoFile(png), new RegExp(shatter.ERR_NOT_SHATTER));
});

test('decrypting garbage -> clean "not a SHATTER file" error', () => {
  assert.throws(() => shatter.decryptPixels(Buffer.from('hello world'), PASS),
    new RegExp(shatter.ERR_NOT_SHATTER));
});

test('metadata stripping: output has only IHDR + X-Shatter tEXt + IDAT + IEND', () => {
  const img = makePatternImage(6, 6);
  const sneaky = buildRawPng(img.width, img.height, 6, 0, rgbaRows(img), [
    { type: 'tEXt', data: textChunkData('Comment', 'secret comment') },
    { type: 'tEXt', data: textChunkData('Author', 'someone') },
  ]);
  const decoded = shatter.decodePng(sneaky);
  const file = shatter.encryptPixels(decoded.data, decoded.width, decoded.height, PASS);
  const types = parseChunks(file).map((c) => c.type);
  const nonIdat = types.filter((t) => t !== 'IDAT');
  assert.deepEqual(nonIdat, ['IHDR', 'tEXt', 'IEND']);
  const { header } = headerOf(file);
  assert.equal(header.v, 1);
  // the one tEXt chunk is ours
  const kw = Buffer.from('X-Shatter', 'latin1');
  const t = parseChunks(file).find((c) => c.type === 'tEXt');
  assert.ok(t.data.subarray(0, kw.length).equals(kw));
});

test('fresh salt+nonce: encrypting twice gives different files, both decrypt', () => {
  const img = makePatternImage(8, 8);
  const a = shatter.encryptPixels(img.data, img.width, img.height, PASS);
  const b = shatter.encryptPixels(img.data, img.width, img.height, PASS);
  assert.ok(!a.equals(b), 'two encryptions must differ (fresh salt+nonce)');
  assert.deepEqual(shatter.decryptPixels(a, PASS).data, img.data);
  assert.deepEqual(shatter.decryptPixels(b, PASS).data, img.data);
  const ha = headerOf(a).header, hb = headerOf(b).header;
  assert.notEqual(ha.salt, hb.salt);
  assert.notEqual(ha.nonce, hb.nonce);
});

test('shattered file really looks like noise: IDAT bytes are ~uniform, filter bytes all zero', () => {
  const img = makePatternImage(32, 32); // solid-ish pattern compresses; ciphertext must not
  const file = shatter.encryptPixels(img.data, img.width, img.height, PASS);
  const idat = Buffer.concat(parseChunks(file).filter((c) => c.type === 'IDAT').map((c) => c.data));
  const raw = zlib.inflateSync(idat);
  const stride = img.width * 4;
  for (let y = 0; y < img.height; y++) assert.equal(raw[y * (stride + 1)], 0);
  // byte histogram of ciphertext should be roughly flat (chi-square-ish sanity)
  const hist = new Array(256).fill(0);
  for (let y = 0; y < img.height; y++) {
    for (let i = 0; i < stride; i++) hist[raw[y * (stride + 1) + 1 + i]]++;
  }
  const expected = (img.width * img.height * 4) / 256;
  let chi2 = 0;
  for (const h of hist) chi2 += ((h - expected) ** 2) / expected;
  assert.ok(chi2 < 400, `ciphertext bytes should look uniform (chi2=${chi2.toFixed(1)})`);
});

test('empty passphrase is rejected', () => {
  const img = makePatternImage(4, 4);
  assert.throws(() => shatter.encryptPixels(img.data, 4, 4, ''), /must not be empty/);
  const file = shatter.encryptPixels(img.data, 4, 4, PASS);
  assert.throws(() => shatter.decryptPixels(file, ''), /must not be empty/);
});

test('info reads the header without decrypting', () => {
  const img = makePatternImage(13, 9);
  const file = shatter.encryptPixels(img.data, img.width, img.height, PASS);
  const info = shatter.infoFile(file);
  assert.equal(info.version, 1);
  assert.equal(info.width, 13);
  assert.equal(info.height, 9);
  assert.match(info.saltFp, /^[0-9a-f]{8}$/);
  assert.match(info.nonceFp, /^[0-9a-f]{8}$/);
  const { header } = headerOf(file);
  assert.equal(info.saltFp, Buffer.from(header.salt, 'base64url').subarray(0, 4).toString('hex'));
});

test('AAD string format is exactly as specified', () => {
  assert.equal(shatter.aadFor(800, 600), 'X-SHATTER/v1/800x600');
});

test('deterministic vector: fixed salt+nonce+passphrase decrypts (regression pin)', () => {
  const pixels = Buffer.from([
    255, 0, 0, 255, 0, 255, 0, 255,
    0, 0, 255, 255, 255, 255, 255, 255,
  ]);
  const salt = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const nonce = Buffer.from('00112233445566778899aabb', 'hex');
  const file = shatter.encryptPixels(pixels, 2, 2, 'x-shatter-vector-01', { salt, nonce });
  const back = shatter.decryptPixels(file, 'x-shatter-vector-01');
  assert.deepEqual(back.data, pixels);
  // pinned: first 16 ciphertext bytes of this exact vector (guards against
  // accidental changes to KDF/AAD/cipher layout — interop depends on it)
  const idat = Buffer.concat(parseChunks(file).filter((c) => c.type === 'IDAT').map((c) => c.data));
  const raw = zlib.inflateSync(idat);
  const ct = Buffer.alloc(16);
  raw.copy(ct, 0, 1, 9); raw.copy(ct, 8, 10, 18);
  assert.equal(ct.toString('hex'), '8836828e8b0aa02b9822db5da51764d4');
});
