'use strict';
/*
 * CLI <-> dashboard interop.
 *
 * The dashboard (public/app.js) re-implements the format with WebCrypto:
 *   PBKDF2-HMAC-SHA256, 600,000 iterations -> 32-byte key
 *   AES-256-GCM, 12-byte nonce, AAD = "X-SHATTER/v1/{w}x{h}"
 * These tests prove that flow interoperates with the Node CLI by running
 * the exact WebCrypto calls the dashboard uses (via Node's own WebCrypto)
 * against CLI-produced and CLI-consumed files.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const shatter = require('../src/shatter');
const { encodePng, parseChunks, textChunkData } = require('../src/png');
const { makePatternImage } = require('./util');

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();

async function webcryptoDerive(pass, salt) {
  const km = await subtle.importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, km, 256);
  return Buffer.from(bits);
}

function parseShatterFile(file) {
  const chunks = parseChunks(file);
  const kw = Buffer.from('X-Shatter', 'latin1');
  const t = chunks.find((c) => c.type === 'tEXt' && c.data.subarray(0, kw.length).equals(kw));
  assert.ok(t, 'expected X-Shatter header');
  const header = JSON.parse(Buffer.from(t.data.subarray(kw.length + 1).toString('latin1'), 'base64url').toString('utf8'));
  const salt = Buffer.from(header.salt, 'base64url');
  const nonce = Buffer.from(header.nonce, 'base64url');
  const tag = Buffer.from(header.tag, 'base64url');
  const idat = Buffer.concat(chunks.filter((c) => c.type === 'IDAT').map((c) => c.data));
  const raw = zlib.inflateSync(idat);
  const stride = header.w * 4;
  const ct = Buffer.alloc(header.w * header.h * 4);
  for (let y = 0; y < header.h; y++) {
    assert.equal(raw[y * (stride + 1)], 0, 'dashboard/CLI always write filter 0');
    raw.copy(ct, y * stride, y * (stride + 1) + 1, (y + 1) * (stride + 1));
  }
  return { header, salt, nonce, tag, ct };
}

test('WebCrypto PBKDF2 derives the identical key as Node pbkdf2Sync', async () => {
  const pass = 'interop-kdf-check';
  const salt = crypto.randomBytes(16);
  const nodeKey = crypto.pbkdf2Sync(pass, salt, 600000, 32, 'sha256');
  const webKey = await webcryptoDerive(pass, salt);
  assert.deepEqual(webKey, nodeKey);
});

test('dashboard flow (WebCrypto) decrypts CLI-produced files', async () => {
  const img = makePatternImage(10, 7);
  const pass = 'interop-cli-to-web';
  const file = shatter.encryptPixels(img.data, img.width, img.height, pass);
  const { header, salt, nonce, tag, ct } = parseShatterFile(file);

  const keyBits = await webcryptoDerive(pass, salt);
  const key = await subtle.importKey('raw', keyBits, 'AES-GCM', false, ['decrypt']);
  const pt = new Uint8Array(await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: te.encode(`X-SHATTER/v1/${header.w}x${header.h}`),
    },
    key,
    Buffer.concat([ct, tag]), // WebCrypto expects tag appended
  ));
  assert.deepEqual(Buffer.from(pt), img.data);
});

test('CLI decrypts dashboard-produced (WebCrypto-encrypted) files', async () => {
  const img = makePatternImage(9, 6);
  const pass = 'interop-web-to-cli';
  const w = img.width, h = img.height;
  const salt = crypto.randomBytes(16);
  const nonce = crypto.randomBytes(12);

  // Exactly what public/app.js encryptPixels() does:
  const keyBits = await webcryptoDerive(pass, salt);
  const key = await subtle.importKey('raw', keyBits, 'AES-GCM', false, ['encrypt']);
  const full = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: te.encode(`X-SHATTER/v1/${w}x${h}`) },
    key, img.data));
  const ct = Buffer.from(full.slice(0, full.length - 16));
  const tag = Buffer.from(full.slice(full.length - 16));
  const header = {
    v: 1,
    salt: salt.toString('base64url'),
    nonce: nonce.toString('base64url'),
    tag: tag.toString('base64url'),
    w, h,
  };
  const text = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const file = encodePng(w, h, ct, [{ type: 'tEXt', data: textChunkData('X-Shatter', text) }]);

  const back = shatter.decryptPixels(file, pass);
  assert.equal(back.width, w);
  assert.equal(back.height, h);
  assert.deepEqual(back.data, img.data);
});

test('dashboard flow rejects wrong passphrase on CLI files (auth, not garbage)', async () => {
  const img = makePatternImage(6, 6);
  const file = shatter.encryptPixels(img.data, img.width, img.height, 'right-pass');
  const { header, salt, nonce, tag, ct } = parseShatterFile(file);
  const keyBits = await webcryptoDerive('wrong-pass', salt);
  const key = await subtle.importKey('raw', keyBits, 'AES-GCM', false, ['decrypt']);
  await assert.rejects(
    subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: te.encode(`X-SHATTER/v1/${header.w}x${header.h}`) },
      key, Buffer.concat([ct, tag])),
    /OperationError/,
  );
});
