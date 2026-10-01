'use strict';
/*
 * X-SHATTER core — real cryptography, no toy obfuscation.
 *
 * FILE FORMAT (v1):
 *   - PNG, same width/height as input, 8-bit RGBA (color type 6).
 *   - IDAT pixel bytes = AES-256-GCM ciphertext of the raw RGBA pixel
 *     buffer (row-major, top-to-bottom left-to-right, NO PNG filter
 *     bytes in the plaintext — encryption happens on raw pixels only).
 *   - Exactly one tEXt chunk, keyword "X-Shatter", whose text is
 *     base64url (no padding) of:
 *       {"v":1,"salt":"…","nonce":"…","tag":"…","w":W,"h":H}
 *     salt = 16 bytes, nonce = 12 bytes, tag = 16-byte GCM auth tag.
 *   - GCM AAD = ASCII "X-SHATTER/v1/{w}x{h}" — tampering with the
 *     stored dimensions fails authentication.
 *   - KDF: PBKDF2-HMAC-SHA256, 600,000 iterations, fresh 16-byte salt
 *     per file, 32-byte key. (PBKDF2 is used deliberately so the Node
 *     CLI and the browser dashboard — WebCrypto has no scrypt —
 *     derive identical keys.)
 *   - All input ancillary chunks are stripped: output contains only
 *     IHDR, the X-Shatter tEXt, IDAT, IEND.
 *
 * Wrong passphrase / any tampering -> authentication failure, and no
 * output file is ever written. Decryption happens fully in memory and
 * is verified BEFORE anything touches disk.
 */

const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { decodePng, encodePng, parseChunks, textChunkData } = require('./png');

const HEADER_KEYWORD = 'X-Shatter';
const PBKDF2_ITERATIONS = 600000;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const MAX_DIM = 30000; // sanity cap against absurd allocation claims

const ERR_NOT_SHATTER = 'Not a SHATTER file: missing X-Shatter header.';
const ERR_AUTH = 'Authentication failed: wrong passphrase or corrupted file.';
const ERR_EMPTY_PASS = 'Passphrase must not be empty.';

function aadFor(w, h) {
  return `X-SHATTER/v1/${w}x${h}`;
}

function findHeaderChunk(chunks) {
  const kw = Buffer.from(HEADER_KEYWORD, 'latin1');
  return chunks.find((c) =>
    c.type === 'tEXt' &&
    c.data.length > kw.length + 1 &&
    c.data.subarray(0, kw.length).equals(kw) &&
    c.data[kw.length] === 0
  );
}

/** Parse + validate the X-Shatter header. Throws NOT_SHATTER or AUTH errors. */
function parseHeader(pngBuf) {
  let chunks;
  try {
    chunks = parseChunks(pngBuf);
  } catch {
    throw new Error(ERR_NOT_SHATTER);
  }
  const t = findHeaderChunk(chunks);
  if (!t) throw new Error(ERR_NOT_SHATTER);

  let header;
  try {
    const b64 = t.data.subarray(HEADER_KEYWORD.length + 1).toString('latin1');
    header = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
  } catch {
    throw new Error(ERR_AUTH);
  }

  const okShape =
    header && header.v === 1 &&
    Number.isInteger(header.w) && Number.isInteger(header.h) &&
    header.w > 0 && header.h > 0 && header.w <= MAX_DIM && header.h <= MAX_DIM &&
    typeof header.salt === 'string' && typeof header.nonce === 'string' && typeof header.tag === 'string';
  if (!okShape) throw new Error(ERR_AUTH);

  let salt, nonce, tag;
  try {
    salt = Buffer.from(header.salt, 'base64url');
    nonce = Buffer.from(header.nonce, 'base64url');
    tag = Buffer.from(header.tag, 'base64url');
  } catch {
    throw new Error(ERR_AUTH);
  }
  if (salt.length !== SALT_LEN || nonce.length !== NONCE_LEN || tag.length !== TAG_LEN) {
    throw new Error(ERR_AUTH);
  }

  const ihdr = chunks.find((c) => c.type === 'IHDR');
  if (!ihdr || ihdr.data.readUInt32BE(0) !== header.w || ihdr.data.readUInt32BE(4) !== header.h) {
    throw new Error(ERR_AUTH);
  }
  return { chunks, header, salt, nonce, tag, w: header.w, h: header.h };
}

function deriveKey(passphrase, salt) {
  return crypto.pbkdf2Sync(String(passphrase), salt, PBKDF2_ITERATIONS, KEY_LEN, 'sha256');
}

/**
 * Encrypt a raw RGBA buffer. Returns a complete SHATTER PNG buffer.
 * opts.salt / opts.nonce (Buffers) may be supplied for test vectors;
 * otherwise fresh random values are generated.
 */
function encryptPixels(rgba, w, h, passphrase, opts = {}) {
  if (passphrase === undefined || passphrase === null || String(passphrase).length === 0) {
    throw new Error(ERR_EMPTY_PASS);
  }
  if (!Number.isInteger(w) || !Number.isInteger(h) || w <= 0 || h <= 0 ||
      !Buffer.isBuffer(rgba) || rgba.length !== w * h * 4) {
    throw new Error('Pixel buffer size mismatch.');
  }
  const salt = opts.salt || crypto.randomBytes(SALT_LEN);
  const nonce = opts.nonce || crypto.randomBytes(NONCE_LEN);
  if (salt.length !== SALT_LEN || nonce.length !== NONCE_LEN) throw new Error('Bad salt/nonce length.');

  const key = deriveKey(passphrase, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(aadFor(w, h), 'ascii'));
  const ct = Buffer.concat([cipher.update(rgba), cipher.final()]);
  const tag = cipher.getAuthTag();

  const header = {
    v: 1,
    salt: salt.toString('base64url'),
    nonce: nonce.toString('base64url'),
    tag: tag.toString('base64url'),
    w, h,
  };
  const text = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  return encodePng(w, h, ct, [{ type: 'tEXt', data: textChunkData(HEADER_KEYWORD, text) }]);
}

/**
 * Decrypt a SHATTER PNG buffer. Returns {width, height, data} with
 * byte-identical pixels, or throws NOT_SHATTER / AUTH errors.
 * Fully in-memory — nothing is written anywhere.
 */
function decryptPixels(pngBuf, passphrase) {
  if (passphrase === undefined || passphrase === null || String(passphrase).length === 0) {
    throw new Error(ERR_EMPTY_PASS);
  }
  const { chunks, salt, nonce, tag, w, h } = parseHeader(pngBuf);

  const idat = Buffer.concat(chunks.filter((c) => c.type === 'IDAT').map((c) => c.data));
  let raw;
  try {
    raw = zlib.inflateSync(idat);
  } catch {
    throw new Error(ERR_AUTH);
  }
  const stride = w * 4;
  if (raw.length !== h * (stride + 1)) throw new Error(ERR_AUTH);

  const ct = Buffer.alloc(w * h * 4);
  for (let y = 0; y < h; y++) {
    const base = y * (stride + 1);
    if (raw[base] !== 0) throw new Error(ERR_AUTH); // we always write filter 0
    raw.copy(ct, y * stride, base + 1, base + 1 + stride);
  }

  const key = deriveKey(passphrase, salt);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);
    decipher.setAAD(Buffer.from(aadFor(w, h), 'ascii'));
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    if (pt.length !== w * h * 4) throw new Error(ERR_AUTH);
    return { width: w, height: h, data: pt };
  } catch (e) {
    if (e && e.message === ERR_AUTH) throw e;
    throw new Error(ERR_AUTH);
  }
}

/** Read header info without decrypting. Throws NOT_SHATTER if absent. */
function infoFile(pngBuf) {
  const { header, salt, nonce } = parseHeader(pngBuf);
  return {
    version: header.v,
    width: header.w,
    height: header.h,
    saltFp: salt.subarray(0, 4).toString('hex'),
    nonceFp: nonce.subarray(0, 4).toString('hex'),
  };
}

/** Strong random passphrase: 32 random bytes, base64url (43 chars). */
function generatePassphrase() {
  return crypto.randomBytes(32).toString('base64url');
}

module.exports = {
  HEADER_KEYWORD,
  PBKDF2_ITERATIONS,
  SALT_LEN,
  NONCE_LEN,
  TAG_LEN,
  KEY_LEN,
  ERR_NOT_SHATTER,
  ERR_AUTH,
  ERR_EMPTY_PASS,
  aadFor,
  deriveKey,
  encryptPixels,
  decryptPixels,
  infoFile,
  generatePassphrase,
  decodePng,
  encodePng,
};
