'use strict';
/*
 * X-SHATTER dashboard — WebCrypto + Canvas implementation.
 *
 * Byte-identical FILE FORMAT to the Node CLI (see src/shatter.js):
 *   KDF  PBKDF2-HMAC-SHA256, 600,000 iterations -> 32-byte key
 *        (PBKDF2 is used on both sides deliberately: WebCrypto has no scrypt,
 *         so this is what makes CLI <-> dashboard interop possible)
 *   AEAD AES-256-GCM, fresh 12-byte nonce per file
 *   AAD  ASCII "X-SHATTER/v1/{w}x{h}"
 *   PNG  8-bit RGBA; IDAT = ciphertext of raw RGBA pixels (filter 0);
 *        single tEXt chunk "X-Shatter" with base64url(JSON header);
 *        GCM tag stored in the header, not in the pixel data.
 *
 * WebCrypto's AES-GCM returns ciphertext with the 16-byte tag APPENDED,
 * so we split it off to match the CLI layout (and re-append on decrypt).
 */

const HEADER_KEYWORD = 'X-Shatter';
const ITER = 600000;
// Keep browser-side canvas/crypto allocations bounded for large or hostile files.
const MAX_PIXELS = 12_000_000;
const SALT_LEN = 16, NONCE_LEN = 12, TAG_LEN = 16;
const AUTH_FAIL = 'Authentication failed: wrong passphrase or corrupted file.';
const NOT_SHATTER = 'Not a SHATTER file: missing X-Shatter header.';

const te = new TextEncoder();
const td = new TextDecoder();

/* ---------------- CRC32 ---------------- */
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(u8) {
  let c = 0xffffffff;
  for (let i = 0; i < u8.length; i++) c = CRC_TABLE[(c ^ u8[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/* ---------------- base64url (no padding) ---------------- */
function b64urlEncode(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

function concat(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function aadFor(w, h) { return `X-SHATTER/v1/${w}x${h}`; }

/* ---------------- PNG chunks ---------------- */
const PNG_SIG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function chunkBytes(type, data) {
  const td8 = te.encode(type);
  const out = new Uint8Array(12 + data.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, data.length);
  out.set(td8, 4);
  out.set(data, 8);
  dv.setUint32(8 + data.length, crc32(out.slice(4, 8 + data.length)));
  return out;
}

function parsePngChunks(u8) {
  for (let i = 0; i < 8; i++) {
    if (u8[i] !== PNG_SIG[i]) throw new Error('Not a PNG file: bad signature.');
  }
  const chunks = [];
  let off = 8;
  while (off + 8 <= u8.length) {
    const len = (((u8[off] << 24) | (u8[off + 1] << 16) | (u8[off + 2] << 8) | u8[off + 3]) >>> 0);
    const type = String.fromCharCode(u8[off + 4], u8[off + 5], u8[off + 6], u8[off + 7]);
    if (off + 12 + len > u8.length) throw new Error('Not a PNG file: truncated chunk.');
    const data = u8.slice(off + 8, off + 8 + len);
    const want = (((u8[off + 8 + len] << 24) | (u8[off + 8 + len + 1] << 16) |
                   (u8[off + 8 + len + 2] << 8) | u8[off + 8 + len + 3]) >>> 0);
    const got = crc32(u8.slice(off + 4, off + 8 + len));
    if (want !== got) throw new Error('Not a PNG file: CRC mismatch in ' + type + ' chunk.');
    chunks.push({ type, data });
    off += 12 + len;
    if (type === 'IEND') break;
  }
  return chunks;
}

async function deflateBytes(u8) {
  // Drain readable concurrently with writes. Waiting for write/close before
  // reading can deadlock once stream backpressure is reached on large images.
  const cs = new CompressionStream('deflate');
  const writer = cs.writable.getWriter();
  const reader = cs.readable.getReader();
  const outputPromise = (async () => {
    const parts = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
    }
    return concat(parts);
  })();
  const inputPromise = (async () => {
    await writer.write(u8);
    await writer.close();
  })();
  const [, output] = await Promise.all([inputPromise, outputPromise]);
  return output;
}

async function inflateBytes(u8, maxOutputBytes = Infinity) {
  // Read while writing to avoid a backpressure deadlock on larger payloads.
  const ds = new DecompressionStream('deflate');
  const writer = ds.writable.getWriter();
  const reader = ds.readable.getReader();
  const outputPromise = (async () => {
    const parts = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxOutputBytes) {
        await reader.cancel();
        throw new Error('Decoded image data exceeds the supported size.');
      }
      parts.push(value);
    }
    return concat(parts);
  })();
  const inputPromise = (async () => {
    await writer.write(u8);
    await writer.close();
  })();
  const [, output] = await Promise.all([inputPromise, outputPromise]);
  return output;
}

async function buildPng(w, h, scanlines, extraChunks) {
  const ihdr = new Uint8Array(13);
  const dv = new DataView(ihdr.buffer);
  dv.setUint32(0, w); dv.setUint32(4, h);
  ihdr[8] = 8; ihdr[9] = 6; // 8-bit RGBA
  const parts = [PNG_SIG, chunkBytes('IHDR', ihdr)];
  for (const ch of extraChunks || []) parts.push(chunkBytes(ch.type, ch.data));
  parts.push(chunkBytes('IDAT', await deflateBytes(scanlines)));
  parts.push(chunkBytes('IEND', new Uint8Array(0)));
  return concat(parts);
}

function findHeaderChunk(chunks) {
  const kw = te.encode(HEADER_KEYWORD);
  return chunks.find((c) =>
    c.type === 'tEXt' && c.data.length > kw.length + 1 &&
    c.data.slice(0, kw.length).every((b, i) => b === kw[i]) &&
    c.data[kw.length] === 0
  );
}

function readHeader(u8) {
  let chunks;
  try { chunks = parsePngChunks(u8); }
  catch { throw new Error(NOT_SHATTER); }
  const t = findHeaderChunk(chunks);
  if (!t) throw new Error(NOT_SHATTER);
  let header;
  try {
    header = JSON.parse(td.decode(b64urlDecode(td.decode(t.data.slice(HEADER_KEYWORD.length + 1)))));
  } catch { throw new Error(AUTH_FAIL); }
  if (!header || header.v !== 1 ||
      !Number.isInteger(header.w) || !Number.isInteger(header.h) ||
      header.w <= 0 || header.h <= 0 || header.w > 30000 || header.h > 30000 ||
      header.w * header.h > MAX_PIXELS ||
      typeof header.salt !== 'string' || typeof header.nonce !== 'string' || typeof header.tag !== 'string') {
    throw new Error(AUTH_FAIL);
  }
  const salt = b64urlDecode(header.salt);
  const nonce = b64urlDecode(header.nonce);
  const tag = b64urlDecode(header.tag);
  if (salt.length !== SALT_LEN || nonce.length !== NONCE_LEN || tag.length !== TAG_LEN) {
    throw new Error(AUTH_FAIL);
  }
  const ihdr = chunks.find((c) => c.type === 'IHDR');
  if (!ihdr || ihdr.data.length !== 13) throw new Error(AUTH_FAIL);
  const idv = new DataView(ihdr.data.buffer, ihdr.data.byteOffset, ihdr.data.byteLength);
  if (idv.getUint32(0) !== header.w || idv.getUint32(4) !== header.h) {
    throw new Error(AUTH_FAIL);
  }
  return { chunks, salt, nonce, tag, w: header.w, h: header.h };
}

/* ---------------- crypto ---------------- */

async function deriveKeyBits(pass, saltU8) {
  const km = await crypto.subtle.importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltU8, iterations: ITER, hash: 'SHA-256' }, km, 256);
  return new Uint8Array(bits);
}

async function encryptPixels(pixels, w, h, pass) {
  if (!pass) throw new Error('Passphrase must not be empty.');
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const keyBits = await deriveKeyBits(pass, salt);
  const key = await crypto.subtle.importKey('raw', keyBits, 'AES-GCM', false, ['encrypt']);
  const full = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: te.encode(aadFor(w, h)) }, key, pixels));
  const ct = full.slice(0, full.length - TAG_LEN);   // WebCrypto appends the tag…
  const tag = full.slice(full.length - TAG_LEN);     // …we store it in the header like the CLI
  const header = {
    v: 1,
    salt: b64urlEncode(salt), nonce: b64urlEncode(nonce), tag: b64urlEncode(tag),
    w, h,
  };
  const text = b64urlEncode(te.encode(JSON.stringify(header)));
  const tdata = concat([te.encode(HEADER_KEYWORD), new Uint8Array([0]), te.encode(text)]);
  const stride = w * 4;
  const scan = new Uint8Array(h * (stride + 1));
  for (let y = 0; y < h; y++) {
    scan[y * (stride + 1)] = 0;
    scan.set(ct.subarray(y * stride, (y + 1) * stride), y * (stride + 1) + 1);
  }
  const png = await buildPng(w, h, scan, [{ type: 'tEXt', data: tdata }]);
  return { png, noise: ct };
}

async function decryptPixels(u8, pass) {
  if (!pass) throw new Error('Passphrase must not be empty.');
  const { chunks, salt, nonce, tag, w, h } = readHeader(u8);
  const idat = concat(chunks.filter((c) => c.type === 'IDAT').map((c) => c.data));
  let raw;
  try { raw = await inflateBytes(idat, h * (w * 4 + 1)); }
  catch { throw new Error(AUTH_FAIL); }
  const stride = w * 4;
  if (raw.length !== h * (stride + 1)) throw new Error(AUTH_FAIL);
  const ct = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) {
    const base = y * (stride + 1);
    if (raw[base] !== 0) throw new Error(AUTH_FAIL);
    ct.set(raw.subarray(base + 1, base + 1 + stride), y * stride);
  }
  const keyBits = await deriveKeyBits(pass, salt);
  const key = await crypto.subtle.importKey('raw', keyBits, 'AES-GCM', false, ['decrypt']);
  let pt;
  try {
    pt = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: te.encode(aadFor(w, h)) },
      key, concat([ct, tag])));
  } catch { throw new Error(AUTH_FAIL); }
  return { w, h, pixels: pt };
}

/* ---------------- UI ---------------- */

function $(id) { return document.getElementById(id); }

function setStatus(el, msg, cls) {
  el.textContent = msg;
  el.className = 'status' + (cls ? ' ' + cls : '');
}

function drawPreview(canvas, pixels, w, h) {
  canvas.width = w; canvas.height = h;
  const ctx = canvas.getContext('2d');
  ctx.putImageData(new ImageData(new Uint8ClampedArray(pixels), w, h), 0, 0);
}

function clearCanvas(canvas) {
  canvas.width = 2; canvas.height = 2;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#000'; ctx.fillRect(0, 0, 2, 2);
}

function wireDrop(dropEl, fileEl, onFile) {
  dropEl.addEventListener('click', () => fileEl.click());
  fileEl.addEventListener('change', () => { if (fileEl.files[0]) onFile(fileEl.files[0]); });
  ['dragenter', 'dragover'].forEach((ev) => dropEl.addEventListener(ev, (e) => {
    e.preventDefault(); dropEl.classList.add('over');
  }));
  ['dragleave', 'drop'].forEach((ev) => dropEl.addEventListener(ev, (e) => {
    e.preventDefault(); dropEl.classList.remove('over');
  }));
  dropEl.addEventListener('drop', (e) => {
    if (e.dataTransfer.files[0]) onFile(e.dataTransfer.files[0]);
  });
}

async function loadPngPixels(file) {
  const bmp = await createImageBitmap(file);
  try {
    if (bmp.width * bmp.height > MAX_PIXELS) {
      throw new Error(`Image is too large for the browser dashboard (max ${MAX_PIXELS.toLocaleString()} pixels). Use the CLI for larger images.`);
    }
    const canvas = document.createElement('canvas');
    canvas.width = bmp.width; canvas.height = bmp.height;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) throw new Error('Browser could not create an image canvas.');
    ctx.drawImage(bmp, 0, 0);
    const id = ctx.getImageData(0, 0, bmp.width, bmp.height);
    return { w: bmp.width, h: bmp.height, pixels: new Uint8Array(id.data.buffer.slice(0)) };
  } finally {
    bmp.close();
  }
}

function downloadLink(el, bytes, name) {
  const blob = new Blob([bytes], { type: 'image/png' });
  if (el.href) URL.revokeObjectURL(el.href);
  el.href = URL.createObjectURL(blob);
  el.download = name;
  el.hidden = false;
}

/* ---- encrypt panel ---- */
let encSrc = null;
wireDrop($('enc-drop'), $('enc-file'), async (file) => {
  setStatus($('enc-status'), 'READING…');
  try {
    encSrc = await loadPngPixels(file);
    drawPreview($('enc-orig'), encSrc.pixels, encSrc.w, encSrc.h);
    clearCanvas($('enc-noise'));
    $('enc-meta').textContent = `${file.name} · ${encSrc.w}×${encSrc.h}`;
    $('enc-dl').hidden = true;
    setStatus($('enc-status'), 'READY — ENTER A PASSPHRASE', 'ok');
  } catch (e) {
    setStatus($('enc-status'), 'ERROR: ' + e.message, 'err');
  }
});

$('enc-go').addEventListener('click', async () => {
  const btn = $('enc-go');
  try {
    if (!encSrc) throw new Error('Drop a PNG first.');
    const p1 = $('enc-pass').value, p2 = $('enc-pass2').value;
    if (!p1) throw new Error('Passphrase must not be empty.');
    if (p1 !== p2) throw new Error('Passphrases do not match.');
    btn.disabled = true;
    setStatus($('enc-status'), 'DERIVING KEY… (600K KDF ROUNDS)');
    await new Promise((resolve) => requestAnimationFrame(resolve));
    const { png, noise } = await encryptPixels(encSrc.pixels, encSrc.w, encSrc.h, p1);
    drawPreview($('enc-noise'), noise, encSrc.w, encSrc.h);
    downloadLink($('enc-dl'), png, 'shattered.png');
    setStatus($('enc-status'), `DONE — ${png.length} BYTES OF PURE NOISE`, 'ok');
  } catch (e) {
    setStatus($('enc-status'), 'ERROR: ' + e.message, 'err');
  } finally {
    btn.disabled = false;
  }
});

/* ---- decrypt panel ---- */
let decSrc = null;
wireDrop($('dec-drop'), $('dec-file'), async (file) => {
  setStatus($('dec-status'), 'READING…');
  try {
    const buf = new Uint8Array(await file.arrayBuffer());
    const hdr = readHeader(buf); // validates structure, not the passphrase
    decSrc = buf;
    // show the noise itself as preview
    const { chunks } = hdr;
    const idat = concat(chunks.filter((c) => c.type === 'IDAT').map((c) => c.data));
    const stride = hdr.w * 4;
    const expectedRawLength = hdr.h * (stride + 1);
    const raw = await inflateBytes(idat, expectedRawLength);
    if (raw.length !== expectedRawLength) throw new Error('Invalid SHATTER image data length.');
    const noise = new Uint8Array(hdr.w * hdr.h * 4);
    for (let y = 0; y < hdr.h; y++) {
      const base = y * (stride + 1);
      if (raw[base] !== 0) throw new Error('Invalid SHATTER PNG filter data.');
      noise.set(raw.subarray(base + 1, base + 1 + stride), y * stride);
    }
    drawPreview($('dec-noise'), noise, hdr.w, hdr.h);
    clearCanvas($('dec-orig'));
    $('dec-meta').textContent = `SHATTER v${1} FILE · ${hdr.w}×${hdr.h}`;
    $('dec-dl').hidden = true;
    setStatus($('dec-status'), 'READY — ENTER THE PASSPHRASE', 'ok');
  } catch (e) {
    decSrc = null;
    setStatus($('dec-status'), 'ERROR: ' + e.message, 'err');
  }
});

$('dec-go').addEventListener('click', async () => {
  const btn = $('dec-go');
  try {
    if (!decSrc) throw new Error('Drop a shattered PNG first.');
    const p = $('dec-pass').value;
    if (!p) throw new Error('Passphrase must not be empty.');
    btn.disabled = true;
    setStatus($('dec-status'), 'VERIFYING… (600K KDF ROUNDS)');
    await new Promise((resolve) => requestAnimationFrame(resolve));
    const { w, h, pixels } = await decryptPixels(decSrc, p);
    drawPreview($('dec-orig'), pixels, w, h);
    const stride = w * 4;
    const scan = new Uint8Array(h * (stride + 1));
    for (let y = 0; y < h; y++) {
      scan[y * (stride + 1)] = 0;
      scan.set(pixels.subarray(y * stride, (y + 1) * stride), y * (stride + 1) + 1);
    }
    const png = await buildPng(w, h, scan, []);
    downloadLink($('dec-dl'), png, 'restored.png');
    setStatus($('dec-status'), 'SIGNATURE VALID — IMAGE RESTORED', 'ok');
  } catch (e) {
    setStatus($('dec-status'), 'ERROR: ' + e.message, 'err');
  } finally {
    btn.disabled = false;
  }
});
