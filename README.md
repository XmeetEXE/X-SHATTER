# X-SHATTER

Local-first image encryption. A PNG goes in — a **valid PNG that looks like pure random noise** comes out. Completely unrecognizable. Only the correct passphrase restores the original, pixel-identical. Wrong passphrase = clean authentication failure, nothing written.

Zero npm dependencies. Only Node.js built-ins (`node:crypto`, `node:zlib`, `node:fs`, `node:http`, `node:readline`, `node:test`). The browser dashboard uses WebCrypto + Canvas — same format, fully interoperable: files shattered in the dashboard decrypt with the CLI and vice versa.

```
original.png  →  [ X-SHATTER ]  →  shattered.png (pure static)
shattered.png →  [ X-SHATTER ]  →  restored.png  (pixel-identical)
```

## Quickstart

```bash
# check your setup
sh setup.sh        # Windows: setup.bat

# CLI
node src/cli.js keygen
node src/cli.js encrypt photo.png -o photo.shattered.png
node src/cli.js decrypt photo.shattered.png -o photo.restored.png
node src/cli.js info photo.shattered.png

# dashboard (dark local web UI)
node server.js
# → http://127.0.0.1:4174/
```

The browser dashboard limits images to 12 million pixels to avoid excessive memory use; use the CLI for larger files. The encrypt/decrypt prompts hide your passphrase. `--pass <p>` exists for scripting but prints a warning — it stays in your shell history.

## File format (v1)

| Item | Spec |
|---|---|
| Container | PNG, same width/height as input, 8-bit RGBA (color type 6) |
| IDAT payload | AES-256-GCM ciphertext of the **raw RGBA pixel buffer** (row-major, top→bottom, left→right — no PNG filter bytes in the plaintext) |
| Header | Exactly one `tEXt` chunk, keyword `X-Shatter`, text = base64url (no padding) of `{"v":1,"salt":"…","nonce":"…","tag":"…","w":W,"h":H}` |
| Salt / nonce / tag | 16 / 12 / 16 bytes; fresh random values for **every** encryption |
| AAD | ASCII `X-SHATTER/v1/{w}x{h}` — editing the stored dimensions fails authentication |
| KDF | PBKDF2-HMAC-SHA256, **600,000 iterations**, 32-byte key |
| Metadata | **All** input ancillary chunks are stripped — output is only `IHDR`, the `X-Shatter` `tEXt`, `IDAT`, `IEND` |

PBKDF2 is used deliberately instead of scrypt/argon2: WebCrypto has no scrypt, and PBKDF2 is what makes the CLI and the dashboard derive identical keys. The GCM tag lives in the header (not appended to the pixel data) on both sides.

## Browser processing note

The dashboard drains compression/decompression streams while feeding them, preventing large payloads from stalling due to stream backpressure.

## Security & limitations — read this

- **Your passphrase is everything.** There is no recovery, no backdoor, no "forgot passphrase" flow. A weak passphrase (short, dictionary word, reused) is the realistic attack — the crypto itself (AES-256-GCM + 600k-round PBKDF2) is not the weak link. Use `keygen`.
- **Keep the exact file.** Decryption needs the shattered PNG byte-for-byte: any recompression, resize, crop, or re-upload through an app that strips/re-encodes metadata (messengers, social apps) breaks it permanently. Store the `.png` as a file.
- **Encryption hides content, not the fact of encryption.** Anyone can see it's a SHATTER file (the `X-Shatter` header is plaintext by design — it's needed to decrypt). If you need deniability, this is the wrong tool.
- **Side channels:** the file leaks only approximate image dimensions (via file size). Timing/power analysis resistance is out of scope.
- **Not steganography.** The output screams "encrypted image" — that's the point: unrecognizable, not invisible.
- Parameters are stated plainly above so they can be scrutinized. No security-through-obscurity claims: the format is fully documented in `src/shatter.js` and `public/app.js`, and `test/interop.test.js` proves both implementations agree.

## Project layout

```
src/png.js       pure-JS PNG codec (decode 8-bit gray/RGB/RGBA, encode RGBA)
src/shatter.js   crypto core: KDF, AES-GCM, file format (shared spec)
src/cli.js       CLI: encrypt / decrypt / keygen / info
server.js        dashboard server, 127.0.0.1:4174 only
public/          dashboard UI (WebCrypto + Canvas, zero deps)
test/            node:test suite — 42 tests, all green (`node --test "test/*.test.js"`)
```

## License

XMEET License 2026 — © 2026 XMEET. Personal, educational, and defensive use. Redistribution or commercial use needs written permission. See `LICENSE`.
