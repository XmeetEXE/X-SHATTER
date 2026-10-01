# X-SHATTER

<p align="center">
  <strong>Turn a PNG into pure static. Restore it only with the right passphrase.</strong>
</p>

<p align="center">
  <a href="https://github.com/XmeetEXE/X-SHATTER"><img src="https://img.shields.io/badge/PROJECT-X--SHATTER-111111?style=for-the-badge&logo=github&logoColor=white" alt="X-SHATTER"></a>
  <img src="https://img.shields.io/badge/Runtime-Node.js-43853D?style=for-the-badge&logo=node.js&logoColor=white" alt="Node.js">
  <img src="https://img.shields.io/badge/Dependencies-Zero-16A34A?style=for-the-badge" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/Crypto-AES--256--GCM-2563EB?style=for-the-badge" alt="AES-256-GCM">
</p>

<p align="center">
  <em>Local-first · Cross-compatible CLI and browser dashboard · No npm dependencies</em>
</p>

---

## What is X-SHATTER?

**X-SHATTER** is a local-first image encryption tool that transforms a PNG into another valid PNG filled with noise-like pixels. The original image can be restored with the correct passphrase.

No cloud upload. No external service. Your files stay on your machine.

```text
  ORIGINAL PNG             X-SHATTER             SHATTERED PNG
  ┌─────────────┐       ┌──────────────┐       ┌─────────────────┐
  │             │       │              │       │ ░▒▓░▒░▓▒▓░▒░▓▒ │
  │   PHOTO     │  ───▶ │   ENCRYPT    │ ───▶  │ ▒▓░▒▓░▒░▓▒▓░▒░ │
  │             │       │              │       │ ▓▒░▓▒▒░▓░▒▓░▒▓ │
  └─────────────┘       └──────────────┘       └─────────────────┘
                                                    │
                                             Correct passphrase
                                                    ▼
                                             ┌─────────────────┐
                                             │ RESTORED PNG    │
                                             │ Pixel-identical │
                                             └─────────────────┘
```

> The output is encrypted data represented as PNG pixel data. It is not steganography, and the file itself reveals that it was processed by X-SHATTER.

## Features

- **Image encryption:** Encrypt PNG pixel data using AES-256-GCM.
- **Passphrase-based keys:** Derive a 256-bit key with PBKDF2-HMAC-SHA256.
- **Noise-like output:** The encrypted pixel data renders as a noise-filled PNG.
- **Pixel-identical restoration:** Restore the original RGBA pixels with the correct passphrase.
- **CLI + browser dashboard:** Use the terminal or a local dark-themed web interface.
- **Cross-compatible format:** Encrypt in the dashboard and decrypt with the CLI, or vice versa.
- **Local-first:** Processing happens locally; no remote upload service is involved.
- **Zero npm dependencies:** Built with Node.js built-ins, WebCrypto, and Canvas.
- **Authentication checks:** Incorrect passphrases or modified encrypted data fail verification.

## Quick start

### Requirements

- Node.js
- A modern browser for the dashboard

### Setup

Clone the repository and enter the project folder:

```bash
git clone https://github.com/XmeetEXE/X-SHATTER.git
cd X-SHATTER
```

Run the setup check:

```bash
# macOS / Linux
sh setup.sh

# Windows
setup.bat
```

### Command-line interface

Generate a passphrase:

```bash
node src/cli.js keygen
```

Encrypt a PNG:

```bash
node src/cli.js encrypt photo.png -o photo.shattered.png
```

Decrypt it:

```bash
node src/cli.js decrypt photo.shattered.png -o photo.restored.png
```

Inspect a Shatter file:

```bash
node src/cli.js info photo.shattered.png
```

### Browser dashboard

Start the local server:

```bash
node server.js
```

Open **http://127.0.0.1:4174/** in your browser.

The dashboard is bound to localhost. Its current image limit is **12 million pixels** to reduce excessive browser memory use. Use the CLI for larger images.

> The interactive passphrase prompt hides input. The `--pass <p>` option is available for scripting, but passing a passphrase directly can expose it in shell history or process information. Prefer the interactive prompt when possible.

## How it works

1. **Read:** X-SHATTER decodes the input PNG into RGBA pixel data.
2. **Derive:** A key is derived from the passphrase and a fresh random salt using PBKDF2-HMAC-SHA256.
3. **Encrypt:** AES-256-GCM encrypts the pixel buffer using a fresh nonce and authenticated additional data (AAD).
4. **Package:** The ciphertext is written into a valid PNG container with X-SHATTER metadata.
5. **Restore:** During decryption, the same key is derived and GCM authentication is checked before the original pixel data is restored.

```text
Passphrase + Salt
       │
       ▼
 PBKDF2-HMAC-SHA256
       │
       ▼
  256-bit Key ───────────────┐
                             ▼
RGBA Pixels ───────────▶ AES-256-GCM ───▶ Ciphertext
                             │
                             └───────────▶ Authentication Tag
```

## File format (v1)

| Component | Specification |
|---|---|
| Container | PNG, same width and height as input, 8-bit RGBA |
| Encrypted payload | AES-256-GCM ciphertext of the raw RGBA pixel buffer |
| Header | One `tEXt` chunk with keyword `X-Shatter` |
| Metadata | Base64url-encoded JSON containing version, salt, nonce, tag, width, and height |
| Salt | 16 random bytes |
| Nonce | 12 random bytes |
| Authentication tag | 16 bytes |
| KDF | PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte key |
| AAD | `X-SHATTER/v1/{w}x{h}` |
| PNG chunks | `IHDR`, X-Shatter `tEXt`, `IDAT`, `IEND` |

The format is documented in `src/shatter.js` and `public/app.js`. PBKDF2 is used for compatibility between Node.js and browser WebCrypto, which does not provide scrypt as a built-in KDF.

## Security notes

- **Keep your passphrase safe.** There is no password reset, recovery mechanism, or backdoor. If the passphrase is lost, the image may be unrecoverable.
- **Use a strong, unique passphrase.** A weak or reused passphrase is a more realistic risk than brute-forcing AES-256-GCM directly.
- **Keep the exact output file.** Recompression, resizing, cropping, or services that strip or rewrite PNG metadata can corrupt the file and prevent decryption.
- **Encryption is not anonymity.** The `X-Shatter` header is intentionally readable so the file can be identified and decrypted. The tool does not hide the fact that encryption was used.
- **Metadata can reveal dimensions.** The image dimensions are stored in the header.
- **No side-channel protection claim.** Resistance to timing, power, or other side-channel analysis is outside the project's scope.
- **Review before relying on it.** Cryptographic parameters are documented for inspection; do not treat this README or the implementation as a substitute for an independent security audit.

## Project structure

```text
X-SHATTER/
├── src/
│   ├── png.js          # PNG decoding and RGBA encoding
│   ├── shatter.js      # Crypto core and file format
│   └── cli.js          # CLI commands
├── public/
│   └──               # Browser dashboard (WebCrypto + Canvas)
├── test/               # Automated tests
├── server.js           # Local dashboard server
├── setup.sh            # macOS / Linux setup check
├── setup.bat           # Windows setup check
└── README.md
```

## Tests

Run the test suite with Node.js:

```bash
node --test test/*.test.js
```

The repository includes tests for the core format and CLI/dashboard interoperability.

## License

**XMEET License 2026** · © 2026 XMEET

Personal, educational, and defensive use. Redistribution or commercial use requires written permission. See [LICENSE](LICENSE) for the full terms.

---

<p align="center">
  <strong>X-SHATTER</strong><br>
  <sub>Local-first image encryption by XMEET</sub>
</p>
