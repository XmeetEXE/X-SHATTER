#!/usr/bin/env node
'use strict';
/*
 * X-SHATTER CLI — local-first image encryption.
 *   node src/cli.js encrypt <in.png> -o <out.png> [--pass <p>]
 *   node src/cli.js decrypt <in.png> -o <out.png> [--pass <p>]
 *   node src/cli.js keygen
 *   node src/cli.js info <file>
 */

const fs = require('node:fs');
const readline = require('node:readline');
const shatter = require('./shatter');

const BANNER = `
 ██╗  ██╗         ███████╗██╗  ██╗ █████╗ ████████╗████████╗███████╗██████╗
 ╚██╗██╔╝         ██╔════╝██║  ██║██╔══██╗╚══██╔══╝╚══██╔══╝██╔════╝██╔══██╗
  ╚███╔╝  █████╗  ███████╗███████║███████║   ██║      ██║   █████╗  ██████╔╝
  ██╔██╗  ╚════╝  ╚════██║██╔══██║██╔══██║   ██║      ██║   ██╔══╝  ██╔══██╗
 ██╔╝ ██╗        ███████║██║  ██║██║  ██║   ██║      ██║   ███████╗██║  ██║
 ╚═╝  ╚═╝        ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═╝
`;

function usage() {
  console.log(BANNER);
  console.log('Usage:');
  console.log('  node src/cli.js encrypt <in.png> -o <out.png> [--pass <p>]');
  console.log('  node src/cli.js decrypt <in.png> -o <out.png> [--pass <p>]');
  console.log('  node src/cli.js keygen');
  console.log('  node src/cli.js info <file>');
  console.log('');
  console.log('Options:');
  console.log('  -o <file>     output file (required for encrypt/decrypt)');
  console.log('  --pass <p>    passphrase on the command line (stays in shell');
  console.log('                history — prefer the hidden interactive prompt)');
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const out = { cmd: args[0], positional: [], output: undefined, pass: undefined, help: false };
  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a === '-o' && i + 1 < args.length) out.output = args[++i];
    else if (a === '--pass' && i + 1 < args.length) out.pass = args[++i];
    else if (a === '--help' || a === '-h') out.help = true;
    else if (a.startsWith('-')) { console.error(`Error: unknown option ${a}`); process.exit(2); }
    else out.positional.push(a);
  }
  return out;
}

/** Hidden passphrase prompt (typed characters are not echoed). */
function promptHidden(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const orig = rl._writeToOutput.bind(rl);
    rl._writeToOutput = (str) => { if (/[\r\n]/.test(str)) orig(str); };
    rl.question(question, (ans) => { rl.close(); resolve(ans); });
  });
}

async function getPassphrase(passOpt, confirm) {
  if (passOpt !== undefined) {
    console.error('Warning: --pass puts the passphrase in shell history; prefer the interactive prompt.');
    return passOpt;
  }
  const p1 = await promptHidden('Passphrase: ');
  if (confirm) {
    const p2 = await promptHidden('Confirm passphrase: ');
    if (p1 !== p2) { console.error('Error: passphrases do not match.'); process.exit(1); }
  }
  return p1;
}

function readFile(p) {
  try {
    return fs.readFileSync(p);
  } catch (e) {
    console.error(`Error: cannot read "${p}": ${e.message}`);
    process.exit(1);
  }
}

async function cmdEncrypt(o) {
  const inPath = o.positional[0];
  if (!inPath) { console.error('Error: input file required.'); process.exit(2); }
  if (!o.output) { console.error('Error: output file required (-o <out.png>).'); process.exit(2); }
  const buf = readFile(inPath);
  let img;
  try {
    img = shatter.decodePng(buf);
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }
  const pass = await getPassphrase(o.pass, true);
  if (!pass) { console.error(`Error: ${shatter.ERR_EMPTY_PASS}`); process.exit(1); }
  const out = shatter.encryptPixels(img.data, img.width, img.height, pass);
  fs.writeFileSync(o.output, out);
  console.log(`Shattered ${img.width}x${img.height} -> ${o.output}`);
}

async function cmdDecrypt(o) {
  const inPath = o.positional[0];
  if (!inPath) { console.error('Error: input file required.'); process.exit(2); }
  if (!o.output) { console.error('Error: output file required (-o <out.png>).'); process.exit(2); }
  const buf = readFile(inPath);
  const pass = await getPassphrase(o.pass, false);
  if (!pass) { console.error(`Error: ${shatter.ERR_EMPTY_PASS}`); process.exit(1); }
  let img;
  try {
    // Fully decrypted + authenticated in memory BEFORE anything is written.
    img = shatter.decryptPixels(buf, pass);
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }
  fs.writeFileSync(o.output, shatter.encodePng(img.width, img.height, img.data));
  console.log(`Restored ${img.width}x${img.height} -> ${o.output}`);
}

function cmdKeygen() {
  console.log(shatter.generatePassphrase());
}

function cmdInfo(o) {
  const inPath = o.positional[0];
  if (!inPath) { console.error('Error: input file required.'); process.exit(2); }
  const buf = readFile(inPath);
  try {
    const info = shatter.infoFile(buf);
    console.log(`SHATTER v${info.version} — ${info.width}x${info.height}`);
    console.log(`salt fingerprint : ${info.saltFp}…`);
    console.log(`nonce fingerprint: ${info.nonceFp}…`);
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }
}

async function main() {
  const o = parseArgs(process.argv);
  if (o.help || !o.cmd) { usage(); process.exit(o.cmd ? 0 : 2); }
  console.log(BANNER);
  switch (o.cmd) {
    case 'encrypt': await cmdEncrypt(o); break;
    case 'decrypt': await cmdDecrypt(o); break;
    case 'keygen': cmdKeygen(); break;
    case 'info': cmdInfo(o); break;
    default:
      console.error(`Error: unknown command "${o.cmd}".`);
      usage();
      process.exit(2);
  }
}

main().catch((e) => { console.error(`Error: ${e.message}`); process.exit(1); });
