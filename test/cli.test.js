'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const shatter = require('../src/shatter');
const { makePatternImage } = require('./util');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
const PASS = 'cli-e2e-passphrase';

function run(args, opts = {}) {
  return execFileSync('node', [CLI, ...args], { cwd: ROOT, encoding: 'utf8', ...opts });
}

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'xshatter-'));
}

test('keygen prints a 43-char base64url passphrase', () => {
  const out = run(['keygen']);
  const line = out.split('\n').find((l) => /^[A-Za-z0-9_-]{43}$/.test(l.trim()));
  assert.ok(line, 'expected a 43-char base64url line in keygen output');
  const out2 = run(['keygen']);
  assert.notEqual(out, out2, 'keygen must be random');
});

test('CLI end-to-end: encrypt -> decrypt restores pixel-identical image', () => {
  const dir = tmp();
  const img = makePatternImage(12, 10);
  const inP = path.join(dir, 'in.png');
  const encP = path.join(dir, 'enc.png');
  const decP = path.join(dir, 'dec.png');
  fs.writeFileSync(inP, shatter.encodePng(img.width, img.height, img.data));

  run(['encrypt', inP, '-o', encP, '--pass', PASS], { stdio: ['ignore', 'pipe', 'pipe'] });
  assert.ok(fs.existsSync(encP), 'encrypted file must exist');

  run(['decrypt', encP, '-o', decP, '--pass', PASS], { stdio: ['ignore', 'pipe', 'pipe'] });
  assert.ok(fs.existsSync(decP), 'decrypted file must exist');

  const back = shatter.decodePng(fs.readFileSync(decP));
  assert.deepEqual(back.data, img.data);
});

test('CLI decrypt with wrong passphrase: non-zero exit, no output file', () => {
  const dir = tmp();
  const img = makePatternImage(8, 8);
  const inP = path.join(dir, 'in.png');
  const encP = path.join(dir, 'enc.png');
  const decP = path.join(dir, 'dec.png');
  fs.writeFileSync(inP, shatter.encodePng(img.width, img.height, img.data));
  run(['encrypt', inP, '-o', encP, '--pass', PASS], { stdio: ['ignore', 'pipe', 'pipe'] });

  let err = null;
  try {
    run(['decrypt', encP, '-o', decP, '--pass', 'nope-wrong'], { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) { err = e; }
  assert.ok(err, 'decrypt must exit non-zero on wrong passphrase');
  assert.notEqual(err.status, 0);
  assert.match(err.stderr, /Authentication failed/);
  assert.ok(!fs.existsSync(decP), 'no output file may be written on auth failure');
});

test('CLI info shows header without decrypting; rejects plain PNGs', () => {
  const dir = tmp();
  const img = makePatternImage(9, 7);
  const inP = path.join(dir, 'in.png');
  const encP = path.join(dir, 'enc.png');
  fs.writeFileSync(inP, shatter.encodePng(img.width, img.height, img.data));
  run(['encrypt', inP, '-o', encP, '--pass', PASS], { stdio: ['ignore', 'pipe', 'pipe'] });

  const info = run(['info', encP]);
  assert.match(info, /9x7/);
  assert.match(info, /salt fingerprint/);

  let err = null;
  try { run(['info', inP]); } catch (e) { err = e; }
  assert.ok(err && err.status !== 0);
  assert.match(err.stderr, /Not a SHATTER file/);
});

test('CLI decrypt of a non-SHATTER PNG fails cleanly', () => {
  const dir = tmp();
  const img = makePatternImage(4, 4);
  const inP = path.join(dir, 'in.png');
  const outP = path.join(dir, 'out.png');
  fs.writeFileSync(inP, shatter.encodePng(img.width, img.height, img.data));
  let err = null;
  try {
    run(['decrypt', inP, '-o', outP, '--pass', PASS], { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) { err = e; }
  assert.ok(err && err.status !== 0);
  assert.match(err.stderr, /Not a SHATTER file/);
  assert.ok(!fs.existsSync(outP));
});
