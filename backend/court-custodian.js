#!/usr/bin/env node
'use strict';
// Run only on the independent custodian's computer. Never install private keys on the platform.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { issueRelease } = require('./court-vault');

function main() {
  const [command, ...args] = process.argv.slice(2);
  const passphrase = process.env.SENTINELQ_CUSTODIAN_PASSPHRASE;
  if (!passphrase || passphrase.length < 20) throw new Error('Set SENTINELQ_CUSTODIAN_PASSPHRASE to a unique passphrase of at least 20 characters on the custodian machine');
  if (command === 'init' && args.length === 1) {
    const directory = path.resolve(args[0]);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const keys = crypto.generateKeyPairSync('rsa', {
      modulusLength: 3072,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase }
    });
    fs.writeFileSync(path.join(directory, 'court-private.pem'), keys.privateKey, { flag: 'wx', mode: 0o600 });
    fs.writeFileSync(path.join(directory, 'court-public.pem'), keys.publicKey, { flag: 'wx', mode: 0o644 });
    console.log('Custodian keys created. Transfer ONLY court-public.pem to the platform; keep the private key and passphrase offline with secure backups.');
  } else if (command === 'release' && args.length === 4) {
    const [privatePath, requestPath, orderReference, outputPath] = args;
    const request = JSON.parse(fs.readFileSync(requestPath, 'utf8'));
    const key = crypto.createPrivateKey({ key: fs.readFileSync(privatePath), passphrase });
    const release = issueRelease(request, key, orderReference);
    fs.writeFileSync(outputPath, release, { flag: 'wx', mode: 0o600 });
    console.log('Release saved; valid for at most five minutes and only for the requesting admin session and evidence. Transfer it securely.');
  } else {
    throw new Error('Usage: node court-custodian.js init <directory> | release <private.pem> <request.json> <court-order-reference> <release.txt>');
  }
}
try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
