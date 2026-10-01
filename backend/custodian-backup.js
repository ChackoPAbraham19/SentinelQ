'use strict';
const crypto = require('node:crypto');

function readRecoveryKey(contents, passphrase) {
  if (contents.length > 16384) throw new Error('Invalid custodian recovery file');
  if (!contents.toString('utf8').trimStart().startsWith('{')) return crypto.createPrivateKey({ key: contents, passphrase });
  const backup = JSON.parse(contents.toString('utf8'));
  if (backup.format !== 'sentinelq-custodian-v1' || backup.iterations !== 600000 || typeof passphrase !== 'string' || passphrase.length < 20) throw new Error('Invalid custodian recovery file');
  const salt = Buffer.from(backup.salt, 'base64'), iv = Buffer.from(backup.iv, 'base64'), encrypted = Buffer.from(backup.encryptedPrivateKey, 'base64');
  if (salt.length !== 16 || iv.length !== 12 || encrypted.length < 17 || encrypted.length > 9000) throw new Error('Invalid custodian recovery file');
  const wrap = crypto.pbkdf2Sync(passphrase, salt, 600000, 32, 'sha256');
  let plaintext;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', wrap, iv);
    decipher.setAAD(Buffer.from(backup.format));
    decipher.setAuthTag(encrypted.subarray(-16));
    plaintext = Buffer.concat([decipher.update(encrypted.subarray(0, -16)), decipher.final()]);
    const key = crypto.createPrivateKey({ key: plaintext, format: 'der', type: 'pkcs8' });
    const publicKey = crypto.createPublicKey(key).export({ type: 'spki', format: 'pem' });
    if (publicKey !== backup.publicKey || key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < 3072) throw new Error('Recovery key mismatch');
    return key;
  } finally { wrap.fill(0); plaintext?.fill(0); }
}
module.exports = { readRecoveryKey };
