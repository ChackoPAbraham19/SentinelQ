'use strict';
// Offline verification uses only the receipt and a trusted public-key fingerprint.
const fs = require('node:fs');
const crypto = require('node:crypto');
const { ml_dsa65 } = require('../backend/node_modules/@noble/post-quantum/ml-dsa.js');
const { canonical } = require('../backend/case-integrity');

function verifyReceipt(receipt, expectedKeyId) {
  if (receipt?.domain !== 'SentinelQ/reporter-receipt/v1' || receipt.algorithm !== 'ML-DSA-65' || !receipt.payload || typeof receipt.publicKey !== 'string' || typeof receipt.signature !== 'string') return false;
  const key = Buffer.from(receipt.publicKey, 'base64');
  const signature = Buffer.from(receipt.signature, 'base64');
  if (key.length !== ml_dsa65.lengths.publicKey || signature.length !== ml_dsa65.lengths.signature || key.toString('base64') !== receipt.publicKey || signature.toString('base64') !== receipt.signature) return false;
  const keyId = `ml-dsa-65:${crypto.createHash('sha256').update(key).digest('hex')}`;
  if (keyId !== receipt.keyId || (expectedKeyId && keyId !== expectedKeyId)) return false;
  return ml_dsa65.verify(signature, Buffer.from(`${receipt.domain}\0${canonical(receipt.payload)}`), key);
}
if (require.main === module) {
  try {
    const [file, expectedKeyId] = process.argv.slice(2);
    if (!file) throw new Error('Usage: node scripts/verify-receipt.js <receipt.json> [trusted-key-id]');
    if (fs.statSync(file).size > 100000) throw new Error('Receipt too large');
    const receipt = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!verifyReceipt(receipt, expectedKeyId)) throw new Error('Receipt signature or trusted key did not match');
    console.log('Receipt signature verified. Key ID: ' + receipt.keyId);
    console.log(expectedKeyId ? 'Verified against the supplied trusted key ID.' : 'The included key verifies the signature; compare its ID with a previously trusted copy to authenticate the issuer.');
    console.log('This attests to the recorded evidence hashes, not the truth of the complaint.');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { verifyReceipt };
