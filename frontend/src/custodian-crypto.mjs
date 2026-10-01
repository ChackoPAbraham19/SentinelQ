const encoder = new TextEncoder();
const FORMAT = 'sentinelq-custodian-v1';
const ITERATIONS = 600000;
const base64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unbase64 = text => Uint8Array.from(atob(text), char => char.charCodeAt(0));
const pem = bytes => `-----BEGIN PUBLIC KEY-----\n${base64(bytes).match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`;

async function wrappingKey(passphrase, salt) {
  if (typeof passphrase !== 'string' || passphrase.length < 20) throw new Error('Use a unique recovery passphrase of at least 20 characters.');
  const material = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function generateRecoveryFile(passphrase) {
  if (!crypto.subtle) throw new Error('Use a browser with secure cryptography support over HTTPS.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrap = await wrappingKey(passphrase, salt);
  const keys = await crypto.subtle.generateKey({ name: 'RSA-PSS', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const privateBytes = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keys.privateKey));
  try {
    const publicKey = pem(await crypto.subtle.exportKey('spki', keys.publicKey));
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(FORMAT) }, wrap, privateBytes);
    return { format: FORMAT, iterations: ITERATIONS, salt: base64(salt), iv: base64(iv), publicKey, encryptedPrivateKey: base64(encrypted) };
  } finally { privateBytes.fill(0); }
}

export async function enrollmentProof(backup, passphrase, challenge) {
  if (backup.format !== FORMAT || backup.iterations !== ITERATIONS || typeof challenge !== 'string' || challenge.length > 1000) throw new Error('Invalid recovery file or invitation.');
  const salt = unbase64(backup.salt), iv = unbase64(backup.iv);
  if (salt.length !== 16 || iv.length !== 12 || backup.encryptedPrivateKey.length > 12000) throw new Error('Invalid recovery file.');
  const wrap = await wrappingKey(passphrase, salt);
  let bytes;
  try {
    bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(FORMAT) }, wrap, unbase64(backup.encryptedPrivateKey)));
    const key = await crypto.subtle.importKey('pkcs8', bytes, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['sign']);
    const proof = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, key, encoder.encode(challenge));
    const publicKey = await crypto.subtle.importKey('spki', unbase64(backup.publicKey.replace(/-----[^-]+-----|\s/g, '')), { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
    if (!await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, publicKey, proof, encoder.encode(challenge))) throw new Error('Key mismatch');
    return { publicKey: backup.publicKey, proof: base64(proof) };
  } catch { throw new Error('The recovery file or passphrase could not be verified.'); }
  finally { bytes?.fill(0); }
}
