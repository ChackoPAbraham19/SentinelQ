'use strict';
const crypto = require('node:crypto');
const court = require('./court-vault');

class CustodySetup {
  constructor(storage, env = process.env, now = Date.now) {
    this.storage = storage; this.env = env; this.now = now; this.invite = null;
  }
  async publicKey() {
    if (this.env.SENTINELQ_COURT_PUBLIC_KEY || this.env.SENTINELQ_COURT_PUBLIC_KEY_PATH) return court.publicKeyFromEnvironment(this.env);
    const pem = await this.storage.getCustodianPublicKey();
    if (!pem) return null;
    return court.publicKeyFromEnvironment({ SENTINELQ_COURT_PUBLIC_KEY: pem });
  }
  async requirePublicKey() {
    const key = await this.publicKey();
    if (!key) throw new Error('Custody setup required');
    return key;
  }
  async createInvite(actor, origin) {
    if (await this.publicKey()) throw new Error('Custody is already configured');
    const token = crypto.randomBytes(32).toString('base64url');
    this.invite = { tokenHash: court.hash(token), actor, expiresAt: this.now() + 30 * 60 * 1000, challenge: `SentinelQ custody enrollment\n${origin}\n${token}` };
    return { token, expiresAt: this.invite.expiresAt };
  }
  check(token) {
    if (typeof token !== 'string' || token.length !== 43 || !this.invite || this.invite.busy || this.now() >= this.invite.expiresAt || court.hash(token) !== this.invite.tokenHash) throw new Error('Setup invitation is invalid, expired, or already used');
    return this.invite;
  }
  async register(token, pem, proof) {
    const invite = this.check(token);
    if (typeof pem !== 'string' || pem.length > 4096 || typeof proof !== 'string' || proof.length > 2048) throw new Error('Invalid enrollment');
    const key = court.publicKeyFromEnvironment({ SENTINELQ_COURT_PUBLIC_KEY: pem });
    if (!crypto.verify('sha256', Buffer.from(invite.challenge), { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, Buffer.from(proof, 'base64'))) throw new Error('Recovery key verification failed');
    invite.busy = true;
    try {
      if (await this.publicKey()) throw new Error('Custody is already configured');
      const normalized = key.export({ type: 'spki', format: 'pem' });
      const stored = await this.storage.registerCustodianPublicKey(normalized);
      if (stored !== normalized) throw new Error('Custody is already configured');
      this.invite = null;
      return { keyId: court.keyId(key), actor: invite.actor };
    } finally { invite.busy = false; }
  }
}
module.exports = { CustodySetup };
